/**
 * x402-trinity/evm-tx - sign and submit EIP-1559 transactions, plus signature recovery.
 *
 * OPTIONAL server-side module. The buyer core never needs this: it produces signed
 * authorizations and hands them over. This is for whoever SUBMITS them - a facilitator,
 * a collector, or anything else that puts transactions on a chain.
 *
 * Zero dependencies: RLP, EIP-1559 encoding and ecrecover are all inline.
 */
import { keccak256, toHex, fromHex, __internals } from './x402.ts';

type Jac = [bigint, bigint, bigint];
// Typed rather than `as any`: the curve constants must stay bigint or arithmetic below
// silently degrades to number and stops type-checking.
const {
  toBig, beBytes, signWith, makeNonce, addressOf, jMul, jAdd, affine, G, N, P,
} = __internals as unknown as {
  toBig: (b: Uint8Array) => bigint;
  beBytes: (v: bigint, len: number) => Uint8Array;
  signWith: (nonce: unknown, z: bigint, d: bigint) => string;
  makeNonce: () => unknown;
  addressOf: (d: bigint) => string;
  jMul: (k: bigint, p: Jac) => Jac;
  jAdd: (a: Jac, b: Jac) => Jac;
  affine: (p: Jac) => [bigint, bigint];
  G: Jac; N: bigint; P: bigint;
};

/* ------------------------------- RLP ------------------------------- */

const cat = (...a: Uint8Array[]): Uint8Array => {
  const t = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { t.set(x, o); o += x.length; }
  return t;
};
/** integer -> minimal big-endian bytes; zero is the empty string, per RLP */
const minimal = (v: bigint): Uint8Array => {
  if (v === 0n) return new Uint8Array(0);
  let h = v.toString(16);
  if (h.length % 2) h = '0' + h;
  return fromHex('0x' + h);
};
const rlpLen = (len: number, offset: number): Uint8Array => {
  if (len < 56) return new Uint8Array([offset + len]);
  const lb = minimal(BigInt(len));
  return cat(new Uint8Array([offset + 55 + lb.length]), lb);
};
type RlpInput = Uint8Array | RlpInput[];
export function rlp(x: RlpInput): Uint8Array {
  if (Array.isArray(x)) {
    const payload = cat(...x.map(rlp));
    return cat(rlpLen(payload.length, 0xc0), payload);
  }
  if (x.length === 1 && x[0] < 0x80) return x;
  return cat(rlpLen(x.length, 0x80), x);
}

/* --------------------------- ecrecover --------------------------- */

const mod = (a: bigint, m: bigint): bigint => { const r = a % m; return r < 0n ? r + m : r; };
const modPow = (b: bigint, e: bigint, m: bigint): bigint => {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = mod(r * b, m); b = mod(b * b, m); e >>= 1n; }
  return r;
};
const inv = (a: bigint, m: bigint): bigint => {
  let r = m, nr = mod(a, m), s = 0n, ns = 1n;
  while (nr !== 0n) { const q = r / nr; [r, nr] = [nr, r - q * nr]; [s, ns] = [ns, s - q * ns]; }
  return mod(s, m);
};

/**
 * Recover the signing address from a digest and a 65-byte r||s||v signature.
 * This is exactly what EIP-3009 does on-chain, so it is the right local check before
 * spending gas submitting something that would revert.
 */
export function recoverSigner(digest: bigint, signature: string): string | null {
  try {
    const sig = fromHex(signature);
    if (sig.length !== 65) return null;
    const r = toBig(sig.slice(0, 32)), s = toBig(sig.slice(32, 64)), v = sig[64] - 27;
    if (r === 0n || r >= N || s === 0n || s >= N || v < 0 || v > 3) return null;
    const x = r + (v >> 1 ? N : 0n);
    if (x >= P) return null;
    let y = modPow(mod(x * x * x + 7n, P), (P + 1n) / 4n, P);
    if (mod(y * y, P) !== mod(x * x * x + 7n, P)) return null;   // not on the curve
    if ((y & 1n) !== BigInt(v & 1)) y = P - y;
    const Q = jMul(inv(r, N), jAdd(jMul(s, [x, y, 1n]), jMul(mod(-digest, N), G)));
    if (Q[2] === 0n) return null;
    const xy = affine(Q);
    return toHex(keccak256(beBytes(xy[0], 32), beBytes(xy[1], 32)).slice(12));
  } catch {
    return null;
  }
}

/* --------------------------- JSON-RPC --------------------------- */

export interface RpcConfig { urls: string[]; timeoutMs?: number; retries?: number }

export function createRpc(cfg: RpcConfig) {
  const urls = cfg.urls;
  const timeoutMs = cfg.timeoutMs ?? 15000;
  const retries = cfg.retries ?? 3;
  if (!urls.length) throw new Error('evm-tx: at least one RPC url is required');

  return async function rpc(method: string, params: unknown[] = []): Promise<any> {
    let last: unknown;
    for (let attempt = 0; attempt < retries; attempt++) {
      for (const url of urls) {
        try {
          const r = await fetch(url, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
            signal: AbortSignal.timeout(timeoutMs),
          });
          const j = await r.json();
          if (j.error) {
            const msg = String(j.error.message ?? '');
            // Transient infrastructure problems are worth failing over for; a real
            // contract revert is not - surface it immediately.
            if (!/healthy|unavailable|rate|limit|timeout|busy|capacity/i.test(msg)) {
              throw new Error(`${method}: ${msg}`);
            }
            last = new Error(`${method}: ${msg}`);
            continue;
          }
          return j.result;
        } catch (e) {
          if (e instanceof Error && e.message.startsWith(method + ':')) throw e;
          last = e;
        }
      }
      await new Promise(r => setTimeout(r, 800 * (attempt + 1)));
    }
    throw last instanceof Error ? last : new Error(`${method}: all RPCs failed`);
  };
}

/* ----------------------- transaction signing ----------------------- */

export interface TxRequest {
  chainId: number;
  to: string;
  data: string;
  gasLimit?: bigint;
  value?: bigint;
  /** Multiplier applied to the observed gas price for maxFeePerGas. Default 4. */
  feeMultiplier?: bigint;
}

/**
 * Sign and broadcast an EIP-1559 transaction.
 *
 * Re-submitting the SAME signed transaction is idempotent at the network layer: identical
 * nonce plus identical signature yields an identical hash. That makes RPC failover safe here.
 */
export async function sendTransaction(
  rpc: (m: string, p?: unknown[]) => Promise<any>,
  privateKey: string,
  tx: TxRequest,
): Promise<{ hash: string; from: string }> {
  const d = toBig(fromHex(privateKey));
  if (d === 0n || d >= N) throw new Error('evm-tx: invalid key material');
  const from = addressOf(d);

  const [nonceHex, gasPriceHex] = await Promise.all([
    rpc('eth_getTransactionCount', [from, 'pending']),
    rpc('eth_gasPrice', []),
  ]);
  const tip = 1_000_000n;                                    // 0.001 gwei
  const maxFee = BigInt(gasPriceHex) * (tx.feeMultiplier ?? 4n) + tip;

  const fields: RlpInput[] = [
    minimal(BigInt(tx.chainId)), minimal(BigInt(nonceHex)), minimal(tip), minimal(maxFee),
    minimal(tx.gasLimit ?? 200_000n), fromHex(tx.to), minimal(tx.value ?? 0n),
    fromHex(tx.data), [],
  ];
  const sigHash = toBig(keccak256(new Uint8Array([0x02]), rlp(fields)));
  const sig = fromHex(signWith(makeNonce(), sigHash, d));

  // Self-check before spending gas: if RLP or the signing hash were wrong this would not
  // recover to us, and the node would reject or - worse - mis-attribute the transaction.
  if (recoverSigner(sigHash, toHex(sig)) !== from) {
    throw new Error('evm-tx: signed transaction does not recover to the sender; refusing to broadcast');
  }

  const raw = toHex(cat(new Uint8Array([0x02]),
    rlp([...fields, minimal(BigInt(sig[64] - 27)), sig.slice(0, 32), sig.slice(32, 64)])));
  const hash = await rpc('eth_sendRawTransaction', [raw]);
  return { hash, from };
}

export async function waitForReceipt(
  rpc: (m: string, p?: unknown[]) => Promise<any>,
  hash: string,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<{ ok: boolean; gasUsed: number; blockNumber: number } | null> {
  const deadline = Date.now() + (opts.timeoutMs ?? 120000);
  const poll = opts.pollMs ?? 2500;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, poll));
    const rc = await rpc('eth_getTransactionReceipt', [hash]).catch(() => null);
    if (rc) return { ok: rc.status === '0x1', gasUsed: Number(BigInt(rc.gasUsed)), blockNumber: Number(BigInt(rc.blockNumber)) };
  }
  return null;
}

/** abi.encode word: bigint, 0x-hex, or bytes. */
export const word = (v: bigint | string | Uint8Array): string => {
  if (typeof v === 'bigint') return toHex(beBytes(v, 32)).slice(2);
  const b = typeof v === 'string' ? fromHex(v) : v;
  const w = new Uint8Array(32);
  w.set(b, 32 - b.length);
  return toHex(w).slice(2);
};

/** 4-byte selector for a solidity signature. */
export const selector = (sig: string): string =>
  toHex(keccak256(new TextEncoder().encode(sig))).slice(0, 10);

/** Calldata for USDC's transferWithAuthorization. */
export function transferWithAuthorizationData(
  auth: { from: string; to: string; value: string; validAfter: string; validBefore: string; nonce: string },
  signature: string,
): string {
  const sig = fromHex(signature);
  return selector('transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)')
    + word(auth.from) + word(auth.to) + word(BigInt(auth.value))
    + word(BigInt(auth.validAfter)) + word(BigInt(auth.validBefore)) + word(auth.nonce)
    + word(BigInt(sig[64])) + word(sig.slice(0, 32)) + word(sig.slice(32, 64));
}
