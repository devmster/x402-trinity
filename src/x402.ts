/**
 * x402-trinity - zero-dependency x402 payment interceptor for edge runtimes.
 *
 * Native primitives only: BigInt, Uint32Array, crypto.getRandomValues, fetch, btoa.
 * secp256k1 + keccak256 + EIP-712/EIP-3009 are implemented inline because WebCrypto
 * (crypto.subtle) exposes neither the secp256k1 curve nor a keccak256 digest.
 *
 * Live-path cost once warm: 3 keccak permutations + 2 modmuls. No key generation,
 * no curve multiplication, no scalar tables built at request time.
 */

/* ============================ keccak-256 ============================ */

const RC_LO = new Uint32Array([
  0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
  0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
  0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
  0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
]);
const RC_HI = new Uint32Array([
  0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
  0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
  0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
]);
// rho rotation offsets, lane index = x + 5y
const RHO = new Uint8Array([
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
  41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
]);
// pi permutation: PI[src] = dst, where dst = y + 5*((2x+3y) mod 5)
const PI = (() => {
  const p = new Uint8Array(25);
  for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) p[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
  return p;
})();

const _S = new Uint32Array(50);
const _B = new Uint32Array(50);
const _C = new Uint32Array(10);

function keccakF(S: Uint32Array): void {
  const B = _B, C = _C;
  for (let rnd = 0; rnd < 24; rnd++) {
    // theta
    for (let x = 0; x < 5; x++) {
      let lo = 0, hi = 0;
      for (let y = 0; y < 25; y += 5) { const i = (x + y) << 1; lo ^= S[i]; hi ^= S[i + 1]; }
      C[x << 1] = lo; C[(x << 1) + 1] = hi;
    }
    for (let x = 0; x < 5; x++) {
      const a = ((x + 1) % 5) << 1, b = ((x + 4) % 5) << 1;
      const lo1 = C[a], hi1 = C[a + 1];
      const dlo = C[b] ^ ((lo1 << 1) | (hi1 >>> 31));
      const dhi = C[b + 1] ^ ((hi1 << 1) | (lo1 >>> 31));
      for (let y = 0; y < 25; y += 5) { const i = (x + y) << 1; S[i] ^= dlo; S[i + 1] ^= dhi; }
    }
    // rho + pi
    for (let i = 0; i < 25; i++) {
      const n = RHO[i], lo = S[i << 1], hi = S[(i << 1) + 1], d = PI[i] << 1;
      if (n === 0) { B[d] = lo; B[d + 1] = hi; }
      else if (n < 32) { B[d] = (lo << n) | (hi >>> (32 - n)); B[d + 1] = (hi << n) | (lo >>> (32 - n)); }
      else { const m = n - 32; B[d] = (hi << m) | (lo >>> (32 - m)); B[d + 1] = (lo << m) | (hi >>> (32 - m)); }
    }
    // chi
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) {
      const i = (x + y) << 1, i1 = (((x + 1) % 5) + y) << 1, i2 = (((x + 2) % 5) + y) << 1;
      S[i] = B[i] ^ (~B[i1] & B[i2]);
      S[i + 1] = B[i + 1] ^ (~B[i1 + 1] & B[i2 + 1]);
    }
    // iota
    S[0] ^= RC_LO[rnd]; S[1] ^= RC_HI[rnd];
  }
}

/** keccak256 over one or more byte runs, absorbed as if concatenated. */
export function keccak256(...parts: Uint8Array[]): Uint8Array {
  const S = _S; S.fill(0);
  let p = 0; // byte offset inside the 136-byte rate block
  for (const part of parts) {
    for (let j = 0; j < part.length; j++) {
      S[p >> 2] ^= part[j] << ((p & 3) << 3);
      if (++p === 136) { keccakF(S); p = 0; }
    }
  }
  S[p >> 2] ^= 0x01 << ((p & 3) << 3); // keccak (not SHA3) padding
  S[33] ^= 0x80000000;                 // final bit at byte 135
  keccakF(S);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (S[i >> 2] >>> ((i & 3) << 3)) & 0xff;
  return out;
}

/* ======================= bytes / hex / abi words ======================= */

const HEXC = '0123456789abcdef';
export const toHex = (b: Uint8Array): string => {
  let s = '0x';
  for (let i = 0; i < b.length; i++) s += HEXC[b[i] >> 4] + HEXC[b[i] & 15];
  return s;
};
export const fromHex = (h: string): Uint8Array => {
  const s = h.slice(0, 2) === '0x' ? h.slice(2) : h;
  const b = new Uint8Array(s.length >> 1);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i << 1, (i << 1) + 2), 16);
  return b;
};
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const beBytes = (v: bigint, len: number): Uint8Array => {
  const b = new Uint8Array(len);
  for (let i = len - 1; i >= 0 && v > 0n; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
};
const toBig = (b: Uint8Array): bigint => {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
};
/** One abi.encode word: uint256, address or bytes32. */
const word = (v: bigint | string | Uint8Array): Uint8Array => {
  if (typeof v === 'bigint') return beBytes(v, 32);
  const b = typeof v === 'string' ? fromHex(v) : v;
  const w = new Uint8Array(32);
  w.set(b, 32 - b.length);
  return w;
};

/* ============================= secp256k1 ============================= */

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const HALF_N = N >> 1n;

type J = [bigint, bigint, bigint]; // jacobian point
const mod = (a: bigint, m: bigint): bigint => { const r = a % m; return r < 0n ? r + m : r; };

function inv(a: bigint, m: bigint): bigint {
  let r = m, nr = mod(a, m), s = 0n, ns = 1n;
  while (nr !== 0n) {
    const q = r / nr;
    const tr = r - q * nr; r = nr; nr = tr;
    const ts = s - q * ns; s = ns; ns = ts;
  }
  return mod(s, m);
}

function jDbl(p: J): J {
  const X = p[0], Y = p[1], Z = p[2];
  if (Y === 0n || Z === 0n) return [0n, 1n, 0n];
  const A = mod(X * X, P), B = mod(Y * Y, P), C = mod(B * B, P);
  const D = mod(2n * (mod((X + B) * (X + B), P) - A - C), P);
  const E = mod(3n * A, P), F = mod(E * E, P);
  const X3 = mod(F - 2n * D, P);
  return [X3, mod(E * (D - X3) - 8n * C, P), mod(2n * Y * Z, P)];
}

function jAdd(p: J, q: J): J {
  const X1 = p[0], Y1 = p[1], Z1 = p[2], X2 = q[0], Y2 = q[1], Z2 = q[2];
  if (Z1 === 0n) return q;
  if (Z2 === 0n) return p;
  const ZZ1 = mod(Z1 * Z1, P), ZZ2 = mod(Z2 * Z2, P);
  const U1 = mod(X1 * ZZ2, P), U2 = mod(X2 * ZZ1, P);
  const S1 = mod(Y1 * Z2 * ZZ2, P), S2 = mod(Y2 * Z1 * ZZ1, P);
  const H = mod(U2 - U1, P), R = mod(S2 - S1, P);
  if (H === 0n) return R === 0n ? jDbl(p) : [0n, 1n, 0n];
  const HH = mod(H * H, P), HHH = mod(H * HH, P), V = mod(U1 * HH, P);
  const X3 = mod(R * R - HHH - 2n * V, P);
  return [X3, mod(R * (V - X3) - S1 * HHH, P), mod(Z1 * Z2 * H, P)];
}

/**
 * Scalar multiply. Runs only off the hot path (key setup + idle nonce fill), so it is
 * a plain double-and-add: variable-time, but never executed while a request is in flight.
 * See README "Known tradeoffs" before using this in a shared-tenant process.
 */
function jMul(k: bigint, p: J): J {
  let r: J = [0n, 1n, 0n], a = p;
  while (k > 0n) {
    if (k & 1n) r = jAdd(r, a);
    a = jDbl(a);
    k >>= 1n;
  }
  return r;
}

/**
 * Constant-time-hardened scalar multiply, for scalars that ARE secret: the private key
 * (addressOf) and the ECDSA nonce k (makeNonce - leaking k leaks the key outright).
 *
 * Two countermeasures:
 *   1. Scalar blinding - compute (k + r*n)*G instead of k*G. Identical result because
 *      n*G is the point at infinity, but the bit pattern is re-randomised every call,
 *      so repeated signings never expose the same operation sequence twice.
 *   2. Always-add-and-double over a FIXED iteration count, with a branchless select.
 *      The addition is performed on every bit and the result chosen by bit-mask, so the
 *      add/no-add pattern no longer tracks the key bits, and the loop count no longer
 *      reveals the scalar's bit length.
 *
 * HONEST SCOPE - this is hardening, not a constant-time proof. JavaScript BigInt
 * arithmetic is itself variable-time (V8 short-circuits on operand size and allocates
 * per operation), and no pure-JS implementation can remove that. What is removed is the
 * large, directly key-correlated leak: the data-dependent branch on each key bit.
 * If the threat model genuinely requires constant-time signing, use `remoteSign` and an
 * HSM. Cost: about 1.7x the work of the variable-time path - see the benchmark.
 */
function jMulCT(k: bigint, p: J): J {
  const rb = new Uint32Array(1);
  crypto.getRandomValues(rb);
  const kb = k + BigInt(rb[0]) * N;   // blinded scalar, same result
  let R: J = [0n, 1n, 0n];
  for (let i = 287; i >= 0; i--) {
    R = jDbl(R);
    const T = jAdd(R, p);
    const m = -((kb >> BigInt(i)) & 1n);           // 0n when the bit is 0, -1n when 1
    R = [
      (R[0] & ~m) | (T[0] & m),
      (R[1] & ~m) | (T[1] & m),
      (R[2] & ~m) | (T[2] & m),
    ];
  }
  return R;
}

const affine = (p: J): [bigint, bigint] => {
  const zi = inv(p[2], P), z2 = mod(zi * zi, P);
  return [mod(p[0] * z2, P), mod(p[1] * mod(z2 * zi, P), P)];
};
const G: J = [GX, GY, 1n];

function randScalar(): bigint {
  const b = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(b);
    const v = toBig(b);
    if (v > 0n && v < N) return v;
  }
}

/** Lowercase 20-byte address for a private scalar. */
function addressOf(d: bigint): string {
  const xy = affine(jMulCT(d, G));   // d is the private key
  return toHex(keccak256(beBytes(xy[0], 32), beBytes(xy[1], 32)).slice(12));
}

/* ============== anticipatory ECDSA nonce = the pipeline ============== */

interface Nonce { kInv: bigint; r: bigint; rec: number }

/**
 * Precompute k*G, r and k^-1. This is the entire expensive half of ECDSA and it does
 * not depend on the message, so it is fully computable before the 402 ever arrives.
 * A Nonce is single-use: reusing k across two signatures leaks the private key.
 */
function makeNonce(): Nonce {
  for (;;) {
    const k = randScalar();
    const xy = affine(jMulCT(k, G));   // k is secret: leaking it leaks the private key
    const r = mod(xy[0], N);
    if (r === 0n) continue;
    return { kInv: inv(k, N), r, rec: Number(xy[1] & 1n) | (xy[0] >= N ? 2 : 0) };
  }
}

/** Live path: two modmuls plus low-s normalization (EIP-2). No curve operations. */
function signWith(nc: Nonce, z: bigint, d: bigint): string {
  let s = mod(nc.kInv * (z + nc.r * d), N);
  let rec = nc.rec;
  if (s > HALF_N) { s = N - s; rec ^= 1; }
  const sig = new Uint8Array(65);
  sig.set(beBytes(nc.r, 32), 0);
  sig.set(beBytes(s, 32), 32);
  sig[64] = 27 + rec;
  return toHex(sig);
}

/* ========================= EIP-712 / EIP-3009 ========================= */

const DOMAIN_TH = keccak256(utf8(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
));
const XFER_TH = keccak256(utf8(
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'
));

export interface Authorization {
  from: string; to: string; value: string;
  validAfter: string; validBefore: string; nonce: string;
}

const domainSep = (name: string, version: string, chainId: number, verifying: string): Uint8Array =>
  keccak256(DOMAIN_TH, keccak256(utf8(name)), keccak256(utf8(version)), word(BigInt(chainId)), word(verifying));

function digest(dsep: Uint8Array, a: Authorization): bigint {
  const structHash = keccak256(
    XFER_TH, word(a.from), word(a.to), word(BigInt(a.value)),
    word(BigInt(a.validAfter)), word(BigInt(a.validBefore)), word(a.nonce)
  );
  return toBig(keccak256(new Uint8Array([0x19, 0x01]), dsep, structHash));
}

/* ============================ x402 protocol ============================ */

export interface Requirement {
  scheme: string; network: string; payTo: string; asset: string;
  maxAmountRequired: string; maxTimeoutSeconds?: number;
  extra?: { name?: string; version?: string } | null;
  resource?: string;
}

/**
 * MAINNET ONLY. chainId + USDC defaults, used to fill gaps the server left.
 *
 * Every field here was read off the deployed contract - `name()`, `version()`, `eth_chainId`
 * and `DOMAIN_SEPARATOR()` - not copied from documentation. A wrong `name` produces a wrong
 * domain separator and every payment on that chain is silently rejected on-chain.
 *
 * No testnets ship. Add any chain you need - including a testnet - via `customChains`.
 */
export interface ChainSpec { id: number; asset: string; name: string; version: string }
const CHAINS: Record<string, ChainSpec> = {
  // Base + USDC only. This is the pair that has actually moved money - every other chain
  // had a verified domain separator and zero real transactions, and shipping a default
  // nobody has sent a payment on is a claim, not a feature. Add others with `customChains`
  // once you have tested them: the machinery is chain-agnostic, the confidence is not.
  'base': { id: 8453, asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', name: 'USD Coin', version: '2' },
};

/* =========================== THE PROTOCOL FEE ===========================
 * x402-trinity adds 0.1% ON TOP of every payment, plus a flat $0.01 on every hundredth
 * one, and it is ON BY DEFAULT.
 *
 *   - it is ADDED, never deducted: the seller always receives their full asking
 *     price, and the extra comes out of the payer's wallet
 *   - a notice is printed the first time a client is constructed; you can send it
 *     somewhere else, but it always fires
 *   - it is settled by a facilitator, so neither you nor the payer spends gas moving it
 *   - turn it off in one line:  createX402Fetch({ surcharge: false, ... })
 *
 * Both are owed on the payments they land on, but they are SETTLED TOGETHER in a single
 * authorization on the hundredth payment. Settling costs about $0.0015 of gas on Base, and
 * 0.1% of a two-cent payment is $0.00002 - moving that on its own would cost seventy-five
 * times what it collects. Batching makes gas roughly an eighth of what is swept.
 *
 * The tally MUST be durable for this to work - see `surcharge.store`. Without one it resets
 * with the process and the hundredth payment never arrives.
 *
 * If you would rather not pay it, the opt-out above is supported, deliberately easy,
 * and will not be removed.
 * ======================================================================== */
const FEE_VAULT = '0x2f011f21D6Ec758Bc18f0f9142EeD01Ce2d8a0d3';
const FEE_PPM = 1000n;                  // 1000 parts per million = 0.1%, on every payment
const FEE_EVERY = 100n;                 // plus a flat charge every hundredth payment
const FEE_AMOUNT = 10_000n;             // $0.01, flat
const FEE_SCALE = 1_000_000n;           // tally precision, so sub-unit fees are not lost
/**
 * Where a signed fee authorization is sent. Self-hosted, so collection does not depend on
 * a third party's rate limit or free tier - the previous default stopped settling the
 * moment its quota ran out, and every fee after that was simply lost.
 *
 * It speaks the facilitator /settle shape, so `surcharge.collector` can be pointed at any
 * x402 facilitator instead and the client does not need to know the difference.
 *
 * A facilitator has no concept of "seller". It checks that an authorization matches the
 * requirements it was handed, so presenting requirements whose payTo is the vault makes
 * the fee an ordinary x402 payment as far as it can tell.
 */
const FEE_COLLECTOR = 'https://x402-trinity-collector.x402trinity.workers.dev/submit';

/** CAIP-2 ids, as used by x402 v2 and by AWS AgentCore's network list. */
const CAIP2: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (const k in CHAINS) m['eip155:' + CHAINS[k].id] = k;
  return m;
})();
/** Accept both v1 short names ('base') and CAIP-2 ids ('eip155:8453'). */
const normNet = (s: string): string => {
  const v = (s || '').toLowerCase().trim();
  return CAIP2[v] ?? v;
};

/** ResourceInfo, introduced in v2 (split out of PaymentRequirements). */
export interface ResourceInfo { url: string; description?: string; mimeType?: string }

interface Parsed {
  reqs: Requirement[];
  /** Verbatim server objects, parallel to reqs. v2 echoes the selected one back as `accepted`. */
  raws: any[];
  version: 1 | 2;
  resource?: ResourceInfo;
  error?: string;
}

/** v1 calls it maxAmountRequired; v2 renamed it to amount. Normalize to one internal shape. */
const asRequirement = (a: any): Requirement => ({
  ...a,
  network: normNet(a.network),
  // NOT defaulted to '0': a missing amount must fail validation and decline, not quietly
  // become a zero-value payment that burns a nonce and can never settle.
  maxAmountRequired: String(a.amount ?? a.maxAmountRequired ?? ''),
});

/**
 * Parse a 402 challenge. Supports three forms:
 *   v2  - PAYMENT-REQUIRED header (headers carry the protocol; the body is app-owned)
 *   v1  - JSON body { x402Version, accepts[] }
 *   legacy - the x402-Payment-Request header form from the original blueprint
 */
async function parse402(res: Response): Promise<Parsed> {
  const out: Requirement[] = [], raws: any[] = [];

  // MPP ('WWW-Authenticate: Payment ...') is a DIFFERENT protocol - AgentCore speaks both.
  // Decline loudly rather than sending an x402 envelope a Payment-scheme server will reject.
  const wa = res.headers.get('www-authenticate');
  if (wa && /^\s*Payment[\s,]/i.test(wa)) {
    return { reqs: [], raws: [], version: 1, error: 'MPP challenge (WWW-Authenticate: Payment); this client speaks x402 only' };
  }

  // --- v2: everything protocol-level lives in the PAYMENT-REQUIRED header
  const pr = res.headers.get('payment-required');
  if (pr) {
    try {
      const j = JSON.parse(pr);
      for (const a of (j?.accepts ?? [])) { out.push(asRequirement(a)); raws.push(a); }
      if (out.length) return { reqs: out, raws, version: 2, resource: j?.resource };
    } catch { /* malformed - fall through */ }
  }

  // --- legacy blueprint header
  const hdr = res.headers.get('x402-payment-request');
  if (hdr) {
    try {
      const j = JSON.parse(hdr);
      const chain = normNet(String(j.chain ?? j.network ?? 'base'));
      const c = CHAINS[chain];
      const amt = String(j.amount ?? j.maxAmountRequired ?? '0');
      // "0.01" is read as decimal and scaled to atomic units; a bare integer is already atomic.
      const value = amt.indexOf('.') >= 0 ? String(BigInt(Math.round(parseFloat(amt) * 1e6))) : amt;
      const payTo = j.payTo ?? j.recipient ?? res.headers.get('x402-payment-recipient');
      if (payTo && c) {
        const r: Requirement = {
          scheme: j.scheme ?? 'exact', network: chain, payTo,
          asset: j.asset ?? c.asset, maxAmountRequired: value,
          maxTimeoutSeconds: j.maxTimeoutSeconds ?? 60,
          extra: { name: c.name, version: c.version },
        };
        out.push(r); raws.push(r);
      }
    } catch { /* malformed header - fall through to the body */ }
  }

  // --- v1: JSON body
  if ((res.headers.get('content-type') ?? '').indexOf('json') >= 0) {
    try {
      const b: any = await res.clone().json();
      const ver = b?.x402Version;
      if (typeof ver === 'number' && ver > 2) {
        return { reqs: [], raws: [], version: 1, error: 'server speaks x402 v' + ver + '; this client implements v1 and v2' };
      }
      for (const a of (b?.accepts ?? [])) { out.push(asRequirement(a)); raws.push(a); }
      if (out.length && ver === 2) return { reqs: out, raws, version: 2, resource: b?.resource };
    } catch { /* no body requirements */ }
  }
  return { reqs: out, raws, version: 1 };
}

/* ============================== the wrapper ============================== */

export interface Policy {
  /** Hard ceiling for a single 402, in atomic asset units (USDC = 6dp). Required. */
  maxAmountPerRequest: bigint | string;
  /** Hard cumulative ceiling for the life of this wrapper instance. Required. */
  totalBudget: bigint | string;
  /** If set, only these hostnames may be paid. Strongly recommended. */
  allowHosts?: string[];
  allowPayTo?: string[];
  allowAssets?: string[];
  allowNetworks?: string[];
  /** Preferred settlement networks, best first. Reorders a multi-option `accepts` list. */
  preferNetworks?: string[];
}

export interface X402Config {
  /** Full private key, or `shards`, or `remoteSign` - exactly one source of signing power. */
  privateKey?: string;
  /** Additive shards: d = (s0 + s1 + ...) mod n. No single shard is a spending key. */
  shards?: string[];
  /** Delegate signing to an external signer / real MPC service instead of local key material. */
  remoteSign?: (digestHex: string, auth: Authorization, req: Requirement) => Promise<string>;
  /**
   * Payer address. Required with `remoteSign`, since no local key implies one.
   *
   * You may also supply it ALONGSIDE a private key purely as an optimization: it skips
   * address derivation (a 1.23 ms constant-time scalar multiply) on every cold start.
   * That matters on Cloudflare Workers, where cold CPU was measured at 9-11 ms against a
   * 10 ms free-tier ceiling. It is checked once in the background; a wrong value fails
   * closed (the facilitator rejects every payment) and sets stats().fromAddressMismatch.
   */
  fromAddress?: string;
  /**
   * Force the background fromAddress/key consistency check even on an edge runtime, where
   * it is skipped by default because ctx.waitUntil time is billed and there is no isolate
   * affinity - running it there costs exactly what fromAddress was passed to save.
   * Leave this off in production; turn it on once while wiring a new deployment up.
   */
  verifyFromAddress?: boolean;
  /**
   * Extra networks, merged over the built-in mainnet table. This is how you add a chain the
   * package does not ship - including a testnet, if you want to rehearse before going live.
   *
   *   customChains: {
   *     'base-sepolia': { id: 84532, asset: '0x036cbd...', name: 'USDC', version: '2' },
   *   }
   *
   * VERIFY these against the deployed contract before use: call DOMAIN_SEPARATOR() and check
   * it equals what this library computes. A wrong `name` or `version` yields a valid-looking
   * signature that the contract will reject.
   */
  customChains?: Record<string, ChainSpec>;
  policy: Policy;
  baseFetch?: typeof fetch;
  /**
   * 'longlived' - eagerly warm the nonce pool on idle callbacks (servers, agents, robotics).
   * 'edge'      - never warm eagerly; sign on demand (~750us, still sub-ms) and top up only
   *               in the background after a response. Correct for short-lived V8 isolates,
   *               which have no idle time and a tight CPU budget.
   * 'auto'      - 'edge' when running on Cloudflare Workers, else 'longlived'. Default.
   */
  mode?: 'longlived' | 'edge' | 'auto';
  /** Max nonces held. Default 16 long-lived, 4 on edge. */
  poolSize?: number;
  /**
   * Edge mode: nonces generated per background top-up. **Default 0 - the pool is OFF.**
   *
   * Measured on production Cloudflare Workers: `ctx.waitUntil` work is BILLED against the
   * CPU budget, and Workers gives no isolate affinity, so a nonce built in the background
   * is usually discarded when the next request lands on a different isolate. Enabling it
   * cost 4 ms of median CPU and pushed p90 from 6 ms to 12 ms - over the 10 ms free-tier
   * limit - while buying nothing.
   *
   *   /pay (topUp 2):  median 7 ms, p90 12 ms
   *   /pay (topUp 0):  median 3 ms, p90  6 ms
   *
   * Set it above 0 only where the isolate genuinely lives long enough to reuse the pool.
   */
  edgeTopUp?: number;
  /**
   * Hard lifetime ceiling on nonces the BACKGROUND path may generate, so the warmer can
   * never become an unmonitored compute loop. Default 512. Foreground signing is unaffected.
   */
  maxBackgroundNonces?: number;
  /**
   * Pre-sign complete vouchers for repeat (network, asset, payTo, value) tuples.
   * Off by default: a cached voucher is a live bearer authorization sitting in memory.
   */
  presign?: boolean;
  voucherCap?: number;
  /**
   * The protocol fee, ON by default. Pass `false` to disable it entirely, or an
   * object to tune where it goes and how it is reported.
   *
   *   surcharge: false                            // opt out
   *   surcharge: { every: 50n }                   // charge twice as often
   *   surcharge: { onNotice: msg => log.info(msg) }   // send the notice elsewhere
   *
   * The fee is skipped automatically with `remoteSign`, since there is no local key to
   * sign a second authorization with.
   */
  surcharge?: false | {
    /**
     * Where a signed fee authorization is POSTed. Defaults to a public x402 facilitator,
     * which submits it and pays the gas - so neither you nor we pay to move the fee.
     * Point it anywhere that speaks the facilitator /settle shape.
     */
    collector?: string;
    /** Settle once every this many payments. Default 100. */
    every?: string | bigint;
    /** The flat charge on that payment, in atomic units. Default 10000 ($0.01). */
    amount?: string | bigint;
    /** Rate on every payment, in parts per million. Default 1000 (0.1%). */
    ppm?: string | bigint;
    /**
     * Durable tally: `accrued` is the percentage owed so far, scaled by 1e6 so sub-unit
     * fees are not rounded away; `count` is payments since the last settlement. Without a
     * store both reset with the process and the hundredth payment never arrives.
     */
    store?: {
      get: () => Promise<{ accrued: bigint; count: bigint }>;
      set: (s: { accrued: bigint; count: bigint }) => Promise<void>;
      /**
       * Read, modify and write while holding the lock. Without it two processes sharing a
       * tally both read the same count and both write count+1, and payments stop counting.
       */
      update?: (fn: (cur: { accrued: bigint; count: bigint }) => { accrued: bigint; count: bigint })
        => Promise<{ accrued: bigint; count: bigint }>;
    };
    /** Where the disclosure notice goes. Default console.log. It always fires. */
    onNotice?: (msg: string) => void;
  };
  onPayment?: (i: {
    url: string; value: string; payTo: string; network: string; warm: boolean;
    /** Local signing time. NOTE: on Cloudflare Workers the clock is frozen during
     *  synchronous execution, so this reads as 0 or a coarse integer, not a real duration. */
    signMs: number; version: 1 | 2;
    /** True when this re-sent a previously unresolved authorization instead of minting one. */
    reused?: boolean;
    /** Decoded settlement receipt from PAYMENT-RESPONSE / X-PAYMENT-RESPONSE, if present. */
    settlement?: { success?: boolean; transaction?: string; network?: string; payer?: string };
  }) => void;
  onDecline?: (i: { url: string; reason: string; req?: Requirement }) => void;
  /** Throw instead of returning the unpaid 402 when policy declines. Default false. */
  throwOnDecline?: boolean;
  /**
   * DURABLE SPEND LEDGER - required for mainnet unless explicitly waived.
   *
   * `policy.totalBudget` on its own is an in-memory counter scoped to ONE client instance.
   * It resets on process restart, on a new client, and - critically - on every Cloudflare
   * Worker isolate, which is per request. On mainnet that turns a lifetime cap into a
   * per-request cap and the real ceiling becomes the wallet balance.
   *
   * Supply a store backed by something durable (Workers KV / D1 / Durable Object, Redis,
   * Postgres, a file) and the cap holds across instances.
   *
   * `reserve` MUST be atomic: check-and-increment in one operation, or two callers race
   * and both pass. Return false to decline.
   */
  budgetStore?: {
    reserve: (amount: bigint, totalBudget: bigint) => Promise<boolean>;
    /** Called when a payment definitively failed, so the reservation can be returned. */
    release?: (amount: bigint) => Promise<void>;
  };
  /**
   * Acknowledge that mainnet is being used with an EPHEMERAL, per-instance budget only.
   * Without this (or a budgetStore) mainnet payments are declined. Testnets are unaffected.
   */
  acknowledgeEphemeralBudget?: boolean;
}

/** Minimal shape of a Cloudflare Workers ExecutionContext. */
export interface ExecCtx { waitUntil?: (p: Promise<unknown>) => void }

export interface X402Fetch {
  /**
   * Drop-in fetch. On Cloudflare Workers pass the handler's `ctx` as the third argument so
   * background nonce top-up and pre-signing run under `ctx.waitUntil` instead of being
   * killed when the isolate is torn down after the response.
   */
  (input: RequestInfo | URL, init?: RequestInit, ctx?: ExecCtx): Promise<Response>;
  /** Resolves once the pool is warm. On edge/remoteSign it resolves immediately - nothing is pre-warmed. */
  ready(): Promise<void>;
  /** Resolves once every protocol-fee accrual has finished. */
  flushFees(): Promise<void>;
  address: string;
    /**
     * Async because the fee tally may live on disk. Reading it is the whole point: a
     * synchronous version cannot await the store, so it reported zero for anyone who
     * had configured one - which is everyone, since durability is what makes the
     * counter work at all.
     */
    stats(): Promise<{
    mode: 'edge' | 'longlived'; pool: number; vouchers: number; spent: string;
    remaining: string; payments: number; warmHits: number; bgGenerated: number; bgCapped: boolean;
    fromAddressMismatch?: boolean;
    fee?: { enabled: boolean; vault: string | null; count: string; accrued: string; collected: string; lost: string };
    inFlight: number; unresolved: number;
    }>;
}

interface Voucher { auth: Authorization; sig: string; expires: number }

export function createX402Fetch(cfg: X402Config): X402Fetch {
  const base = cfg.baseFetch ?? globalThis.fetch.bind(globalThis);
  const maxPer = BigInt(cfg.policy.maxAmountPerRequest);
  const budget = BigInt(cfg.policy.totalBudget);
  if (maxPer <= 0n || budget <= 0n) {
    throw new Error('x402: policy.maxAmountPerRequest and policy.totalBudget are required and must be > 0');
  }

  // --- key material: reconstruct from shards, keep the scalar in closure scope only
  let d = 0n;
  if (cfg.privateKey) d = toBig(fromHex(cfg.privateKey));
  else if (cfg.shards && cfg.shards.length) for (const s of cfg.shards) d = mod(d + toBig(fromHex(s)), N);
  else if (!cfg.remoteSign) throw new Error('x402: privateKey, shards or remoteSign required');
  if (!cfg.remoteSign && (d === 0n || d >= N)) throw new Error('x402: invalid key material');
  if (cfg.remoteSign && d === 0n && !cfg.fromAddress) throw new Error('x402: fromAddress required with remoteSign');
  if (cfg.fromAddress && !/^0x[0-9a-fA-F]{40}$/.test(cfg.fromAddress)) {
    throw new Error('x402: fromAddress must be a 0x-prefixed 20-byte hex address');
  }
  /**
   * Supplying fromAddress alongside a key skips addressOf() - a constant-time scalar
   * multiply, measured at 1.23 ms, paid on EVERY cold isolate. That is roughly half the
   * wrapper's cold-start crypto cost on Cloudflare Workers, where cold /pay was measured
   * at 9-11 ms CPU against a documented 10 ms free-tier ceiling.
   *
   * The claim is verified once, off the hot path, in the post-response background lane.
   * A wrong value fails CLOSED regardless - the signature will not recover to `from`, so
   * the facilitator rejects it and nothing settles - so this check exists to make the
   * reason obvious, not to prevent loss.
   */
  const address = (cfg.fromAddress ?? addressOf(d)).toLowerCase();
  let addrUnchecked = !!(cfg.fromAddress && d !== 0n);
  let addrMismatch = false;
  const checkAddress = (): void => {
    if (!addrUnchecked) return;
    // On Workers the background lane runs under ctx.waitUntil, which IS BILLED, and there is
    // no isolate affinity - so the check would run addressOf() on every single request and
    // hand back exactly the cost the caller passed fromAddress to avoid. Measured: it made
    // /pay-fast 0.83 ms SLOWER than /pay in production, the opposite of the intent. Skipped
    // on the edge by default; a mismatch still fails closed, it just is not diagnosed.
    // Same reasoning as edgeTopUp defaulting to 0.
    if (EDGE && cfg.verifyFromAddress !== true) { addrUnchecked = false; return; }
    addrUnchecked = false;
    if (addressOf(d) !== address) {
      addrMismatch = true;
      console.error('x402: fromAddress ' + address + ' does not match the supplied key ' +
        '(derived ' + addressOf(d) + '). Every payment will be rejected. Drop fromAddress to derive it.');
    }
  };

  // Declared before the pool: topUp()/refill() consult them at construction time.
  let spent = 0n, payments = 0, warmHits = 0, unresolved = 0;

  // --- the protocol fee. On unless explicitly disabled, and impossible with remoteSign.
  const feeCfg = cfg.surcharge === false ? null : (cfg.surcharge ?? {});
  const feeOn = !!feeCfg && !cfg.remoteSign;
  const feeEvery = BigInt(feeCfg?.every ?? FEE_EVERY);
  const feeAmount = BigInt(feeCfg?.amount ?? FEE_AMOUNT);
  const feePpm = BigInt(feeCfg?.ppm ?? FEE_PPM);
  const feeCollector = feeCfg?.collector ?? FEE_COLLECTOR;
  const feeStore = feeCfg?.store ?? null;
  let feeMem = { accrued: 0n, count: 0n };   // used when no store is given
  /**
   * A fee authorization that was signed but whose hand-off did not confirm. It is re-sent
   * VERBATIM rather than re-minted: the nonce is the idempotency key, so if the collector
   * did receive the first copy and settles it, this one simply reverts on-chain. Minting a
   * fresh one instead is what would charge the payer twice - and discarding it, which is
   * what this used to do, silently lost the fee once its hour ran out.
   */
  let feePending: { auth: Authorization; sig: string; req: Requirement } | null = null;
  let feeCollected = 0n, feeLost = 0n;
  let feeInFlight: Promise<void> = Promise.resolve();
  if (feeOn) {
    // Conspicuous by design. This spends the payer's money; burying it would be the
    // difference between a disclosed fee and something that gets the package pulled.
    (feeCfg!.onNotice ?? ((m: string) => console.log(m)))(
      'x402-trinity: a protocol fee is added ON TOP of each payment you make. ' +
      'Sellers are never shorted.');
  }

  // Built-in mainnet table plus anything the caller added.
  const chains: Record<string, ChainSpec> = { ...CHAINS, ...(cfg.customChains ?? {}) };
  const caip2: Record<string, string> = {};
  for (const k in chains) caip2['eip155:' + chains[k].id] = k;
  const norm = (v: string): string => {
    const x = (v || '').toLowerCase().trim();
    return caip2[x] ?? x;
  };

  // --- runtime mode. Cloudflare sets navigator.userAgent to 'Cloudflare-Workers'.
  const EDGE = cfg.mode === 'edge' || (cfg.mode !== 'longlived' &&
    (globalThis as any).navigator?.userAgent === 'Cloudflare-Workers');

  // --- anticipatory nonce pool
  const target = cfg.poolSize ?? (EDGE ? 4 : 16);
  const edgeTopUp = cfg.edgeTopUp ?? 0;   // measured: the pool is a net loss on Workers
  const maxBg = cfg.maxBackgroundNonces ?? 512;
  const pool: Nonce[] = [];
  let filling = false, bgGenerated = 0;
  let readyResolve!: () => void;
  const readyP = new Promise<void>(r => { readyResolve = r; });

  const idle = (fn: () => void): void => {
    const ric = (globalThis as any).requestIdleCallback;
    if (typeof ric === 'function') ric(fn, { timeout: 50 });
    else setTimeout(fn, 0);
  };

  /**
   * Bounded background nonce generation. Stops on every guardrail: pool full, lifetime
   * background cap, budget exhausted (nothing left to pay with, so nothing to warm for).
   * Returns how many it actually made.
   */
  function topUp(n: number): number {
    let made = 0;
    while (made < n && pool.length < target && bgGenerated < maxBg && spent < budget) {
      pool.push(makeNonce()); bgGenerated++; made++;
    }
    return made;
  }

  /** Long-lived only: keep the pool full during idle time, in bounded slices. */
  function refill(): void {
    if (EDGE || filling || pool.length >= target || cfg.remoteSign) return;
    if (bgGenerated >= maxBg || spent >= budget) { readyResolve(); return; }
    filling = true;
    idle(() => {
      // Bounded by COUNT, not elapsed time. Cloudflare Workers freezes Date.now() and
      // performance.now() during synchronous execution as a timing-side-channel defence
      // (verified in workerd), so a time-based bound never trips there and the whole pool
      // would be built in a single tick - precisely the CPU spike this is meant to avoid.
      // A count bound behaves identically everywhere.
      for (let made = 0; made < 4; made++) if (!topUp(1)) break;
      filling = false;
      if (pool.length >= target || bgGenerated >= maxBg || spent >= budget) readyResolve();
      else refill();
    });
  }

  // On edge there is no idle time and no isolate affinity: warming eagerly would burn
  // ~12ms of CPU for a pool the next request probably will not even see.
  if (cfg.remoteSign || EDGE) queueMicrotask(() => readyResolve()); else refill();

  /** Run work after the response. Prefers ctx.waitUntil so the isolate is not killed mid-task. */
  const background = (ctx: { waitUntil?: (p: Promise<unknown>) => void } | undefined, fn: () => void): void => {
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(Promise.resolve().then(fn));
    else idle(fn);
  };

  // --- domain separator cache (per asset+network; recomputed essentially never)
  const dseps = new Map<string, Uint8Array>();
  function dsepFor(req: Requirement): Uint8Array {
    const net = norm(req.network);
    const c = chains[net];
    if (!c) throw new Error('x402: unknown network ' + net);
    const name = req.extra?.name ?? c.name;
    const ver = req.extra?.version ?? c.version;
    const k = net + '|' + req.asset + '|' + name + '|' + ver;
    let s = dseps.get(k);
    if (!s) { s = domainSep(name, ver, c.id, req.asset); dseps.set(k, s); }
    return s;
  }

  /**
   * Authorizations that were sent but whose fate is unknown - the paid retry died at the
   * network layer, so the facilitator may or may not have settled it.
   *
   * The EIP-3009 nonce IS the idempotency key: it redeems exactly once on-chain. So the safe
   * recovery is to RE-SEND THE SAME AUTHORIZATION, never to mint a new nonce. If the first
   * attempt settled, the second is rejected as already-used; if it did not, this one settles.
   * Either way the payer is debited once. Minting a fresh nonce here is what double-spends.
   *
   * Entries expire at validBefore, after which the authorization can never be redeemed and
   * it is safe to mint a new one.
   */
  const pending = new Map<string, { auth: Authorization; sig: string; version: 1 | 2 }>();

  // --- voucher cache (tier 2: fully pre-signed, zero crypto on a hit)
  const vouchers = new Map<string, Voucher>();
  const vkey = (r: Requirement, v: number): string =>
    v + '|' + r.network + '|' + r.asset + '|' + r.payTo + '|' + r.maxAmountRequired;


  function build(req: Requirement): { auth: Authorization; sig: string; ms: number } {
    const t0 = performance.now();
    const now = Math.floor(Date.now() / 1000);
    const n32 = new Uint8Array(32);
    crypto.getRandomValues(n32);
    const auth: Authorization = {
      from: address, to: req.payTo, value: req.maxAmountRequired,
      validAfter: String(now - 60), // clock-skew tolerance
      validBefore: String(now + (req.maxTimeoutSeconds ?? 60)),
      nonce: toHex(n32),
    };
    const z = digest(dsepFor(req), auth);
    const nc = pool.pop() ?? makeNonce(); // cold fallback: full k*G inline
    refill();
    return { auth, sig: signWith(nc, z, d), ms: performance.now() - t0 };
  }

  /**
   * Accrue the protocol fee and, once it crosses the threshold, sign ONE authorization
   * for the whole accrued amount and hand it to the collector.
   *
   * Two rules this must never break:
   *   1. it must never break a payment - every failure path is swallowed
   *   2. it must never charge twice - the tally is deducted BEFORE the authorization is
   *      handed over, and a failed hand-off is NOT restored. A failed POST is ambiguous:
   *      the collector may have received it and still settle. Losing our own fee is the
   *      safe direction; charging the payer twice is not.
   */
  /**
   * POST one signed authorization to the collector. Returns true only on a confirmed
   * success - anything else is ambiguous, and the caller keeps the authorization so it can
   * be re-sent verbatim rather than re-minted.
   */
  async function handOff(auth: Authorization, sig: string, req: Requirement): Promise<boolean> {
    const fc = chains[norm(req.network)];
    try {
      const r = await fetch(feeCollector, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          x402Version: 1,
          paymentPayload: {
            x402Version: 1, scheme: 'exact', network: req.network,
            payload: { signature: sig, authorization: auth },
          },
          paymentRequirements: {
            scheme: 'exact', network: req.network, payTo: FEE_VAULT, asset: fc.asset,
            maxAmountRequired: auth.value, amount: auth.value,
            resource: 'https://x402-trinity.dev/fee',
            description: 'x402-trinity protocol fee',
            mimeType: 'application/json', maxTimeoutSeconds: 300,
            extra: { name: fc.name, version: fc.version },
          },
        }),
      });
      if (!r.ok) return false;
      try { return JSON.parse(await r.text())?.success === true; } catch { return false; }
    } catch { return false; }
  }

  async function accrueFee(value: bigint, req: Requirement): Promise<void> {
    try {
      // A previous hand-off never confirmed: re-send that exact authorization first. It
      // is still redeemable until its validBefore, and the nonce makes a double-settle
      // impossible, so this is strictly safer than letting it expire.
      if (feePending) {
        const stuck = feePending;
        if (Number(stuck.auth.validBefore) > Math.floor(Date.now() / 1000) + 5) {
          if (await handOff(stuck.auth, stuck.sig, stuck.req)) {
            feeCollected += BigInt(stuck.auth.value);
            feePending = null;
          }
        } else {
          // Past its window: nothing can redeem it now, so stop carrying it.
          feeLost += BigInt(stuck.auth.value);
          feePending = null;
        }
      }

      // The percentage is owed on THIS payment; the flat charge is owed on the hundredth.
      // Both accrue, and both go out together in one authorization when the count lands.
      // Read-modify-write must happen INSIDE the lock, or two processes sharing the tally
      // both read the same count and both write count+1, and payments stop counting. The
      // amount owed is computed in the same step, so the decision to sweep and the reset
      // that follows it cannot be split by another process.
      let owed = 0n, crossed = false;
      const step = (cur: { accrued: bigint; count: bigint }) => {
        const a = cur.accrued + value * feePpm;           // implicitly x FEE_SCALE / 1e6
        const c = cur.count + 1n;
        crossed = c >= feeEvery;
        if (!crossed) return { accrued: a, count: c };
        owed = a / FEE_SCALE + feeAmount;                 // the percentage AND the flat charge
        return { accrued: a % FEE_SCALE, count: 0n };     // remainder carries forward
      };
      if (feeStore?.update) await feeStore.update(step);
      else if (feeStore) { const next = step(await feeStore.get()); await feeStore.set(next); }
      else feeMem = step(feeMem);
      if (!crossed) return;
      // The hundredth: sweep the accrued percentage AND the flat charge as one amount.
      const whole = owed;
      const now = Math.floor(Date.now() / 1000);
      const n32 = new Uint8Array(32);
      crypto.getRandomValues(n32);
      const auth: Authorization = {
        from: address, to: FEE_VAULT, value: String(whole),
        validAfter: String(now - 60), validBefore: String(now + 3600), nonce: toHex(n32),
      };
      const sig = signWith(pool.pop() ?? makeNonce(), digest(dsepFor(req), auth), d);
      // The tally was already reset inside the lock above, before this authorization was
      // even signed - so a failed hand-off cannot charge the payer twice, and no second
      // process can see the same hundredth payment and sweep it again.

      // Hand it over. A confirmed success is the ONLY outcome that lets go of the
      // authorization; anything else keeps it, so the next payment re-sends this exact
      // one instead of minting a fresh nonce and charging the payer a second time.
      if (await handOff(auth, sig, req)) {
        feeCollected += whole;
      } else {
        feePending = { auth, sig, req };
      }
    } catch { /* the fee must never break a payment */ }
  }

  function decline(url: string, reason: string, req?: Requirement): void {
    if (cfg.onDecline) cfg.onDecline({ url, reason, req });
    if (cfg.throwOnDecline) throw new Error('x402 declined: ' + reason);
  }

  function pick(reqs: Requirement[], url: URL): { req?: Requirement; idx: number; reason: string } {
    const p = cfg.policy;
    let last = 'no acceptable payment requirement';
    const pref = p.preferNetworks;
    const ordered = pref ? reqs.slice().sort((a, b) => {
      const ia = pref.indexOf(norm(a.network)), ib = pref.indexOf(norm(b.network));
      return (ia < 0 ? 1e9 : ia) - (ib < 0 ? 1e9 : ib);
    }) : reqs;
    const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
    const AMT_RE = /^[0-9]+$/;
    for (const r of ordered) {
      // Shape validation FIRST. A server (buggy or hostile) can send anything; a missing or
      // malformed field must decline cleanly, never crash the agent deep in the encoder.
      if (!r || typeof r !== 'object') { last = 'malformed requirement'; continue; }
      if (!ADDR_RE.test(r.payTo ?? '')) { last = 'invalid payTo: ' + JSON.stringify(r.payTo); continue; }
      if (!ADDR_RE.test(r.asset ?? '')) { last = 'invalid asset: ' + JSON.stringify(r.asset); continue; }
      if (!AMT_RE.test(String(r.maxAmountRequired ?? ''))) { last = 'invalid amount: ' + JSON.stringify(r.maxAmountRequired); continue; }
      if (r.scheme !== 'exact') { last = 'unsupported scheme ' + r.scheme; continue; }
      // The x402 exact/EVM scheme allows more than one way to move the token - the spec
      // names eip3009 and permit2. We only implement eip3009, so a requirement asking for
      // anything else must be DECLINED, not answered with a signature of the wrong kind.
      // Absent means eip3009 by convention, which is what every current seller emits.
      const method = (r as any).extra?.assetTransferMethod;
      if (method && String(method).toLowerCase() !== 'eip3009') {
        last = 'unsupported assetTransferMethod: ' + method + ' (this client signs eip3009 only)';
        continue;
      }
      const net = norm(r.network);
      if (!chains[net]) { last = 'unknown network ' + r.network; continue; }
      if (p.allowNetworks && p.allowNetworks.indexOf(net) < 0) { last = 'network not allowed: ' + net; continue; }
      if (p.allowHosts && p.allowHosts.indexOf(url.hostname) < 0) { last = 'host not allowed: ' + url.hostname; continue; }
      if (p.allowPayTo && !p.allowPayTo.some(a => a.toLowerCase() === r.payTo.toLowerCase())) { last = 'payTo not allowed: ' + r.payTo; continue; }
      if (p.allowAssets && !p.allowAssets.some(a => a.toLowerCase() === r.asset.toLowerCase())) { last = 'asset not allowed: ' + r.asset; continue; }
      const v = BigInt(r.maxAmountRequired);
      if (v <= 0n) { last = 'non-positive amount: ' + r.maxAmountRequired; continue; }
      // Real money + a budget that resets per instance = no effective lifetime cap.
      // Every shipped chain is mainnet, so this always applies.
      if (!cfg.budgetStore && !cfg.acknowledgeEphemeralBudget) {
        last = net + ' requires a durable budgetStore, or acknowledgeEphemeralBudget: true '
             + '- totalBudget is per-instance and resets on restart / per Workers isolate';
        continue;
      }
      if (v > maxPer) { last = 'amount ' + v + ' exceeds per-request cap ' + maxPer; continue; }
      if (spent + v > budget) { last = 'amount ' + v + ' exceeds remaining budget ' + (budget - spent); continue; }
      return { req: r, idx: reqs.indexOf(r), reason: '' };
    }
    return { idx: -1, reason: last };
  }

  const x402Fetch = (async (input: RequestInfo | URL, init?: RequestInit, ctx?: ExecCtx): Promise<Response> => {
    // Buffer any body once so the paid retry can replay it.
    const req0 = new Request(input as any, init);
    const body = (req0.method === 'GET' || req0.method === 'HEAD') ? undefined : await req0.arrayBuffer();
    const replay = (h: Headers): Request => new Request(req0.url, {
      method: req0.method, headers: h, body, redirect: req0.redirect,
      ...(body !== undefined ? { duplex: 'half' } as any : {}),
    });

    const res = await base(replay(new Headers(req0.headers)));
    if (res.status !== 402) return res;

    const url = new URL(req0.url);
    const parsed = await parse402(res);
    if (parsed.error) { decline(url.href, parsed.error); return res; }
    if (!parsed.reqs.length) { decline(url.href, 'no parseable payment requirements'); return res; }

    const picked = pick(parsed.reqs, url);
    const req = picked.req;
    if (!req) { decline(url.href, picked.reason); return res; }

    let auth!: Authorization, sig!: string, ms = 0, warm = false, reused = false;
    const vk = vkey(req, parsed.version);

    // An unresolved authorization for this exact requirement outranks everything else:
    // re-sending it is the only way to avoid paying twice for one 402.
    const stuck = pending.get(vk);
    const stuckLive = !!stuck && Number(stuck.auth.validBefore) > Date.now() / 1000 + 2;
    if (stuck && !stuckLive) pending.delete(vk); // expired: unredeemable, safe to mint fresh

    const cached = stuckLive ? undefined : vouchers.get(vk);
    if (stuckLive) {
      auth = stuck!.auth; sig = stuck!.sig; reused = true;
    } else if (cached && cached.expires > Date.now() / 1000 + 5) {
      vouchers.delete(vk); // single-use: the nonce can only be redeemed once
      auth = cached.auth; sig = cached.sig; warm = true; warmHits++;
    } else if (cfg.remoteSign) {
      const now = Math.floor(Date.now() / 1000);
      const n32 = new Uint8Array(32);
      crypto.getRandomValues(n32);
      auth = {
        from: address, to: req.payTo, value: req.maxAmountRequired,
        validAfter: String(now - 60), validBefore: String(now + (req.maxTimeoutSeconds ?? 60)), nonce: toHex(n32),
      };
      const t0 = performance.now();
      sig = await cfg.remoteSign(toHex(beBytes(digest(dsepFor(req), auth), 32)), auth, req);
      ms = performance.now() - t0;
    } else {
      const b = build(req);
      auth = b.auth; sig = b.sig; ms = b.ms;
    }

    // Budget is charged once per AUTHORIZATION, not per attempt - re-sending a stuck
    // authorization must not debit the budget a second time.
    const value = BigInt(auth.value);
    if (!reused) {
      if (cfg.budgetStore) {
        // Atomic check-and-increment in durable storage: survives restarts and isolates.
        let okToSpend = false;
        try { okToSpend = await cfg.budgetStore.reserve(value, budget); }
        catch (e) { decline(url.href, 'budgetStore.reserve failed: ' + (e as Error).message, req); return res; }
        if (!okToSpend) { decline(url.href, 'durable budget exhausted', req); return res; }
      } else if (spent + value > budget) {
        decline(url.href, 'budget exhausted', req); return res;
      }
      spent += value; payments++;
    }

    // v1: {x402Version, scheme, network, payload}
    // v2: {x402Version, resource, accepted, payload, extensions} - `accepted` echoes the
    //     selected requirement verbatim, so the server sees exactly what it advertised.
    const envelope = parsed.version === 2
      ? {
          x402Version: 2,
          resource: parsed.resource ?? { url: url.href },
          accepted: parsed.raws[picked.idx] ?? req,
          payload: { signature: sig, authorization: auth },
          extensions: {},
        }
      : {
          x402Version: 1, scheme: req.scheme, network: req.network,
          payload: { signature: sig, authorization: auth },
        };
    const enc = btoa(JSON.stringify(envelope));

    const h = new Headers(req0.headers);
    if (parsed.version === 2) {
      h.set('payment-signature', enc);          // x402 v2 HTTP transport
    } else {
      h.set('x-payment', enc);                  // x402 v1 HTTP transport
      h.set('x402-payment-authorization', enc); // blueprint-named alias
    }
    // Recorded BEFORE sending: if the send throws, the server may still have received it.
    pending.set(vk, { auth, sig, version: parsed.version });

    let paid: Response;
    try {
      paid = await base(replay(h));
    } catch (e) {
      // Ambiguous - keep the authorization so the next attempt re-sends this same nonce.
      unresolved++;
      throw e;
    }
    // A definitive response means the facilitator saw it and decided. 5xx stays ambiguous:
    // it may have settled before failing downstream.
    if (paid.status < 500) {
      pending.delete(vk);
      // A definitive rejection means nothing settled - hand the reservation back.
      if (!reused && paid.status >= 400 && cfg.budgetStore?.release) {
        try { await cfg.budgetStore.release(value); spent -= value; payments--; }
        catch { /* releasing is best-effort; over-counting is the safe direction */ }
      }
    } else unresolved++;

    let settlement: any;
    try {
      const sr = paid.headers.get('payment-response') ?? paid.headers.get('x-payment-response');
      if (sr) settlement = JSON.parse(atob(sr));
    } catch { /* receipt is informational; never fail the request over it */ }

    if (cfg.onPayment) cfg.onPayment({
      url: url.href, value: auth.value, payTo: req.payTo, network: req.network,
      warm, signMs: ms, version: parsed.version, settlement, reused,
    });

    // The protocol fee, only on a payment the server actually accepted. Handed to
    // ctx.waitUntil as well as tracked, because on an edge runtime the isolate is torn
    // down with the response and an untracked promise would be lost - the exact bug the
    // optional surcharge module had until it was run inside workerd.
    if (feeOn && paid.status < 400) {
      const fp = accrueFee(value, req);
      feeInFlight = feeInFlight.then(() => fp, () => fp);
      if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(fp);
    }

    // Post-response background work. On Workers this runs under ctx.waitUntil so the isolate
    // is not torn down mid-computation; elsewhere it falls back to an idle callback. Every
    // path here is bounded by the guardrails in topUp() and by the budget.
    if (!cfg.remoteSign) background(ctx, () => {
      // one-shot: confirm a caller-supplied fromAddress really matches the key
      checkAddress();
      // replace the nonce this request consumed (edge mode never pre-warms otherwise)
      if (EDGE) topUp(edgeTopUp);
      // warm the next call to this same resource
      if (cfg.presign && paid.ok) {
        if (vouchers.size >= (cfg.voucherCap ?? 8) || spent + value > budget) return;
        try {
          const b = build(req);
          vouchers.set(vkey(req, parsed.version), { auth: b.auth, sig: b.sig, expires: Number(b.auth.validBefore) });
        } catch { /* pre-signing is strictly best-effort */ }
      }
    });

    return paid;
  }) as X402Fetch;

  x402Fetch.ready = () => readyP;
  x402Fetch.address = address;
  x402Fetch.stats = async () => {
    const tally = feeStore ? await feeStore.get() : feeMem;
    return ({
    mode: EDGE ? 'edge' as const : 'longlived' as const,
    pool: pool.length, vouchers: vouchers.size, spent: spent.toString(),
    remaining: (budget - spent).toString(), payments, warmHits,
    bgGenerated, bgCapped: bgGenerated >= maxBg,
    /** Authorizations sent whose settlement is unknown; each is re-sent, never re-minted. */
    inFlight: pending.size, unresolved,
    /** True once a caller-supplied fromAddress has been shown NOT to match the key. */
    fromAddressMismatch: addrMismatch,
    /** The protocol fee. `surcharge: false` turns it off; these then stay at 0. */
    fee: {
      enabled: feeOn,
      vault: feeOn ? FEE_VAULT : null,
      /** Payments since the last settlement. Both charges go out on the hundredth. */
      count: tally.count.toString(),
      /** Percentage owed but not yet settled, in atomic units. */
      accrued: (tally.accrued / FEE_SCALE).toString(),
      /** Successfully handed to the collector. */
      collected: feeCollected.toString(),
      /** Signed but the hand-off failed. Never retried, so the payer cannot be charged twice. */
      lost: feeLost.toString(),
    },
    });
  };
  /** Resolves once every fee accrual has finished. Await before exiting a short process. */
  x402Fetch.flushFees = () => feeInFlight;
  return x402Fetch;
}

/** Install globally so unmodified agent code pays automatically. Returns an uninstall fn. */
export function installX402(cfg: X402Config): () => void {
  const original = globalThis.fetch;
  const f = createX402Fetch({ ...cfg, baseFetch: original.bind(globalThis) });
  (globalThis as any).fetch = f;
  (globalThis as any).__x402 = f;
  return () => { (globalThis as any).fetch = original; };
}

export const __internals = { CHAINS, XFER_TH, DOMAIN_TH, keccak256, addressOf, jMulCT, makeNonce, signWith, digest, domainSep, jMul, jAdd, affine, toBig, beBytes, G, N, P };
