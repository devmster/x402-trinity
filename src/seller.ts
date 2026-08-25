/**
 * x402-trinity/seller - the OTHER half of the protocol: charge for a resource and get paid.
 *
 * Zero dependencies. Optional module - not part of the buyer core, so it does not count
 * against the wrapper's footprint.
 *
 *     import { createX402Seller } from './seller.ts';
 *
 *     const seller = createX402Seller({
 *       payTo: '0xYourWallet',          // 100% of every payment lands here
 *       price: '1000',                   // atomic units (USDC = 6dp) -> 0.001 USDC
 *       network: 'base',
 *       facilitator: 'https://your-facilitator.example',
 *     });
 *
 *     // in any fetch-style handler:
 *     const gate = await seller.guard(request);
 *     if (gate.response) return gate.response;      // unpaid or rejected
 *     return new Response(mySecretData);            // paid; gate.settlement has the tx
 *
 * The seller never holds funds and never needs a private key. It quotes a price, then
 * asks a facilitator to verify and settle. Money moves buyer -> payTo directly on-chain.
 */

export interface SellerConfig {
  /** Your wallet. Receives 100% of each payment. */
  payTo: string;
  /** Price in atomic units of the asset (USDC has 6 decimals). */
  price: string;
  /** 'base', or the CAIP-2 id 'eip155:8453'. Other chains need explicit asset + extra. */
  network: string;
  /** Token contract. Defaults to USDC for the network. */
  asset?: string;
  /** EIP-712 domain for the asset. Defaults to USDC's. */
  extra?: { name: string; version: string };
  /**
   * Facilitator base URL. REQUIRED - there is no safe default.
   *
   * The public facilitator at x402.org settles TESTNET ONLY on EVM. Defaulting to it in a
   * mainnet package would mean every payment verifies and then fails to settle, which looks
   * like your service is broken. Supply one that settles on your network:
   *   - Coinbase CDP (needs an API key)
   *   - your own, if you run settlement yourself
   */
  facilitator: string;
  /** How long a quote stays valid. Default 600s. */
  maxTimeoutSeconds?: number;
  /** Human-readable description surfaced in the challenge. */
  description?: string;
  /**
   * Replay guard. An authorization nonce redeems once ON-CHAIN, but nothing stops a buyer
   * re-presenting an already-settled payment to get the resource a second time for free.
   * That is revenue loss, and the default in-memory guard forgets everything on restart.
   *
   * `add` receives the authorization's `validBefore`, so a store only has to remember a
   * nonce until it expires - after that the authorization is dead on-chain anyway and the
   * entry can be pruned. Without that, the guard grows without bound.
   *
   * REQUIRED on mainnet unless `acknowledgeEphemeralReplayGuard` is set.
   */
  nonceStore?: {
    seen: (nonce: string) => Promise<boolean>;
    add: (nonce: string, expiresAtUnix: number) => Promise<void>;
  };
  /** Accept an in-memory replay guard. Only sane for local development. */
  acknowledgeEphemeralReplayGuard?: boolean;
  onSettled?: (i: { transaction: string; payer: string; amount: string; network: string }) => void;
  /** Settlement attempts before giving up. Default 3. Public facilitators are flaky. */
  settleRetries?: number;
  /** Base backoff between settlement attempts, ms. Default 1500 (then 3000, 4500...). */
  settleBackoffMs?: number;
  onSettleFailure?: (i: { reason: string; attempts: number; nonce: string }) => void;
}

/** MAINNET ONLY. For any other network pass `asset` and `extra` explicitly. */
const USDC: Record<string, { asset: string; caip2: string; name: string; version: string }> = {
  // Base only, matching the wrapper. Anything else needs explicit asset + extra.
  'base': { asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', caip2: 'eip155:8453', name: 'USD Coin', version: '2' },
};

export interface GateResult {
  /** Non-null when the caller must return this instead of serving the resource. */
  response: Response | null;
  settlement?: { transaction: string; payer: string; network: string };
  reason?: string;
  /**
   * True when the payment was VALID but settlement failed on our side. The response is a
   * 503, not a 402 - see the note on `guard`.
   */
  settlementFailed?: boolean;
}

export function createX402Seller(cfg: SellerConfig) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(cfg.payTo)) throw new Error('x402 seller: payTo must be a 20-byte address');
  if (!/^[0-9]+$/.test(cfg.price) || BigInt(cfg.price) <= 0n) throw new Error('x402 seller: price must be a positive integer in atomic units');

  const key = cfg.network.toLowerCase();
  const known = USDC[key] ?? Object.values(USDC).find(u => u.caip2 === key);
  if (!known && !(cfg.asset && cfg.extra)) throw new Error(`x402 seller: unknown network '${cfg.network}' - pass asset and extra explicitly`);

  if (!cfg.facilitator || !/^https?:\/\//.test(cfg.facilitator)) {
    throw new Error(
      'x402 seller: `facilitator` is required and must be an http(s) URL. There is no default - ' +
      'the public x402.org facilitator settles testnet only, so defaulting to it would make every ' +
      'mainnet payment verify and then fail to settle.'
    );
  }
  const facilitator = cfg.facilitator.replace(/\/$/, '');
  const timeout = cfg.maxTimeoutSeconds ?? 600;

  const requirements = {
    scheme: 'exact',
    network: known?.caip2 ?? cfg.network,
    amount: cfg.price,
    asset: cfg.asset ?? known!.asset,
    payTo: cfg.payTo,
    maxTimeoutSeconds: timeout,
    extra: cfg.extra ?? { name: known!.name, version: known!.version },
  };

  // A guard that forgets on restart = paid content served twice for free. Every shipped
  // network is mainnet, so this always applies.
  if (!cfg.nonceStore && !cfg.acknowledgeEphemeralReplayGuard) {
    throw new Error(
      `x402 seller: network '${cfg.network}' needs a durable nonceStore. ` +
      `The default replay guard is in-memory and forgets every settled payment on restart, ` +
      `so a buyer could re-present one and get the resource again for free. ` +
      `Pass nonceStore (see createFileNonceStore) or acknowledgeEphemeralReplayGuard: true.`
    );
  }

  // Default guard: in-memory, expiry-aware so it cannot grow without bound. A nonce only
  // has to be remembered until validBefore - after that the authorization cannot settle.
  const seenLocal = new Map<string, number>();
  let lastPrune = 0;
  const store = cfg.nonceStore ?? {
    seen: async (n: string) => {
      const now = Math.floor(Date.now() / 1000);
      if (now - lastPrune > 60) {
        lastPrune = now;
        for (const [k, exp] of seenLocal) if (exp <= now) seenLocal.delete(k);
      }
      const exp = seenLocal.get(n.toLowerCase());
      return exp !== undefined && exp > now;
    },
    add: async (n: string, expiresAt: number) => { seenLocal.set(n.toLowerCase(), expiresAt); },
  };

  const post = async (path: string, body: unknown) => {
    const r = await fetch(facilitator + path, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(45000),
    });
    const text = await r.text();
    try { return JSON.parse(text); } catch { return { _raw: text, _status: r.status }; }
  };

  const challenge = (url: string): Response => new Response(
    JSON.stringify({ error: 'payment required', price: cfg.price, payTo: cfg.payTo }),
    {
      status: 402,
      headers: {
        'content-type': 'application/json',
        // v2 transport: protocol data rides in the header, the body is the app's own
        'payment-required': JSON.stringify({
          x402Version: 2,
          error: 'PAYMENT-SIGNATURE header is required',
          resource: { url, description: cfg.description ?? 'paid resource', mimeType: 'application/json' },
          accepts: [requirements],
        }),
      },
    });

  return {
    requirements,

    /** Returns {response} when the caller must NOT serve the resource. */
    async guard(request: Request): Promise<GateResult> {
      const url = request.url;
      const header = request.headers.get('payment-signature') ?? request.headers.get('x-payment');
      if (!header) return { response: challenge(url), reason: 'no payment presented' };

      let payload: any;
      try { payload = JSON.parse(atob(header)); }
      catch { return { response: challenge(url), reason: 'malformed payment header' }; }

      const nonce = payload?.payload?.authorization?.nonce;
      if (typeof nonce !== 'string') return { response: challenge(url), reason: 'payment missing an authorization nonce' };

      // Replay guard: a settled payment must not buy the resource twice.
      if (await store.seen(nonce)) return { response: challenge(url), reason: 'authorization nonce already used' };

      const v = await post('/verify', { x402Version: 2, paymentPayload: payload, paymentRequirements: requirements });
      if (v?.isValid !== true) {
        return { response: challenge(url), reason: 'facilitator rejected: ' + (v?.invalidReason ?? JSON.stringify(v)) };
      }

      // Settlement, with retries. Public facilitators fall over - we have watched one race
      // its own transaction nonce mid-demo - and a transient failure must not be reported as
      // "you did not pay".
      const attempts = Math.max(1, cfg.settleRetries ?? 3);
      const backoff = cfg.settleBackoffMs ?? 1500;
      let s: any = null;
      for (let i = 0; i < attempts; i++) {
        s = await post('/settle', { x402Version: 2, paymentPayload: payload, paymentRequirements: requirements });
        if (s?.success === true) break;
        if (i < attempts - 1) await new Promise(r => setTimeout(r, backoff * (i + 1)));
      }

      if (s?.success !== true) {
        // CRITICAL: 503, not 402.
        //
        // The payment verified. The failure is ours. Answering 402 would tell the buyer
        // "you have not paid", and a correct buyer would then mint a FRESH authorization -
        // so if this settlement later lands, they have paid twice.
        //
        // 503 says "valid, but we could not complete it". This wrapper's buyer treats any
        // 5xx as ambiguous and re-sends the SAME authorization, whose nonce can only be
        // redeemed once on-chain. Exactly one payment either way.
        //
        // The nonce is deliberately NOT recorded as used, so the retry is accepted.
        const reason = 'settlement failed after ' + attempts + ' attempts: ' + (s?.errorReason ?? JSON.stringify(s));
        cfg.onSettleFailure?.({ reason, attempts, nonce });
        return {
          settlementFailed: true,
          reason,
          response: new Response(JSON.stringify({
            error: 'settlement_unavailable',
            detail: 'Your payment was valid. Settlement failed on our side. Retry with the SAME payment header.',
            reason: s?.errorReason ?? null,
          }), {
            status: 503,
            headers: { 'content-type': 'application/json', 'retry-after': '5' },
          }),
        };
      }

      // Remember it only until the authorization expires; after that it is dead on-chain.
      const expiresAt = Number(payload?.payload?.authorization?.validBefore ?? 0)
        || Math.floor(Date.now() / 1000) + timeout;
      await store.add(nonce, expiresAt);
      const settlement = { transaction: s.transaction, payer: s.payer, network: s.network };
      cfg.onSettled?.({ ...settlement, amount: cfg.price });
      return { response: null, settlement };
    },

    /** Header a paid response should carry, so the buyer can read the receipt. */
    receiptHeader(settlement: { transaction: string; payer: string; network: string }): Record<string, string> {
      return { 'payment-response': btoa(JSON.stringify({ success: true, ...settlement })) };
    },
  };
}
