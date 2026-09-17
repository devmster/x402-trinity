/**
 * THE TYPESCRIPT SEAT.
 *
 * Reads tests/fixtures/buyer_policy_vectors.json, runs every vector through the SHIPPED
 * client, and prints one line per step. The Python seat prints the same lines from the same
 * fixture. CI compares the two byte for byte.
 *
 *   node tests/parity/ts_seat.mjs
 *
 * WHY IT GOES THROUGH createX402Fetch RATHER THAN CALLING THE GATE DIRECTLY. The policy
 * decision is closed over inside the client and is not exported. Reaching past that would
 * mean testing a copy of the logic rather than the logic itself - the exact failure this
 * exercise exists to prevent. So the seat drives the real 402 flow against a stub origin.
 *
 * NOTHING HERE TOUCHES THE NETWORK. The stub is origin and facilitator at once: it answers
 * the challenge, accepts the signed authorization, and reports settlement. No RPC, no
 * collector, no money.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createX402Fetch } from '../../dist/x402.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'buyer_policy_vectors.json'), 'utf8'));

/** A throwaway key. It signs nothing that ever reaches a chain. */
const KEY = '0x' + '11'.repeat(32);

let mismatches = 0;

for (const vector of fixture.vectors) {
  // The client is built ONCE per vector and reused across its steps. A fresh client per step
  // would reset `spent`, and the budget vectors would never run out - which is most of what
  // this fixture is for.
  let current = null;          // the requirement for the step being run
  let declined = '';           // reason captured from the most recent decline

  const baseFetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const pay = req.headers.get('x-payment') ?? req.headers.get('x402-payment-authorization');
    if (!pay) {
      return new Response(
        JSON.stringify({ x402Version: 1, error: 'X-PAYMENT header is required', accepts: [current] }),
        { status: 402, headers: { 'content-type': 'application/json' } },
      );
    }
    // The signature has its own vectors elsewhere; a parity run should fail for policy
    // reasons or not at all, so the stub settles whatever it is handed.
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-payment-response': btoa(JSON.stringify({ success: true, network: current.network })),
      },
    });
  };

  const f = createX402Fetch({
    privateKey: KEY,
    acknowledgeEphemeralBudget: true,
    policy: vector.policy,
    baseFetch,
    onDecline: (d) => { declined = d.reason; },
  });

  for (let i = 0; i < vector.steps.length; i++) {
    const step = vector.steps[i];
    const host = step.host ?? fixture.host;
    const payTo = step.payTo ?? fixture.payTo;

    current = {
      scheme: 'exact',
      network: fixture.network,
      payTo,
      asset: fixture.asset,
      maxAmountRequired: step.amount,
      maxTimeoutSeconds: 120,
      extra: { name: 'USD Coin', version: '2' },
      resource: `https://${host}/v1/resource`,
    };
    declined = '';

    let decision;
    try {
      const res = await f(current.resource);
      decision = res.status === 200 ? 'allow' : 'deny';
    } catch {
      decision = 'deny';
    }
    const reason = decision === 'deny' ? declined : '';
    const { remaining } = await f.stats();

    console.log(`${vector.id}|${i}|${decision}|${remaining}|${reason}`);

    const want = step.expect;
    if (decision !== want.decision || remaining !== want.remaining || reason !== want.reason) {
      console.error(
        `  gold mismatch in ${vector.id} step ${i}\n` +
        `    expected  ${want.decision}|${want.remaining}|${want.reason}\n` +
        `    got       ${decision}|${remaining}|${reason}`,
      );
      mismatches++;
    }
  }
}

if (mismatches) {
  console.error(`\n${mismatches} step(s) disagree with the gold fixture.`);
  process.exit(1);
}
