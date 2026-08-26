# x402-trinity

**A drop-in `fetch` replacement that lets an AI agent pay for things by itself — with hard
spending limits, no hosted wallet service, and no changes to the agent's own code.**

Zero runtime dependencies. 7 KB gzipped. Buyer *and* seller in TypeScript; buyer in Python.

```bash
npm install x402-trinity
```

## Why

When an agent hits a paid resource it gets `402 Payment Required`. Without something to
handle that, the request simply fails.

x402-trinity handles it: reads the challenge, checks it against limits you set, signs, retries.
All of it locally — no hosted wallet service, no third-party API, and the key never leaves
your process.

Gas exists but the payer doesn't pay it — under EIP-3009 the facilitator submits the
transfer, so an agent's wallet only ever needs USDC.

---

## Buy (agent pays for things)

```js
import { createX402Fetch } from 'x402-trinity';

const x402Fetch = createX402Fetch({
  privateKey: process.env.X402_PRIVATE_KEY,   // never hardcode
  policy: {
    maxAmountPerRequest: '5000',              // 0.005 USDC max per call  (REQUIRED)
    totalBudget: '1000000',                   // 1.00 USDC lifetime       (REQUIRED)
    allowHosts: ['api.example.com'],
    allowPayTo: ['0x...'],
  },
});

const r = await x402Fetch('https://api.example.com/data');   // 402 handled, returns 200
```

Or patch the global so unmodified code pays automatically:

```js
import { installX402 } from 'x402-trinity';
const uninstall = installX402(cfg);   // globalThis.fetch now pays 402s
```

**Confirm which wallet will pay before funding anything:**

```bash
X402_PRIVATE_KEY=0x... npx x402-trinity-whoami
```

It prints the address and its balance on every chain, and **never prints the key**. If the
address is not the wallet you meant, stop before sending anything.

## Sell (charge for a resource, get paid)

```js
import { createX402Seller } from 'x402-trinity/seller';
import { createFileNonceStore } from 'x402-trinity/budget-file';

const seller = createX402Seller({
  payTo: '0xYourWallet',      // 100% of every payment lands here
  price: '10000',             // 0.01 USDC, atomic units
  network: 'base',
  facilitator: 'https://your-facilitator.example',   // REQUIRED — no default exists
  nonceStore: createFileNonceStore('./.x402-nonces.json'),  // REQUIRED — see below
});

// in any fetch-style handler:
const gate = await seller.guard(request);
if (gate.response) return gate.response;          // unpaid or refused — hand back the 402
return new Response(yourData, { headers: seller.receiptHeader(gate.settlement) });
```

Both required fields are deliberate. There is no default facilitator because settling is
someone's real money and guessing an endpoint is not a default. And the replay guard has to
outlive the process: an in-memory one forgets every settled payment on restart, so a buyer
could re-present a spent authorization and get the resource again for free. The constructor
throws rather than let either be implicit.

The seller never holds a private key and never touches funds. It quotes a price and asks a
facilitator to verify and settle; money moves buyer → you directly on-chain.

> **This release ships Base + USDC only.** Any other EVM chain works through `customChains`;
> your address is the same on all of them.

---

## What it does

| | |
|---|---|
| **Protocols** | x402 **v1 and v2**, detected per response. Unknown versions and MPP challenges declined with a clear reason, never guessed |
| **Chains** | Base mainnet + USDC, shipped as the default. Any other EVM chain via `customChains` |
| **Networks** | short names *and* CAIP-2 (`eip155:8453`) |
| **Custody** | `privateKey`, additive `shards`, or `remoteSign` (HSM/MPC) — your choice, not the architecture's |
| **Speed** | 3.2 µs warm / 1.0 ms cold (TypeScript); 1.2 µs / 1.7 ms (Python) |
| **Runtime** | auto-detects Cloudflare Workers and changes strategy; also Node, Bun, Deno |
| **Safety** | mandatory caps, allowlists, never-pay-twice reconciliation, timing-hardened signing |

### Another chain

Base is the default. The signing is chain-agnostic, so add whatever you need — including a
testnet to rehearse on:

```js
const fetch2 = createX402Fetch({
  privateKey: process.env.X402_PRIVATE_KEY,
  maxAmountPerRequest: '10000',
  totalBudget: '100000',
  customChains: {
    'base-sepolia': { id: 84532, asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e', name: 'USDC', version: '2' },
  },
});
```

Verify the entry against the deployed contract first: call `DOMAIN_SEPARATOR()` and check it
equals what this library computes. A wrong `name` or `version` produces a signature that looks
valid and the contract rejects.


### It deliberately will not

Broadcast to a chain · hold funds · need gas or an RPC · take a cut of a payment
(structurally impossible — EIP-3009 has one recipient) · require a hosted signer ·
pay without limits · guess at a protocol it doesn't speak.

---

## Safety — read this before real money

**Caps are mandatory.** `maxAmountPerRequest` and `totalBudget` have no defaults; the wrapper
refuses to construct without them. An auto-payer without limits is a money leak controlled by
whoever runs the server.

**`totalBudget` alone is per-instance.** It is an in-memory counter that resets on restart, on
a new client, and on every Cloudflare Worker isolate — which is per request. On mainnet that
turns a lifetime cap into a per-request cap. **Mainnet therefore requires a durable
`budgetStore`**, or an explicit `acknowledgeEphemeralBudget: true`:

```js
import { createFileBudgetStore } from 'x402-trinity/budget-file';

createX402Fetch({
  ...,
  budgetStore: createFileBudgetStore('./.x402-budget.json'),   // survives restarts
});
```

**The key is in the process.** That is the trade for having no hosted signer. Bound it:
use a dedicated wallet holding only what you would accept losing, set `allowPayTo` so an
exfiltrated key still cannot pay a stranger through this wrapper, and use `remoteSign` if you
need enclave-grade custody.

**Timing hardening is hardening, not a proof.** Secret scalars use blinding plus
always-add-and-double, which cut the timing spread from 99.6% to 12% (Python: 99.9% → 1.1%).
BigInt arithmetic is itself variable-time and no pure-JS implementation removes that.

---

## MCP server — give an agent a wallet

MCP is how an assistant gets tools. This exposes three:

| tool | |
|---|---|
| `check_price` | what a resource costs, **without paying** |
| `pay_and_fetch` | fetch it, paying if it is within your limits |
| `wallet_status` | address, balance, spent, remaining |

```json
{
  "mcpServers": {
    "x402-trinity": {
      "command": "npx",
      "args": ["-y", "x402-trinity-mcp"],
      "env": {
        "X402_PRIVATE_KEY": "0x...",
        "X402_MAX_PER_REQUEST": "50000",
        "X402_TOTAL_BUDGET": "1000000",
        "X402_BUDGET_FILE": "./.x402-budget.json",
        "X402_ALLOW_HOSTS": "api.example.com",
        "X402_NETWORKS": "base"
      }
    }
  }
}
```

**A model decides when these run.** It cannot be reasoned with about budgets, and a
paywalled page can claim any price it likes. So the limits are not parameters the model can
set — they come from the environment, and the server **refuses to start** without
`X402_PRIVATE_KEY`, `X402_MAX_PER_REQUEST` and `X402_TOTAL_BUDGET`.

Set `X402_BUDGET_FILE` too, or the lifetime ceiling resets every restart. Set
`X402_ALLOW_HOSTS` and nothing else can be paid, however convincing the challenge looks.
Use a wallet holding only what you would accept losing.

---

## Python

Same protocol, standard library only. **Buyer only** — to charge for a resource, use the
TypeScript seller. Aimed at long-lived processes: on-body agents, robotics controllers,
harvesting scripts.

```python
from x402_trinity import X402Client, Policy

client = X402Client(
    private_key=os.environ["X402_PRIVATE_KEY"],
    policy=Policy(max_amount_per_request=5000, total_budget=1_000_000,
                  allow_hosts=["api.example.com"]),
)
body = client.urlopen("https://api.example.com/data").read()
```

Or as a decorator, so payment-unaware code just works:

```python
from x402_trinity import x402_telemetry

@x402_telemetry(private_key=KEY, policy=Policy(...))
def harvest():
    return urllib.request.urlopen("https://sensor.local/v1/lidar").read()
```

The warm path is **1.1 µs** — a long-lived controller is warm after its first payment.

---

## Development

```bash
npm install
npm run build        # dist/*.js + *.min.js + *.d.ts
```

`esbuild`, `typescript` and `wrangler` are **dev dependencies only**, used for building.
The shipped package has **zero runtime dependencies**.

## License

Business Source License 1.1. The source is open to read, modify and use non-commercially;
production use is granted except as a hosted or managed service offering its functionality
to third parties. It converts to MIT on 2029-08-25. See [LICENSE](LICENSE).

This software moves money — read the additional notice there, and set your spending caps.
