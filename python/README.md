# x402-trinity

**Let a Python process pay for things by itself — with hard spending limits, no hosted wallet
service, and no changes to the code doing the fetching.**

Standard library only. No dependencies, at all.

```bash
pip install x402-trinity
```

## Why

When a script hits a paid resource it gets `402 Payment Required`. Without something to handle
that, the request simply fails.

x402-trinity handles it: reads the challenge, checks it against limits you set, signs, retries.
All of it locally — no hosted wallet service, no third-party API, and the key never leaves your
process.

Gas exists but the payer doesn't pay it — under EIP-3009 the facilitator submits the transfer,
so the wallet only ever needs USDC.

## Use

```python
import os
from x402_trinity import X402Client, Policy

client = X402Client(
    private_key=os.environ["X402_PRIVATE_KEY"],
    policy=Policy(
        max_amount_per_request=5000,      # 0.005 USDC per call   (REQUIRED)
        total_budget=1_000_000,           # 1.00 USDC lifetime    (REQUIRED)
        allow_hosts=["api.example.com"],
    ),
)

body = client.urlopen("https://api.example.com/data").read()
```

Or as a decorator, so payment-unaware code just works:

```python
from x402_trinity import x402_telemetry, Policy

@x402_telemetry(private_key=KEY, policy=Policy(max_amount_per_request=5000,
                                               total_budget=1_000_000))
def harvest():
    return urllib.request.urlopen("https://sensor.local/v1/lidar").read()
```

Inside the decorated function `urllib.request.urlopen` pays 402s automatically. Existing code
is untouched.

## Scope

**Buyer only.** To charge for a resource, use the TypeScript seller in the same project.

**Base mainnet + USDC.** Other EVM chains work by passing `custom_chains` to `X402Client`.
Check any entry against the deployed contract first: call `DOMAIN_SEPARATOR()` and confirm it
equals what this library computes. A wrong `name` or `version` produces a signature that looks
valid and the contract rejects.

## Limits are not optional

`max_amount_per_request` and `total_budget` are required arguments. An auto-payer without caps
is a money leak controlled by whoever runs the server on the other end. Set `allow_hosts` and
nothing else can be paid, however convincing the challenge looks.

## Before you use it with real money

This software signs payment authorizations. You are responsible for the funds in any wallet you
configure it with, for the limits you set, and for the behaviour of any autonomous process you
connect to it. Use a dedicated wallet holding only what you would accept losing.

## Links

- Source: https://github.com/devmster/x402-trinity
- TypeScript package (buyer, seller, MCP server): `npm install x402-trinity`

MIT
