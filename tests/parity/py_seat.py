"""
THE PYTHON SEAT.

Reads tests/fixtures/buyer_policy_vectors.json, runs every vector through the SHIPPED client,
and prints one line per step. The TypeScript seat prints the same lines from the same fixture.
CI compares the two byte for byte.

    python tests/parity/py_seat.py

WHY IT GOES THROUGH urlopen RATHER THAN CALLING _pick DIRECTLY. Python does expose the gate,
but the TypeScript client does not - and a comparison is only worth having if both sides are
driven the same way. So both seats run the real 402 flow against a stub.

NOTHING HERE TOUCHES THE NETWORK. The stub is origin and facilitator at once: it answers the
challenge, accepts the signed authorization, and reports settlement. No RPC, no collector,
no money.
"""

import io
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

from x402_trinity import X402Client, Policy          # noqa: E402

# LF, always. Windows would otherwise translate every newline to CRLF and the seats would
# differ by a byte per line for a reason that has nothing to do with policy.
sys.stdout.reconfigure(newline="\n")

FIXTURE = os.path.join(HERE, "..", "fixtures", "buyer_policy_vectors.json")
with open(FIXTURE, encoding="utf8") as fh:
    fixture = json.load(fh)

# A throwaway key. It signs nothing that ever reaches a chain.
KEY = "0x" + "11" * 32

# The fixture speaks the wire's camelCase; Python's Policy takes snake_case. Mapping it here
# keeps ONE fixture for both languages rather than two that can drift - which is the whole point.
POLICY_KEYS = {
    "maxAmountPerRequest": "max_amount_per_request",
    "totalBudget": "total_budget",
    "allowHosts": "allow_hosts",
    "allowPayTo": "allow_pay_to",
    "allowAssets": "allow_assets",
    "allowNetworks": "allow_networks",
}


class _Served:
    """The minimum a urlopen caller needs back on success."""

    def __init__(self, body: bytes, headers: dict):
        self._fp = io.BytesIO(body)
        self.status = 200
        self.headers = headers

    def read(self, *a):
        return self._fp.read(*a)

    def getcode(self):
        return 200

    def info(self):
        return self.headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


mismatches = 0

for vector in fixture["vectors"]:
    kwargs = {POLICY_KEYS[k]: v for k, v in vector["policy"].items()}
    # Amounts arrive as strings so no precision is lost in JSON; Policy wants ints.
    for k in ("max_amount_per_request", "total_budget"):
        if k in kwargs:
            kwargs[k] = int(kwargs[k])

    state = {"current": None, "declined": ""}

    def opener(req, timeout=None, _s=state):
        """Origin and facilitator in one. Challenge first, then serve what is paid for."""
        has_pay = any(h.lower() in ("x-payment", "x402-payment-authorization")
                      for h in req.headers)
        if not has_pay:
            body = json.dumps({
                "x402Version": 1,
                "error": "X-PAYMENT header is required",
                "accepts": [_s["current"]],
            }).encode()
            raise urllib.error.HTTPError(
                req.full_url, 402, "Payment Required",
                {"content-type": "application/json"}, io.BytesIO(body),
            )
        return _Served(json.dumps({"ok": True}).encode(),
                       {"content-type": "application/json"})

    def on_decline(d, _s=state):
        _s["declined"] = d["reason"]

    # Built ONCE per vector and reused across its steps. A fresh client per step would reset
    # `spent`, and the budget vectors would never run out.
    client = X402Client(
        private_key=KEY,
        acknowledge_ephemeral_budget=True,
        warm_in_background=False,
        policy=Policy(**kwargs),
        opener=opener,
        on_decline=on_decline,
    )

    for i, step in enumerate(vector["steps"]):
        host = step.get("host", fixture["host"])
        pay_to = step.get("payTo", fixture["payTo"])
        resource = "https://%s/v1/resource" % host

        state["current"] = {
            "scheme": "exact",
            "network": fixture["network"],
            "payTo": pay_to,
            "asset": fixture["asset"],
            "maxAmountRequired": step["amount"],
            "maxTimeoutSeconds": 120,
            "extra": {"name": "USD Coin", "version": "2"},
            "resource": resource,
        }
        state["declined"] = ""

        try:
            client.urlopen(resource)
            decision = "allow"
        except Exception:
            decision = "deny"

        reason = state["declined"] if decision == "deny" else ""
        remaining = str(client.policy.budget - client.spent)

        print("%s|%d|%s|%s|%s" % (vector["id"], i, decision, remaining, reason))

        want = step["expect"]
        if (decision != want["decision"] or remaining != want["remaining"]
                or reason != want["reason"]):
            sys.stderr.write(
                "  gold mismatch in %s step %d\n"
                "    expected  %s|%s|%s\n"
                "    got       %s|%s|%s\n"
                % (vector["id"], i, want["decision"], want["remaining"], want["reason"],
                   decision, remaining, reason))
            mismatches += 1

if mismatches:
    sys.stderr.write("\n%d step(s) disagree with the gold fixture.\n" % mismatches)
    sys.exit(1)
