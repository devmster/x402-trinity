"""
File-backed durable budget store for the Python wrapper. OPTIONAL, stdlib only.

Needs no Cloudflare, no database, no network - a laptop, a VPS or a robotics controller
is enough.

    from x402_trinity import X402Client, Policy
    from budget_file import FileBudgetStore

    client = X402Client(
        private_key=os.environ["X402_PRIVATE_KEY"],
        policy=Policy(max_amount_per_request=5000, total_budget=1_000_000,
                      allow_networks=["base"]),
        budget_store=FileBudgetStore("./.x402-budget.json"),
    )

The spend total survives restarts, which is the point: an in-memory budget resets every
time the process starts, so on mainnet it caps nothing.

Concurrency: an exclusive lock file (O_EXCL) prevents two processes on the same machine
from both passing the same check. It does NOT coordinate across machines - back the same
interface with Redis/Postgres for that.
"""

import json
import os
import time
from datetime import datetime, timezone


class BudgetError(Exception):
    pass


class FileBudgetStore:
    def __init__(self, path: str, lock_timeout: float = 5.0):
        self.path = path
        self.lock_path = path + ".lock"
        self.lock_timeout = lock_timeout

    # ---- internals ----

    def _read(self) -> int:
        if not os.path.exists(self.path):
            return 0
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                v = int(json.load(f).get("spent", 0))
            return max(v, 0)
        except Exception as e:
            # A corrupt ledger must NOT read as zero - that would silently reset the budget
            # and re-open unlimited spending. Fail closed.
            raise BudgetError(
                "x402 budget file is unreadable: %s (%s). "
                "Refusing to treat it as zero spend." % (self.path, e)
            )

    def _write(self, v: int) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"spent": str(v), "updated": datetime.now(timezone.utc).isoformat()}, f)
        os.replace(tmp, self.path)          # atomic on the same filesystem

    class _Lock:
        def __init__(self, outer):
            self.outer = outer
            self.fd = None

        def __enter__(self):
            deadline = time.time() + self.outer.lock_timeout
            while True:
                try:
                    self.fd = os.open(self.outer.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    return self
                except FileExistsError:
                    if time.time() > deadline:
                        raise BudgetError("x402 budget lock timed out: %s" % self.outer.lock_path)
                    time.sleep(0.015)

        def __exit__(self, *a):
            try:
                if self.fd is not None:
                    os.close(self.fd)
            except Exception:
                pass
            try:
                os.unlink(self.outer.lock_path)
            except Exception:
                pass

    # ---- the interface the wrapper calls ----

    def reserve(self, amount: int, total_budget: int) -> bool:
        """Atomic check-and-increment. False if the payment would exceed the budget."""
        with self._Lock(self):
            now = self._read()
            if now + amount > total_budget:
                return False
            self._write(now + amount)
            return True

    def release(self, amount: int) -> None:
        with self._Lock(self):
            now = self._read()
            self._write(max(now - amount, 0))

    def spent(self) -> int:
        return self._read()
