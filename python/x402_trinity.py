"""
x402-trinity (Python) - zero-dependency x402 payment interceptor.

Sibling of the TypeScript edge build. Same protocol, same EIP-712 encoder, same
ground-truth fixtures - targeted at long-lived processes: on-body agents, robotics
controllers, data-harvesting scripts.

Standard library only. No requests, no eth-account, no coincurve, no pycryptodome.

Why the crypto is inline:
  - hashlib has NO keccak256. hashlib.sha3_256 is a DIFFERENT function (SHA-3 uses
    0x06 padding, keccak uses 0x01) and produces a different digest, so every
    signature built on it would be rejected on-chain.
  - There is no stdlib secp256k1 at all.

Performance shape (measure with bench(), do not assume):
  cold  - must compute k*G inline; interpreted point math, tens of milliseconds
  warm  - a precomputed nonce is available; two modular multiplies, microseconds
A long-lived controller is warm after its first payment, which is the whole point
of the anticipatory pool. This is the wrong trade for a short-lived edge isolate;
use the TypeScript build there.
"""

from __future__ import annotations

import json
import base64
import secrets
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = ["keccak256", "X402Client", "x402_telemetry", "Policy", "address_of"]

# Captured at import, BEFORE anything can monkey-patch the global. x402_telemetry patches
# urllib.request.urlopen process-wide; if the client also went through the global it would
# re-enter itself forever. The client always uses this pristine reference.
_URLOPEN = urllib.request.urlopen

# ============================== keccak-256 ==============================

_MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# rho rotation offsets, lane index = x + 5y
_RHO = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
]
# pi permutation: _PI[src] = dst, dst = y + 5*((2x+3y) mod 5)
_PI = [0] * 25
for _y in range(5):
    for _x in range(5):
        _PI[_x + 5 * _y] = _y + 5 * ((2 * _x + 3 * _y) % 5)


def _rotl(v: int, n: int) -> int:
    if n == 0:
        return v
    return ((v << n) | (v >> (64 - n))) & _MASK


def _keccak_f(S: List[int]) -> None:
    for rnd in range(24):
        # theta
        C = [S[x] ^ S[x + 5] ^ S[x + 10] ^ S[x + 15] ^ S[x + 20] for x in range(5)]
        for x in range(5):
            D = C[(x + 4) % 5] ^ _rotl(C[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                S[x + y] ^= D
        # rho + pi
        B = [0] * 25
        for i in range(25):
            B[_PI[i]] = _rotl(S[i], _RHO[i])
        # chi
        for y in range(0, 25, 5):
            for x in range(5):
                S[x + y] = B[x + y] ^ ((~B[(x + 1) % 5 + y] & _MASK) & B[(x + 2) % 5 + y])
        # iota
        S[0] ^= _RC[rnd]


def keccak256(*parts: bytes) -> bytes:
    """keccak256 over one or more byte runs, absorbed as if concatenated."""
    data = b"".join(parts)
    S = [0] * 25
    rate = 136
    off = 0
    while len(data) - off >= rate:
        blk = data[off:off + rate]
        for i in range(17):
            S[i] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], "little")
        _keccak_f(S)
        off += rate
    rem = bytearray(data[off:])
    rem.append(0x01)                       # keccak padding, NOT SHA-3's 0x06
    rem.extend(b"\x00" * (rate - len(rem)))
    rem[rate - 1] |= 0x80
    for i in range(17):
        S[i] ^= int.from_bytes(bytes(rem[i * 8:(i + 1) * 8]), "little")
    _keccak_f(S)
    return b"".join(S[i].to_bytes(8, "little") for i in range(4))


# ============================== secp256k1 ==============================

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_HALF_N = _N >> 1
_G = (_GX, _GY, 1)

Point = Tuple[int, int, int]  # jacobian


def _j_dbl(p: Point) -> Point:
    X, Y, Z = p
    if Y == 0 or Z == 0:
        return (0, 1, 0)
    A = X * X % _P
    B = Y * Y % _P
    C = B * B % _P
    D = 2 * (((X + B) * (X + B) - A - C) % _P) % _P
    E = 3 * A % _P
    F = E * E % _P
    X3 = (F - 2 * D) % _P
    return (X3, (E * (D - X3) - 8 * C) % _P, 2 * Y * Z % _P)


def _j_add(p: Point, q: Point) -> Point:
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    if Z1 == 0:
        return q
    if Z2 == 0:
        return p
    ZZ1 = Z1 * Z1 % _P
    ZZ2 = Z2 * Z2 % _P
    U1 = X1 * ZZ2 % _P
    U2 = X2 * ZZ1 % _P
    S1 = Y1 * Z2 * ZZ2 % _P
    S2 = Y2 * Z1 * ZZ1 % _P
    H = (U2 - U1) % _P
    R = (S2 - S1) % _P
    if H == 0:
        return _j_dbl(p) if R == 0 else (0, 1, 0)
    HH = H * H % _P
    HHH = H * HH % _P
    V = U1 * HH % _P
    X3 = (R * R - HHH - 2 * V) % _P
    return (X3, (R * (V - X3) - S1 * HHH) % _P, Z1 * Z2 * H % _P)


def _j_mul(k: int, p: Point) -> Point:
    """
    Double-and-add. Variable-time: it branches on key bits. Runs only during key setup
    and idle nonce fill, never while a request is in flight - but it is NOT hardened
    against a co-resident attacker measuring timing. See README before using this in a
    shared-tenant process.
    """
    r: Point = (0, 1, 0)
    a = p
    while k > 0:
        if k & 1:
            r = _j_add(r, a)
        a = _j_dbl(a)
        k >>= 1
    return r


def _j_mul_ct(k: int, p: Point) -> Point:
    """
    Constant-time-hardened scalar multiply, for scalars that ARE secret: the private key
    and the ECDSA nonce k (leaking k leaks the key outright).

    Two countermeasures:
      1. Scalar blinding - compute (k + r*n)*G. Identical result, since n*G is the point
         at infinity, but the bit pattern is re-randomised on every call.
      2. Always-add-and-double over a FIXED iteration count with a branchless select, so
         the add/no-add pattern no longer tracks key bits and the loop count no longer
         reveals the scalar's bit length.

    HONEST SCOPE - hardening, not a constant-time proof. Python's int arithmetic is itself
    variable-time (CPython short-circuits on operand size and allocates per operation) and
    no pure-Python implementation can remove that. What is removed is the large,
    directly key-correlated leak: the data-dependent branch on each key bit. If the threat
    model truly requires constant-time signing, use remote_sign and an HSM.
    Cost: roughly 2x the variable-time path. This matters here because a robotics
    controller is long-lived and may share hardware with other tenants.
    """
    kb = k + secrets.randbits(32) * _N          # blinded: same result, randomised bits
    R: Point = (0, 1, 0)
    for i in range(287, -1, -1):
        R = _j_dbl(R)
        T = _j_add(R, p)
        m = -((kb >> i) & 1)                    # 0 when the bit is 0, -1 when 1
        R = ((R[0] & ~m) | (T[0] & m),
             (R[1] & ~m) | (T[1] & m),
             (R[2] & ~m) | (T[2] & m))
    return R


def _affine(p: Point) -> Tuple[int, int]:
    zi = pow(p[2], -1, _P)
    z2 = zi * zi % _P
    return (p[0] * z2 % _P, p[1] * z2 % _P * zi % _P)


def _rand_scalar() -> int:
    while True:
        v = int.from_bytes(secrets.token_bytes(32), "big")
        if 0 < v < _N:
            return v


def address_of(d: int) -> str:
    """Lowercase 20-byte address for a private scalar."""
    x, y = _affine(_j_mul_ct(d, _G))            # d is the private key
    return "0x" + keccak256(x.to_bytes(32, "big"), y.to_bytes(32, "big"))[12:].hex()


# ============ anticipatory ECDSA nonce = the pipeline ============

class _Nonce:
    __slots__ = ("k_inv", "r", "rec")

    def __init__(self, k_inv: int, r: int, rec: int):
        self.k_inv = k_inv
        self.r = r
        self.rec = rec


def make_nonce() -> _Nonce:
    """
    Precompute k*G, r and k^-1 - the entire expensive half of ECDSA, none of which
    depends on the message. Single-use: reusing k across two signatures leaks the key.
    """
    while True:
        k = _rand_scalar()
        rx, ry = _affine(_j_mul_ct(k, _G))      # k is secret: leaking it leaks the key
        r = rx % _N
        if r == 0:
            continue
        return _Nonce(pow(k, -1, _N), r, (ry & 1) | (2 if rx >= _N else 0))


def sign_with(nc: _Nonce, z: int, d: int) -> str:
    """Live path: two modular multiplies plus low-s normalization (EIP-2)."""
    s = nc.k_inv * (z + nc.r * d) % _N
    rec = nc.rec
    if s > _HALF_N:
        s = _N - s
        rec ^= 1
    return "0x" + nc.r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()


# ===================== EIP-712 / EIP-3009 =====================

_DOMAIN_TH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_XFER_TH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,"
    b"uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)


def _word(v) -> bytes:
    """One abi.encode word: int, hex string, or bytes."""
    if isinstance(v, int):
        return v.to_bytes(32, "big")
    b = bytes.fromhex(v[2:] if v.startswith("0x") else v) if isinstance(v, str) else v
    return b"\x00" * (32 - len(b)) + b


def domain_sep(name: str, version: str, chain_id: int, verifying: str) -> bytes:
    return keccak256(_DOMAIN_TH, keccak256(name.encode()), keccak256(version.encode()),
                     _word(chain_id), _word(verifying))


def digest(dsep: bytes, auth: Dict[str, str]) -> int:
    struct_hash = keccak256(
        _XFER_TH, _word(auth["from"]), _word(auth["to"]), _word(int(auth["value"])),
        _word(int(auth["validAfter"])), _word(int(auth["validBefore"])), _word(auth["nonce"]),
    )
    return int.from_bytes(keccak256(b"\x19\x01", dsep, struct_hash), "big")


# ========================= x402 protocol =========================

# MAINNET ONLY. Every field was read off the deployed contract - name(), version(),
# eth_chainId and DOMAIN_SEPARATOR() - not copied from documentation. A wrong `name`
# produces a wrong domain separator and every payment on that chain is silently rejected.
# Add other networks (including a testnet, to rehearse) via X402Client(custom_chains=...).
CHAINS: Dict[str, Dict[str, Any]] = {
    # Base + USDC only - the pair that has actually moved money. Add anything else with
    # X402Client(custom_chains=...); the machinery is chain-agnostic, the confidence is not.
    "base":           {"id": 8453,  "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "name": "USD Coin", "version": "2"},
}
_CAIP2 = {"eip155:%d" % c["id"]: k for k, c in CHAINS.items()}


def _norm_net(s: str) -> str:
    v = (s or "").strip().lower()
    return _CAIP2.get(v, v)


class Policy:
    """
    Spend limits. max_amount_per_request and total_budget are REQUIRED - an auto-payer
    without caps is a money leak controlled by whoever runs the server.
    """

    def __init__(self, max_amount_per_request, total_budget, allow_hosts=None,
                 allow_pay_to=None, allow_assets=None, allow_networks=None,
                 prefer_networks=None):
        self.max_per = int(max_amount_per_request)
        self.budget = int(total_budget)
        if self.max_per <= 0 or self.budget <= 0:
            raise ValueError("x402: max_amount_per_request and total_budget must be > 0")
        self.allow_hosts = allow_hosts
        self.allow_pay_to = [a.lower() for a in allow_pay_to] if allow_pay_to else None
        self.allow_assets = [a.lower() for a in allow_assets] if allow_assets else None
        self.allow_networks = allow_networks
        self.prefer_networks = prefer_networks


class X402Error(Exception):
    pass


class X402Client:
    """
    Wraps urllib. On a 402 it signs an EIP-3009 authorization and replays the request.

    client = X402Client(private_key=KEY, policy=Policy(max_amount_per_request=5000,
                                                       total_budget=1_000_000,
                                                       allow_hosts=["telemetry.local"]))
    body = client.urlopen("https://telemetry.local/v1/stream").read()
    """

    def __init__(self, private_key: Optional[str] = None, shards: Optional[List[str]] = None,
                 remote_sign: Optional[Callable[[str, dict, dict], str]] = None,
                 from_address: Optional[str] = None, policy: Optional[Policy] = None,
                 pool_size: int = 16, warm_in_background: bool = True,
                 max_background_nonces: int = 512, presign: bool = False, voucher_cap: int = 8,
                 on_payment: Optional[Callable[[dict], None]] = None,
                 on_decline: Optional[Callable[[dict], None]] = None,
                 raise_on_decline: bool = False, opener: Optional[Callable] = None,
                 budget_store: Optional[Any] = None,
                 acknowledge_ephemeral_budget: bool = False,
                 custom_chains: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        budget_store - DURABLE spend ledger, required for mainnet unless waived.

        policy.total_budget alone is an in-memory counter scoped to ONE client. It resets on
        process restart and on every new client, so on mainnet the real ceiling becomes the
        wallet balance rather than the cap you set. Pass an object with:

            reserve(amount: int, total_budget: int) -> bool   # MUST be atomic
            release(amount: int) -> None                      # optional

        backed by something durable (sqlite, Redis, a file with a lock).

        acknowledge_ephemeral_budget - opt out of the guard and accept a per-instance cap.
        Testnets are unaffected either way.
        """
        if policy is None:
            raise ValueError("x402: policy is required")
        self.policy = policy
        self.remote_sign = remote_sign
        self.on_payment = on_payment
        self.on_decline = on_decline
        self.raise_on_decline = raise_on_decline
        self._open = opener or _URLOPEN
        self.budget_store = budget_store
        self.ack_ephemeral = acknowledge_ephemeral_budget
        # Built-in mainnet table plus anything the caller added. VERIFY a custom chain
        # against its deployed DOMAIN_SEPARATOR() before using it with real funds.
        self.chains = dict(CHAINS)
        if custom_chains:
            self.chains.update(custom_chains)
        self._caip2 = {"eip155:%d" % c["id"]: k for k, c in self.chains.items()}
        self.presign = presign
        self.voucher_cap = voucher_cap

        d = 0
        if private_key:
            d = int(private_key[2:] if private_key.startswith("0x") else private_key, 16)
        elif shards:
            for s in shards:
                d = (d + int(s[2:] if s.startswith("0x") else s, 16)) % _N
        elif not remote_sign:
            raise ValueError("x402: private_key, shards or remote_sign required")
        if not remote_sign and not (0 < d < _N):
            raise ValueError("x402: invalid key material")
        if remote_sign and d == 0 and not from_address:
            raise ValueError("x402: from_address required with remote_sign")
        self._d = d
        self.address = (from_address if d == 0 else address_of(d)).lower()

        self._pool: List[_Nonce] = []
        self._pool_target = pool_size
        self._max_bg = max_background_nonces
        self._bg_generated = 0
        self._lock = threading.Lock()
        self._dseps: Dict[str, bytes] = {}
        self._vouchers: Dict[str, dict] = {}
        self._pending: Dict[str, dict] = {}
        self.spent = 0
        self.payments = 0
        self.warm_hits = 0
        self.unresolved = 0

        self._stop = threading.Event()
        self._thread = None
        if warm_in_background and not remote_sign:
            self._thread = threading.Thread(target=self._warm_loop, daemon=True)
            self._thread.start()

    # ---- nonce pool -------------------------------------------------

    def _warm_loop(self) -> None:
        """Fill the pool during idle time. Bounded by every guardrail."""
        while not self._stop.is_set():
            with self._lock:
                need = (len(self._pool) < self._pool_target
                        and self._bg_generated < self._max_bg
                        and self.spent < self.policy.budget)
            if not need:
                self._stop.wait(0.25)
                continue
            nc = make_nonce()                      # outside the lock: this is the slow part
            with self._lock:
                if len(self._pool) < self._pool_target:
                    self._pool.append(nc)
                    self._bg_generated += 1

    def ready(self, timeout: float = 30.0) -> bool:
        """Block until the pool is warm. Returns False on timeout."""
        end = time.time() + timeout
        while time.time() < end:
            with self._lock:
                if len(self._pool) >= self._pool_target:
                    return True
            time.sleep(0.01)
        return False

    def close(self) -> None:
        self._stop.set()

    def _take_nonce(self) -> _Nonce:
        with self._lock:
            if self._pool:
                return self._pool.pop()
        return make_nonce()                        # cold fallback: full k*G inline

    # ---- protocol ---------------------------------------------------

    def _norm(self, v: str) -> str:
        x = (v or "").strip().lower()
        return self._caip2.get(x, x)

    def _dsep_for(self, req: dict) -> bytes:
        net = self._norm(req["network"])
        c = self.chains.get(net)
        if not c:
            raise X402Error("unknown network " + net)
        extra = req.get("extra") or {}
        name = extra.get("name", c["name"])
        ver = extra.get("version", c["version"])
        key = "%s|%s|%s|%s" % (net, req["asset"], name, ver)
        if key not in self._dseps:
            self._dseps[key] = domain_sep(name, ver, c["id"], req["asset"])
        return self._dseps[key]

    @staticmethod
    def _as_requirement(a: dict) -> dict:
        r = dict(a)
        r["network"] = _norm_net(a.get("network", ""))
        # NOT defaulted to "0": a missing amount must decline, not quietly become a
        # zero-value payment that burns a nonce and can never settle.
        r["maxAmountRequired"] = str(a.get("amount", a.get("maxAmountRequired", "")))
        return r

    def _parse_402(self, headers, body: bytes) -> dict:
        """Returns {reqs, raws, version, resource, error}."""
        get = lambda h: headers.get(h) or headers.get(h.title()) or headers.get(h.upper())

        wa = get("www-authenticate")
        if wa and wa.strip().lower().startswith("payment"):
            return {"reqs": [], "raws": [], "version": 1,
                    "error": "MPP challenge (WWW-Authenticate: Payment); this client speaks x402 only"}

        pr = get("payment-required")               # x402 v2
        if pr:
            try:
                j = json.loads(pr)
                raws = list(j.get("accepts") or [])
                if raws:
                    return {"reqs": [self._as_requirement(a) for a in raws], "raws": raws,
                            "version": 2, "resource": j.get("resource"), "error": None}
            except Exception:
                pass

        try:                                        # x402 v1
            j = json.loads(body.decode("utf-8"))
            ver = j.get("x402Version")
            if isinstance(ver, int) and ver > 2:
                return {"reqs": [], "raws": [], "version": 1,
                        "error": "server speaks x402 v%d; this client implements v1 and v2" % ver}
            raws = list(j.get("accepts") or [])
            if raws:
                return {"reqs": [self._as_requirement(a) for a in raws], "raws": raws,
                        "version": 2 if ver == 2 else 1, "resource": j.get("resource"), "error": None}
        except Exception:
            pass
        return {"reqs": [], "raws": [], "version": 1, "error": None}

    def _pick(self, reqs: List[dict], host: str) -> Tuple[Optional[dict], int, str]:
        p = self.policy
        last = "no acceptable payment requirement"
        order = list(range(len(reqs)))
        if p.prefer_networks:
            pref = p.prefer_networks
            order.sort(key=lambda i: pref.index(self._norm(reqs[i]["network"])) if self._norm(reqs[i]["network"]) in pref else 10 ** 9)
        import re as _re
        addr_re = _re.compile(r"^0x[0-9a-fA-F]{40}$")
        for i in order:
            r = reqs[i]
            # Shape validation FIRST: a buggy or hostile server must produce a clean decline,
            # never an exception deep inside the encoder.
            if not isinstance(r, dict):
                last = "malformed requirement"; continue
            if not addr_re.match(str(r.get("payTo") or "")):
                last = "invalid payTo: %r" % (r.get("payTo"),); continue
            if not addr_re.match(str(r.get("asset") or "")):
                last = "invalid asset: %r" % (r.get("asset"),); continue
            if not str(r.get("maxAmountRequired") or "").isdigit():
                last = "invalid amount: %r" % (r.get("maxAmountRequired"),); continue
            if r.get("scheme") != "exact":
                last = "unsupported scheme %s" % r.get("scheme"); continue
            net = r["network"]
            if net not in self.chains:
                last = "unknown network %s" % net; continue
            if p.allow_networks and net not in p.allow_networks:
                last = "network not allowed: %s" % net; continue
            if p.allow_hosts and host not in p.allow_hosts:
                last = "host not allowed: %s" % host; continue
            if p.allow_pay_to and r["payTo"].lower() not in p.allow_pay_to:
                last = "payTo not allowed: %s" % r["payTo"]; continue
            if p.allow_assets and r["asset"].lower() not in p.allow_assets:
                last = "asset not allowed: %s" % r["asset"]; continue
            v = int(r["maxAmountRequired"])
            if v <= 0:
                last = "non-positive amount: %s" % r["maxAmountRequired"]; continue
            # Real money + a budget that resets per instance = no effective lifetime cap.
            # Every shipped chain is mainnet, so this always applies.
            if not self.budget_store and not self.ack_ephemeral:
                last = ("%s requires a durable budget_store, or "
                        "acknowledge_ephemeral_budget=True - total_budget is per-instance "
                        "and resets on restart" % net)
                continue
            if v > p.max_per:
                last = "amount %d exceeds per-request cap %d" % (v, p.max_per); continue
            if self.spent + v > p.budget:
                last = "amount %d exceeds remaining budget %d" % (v, p.budget - self.spent); continue
            return r, i, ""
        return None, -1, last

    def _build(self, req: dict) -> Tuple[dict, str, float]:
        t0 = time.perf_counter()
        now = int(time.time())
        auth = {
            "from": self.address, "to": req["payTo"], "value": req["maxAmountRequired"],
            "validAfter": str(now - 60),
            "validBefore": str(now + int(req.get("maxTimeoutSeconds") or 60)),
            "nonce": "0x" + secrets.token_bytes(32).hex(),
        }
        z = digest(self._dsep_for(req), auth)
        sig = sign_with(self._take_nonce(), z, self._d)
        return auth, sig, (time.perf_counter() - t0) * 1000.0

    def _decline(self, url: str, reason: str, req=None) -> None:
        if self.on_decline:
            self.on_decline({"url": url, "reason": reason, "req": req})
        if self.raise_on_decline:
            raise X402Error("x402 declined: " + reason)

    # ---- the interceptor --------------------------------------------

    def urlopen(self, url, data: Optional[bytes] = None,
                headers: Optional[dict] = None, timeout: Optional[float] = None):
        headers = dict(headers or {})
        req0 = urllib.request.Request(url, data=data, headers=headers)
        try:
            return self._open(req0, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code != 402:
                raise
            body = e.read()
            resp_headers = dict(e.headers.items())
            err = e

        parsed = self._parse_402(resp_headers, body)
        full_url = req0.full_url
        host = urllib.parse.urlparse(full_url).hostname or ""

        if parsed["error"]:
            self._decline(full_url, parsed["error"]); raise err
        if not parsed["reqs"]:
            self._decline(full_url, "no parseable payment requirements"); raise err

        req, idx, reason = self._pick(parsed["reqs"], host)
        if req is None:
            self._decline(full_url, reason); raise err

        version = parsed["version"]
        vk = "%d|%s|%s|%s|%s" % (version, req["network"], req["asset"], req["payTo"], req["maxAmountRequired"])

        reused = warm = False
        ms = 0.0
        stuck = self._pending.get(vk)
        if stuck and int(stuck["auth"]["validBefore"]) > time.time() + 2:
            # The EIP-3009 nonce is the idempotency key: re-send the SAME authorization.
            # Minting a fresh nonce here is what double-spends.
            auth, sig, reused = stuck["auth"], stuck["sig"], True
        else:
            self._pending.pop(vk, None)            # expired: unredeemable, safe to mint fresh
            v = self._vouchers.pop(vk, None)
            if v and v["expires"] > time.time() + 5:
                auth, sig, warm = v["auth"], v["sig"], True
                self.warm_hits += 1
            elif self.remote_sign:
                now = int(time.time())
                auth = {
                    "from": self.address, "to": req["payTo"], "value": req["maxAmountRequired"],
                    "validAfter": str(now - 60),
                    "validBefore": str(now + int(req.get("maxTimeoutSeconds") or 60)),
                    "nonce": "0x" + secrets.token_bytes(32).hex(),
                }
                t0 = time.perf_counter()
                z = digest(self._dsep_for(req), auth)
                sig = self.remote_sign("0x" + z.to_bytes(32, "big").hex(), auth, req)
                ms = (time.perf_counter() - t0) * 1000.0
            else:
                auth, sig, ms = self._build(req)

        value = int(auth["value"])
        if not reused:
            if self.budget_store is not None:
                try:
                    allowed = self.budget_store.reserve(value, self.policy.budget)
                except Exception as e:
                    self._decline(full_url, "budget_store.reserve failed: %s" % e, req); raise err
                if not allowed:
                    self._decline(full_url, "durable budget exhausted", req); raise err
            elif self.spent + value > self.policy.budget:
                self._decline(full_url, "budget exhausted", req); raise err
            self.spent += value
            self.payments += 1

        if version == 2:
            envelope = {
                "x402Version": 2,
                "resource": parsed.get("resource") or {"url": full_url},
                "accepted": parsed["raws"][idx],
                "payload": {"signature": sig, "authorization": auth},
                "extensions": {},
            }
            pay_header = "PAYMENT-SIGNATURE"
        else:
            envelope = {"x402Version": 1, "scheme": req["scheme"], "network": req["network"],
                        "payload": {"signature": sig, "authorization": auth}}
            pay_header = "X-PAYMENT"
        enc = base64.b64encode(json.dumps(envelope).encode()).decode()

        h2 = dict(headers)
        h2[pay_header] = enc
        if version == 1:
            h2["x402-payment-authorization"] = enc

        self._pending[vk] = {"auth": auth, "sig": sig}   # recorded BEFORE sending
        req2 = urllib.request.Request(full_url, data=data, headers=h2)
        try:
            resp = self._open(req2, timeout=timeout)
        except urllib.error.HTTPError as e2:
            if e2.code >= 500:
                self.unresolved += 1                # ambiguous: keep it, re-send next time
            else:
                self._pending.pop(vk, None)
                # A definitive rejection means nothing settled - return the reservation.
                if not reused and e2.code >= 400 and self.budget_store is not None:
                    rel = getattr(self.budget_store, "release", None)
                    if rel:
                        try:
                            rel(value); self.spent -= value; self.payments -= 1
                        except Exception:
                            pass          # best-effort; over-counting is the safe direction
            raise
        except Exception:
            self.unresolved += 1                    # connection died: outcome unknown
            raise
        self._pending.pop(vk, None)

        settlement = None
        try:
            sr = resp.headers.get("payment-response") or resp.headers.get("x-payment-response")
            if sr:
                settlement = json.loads(base64.b64decode(sr))
        except Exception:
            pass

        if self.on_payment:
            self.on_payment({"url": full_url, "value": auth["value"], "payTo": req["payTo"],
                             "network": req["network"], "warm": warm, "reused": reused,
                             "sign_ms": ms, "version": version, "settlement": settlement})

        if self.presign and not self.remote_sign and len(self._vouchers) < self.voucher_cap \
                and self.spent + value <= self.policy.budget:
            try:
                a2, s2, _ = self._build(req)
                self._vouchers[vk] = {"auth": a2, "sig": s2, "expires": int(a2["validBefore"])}
            except Exception:
                pass                                # pre-signing is strictly best-effort

        return resp

    def stats(self) -> dict:
        with self._lock:
            pool = len(self._pool)
            bg = self._bg_generated
        return {"pool": pool, "vouchers": len(self._vouchers), "spent": self.spent,
                "remaining": self.policy.budget - self.spent, "payments": self.payments,
                "warm_hits": self.warm_hits, "bg_generated": bg,
                "bg_capped": bg >= self._max_bg, "in_flight": len(self._pending),
                "unresolved": self.unresolved}


# ======================== the decorator ========================

def x402_telemetry(client: Optional[X402Client] = None, **cfg):
    """
    Hooks payment into raw data-harvesting scripts. Inside the decorated function,
    urllib.request.urlopen pays 402s automatically - existing code is untouched.

        @x402_telemetry(private_key=KEY, policy=Policy(max_amount_per_request=5000,
                                                       total_budget=1_000_000))
        def harvest():
            return urllib.request.urlopen("https://sensor.local/v1/lidar").read()

    The patch is process-global for the duration of the call and is always restored.
    """
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            c = client or X402Client(**cfg)
            original = urllib.request.urlopen

            def patched(url, data=None, timeout=None, *a, **kw):
                if isinstance(url, urllib.request.Request):
                    return c.urlopen(url.full_url, data=url.data if url.data else data,
                                     headers=dict(url.headers), timeout=timeout)
                return c.urlopen(url, data=data, timeout=timeout)

            urllib.request.urlopen = patched
            try:
                return fn(*args, **kwargs)
            finally:
                urllib.request.urlopen = original
                if client is None:
                    c.close()
        wrapper.x402_client = client
        return wrapper
    return decorate

