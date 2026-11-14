#!/usr/bin/env python3
"""chain.py — minimal read-only EVM plumbing for the MCP server.

Two jobs, nothing more:
  * build calldata from a real signature string + args (selector via keccak, args via eth_abi);
  * a read-only JSON-RPC `eth_call` for simulation (offline-tolerant: a dead RPC is an ERROR
    you can see, never a silent zero — GOTCHAS #112/#138).

No signing, no keys, no web3 session object. Pure encode + one RPC POST.
"""
from __future__ import annotations

import functools
import json
import os
import threading
import time

# IMPORTS ARE LAZY (MCP-8). `import server` used to pull httpx + eth_abi + eth_utils eagerly, so even
# the OFFLINE helpers (`escrow_new_secret`, `server_info`, every calldata builder) paid a ~200 ms
# import and required the web stack installed just to start. Nothing at module scope needs them; each
# heavy import happens on first use and is cached. `python3 -c "import spec"` alone now works with no
# httpx on the box. (concurrent.futures is stdlib and cheap, so it stays eager.)
from concurrent.futures import ThreadPoolExecutor


def _httpx():
    global _HX
    try:
        return _HX
    except NameError:
        pass
    import httpx as _m
    _HX = _m
    return _m


def _abi_encode(types, vals):
    global _AE
    if "_AE" not in globals():
        from eth_abi import encode as _m
        _AE = _m
    return _AE(types, vals)


def _abi_decode(types, data):
    global _AD
    if "_AD" not in globals():
        from eth_abi import decode as _m
        _AD = _m
    return _AD(types, data)


def keccak(*a, **kw):
    """Lazy `eth_utils.keccak` — kept a module-level NAME because selftest/spec call `chain.keccak`."""
    global _K
    if "_K" not in globals():
        from eth_utils import keccak as _m
        _K = _m
    return _K(*a, **kw)


DEFAULT_RPC = "https://base-rpc.publicnode.com"
# Fallback list. A single default endpoint is a SPOF: publicnode answers "Rate limit (1200rqs/60s)"
# with a plain-text body that parses as a JSONDecodeError and reads on the surface like "the contract
# reverted". Override with MCP_RPC (comma-separated).
_RPCS = [u for u in os.environ.get("MCP_RPC", "").split(",") if u] or [
    DEFAULT_RPC,
    "https://mainnet.base.org",
    "https://base.llamarpc.com",
]
CHAIN_ID = 8453

# MCP-3: QUORUM FOR STATE READS. The old walk was sequential and took the FIRST responder — so one
# stale, forked, or lying endpoint defined the answer and nothing could notice. State reads now fire
# at every endpoint AT ONCE and require QUORUM matching results; disagreement is reported, never
# smoothed over. `QUORUM` is 2 by default (of the 3 defaults). A single-endpoint override (MCP_RPC
# with one URL) degrades to 1 — quorum is impossible there and pretending otherwise would be a lie.
QUORUM = int(os.environ.get("MCP_QUORUM", "2"))   # of the 3 defaults; degrades to len(urls)
QUORUM_WAIT = float(os.environ.get("MCP_QUORUM_WAIT", "1.5"))  # s to wait for agreement
# TTL CACHE (MCP-2). Contract code, selectors, fee reads, and previewFee are read repeatedly within a
# session and cannot change between ticks; re-fetching them per call is what rate-limits the fleet. 0
# disables. Only `eth_call`/`eth_getCode`/`eth_chainId` are cached — tx receipts are NOT (they flip
# pending->mined and a cached miss is the dangerous direction).
CACHE_TTL = float(os.environ.get("MCP_CACHE_TTL", "8"))
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_POOL = ThreadPoolExecutor(max_workers=8)


def _cache_get(key):
    if CACHE_TTL <= 0:
        return None
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if not hit:
            return None
        ts, val = hit
        if time.time() - ts > CACHE_TTL:
            _CACHE.pop(key, None)
            return None
        return val


def _cache_put(key, val):
    if CACHE_TTL <= 0:
        return
    with _CACHE_LOCK:
        _CACHE[key] = (time.time(), val)


def clear_cache():
    with _CACHE_LOCK:
        _CACHE.clear()


def selector(sig: str) -> str:
    """4-byte selector from a real signature string — derived, never hand-typed (GOTCHA #73)."""
    return "0x" + keccak(text=sig)[:4].hex()


def split_types(sig: str) -> list[str]:
    """Types of a signature string `name(t1,t2,…)` — strips the function name first, then
    top-level comma splits respecting nested ( ) and [ ] so a tuple arg stays one type."""
    inner = sig[sig.index("(") + 1:sig.rindex(")")]
    if inner.strip() == "":
        return []
    return _split_top(inner)


def _split_top(s: str) -> list[str]:
    depth = 0
    out, cur = [], []
    for ch in s:
        if ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


def _split_array(typ: str) -> tuple[str, str]:
    """Peel a trailing array suffix: `(a,b)[]` -> ('(a,b)', '[]'); `uint8[3]` -> ('uint8','[3]')."""
    if typ.endswith("]"):
        i = typ.rindex("[")
        return typ[:i], typ[i:]
    return typ, ""


def _split_tuple(typ: str) -> list[str] | None:
    """Component types of a tuple type `(a,b,(c,d)[])`, or None if not a tuple."""
    if not (typ.startswith("(") and typ.endswith(")")):
        return None
    return _split_top(typ[1:-1])


def _norm(typ: str, val):
    """Normalise a user value into what eth_abi.encode expects — RECURSING through tuples/arrays so
    a nested `bytes` (e.g. the `execute((address,uint256,bytes)[])` sig) is converted too."""
    if val is None:
        return val
    base, arr = _split_array(typ)
    if arr:
        return [_norm(base, v) for v in val]
    comps = _split_tuple(base)
    if comps is not None:
        if isinstance(val, dict):
            val = [val[c] for c in comps]
        return [_norm(c, v) for c, v in zip(comps, val)]
    if base == "address":
        return val if val.startswith("0x") else "0x" + val
    if base.startswith("bytes") and base != "bytes":
        h = val[2:] if val.startswith("0x") else val
        n = int(base[5:])
        if len(h) > n * 2:
            raise ValueError(f"{base} too long: {val}")
        return bytes.fromhex(h.ljust(n * 2, "0"))
    if base == "bytes":
        return bytes.fromhex(val[2:] if val.startswith("0x") else val)
    if base.startswith("uint") or base.startswith("int") or base == "bool":
        return val
    return val


def build_call(sig: str, args: list) -> str:
    """Full calldata: selector ++ abi-encoded args. `sig` excludes the leading function name arity
    mismatch is caught by eth_abi against the type list."""
    types = split_types(sig)
    if len(types) != len(args):
        raise ValueError(f"arg count {len(args)} != sig arity {len(types)} for `{sig}`")
    enc = _abi_encode(types, [_norm(t, v) for t, v in zip(types, args)])
    return selector(sig) + enc.hex()


def _walk(rpc: str = DEFAULT_RPC) -> list[str]:
    """Endpoints to try: the caller's `rpc` first if it is NOT the default, else the default chain.

    `rpc` defaults to DEFAULT_RPC; when a caller passes an explicit URL it stays a single try or a
    one-element list (their choice is honored, no silent substitution)."""
    if rpc and rpc != DEFAULT_RPC:
        return [rpc]
    return _RPCS


def _post_one(url: str, method: str, params: list, timeout: float) -> dict:
    """One endpoint, one request. Returns {'ok', 'result'|'error', 'url'} — never raises.

    TWO error SHAPES, both must be caught. The spec shape is `{"error": {...}}`; but public Base
    endpoints ALSO answer a rate limit with a BARE `{"code":-32007,"message":"25/second request limit
    reached"}` — no envelope, no `error` key, HTTP 200. Reading only `"error"` made that a SUCCESS
    carrying `result: None`, so a rate-limited endpoint voted "None" against a real hex answer and
    quorum failed (observed: mainnet.base.org alternating ok-None / ok-hex on the same calldata).
    So: success requires an actual `result` key; anything else is an error, named from whatever
    message the body carries."""
    try:
        r = _httpx().post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                          timeout=timeout)
        j = r.json()
    except Exception as e:  # httpx errors, JSON errors (HTML/plain-text bodies), timeouts
        return {"ok": False, "error": f"{url}: {type(e).__name__}: {e}", "url": url}
    if isinstance(j, dict) and "result" in j and "error" not in j:
        return {"ok": True, "result": j["result"], "url": url}
    if isinstance(j, dict) and "error" in j:
        err = j["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        return {"ok": False, "error": f"{url}: {msg}", "url": url}
    return {"ok": False, "error": f"{url}: {json.dumps(j)[:120]}", "url": url}


def _race(method: str, params: list, urls: list[str], timeout: float) -> dict:
    """Fire at every endpoint at once and take the FIRST majority (MCP-3).

    Returns {'ok', 'result', 'url', 'agree', 'dissent', 'quorum'}:
      * quorum reached  -> ok=True, `agree` = how many endpoints said the same thing
      * no majority in QUORUM_WAIT -> the fastest success is returned but `agree`=1 and `quorum`=False
        (a single endpoint answering IS better than nothing; the caller can see the grade)
      * nobody succeeded -> ok=False with every error joined.

    Values are compared as exact JSON strings. `eth_getCode`/`eth_call` results are canonical hex, so
    string equality is the right comparison; a real fork or a stale node differs byte-for-byte."""
    if not urls:
        return {"ok": False, "error": "no endpoints"}
    need = min(QUORUM, len(urls))
    futs = [_POOL.submit(_post_one, u, method, params, timeout) for u in urls]
    votes: dict[str, list[str]] = {}
    errs: list[str] = []
    deadline = time.time() + QUORUM_WAIT
    first_ok = None
    pending = set(futs)
    while pending and time.time() < deadline:
        done, pending = _wait(pending, deadline)
        for f in done:
            r = f.result()
            if not r["ok"]:
                errs.append(r["error"])
                continue
            key = json.dumps(r["result"], sort_keys=True)
            who = votes.setdefault(key, [])
            who.append(r["url"])
            if first_ok is None:
                first_ok = r
            if len(who) >= need:
                dissent = [u for k, v in votes.items() if k != key for u in v]
                return {"ok": True, "result": r["result"], "url": r["url"],
                        "agree": len(who), "dissent": dissent, "quorum": True}
    # out of time: no majority. Return the MOST-VOTED answer (ties -> fastest), graded, and say how
    # many distinct answers there were. Picking the fastest alone let a single fast liar define the
    # answer whenever a second endpoint was also down (observed: liar fast + one 525 = tie, and the
    # lie was returned); a tied read is now flagged `ambiguous` instead of looking settled.
    if first_ok is not None:
        key = max(votes, key=lambda k: (len(votes[k]), -min(urls.index(u) for u in votes[k])))
        chosen = next(u for u in votes[key])
        dissent = [u for k, v in votes.items() if k != key for u in v]
        out = {"ok": True, "result": json.loads(key), "url": chosen,
               "agree": len(votes[key]), "dissent": dissent, "quorum": False}
        if len(votes) > 1:
            out["ambiguous"] = True
            out["distinct_answers"] = len(votes)
        return out
    return {"ok": False, "error": " | ".join(errs) or "no endpoint answered"}


def _wait(pending, deadline):
    """Whichever comes first: any future completing, or the deadline passing (bounded polling)."""
    from concurrent.futures import wait, FIRST_COMPLETED
    remain = max(0.0, deadline - time.time())
    done, still = wait(pending, timeout=min(remain, 0.25), return_when=FIRST_COMPLETED)
    return done, still


def rpc_quorum(method: str, params: list, rpc_url: str = DEFAULT_RPC, timeout: float = 20.0) -> dict:
    """A READ that grades itself: quorum where possible, and the block it was answered at.

    `blockNumber` is included so a caller can pin what "latest" meant — the missing piece that made a
    raced read unauditable."""
    res = _race(method, params, _walk(rpc_url), timeout)
    if res.get("ok"):
        try:
            bn = _post_one(_walk(rpc_url)[0], "eth_blockNumber", [], 5.0)
            if bn["ok"]:
                res["block"] = int(bn["result"], 16)
        except Exception:  # noqa: BLE001
            pass
    return res


def eth_call(to: str, data: str, rpc: str = DEFAULT_RPC, timeout: float = 12.0,
             frm: str | None = None, overrides: dict | None = None,
             quorum: bool = True) -> dict:
    """Read-only eth_call. Returns {'ok': bool, 'result'|'error': …} — never raises on RPC.

    `frm` sets the simulated sender. Without it the sender is the zero address and any call whose
    first effect is `token.approve(...)` reverts with "approve from the zero address" — an artifact of
    the messenger, not bad calldata. Pass a real EOA to see the true flow.

    `overrides` is a stateOverride map ({addr: {balance|nonce|code|state|stateDiff}}) — the third
    eth_call param. It lets a caller simulate a funded/loaded account without a fork or a key.
    A call that CARRIES overrides skips the TTL cache (the override is part of what it asked).

    `quorum` races endpoints and requires agreement (MCP-3); pass False for a call whose result is
    explicitly timing-dependent. Returns `agree`/`quorum`/`dissent` so the caller can grade it."""
    tx = {"to": to, "data": data}
    if frm:
        tx["from"] = frm
    params = [tx, "latest"] + ([overrides] if overrides else [])
    ck = ("eth_call", to.lower(), data, (frm or "").lower(), json.dumps(overrides, sort_keys=True) if overrides else "")
    if not overrides:
        hit = _cache_get(ck)
        if hit is not None:
            return {**hit, "cached": True}
    if not quorum or len(_walk(rpc)) == 1:
        res = _race_first(method="eth_call", params=params, urls=_walk(rpc), timeout=timeout)
    else:
        res = _race("eth_call", params, _walk(rpc), timeout)
    if res.get("ok"):
        res["rpc"] = res.get("url")
        # MCP-3: pin WHAT "latest" meant. A sim answer with no height cannot be audited or compared
        # later; ask the endpoint that answered (one cheap call, skipped entirely on a cache hit).
        try:
            bn = _post_one(res["url"], "eth_blockNumber", [], 5.0)
            if bn["ok"]:
                res["block"] = int(bn["result"], 16)
        except Exception:  # noqa: BLE001
            pass
        if not overrides:
            _cache_put(ck, res)
    return res


def _race_first(method: str, params: list, urls: list[str], timeout: float) -> dict:
    """First success wins, no quorum — for single-endpoint callers and explicit opt-outs."""
    errs = []
    for u in urls:
        r = _post_one(u, method, params, timeout)
        if r["ok"]:
            return r
        errs.append(r["error"])
    return {"ok": False, "error": " | ".join(errs)}


def http_get(url: str, timeout: float = 12.0, headers: dict | None = None) -> dict:
    """Plain GET for an x402 challenge probe. Returns {'ok', 'status', 'json'|'text', 'headers'}.

    A 402 is a SUCCESS here, not an error — the status is reported and the caller decides. Only a
    transport failure (no answer at all) sets ok=False, because "the server is down" and "the server
    wants money" must not look alike.
    """
    try:
        r = _httpx().get(url, timeout=timeout, headers=headers or {})
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    out = {"ok": True, "status": r.status_code, "headers": dict(r.headers)}
    try:
        out["json"] = r.json()
    except Exception:  # noqa: BLE001 — not JSON is fine; the text is still evidence
        out["text"] = r.text[:2000]
    return out


def decode_uint(result_hex: str) -> int:
    if not result_hex or result_hex == "0x":
        return 0
    return int(result_hex, 16)


def decode_uint_addr(result_hex: str) -> tuple[int, str]:
    """Decode a (uint256, address) return word-pair (e.g. RequestRegistry.request)."""
    h = result_hex[2:]
    a = int(h[0:64], 16)
    b = "0x" + h[64 + 24:128]
    return a, b


def decode_addr(result_hex: str) -> str:
    return "0x" + result_hex[2:][24:64]


def decode_addrs(result_hex: str) -> list[str]:
    """Every 32-byte word decoded as an address (word-aligned; for a multi-address return)."""
    h = result_hex[2:]
    return ["0x" + h[i + 24:i + 64] for i in range(0, len(h), 64) if len(h[i:i + 64]) == 64]


def decode_uint_at(result_hex: str, word: int = 0) -> int:
    """The `word`-th 32-byte uint from a hex return (0-indexed). Used to pull an id off a struct."""
    h = result_hex[2:]
    return int(h[word * 64:(word + 1) * 64], 16)


def topic0(sig: str) -> str:
    """The event topic0 = keccak of the canonical event signature — derived, never typed."""
    return "0x" + keccak(text=sig).hex()


def find_log(receipt: dict, address: str, topic0_hex: str) -> dict | None:
    """First log in a receipt matching (emitting address, topic0), returned whole (topics + data).

    Kept dependency-free (no ABI file): the caller indexes topics/data positionally."""
    want = address.lower()
    for lg in receipt.get("logs", []):
        topics = lg.get("topics") or []
        if (lg.get("address", "").lower() == want and topics
                and topics[0].lower() == topic0_hex.lower()):
            return lg
    return None


def rpc(method: str, params: list, rpc_url: str = DEFAULT_RPC, timeout: float = 20.0,
        quorum: bool = False, cache: bool = False) -> dict:
    """A generic read-only JSON-RPC call (eth_getTransactionReceipt, eth_getCode, …). Never raises.

    Same endpoint walk as eth_call: a rate-limit body from the first endpoint must not be reported as
    if the chain itself said no. `quorum`/`cache` are OPT-IN here (receipts flip pending->mined, so a
    generic call must not be cached by default); `get_code` turns both on for its own read."""
    urls = _walk(rpc_url)
    ck = (method, json.dumps(params, sort_keys=True))
    if cache:
        hit = _cache_get(ck)
        if hit is not None:
            return {**hit, "cached": True}
    if quorum and len(urls) > 1:
        res = _race(method, params, urls, timeout)
    else:
        res = _race_first(method=method, params=params, urls=urls, timeout=timeout)
    if res.get("ok"):
        res["rpc"] = res.get("url")
        if cache:
            _cache_put(ck, res)
    return res


def get_code(addr: str) -> dict:
    """`eth_getCode` with cache + quorum — code is immutable in practice and read constantly."""
    return rpc("eth_getCode", [addr, "latest"], quorum=True, cache=True)


if __name__ == "__main__":
    # tiny self-proof of the encoder
    assert selector("register(address)") == "0x4420e486"
    c = build_call("mintForEscrow(address)", ["0x4B05fA6aD0Ba0D0120Dce19Ce34dde6d1316C237"])
    assert c.startswith("0xa98aeecb"), c
    print("chain.py OK:", c[:10], "…")
