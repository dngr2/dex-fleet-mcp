#!/usr/bin/env python3
"""chain.py — minimal read-only EVM plumbing for the MCP server.

Two jobs, nothing more:
  * build calldata from a real signature string + args (selector via keccak, args via eth_abi);
  * a read-only JSON-RPC `eth_call` for simulation (offline-tolerant: a dead RPC is an ERROR
    you can see, never a silent zero — GOTCHAS #112/#138).

No signing, no keys, no web3 session object. Pure encode + one RPC POST.
"""
from __future__ import annotations

import json

import httpx
from eth_abi import encode as abi_encode
from eth_abi import decode as abi_decode
from eth_utils import keccak

DEFAULT_RPC = "https://base-rpc.publicnode.com"
CHAIN_ID = 8453


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
    enc = abi_encode(types, [_norm(t, v) for t, v in zip(types, args)])
    return selector(sig) + enc.hex()


def eth_call(to: str, data: str, rpc: str = DEFAULT_RPC, timeout: float = 12.0,
             frm: str | None = None) -> dict:
    """Read-only eth_call. Returns {'ok': bool, 'result'|'error': ...} — never raises on RPC.

    `frm` sets the simulated sender. Without it the sender is the zero address and any call whose
    first effect is `token.approve(...)` reverts with "approve from the zero address" — an artifact of
    the messenger, not bad calldata. Pass a real EOA to see the true flow."""
    try:
        tx = {"to": to, "data": data}
        if frm:
            tx["from"] = frm
        r = httpx.post(
            rpc,
            json={"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                  "params": [tx, "latest"]},
            timeout=timeout,
        )
        j = r.json()
        if "error" in j:
            return {"ok": False, "error": j["error"].get("message", str(j["error"]))}
        return {"ok": True, "result": j.get("result")}
    except Exception as e:  # httpx errors, JSON errors, timeouts
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


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


def rpc(method: str, params: list, rpc_url: str = DEFAULT_RPC, timeout: float = 20.0) -> dict:
    """A generic read-only JSON-RPC call (eth_getTransactionReceipt, eth_getCode, …). Never raises."""
    try:
        r = httpx.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                       timeout=timeout)
        j = r.json()
        if "error" in j:
            return {"ok": False, "error": j["error"].get("message", str(j["error"]))}
        return {"ok": True, "result": j.get("result")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":
    # tiny self-proof of the encoder
    assert selector("register(address)") == "0x4420e486"
    c = build_call("mintForEscrow(address)", ["0x80793a7d35f735bc76BeAf22B1f413926818f410"])
    assert c.startswith("0xa98aeecb"), c
    print("chain.py OK:", c[:10], "…")
