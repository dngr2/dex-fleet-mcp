#!/usr/bin/env python3
"""server.py — the DEX fleet MCP payment server.

An agent discovers this over MCP (no npm, no account) and gets, per product, the ONE call that
pays. Every tool is READ-ONLY by default: it builds calldata and (unless you say otherwise)
simulates via eth_call. Nothing is signed or broadcast here — a wallet layer does that.

  run (stdio):     python3 server.py
  list tools once: python3 selftest.py
  dry-run all:     python3 dryrun.py

Spec: the tool surface mirrors the published https://dngr2.github.io/dex-products/llms.txt 1:1
(sig strings verbatim; selectors keccak-derived). Addresses copied from PRODUCTS.json (GOTCHA #73).
Fees are read LIVE per contract (GOTCHA #144: p3's MAX_FEE_BPS=10000 is a DENOMINATOR, never the take).
"""
from __future__ import annotations

import json
from typing import Optional

from mcp.server.mcpserver import MCPServer

import chain
import spec

server = MCPServer(
    name="dex-fleet",
    title="DEX fleet — non-custodial payment rails on Base",
    version="0.1.0",
    instructions=(
        "Non-custodial payment rails on Base (chainId 8453). Each tool returns the calldata to send "
        "to a live mainnet contract — no server holds funds. Tools simulate by default (dry_run=true). "
        "Spec: " + spec.SPEC_URL
    ),
)


# ---- helpers -------------------------------------------------------------------------------------

# Default simulated SENDER. eth_call with no `from` is the zero address, so any leg whose first
# effect is token.approve() reverts "approve from the zero address" — a caller-identity artifact,
# not bad calldata. A canonical funded Base EOA makes the sim reflect a real flow. Agents with their
# own address should pass it; this is only the default.
SIM_FROM = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth — funded on Base (public)


def _bytes32(v: str) -> str:
    """A 32-byte hex word from either a 0x-hex value or a utf-8 string (keccak'd)."""
    if not v:
        return "0x" + "00" * 32
    if v.startswith("0x") and len(v) == 66:
        return v
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "0x" + v
    from eth_utils import keccak
    return "0x" + keccak(text=v).hex()


def _addr(v: str) -> str:
    if not v:
        return "0x" + "00" * 20
    return v  # eth_abi accepts 0x-prefixed; chain._norm guards the rest


def _json(o) -> str:
    return json.dumps(o, indent=2, sort_keys=False)


# Session-scoped memory of the fee the caller has SEEN. Fee is live STATE (#162/#144): a long-lived
# agent that caches a quote can overpay after an owner `setFeeBps`. `read_fee` records each product's
# live value here; a money verb that takes a fee warns when its product was never read this session.
_FEE_SEEN: dict[str, int] = {}


def _fee_gate(product: str, expect_bps: int = -1) -> list[str]:
    """A warning list for a fee-bearing verb. Empty only if the fee was read this session AND (when
    the caller supplied expect_bps) it equals the live read. Never fatal — the caller may know
    better — but never silent: the stale-quote overpay is exactly the case this catches."""
    if product not in _FEE_SEEN:
        w = [f"read_fee not called this session for `{product}` — its fee is LIVE state (#162); "
             f"call read_fee('{product}') before sending so a stale client does not overpay"]
    else:
        w = [f"`{product}` fee last read this session = {_FEE_SEEN[product]} bps "
             f"(live; re-read read_fee if state may have moved)"]
    if expect_bps >= 0 and product in _FEE_SEEN and _FEE_SEEN[product] != expect_bps:
        w.append(f"FEE MISMATCH: caller expected {expect_bps} bps but the live take is "
                 f"{_FEE_SEEN[product]} bps — a stale quote would overpay/underpay; re-quote before sending")
    return w


def _result(tool: str, calls: list[dict], note: str = "", warn: Optional[list[str]] = None) -> str:
    o = {
        "tool": tool,
        "product": spec.CALLS[tool]["product"] if tool in spec.CALLS else "",
        "chain": {"name": spec.CHAIN_NAME, "id": spec.CHAIN_ID},
        "calls": calls,
        "note": note,
        "spec": spec.SPEC_URL,
    }
    if warn:
        o["warnings"] = warn
    return _json(o)


def _sim(to: str, data: str, dry_run: bool, frm: Optional[str] = None) -> dict:
    if not dry_run:
        return {"simulated": False}
    frm = frm or SIM_FROM
    r = chain.eth_call(to, data, frm=frm)
    # do not raise on revert; report it honestly (the calldata may still be right). A revert here is
    # usually a TRUE STATE revert, not bad calldata: approvals are only simulated (no state change),
    # so a later pull/create reverts for lack of allowance. Say so, so an agent reads it right.
    out = {"simulated": True, "ok": r["ok"],
           "result": r.get("result") if r["ok"] else None,
           "revert": None if r["ok"] else r.get("error")}
    if frm:
        out["from"] = frm
    if not r["ok"]:
        out["hint"] = ("sim is stateless: a prior approve here did not persist, so this leg reverts "
                       "for allowance/state. Send the legs in order, or pre-approve, to pass.")
    return out


def _one(tool: str, sig: str, args: list, to: str, dry_run: bool, frm: Optional[str] = None) -> dict:
    data = chain.build_call(sig, args)
    return {"to": to, "sig": sig, "selector": chain.selector(sig), "data": data,
            "sim": _sim(to, data, dry_run, frm)}


def _hops_obj(hops):
    """hops: a JSON string OR a python list of [venue,tokenIn,tokenOut,feeTier,stable?,venueRouter,factory?].
    Normalises the 5-field duster form and the 7-field router form."""
    if isinstance(hops, str):
        hops = json.loads(hops or "[]")
    out = []
    for h in hops:
        if len(h) == 7:  # router Hop: venue,tokenIn,tokenOut,feeTier,stable,venueRouter,factory
            out.append([h[0], _addr(h[1]), _addr(h[2]), h[3], bool(h[4]), _addr(h[5]), _addr(h[6])])
        elif len(h) == 5:  # duster HopInput: venue,tokenIn,tokenOut,feeTier,venueRouter
            out.append([h[0], _addr(h[1]), _addr(h[2]), h[3], _addr(h[4])])
        else:
            raise ValueError(f"hop must have 5 or 7 fields, got {len(h)}")
    return out


# ---- tools ---------------------------------------------------------------------------------------

@server.tool(description="Create a payment link: mint a request (f1a RequestRegistry) that yields a deposit address auto-forwarding to `destination`. Returns the on-chain call and the shareable link.")
def create_pay_link(destination: str, token: str = spec.USDC, amount: int = 0,
                    memo: str = "", dry_run: bool = True) -> str:
    """amount is in BASE UNITS (USDC 6 dp: 5000000 = 5 USDC). memo: hex32 or a string (keccak'd)."""
    sig = spec.CALLS["create_pay_link"]["sigs"][0]
    to = spec.ADDR["f1a-payment-links"]
    c = _one("create_pay_link", sig, [_addr(destination), _addr(token), int(amount), _bytes32(memo)], to, dry_run)
    link = f"{spec.BASE}/f1a-payment-links/payme/#to={destination}&tk={token}&amt={amount}"
    return _result("create_pay_link", [c],
                   f"share this link; provider `request(...)` returns (id, depositAddr). link: {link}")


@server.tool(description="Register a personal deposit address (p2 Registry) that auto-forwards to `destination`. A payer then sends the token to that address. WARNs if read_fee wasn't called this session (fee is live state); pass expect_fee_bps to also flag a mismatch.")
def pay(destination: str, dry_run: bool = True, expect_fee_bps: int = -1) -> str:
    sig = spec.CALLS["pay"]["sigs"][0]
    to = spec.ADDR["p2-forwarder"]
    c = _one("pay", sig, [_addr(destination)], to, dry_run)
    return _result("pay", [c], "returns a deposit address; the forwarder sweeps deposits to `destination`",
                   warn=_fee_gate("p2-forwarder", expect_fee_bps))


@server.tool(description="Create an escrow (g2b) locked against a hashlock or arbiter; funds sit in the contract until release or refund.")
def escrow_create(counterparty: str, token: str = spec.USDC, amount: int = 0,
                  hashlock: str = "", timeout: int = 0, dry_run: bool = True) -> str:
    sig = spec.CALLS["escrow_create"]["sigs"][0]
    to = spec.ADDR["g2b-escrow"]
    c = _one("escrow_create", sig,
             [_addr(counterparty), _addr(token), int(amount), _bytes32(hashlock), int(timeout)], to, dry_run)
    return _result("escrow_create", [c],
                   "returns an escrow address; release with the preimage (escrow_release), or refund after timeout")


@server.tool(description="Settle a g2b escrow: release(preimage) | refund() | arbiterRelease() | arbiterRefund(). Called on the ESCROW address, not the factory.")
def escrow_release(escrow: str, which: str = "release", preimage: str = "", dry_run: bool = True) -> str:
    sig = {"release": "release(bytes32)", "refund": "refund()",
           "arbiterRelease": "arbiterRelease()", "arbiterRefund": "arbiterRefund()"}[which]
    args = [_bytes32(preimage)] if which == "release" else []
    c = _one("escrow_release", sig, args, _addr(escrow), dry_run)
    return _result("escrow_release", [c], f"{which} on {escrow}")


@server.tool(description="Create a payment stream (g2a): approve the factory, then createStream(recipient, token, amount, start, end); the recipient withdraw()s as it vests.")
def stream_create(recipient: str, token: str = spec.USDC, amount: int = 0,
                  start: int = 0, end: int = 0, dry_run: bool = True) -> str:
    factory = spec.ADDR["g2a-streams"]
    a = spec.CALLS["stream_create"]["sigs"][0]  # approve(address,uint256)
    s = spec.CALLS["stream_create"]["sigs"][1]  # createStream(...)
    calls = [
        _one("stream_create", a, [_addr(factory), int(amount)], _addr(token), dry_run),
        _one("stream_create", s, [_addr(recipient), _addr(token), int(amount), int(start), int(end)], factory, dry_run),
    ]
    return _result("stream_create", calls, "call approve on the TOKEN first, then createStream on the FACTORY")


@server.tool(description="Subscribe (g2a): ONE bounded approve(factory, ticket*periods) is the whole mandate; a keeper calls createStreamFor per period. Revoke with approve(factory,0).")
def subscribe(payer: str, recipient: str, token: str = spec.USDC, amount: int = 0,
              start: int = 0, end: int = 0, periods: int = 1, dry_run: bool = True) -> str:
    factory = spec.ADDR["g2a-subscriptions"]
    a = spec.CALLS["subscribe"]["sigs"][0]
    s = spec.CALLS["subscribe"]["sigs"][1]
    calls = [
        _one("subscribe", a, [_addr(factory), int(amount) * int(periods)], _addr(token), dry_run),
        _one("subscribe", s, [_addr(payer), _addr(recipient), _addr(token), int(amount), int(start), int(end)], factory, dry_run),
    ]
    return _result("subscribe", calls,
                   f"bounded mandate = amount*periods = {int(amount)*int(periods)} base units (NOT max-uint)")


@server.tool(description="Swap (p3 router). Hops are handed in; the router takes a 5 bps fee on INPUT to treasury. amount_out_min is your slippage guard.")
def swap(amount_in: int, amount_out_min: int, hops, recipient: str,
         deadline: int = 0, token_in: str = "", dry_run: bool = True) -> str:
    sig = spec.CALLS["swap"]["sigs"][0]
    to = spec.ADDR["p3-router"]
    params = [int(amount_in), int(amount_out_min), _hops_obj(hops), _addr(recipient), int(deadline)]
    c = _one("swap", sig, [params], to, dry_run)
    return _result("swap", [c],
                   "hop = [venue,tokenIn,tokenOut,feeTier,stable,venueRouter,factory]; fee is taken on INPUT "
                   "(read_fee(p3-router) for the live bps). Approve the router for amount_in.")


@server.tool(description="Sweep dust to USDC (f1c). One tx: pull balances via Permit2, one-hop each token to USDC, deliver to you. Needs Permit2 approvals first.")
def sweep_dust(tokens, hops, min_out, dry_run: bool = True) -> str:
    sig = spec.CALLS["sweep_dust"]["sigs"][0]
    to = spec.ADDR["f1c-duster"]
    tk = json.loads(tokens) if isinstance(tokens, str) else tokens
    mo = json.loads(min_out) if isinstance(min_out, str) else min_out
    c = _one("sweep_dust", sig, [list(tk), _hops_obj(hops), [int(x) for x in mo]], to, dry_run)
    return _result("sweep_dust", [c],
                   "hop = [venue,tokenIn,tokenOut,feeTier,venueRouter]; zero fee by design. Approve Permit2 first.")


@server.tool(description="Gasless call (g3a): sponsoredCall(target, data) — the relay pays gas, the actor EOA does not (EIP-7702 delegate).")
def sponsored_call(target: str, data: str, dry_run: bool = True) -> str:
    sig = spec.CALLS["sponsored_call"]["sigs"][0]
    to = spec.ADDR["g3a-sponsorship"]
    c = _one("sponsored_call", sig, [_addr(target), data], to, dry_run)
    return _result("sponsored_call", [c], "no bps getter — fee is per sponsored tx (>=1.5x gas floor)")


@server.tool(description="Mint the one proof-of-payment receipt NFT (g4b) for a SETTLED escrow, to the payer. Payable: send mintFeeWei.")
def mint_receipt(escrow: str, dry_run: bool = True) -> str:
    sig = spec.CALLS["mint_receipt"]["sigs"][0]
    to = spec.ADDR["g4b-receipts"]
    c = _one("mint_receipt", sig, [_addr(escrow)], to, dry_run)
    fee = chain.eth_call(to, chain.selector("mintFeeWei()") + "0" * 0 + "0" * 0)
    return _result("mint_receipt", [c], "payable {value} = mintFeeWei (see read_fee('g4b-receipts'))")


@server.tool(description="Read live fee info for a product (or all). Fee getters are read on-chain; MAX_FEE_BPS is a DENOMINATOR on p3, never the take (GOTCHA #144).")
def read_fee(product: str = "") -> str:
    items = {product: spec.FEE_GETTERS[product]} if product in spec.FEE_GETTERS else spec.FEE_GETTERS
    out = {}
    for pid, g in items.items():
        entry = {"unit": g["unit"], "note": g["note"]}
        if g["sig"]:
            who = spec.ADDR.get(g.get("contract", pid))
            data = chain.selector(g["sig"].split("(")[0] + "()")
            r = chain.eth_call(who, data)
            if r["ok"]:
                v = chain.decode_uint(r["result"])
                entry["live"] = v
                if g["unit"] == "bps":
                    _FEE_SEEN[pid] = v  # remember the live take so a later `pay` can gate on it
                    entry["pct"] = f"{v/100:.4f}%"
                    entry["denominator"] = 10_000
                    entry["max_check"] = "this is the TAKE; do not confuse with a MAX_*_BPS cap"
            else:
                entry["live"] = None
                entry["read_error"] = r["error"]
        else:
            entry["live"] = None
        out[pid] = entry
    return _json({"tool": "read_fee", "chain": {"id": spec.CHAIN_ID}, "fees": out, "spec": spec.SPEC_URL})


@server.tool(description="Server + chain info: the product map, addresses (copied from PRODUCTS.json), and the published spec URL.")
def server_info() -> str:
    return _json({
        "name": "dex-fleet", "version": "0.1.0",
        "chain": {"name": spec.CHAIN_NAME, "id": spec.CHAIN_ID, "explorer": spec.EXPLORER},
        "usdc": spec.USDC, "usdc_decimals": spec.USDC_DECIMALS, "treasury": spec.TREASURY,
        "products": [{"id": pid, "contract": a} for pid, a in spec.ADDR.items()],
        "tools": list(spec.CALLS) + ["read_fee", "server_info"],
        "spec": spec.SPEC_URL, "catalog": spec.CATALOG_URL,
        "custody": "non-custodial: funds move payer -> vault/escrow, never into a server",
    })


if __name__ == "__main__":
    server.run()  # stdio by default
