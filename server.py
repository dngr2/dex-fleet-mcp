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


def _pad32(v: str) -> str:
    """A 32-byte word from a hex value (passthrough) OR a UTF-8 string (right-padded). Not hashed."""
    if not v:
        return "0x" + "00" * 32
    if v.startswith("0x") and len(v) == 66:
        return v
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "0x" + v
    b = v.encode("utf-8")[:32]
    return "0x" + b.hex().ljust(64, "0")


def _hashlock_arg(v: str) -> str:
    """The `hashlock` arg for escrow_create. A 32-byte hex is TAKEN AS the hashlock (raw); anything
    else is treated as the SECRET (a preimage) and stored as keccak of its padded bytes. Mirrors
    `_preimage_arg`, so a plain string round-trips: create hashes it once, release sends it raw."""
    if v.startswith("0x") and len(v) == 66:
        return v
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "0x" + v
    from eth_utils import keccak
    return "0x" + keccak(hexstr=_pad32(v)).hex()


def _preimage_arg(v: str) -> str:
    """The `preimage` arg for escrow_release: the RAW 32-byte secret (escrow_new_secret's output),
    never a re-hash. A plain string is padded to bytes32 the same way create hashed it."""
    return _pad32(v)


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

@server.tool(description="Create a payment link: mint a request (f1a RequestRegistry) yielding a deposit address that auto-forwards to `destination`. Returns the on-chain call AND the shareable PAYER link (the real frontend route). Then `resolve_pay_link(txHash)` turns the receipt into the link if you didn't capture the return.")
def create_pay_link(destination: str, token: str = spec.USDC, amount: int = 0,
                    memo: str = "", dry_run: bool = True) -> str:
    """amount is in BASE UNITS (USDC 6 dp: 5000000 = 5 USDC). memo: hex32 or a string (keccak'd)."""
    sig = spec.CALLS["create_pay_link"]["sigs"][0]
    to = spec.ADDR["f1a-payment-links"]
    c = _one("create_pay_link", sig, [_addr(destination), _addr(token), int(amount), _bytes32(memo)], to, dry_run)
    # The REAL frontend route is the chain-pinned hash form served by the p2-forwarder page
    # (`#/pay/<chainId>/<registry>/<id>`); the old `/f1a-payment-links/payme/#to=…` 404s. `registry`
    # is the f1a RequestRegistry (the page decodes request_(id) from it), id is the next id.
    reg = to
    link = f"{spec.BASE}/p2-forwarder/#/pay/{spec.CHAIN_ID}/{reg}/<id>"
    return _result("create_pay_link", [c],
                   f"provider `request(...)` returns (id, depositAddr). Payer link template: {link} "
                   f"(substitute <id> from the receipt, or call resolve_pay_link(txHash) after sending)")


@server.tool(description="READ a tx receipt and return the payment links it minted: parses the f1a RequestCreated log (id + depositAddr) into the real payer link and the auto-forwarding deposit address. Use after create_pay_link if you didn't capture the return value.")
def resolve_pay_link(tx_hash: str) -> str:
    r = chain.rpc("eth_getTransactionReceipt", [tx_hash])
    if not r["ok"]:
        return _json({"tool": "resolve_pay_link", "txHash": tx_hash, "error": r["error"]})
    rc = r["result"]
    if not rc:
        return _json({"tool": "resolve_pay_link", "txHash": tx_hash, "error": "no receipt yet (pending?)"})
    # RequestCreated(uint256 indexed id, address indexed merchant, address indexed payer,
    #                address depositAddr, ...) — id is INDEXED (topics[1]); depositAddr is data word 0.
    # Try the LIVE (v2) registry first, then the v1 registry: requests minted before the 2026-11-10
    # cutover were emitted by v1, and the link MUST name the emitter — the /p2-forwarder page re-reads
    # the RequestCreated log from that exact address, so a v1 id under the v2 emitter would 404.
    t0 = chain.topic0("RequestCreated(uint256,address,address,address,address,address,uint256,bytes32,uint64)")
    for reg in (spec.ADDR["f1a-payment-links"], spec.V1_F1A):
        lg = chain.find_log(rc, reg, t0)
        if lg is not None:
            break
    if lg is None:
        return _json({"tool": "resolve_pay_link", "txHash": tx_hash,
                      "error": f"no RequestCreated log from {spec.ADDR['f1a-payment-links']} "
                               f"(or v1 {spec.V1_F1A}) in this receipt"})
    topics = lg.get("topics") or []
    if len(topics) < 2:
        return _json({"tool": "resolve_pay_link", "txHash": tx_hash, "error": "malformed log"})
    id_ = int(topics[1], 16)
    data = lg.get("data", "0x")
    dep = "0x" + data[2:][24:64]  # data word 0 = depositAddr (first NON-indexed arg)
    link = f"{spec.BASE}/p2-forwarder/#/pay/{spec.CHAIN_ID}/{reg}/{id_}"
    return _json({"tool": "resolve_pay_link", "txHash": tx_hash, "chain": {"id": spec.CHAIN_ID},
                  "id": id_, "depositAddr": dep, "link": link, "registry": reg,
                  "note": "share `link` with the payer; sending the token to depositAddr auto-forwards",
                  "spec": spec.SPEC_URL})


@server.tool(description="Register a personal deposit address (p2 Registry) forwarding to `destination`. REGISTER-ONLY (returns the address to send to). For the full pay flow use `pay`.")
def register_deposit_address(destination: str, dry_run: bool = True, expect_fee_bps: int = -1) -> str:
    sig = spec.CALLS["register_deposit_address"]["sigs"][0]
    to = spec.ADDR["p2-forwarder"]
    c = _one("register_deposit_address", sig, [_addr(destination)], to, dry_run)
    return _result("register_deposit_address", [c],
                   "returns a deposit address; the forwarder sweeps deposits to `destination`",
                   warn=_fee_gate("p2-forwarder", expect_fee_bps))


@server.tool(description="PAY: the real two-step. Leg 1 register(destination) on the p2 Registry (mints your deposit address, idempotent per nonce); Leg 2 transfer(token, depositAddr, amount) on the TOKEN. Replace depositAddr with leg 1's return before sending leg 2. WARNs if read_fee wasn't called this session.")
def pay(destination: str, token: str = spec.USDC, amount: int = 0, deposit_addr: str = "",
        dry_run: bool = True, expect_fee_bps: int = -1) -> str:
    reg = spec.ADDR["p2-forwarder"]
    c1 = _one("pay", spec.CALLS["pay"]["sigs"][0], [_addr(destination)], reg, dry_run)
    # leg 2: transfer on the token. If the caller hasn't supplied the deposit address, hand them the
    # echo of leg 1's result as the placeholder so the calldata is still concrete.
    dep = _addr(deposit_addr) if deposit_addr else (c1["sim"].get("result") and
          "0x" + c1["sim"]["result"][2:][24:64]) or "0x" + "00" * 20
    c2 = _one("pay", spec.TRANSFER_SIG, [dep, int(amount)], _addr(token), dry_run)
    return _result("pay", [c1, c2],
                   "leg1 mints your deposit address (Registry); leg2 sends the token to it (token. "
                   "transfer). The forwarder then sweeps to `destination`. Send leg1 first, substitute "
                   "its return for the placeholder in leg2.",
                   warn=_fee_gate("p2-forwarder", expect_fee_bps))


@server.tool(description="Create an escrow (g2b) locked against a hashlock or arbiter; funds sit in the contract until release or refund. `hashlock` is ALREADY bytes32 — call escrow_new_secret() first and pass its `hashlock`; the matching `preimage` goes to escrow_release (never re-hash it).")
def escrow_create(counterparty: str, token: str = spec.USDC, amount: int = 0,
                  hashlock: str = "", timeout: int = 0, dry_run: bool = True) -> str:
    sig = spec.CALLS["escrow_create"]["sigs"][0]
    to = spec.ADDR["g2b-escrow"]
    h = _hashlock_arg(hashlock)  # 32-byte hashlock straight through; a STRING is keccak'd ONCE
    c = _one("escrow_create", sig,
             [_addr(counterparty), _addr(token), int(amount), h, int(timeout)], to, dry_run)
    return _result("escrow_create", [c],
                   "returns an escrow address; release with the SAME secret's preimage (escrow_release), "
                   "or refund after timeout. NB: do NOT pass keccak(string) as the preimage later — the "
                   "contract checks keccak(preimage)==hashlock, so pass the raw secret.")


@server.tool(description="OFFLINE helper (no RPC): returns a fresh {preimage, hashlock} pair, both 32-byte. Pass `hashlock` to escrow_create and the SAME `preimage` to escrow_release — that round-trip is the only shape the contract accepts (keccak(preimage)==hashlock).")
def escrow_new_secret(preimage: str = "") -> str:
    import secrets as _secrets

    from eth_utils import keccak
    pre = _bytes32(preimage) if preimage else ("0x" + _secrets.token_hex(32))
    h = "0x" + keccak(hexstr=pre).hex()
    return _json({"tool": "escrow_new_secret", "preimage": pre, "hashlock": h,
                  "note": "create with `hashlock`; release with `preimage`. Both 32-byte; the contract "
                          "does keccak(preimage)==hashlock, so pass the RAW preimage (never re-hash it)."})


@server.tool(description="Settle a g2b escrow: release(preimage) | refund() | arbiterRelease() | arbiterRefund(). Called on the ESCROW address, not the factory. `preimage` is the RAW secret bytes32 (use escrow_new_secret); a plain string is keccak'd ONCE — the same way escrow_create hashes its hashlock string.")
def escrow_release(escrow: str, which: str = "release", preimage: str = "", dry_run: bool = True) -> str:
    sig = {"release": "release(bytes32)", "refund": "refund()",
           "arbiterRelease": "arbiterRelease()", "arbiterRefund": "arbiterRefund()"}[which]
    args = [_preimage_arg(preimage)] if which == "release" else []
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


@server.tool(description="Subscribe (g2a): approve(factory_v2, ticket*periods) then createStreamFor on the v2 StreamFactory. Includes a `revoke` leg against the PAUSED v1 factory — send it if you granted the old allowance before the migration. A keeper then fires createStreamFor once per period.")
def subscribe(payer: str, recipient: str, token: str = spec.USDC, amount: int = 0,
              start: int = 0, end: int = 0, periods: int = 1, dry_run: bool = True) -> str:
    factory = spec.ADDR["g2a-subscriptions"]  # v2 (the v1 factory is paused)
    a = spec.CALLS["subscribe"]["sigs"][0]
    s = spec.CALLS["subscribe"]["sigs"][1]
    calls = [
        _one("subscribe", a, [_addr(factory), int(amount) * int(periods)], _addr(token), dry_run),
        _one("subscribe", s, [_addr(payer), _addr(recipient), _addr(token), int(amount), int(start), int(end)], factory, dry_run),
    ]
    revoke = _one("subscribe", spec.V1_APPROVE_REVOKE[0]["sig"], [_addr(spec.V1_APPROVE_REVOKE[0]["to"]), 0],
                  _addr(token), dry_run)
    return _result("subscribe", calls,
                   f"bounded mandate = amount*periods = {int(amount)*int(periods)} base units (NOT max-uint). "
                   f"Revoke leg (send only if you hold an OLD v1 allowance): "
                   f"approve({spec.V1_APPROVE_REVOKE[0]['to']}, 0)") + \
        _json({"tool": "subscribe.revoke", "calls": [revoke]})


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


def _univ3_quote(token_in: str, token_out: str, amount_in: int, fee_tier: int) -> dict:
    """QuoterV2.quoteExactInputSingle for one Uniswap-V3 hop. Returns {ok, amountOut} — the venue
    quoter is a read (eth_call), never a tx. sqrtPriceLimitX96=0. The sig takes ONE tuple param."""
    data = chain.build_call(spec.QUOTER_SIG,
                            [[_addr(token_in), _addr(token_out), int(amount_in), int(fee_tier), 0]])
    r = chain.eth_call(spec.QUOTER, data)
    if not r["ok"]:
        return {"ok": False, "error": r.get("error")}
    # quoteExactInputSingle returns (uint256 amountOut, uint160, uint32, uint256) — word 0.
    return {"ok": True, "amountOut": chain.decode_uint_at(r["result"], 0)}


@server.tool(description="READ: quote one or more UniV3 hops and return amountOut per hop plus the router fee, so you can choose `amount_out_min` for `swap`. hops = [[tokenIn,tokenOut,feeTier],…]. Slippage bps turns the net into a min.")
def quote_swap(hops, amount_in: int, slippage_bps: int = 50, dry_run: bool = True) -> str:
    if isinstance(hops, str):
        hops = json.loads(hops or "[]")
    router = spec.ADDR["p3-router"]
    amt = int(amount_in)
    # the router takes the fee on INPUT to treasury FIRST, then swaps the post-fee amount — so the
    # quote must start from (amt - fee), matching swapExactTokensForTokens's real arithmetic.
    fee_r = chain.eth_call(router, chain.build_call("previewFee(uint256)", [amt]))
    fee = chain.decode_uint_at(fee_r["result"], 0) if fee_r["ok"] else None
    start_amt = amt - fee if fee is not None else amt
    steps = []
    cur = start_amt
    for h in hops:
        tin, tout, tier = _addr(h[0]), _addr(h[1]), int(h[2])
        q = _univ3_quote(tin, tout, cur, tier)
        steps.append({"tokenIn": tin, "tokenOut": tout, "feeTier": tier,
                      "amountIn": cur, **({"amountOut": q["amountOut"]} if q["ok"] else {"error": q["error"]})})
        if not q["ok"]:
            break
        cur = q["amountOut"]
    sugg = cur - (cur * int(slippage_bps)) // 10_000 if steps and "amountOut" in steps[-1] else None
    return _json({"tool": "quote_swap", "chain": {"id": spec.CHAIN_ID}, "router": router,
                  "amountIn": amt, "routerFee": fee, "routerFeeUnit": "token-in base units",
                  "hops": steps, "amountOut": cur if steps and "amountOut" in steps[-1] else None,
                  "slippageBps": int(slippage_bps), "suggested_amount_out_min": sugg,
                  "note": "router fee is on INPUT to treasury; pass suggested_amount_out_min to `swap`",
                  "spec": spec.SPEC_URL})


@server.tool(description="READ: same UniV3 quote as quote_swap but the f1c duster takes ZERO fee, so minOut == the quoted out minus slippage. tokens+hops are the same shapes the sweep takes; returns suggested minOut per token.")
def quote_sweep(tokens, hops, slippage_bps: int = 50, dry_run: bool = True) -> str:
    tk = json.loads(tokens) if isinstance(tokens, str) else tokens
    hs = json.loads(hops) if isinstance(hops, str) else hops
    out = []
    for tok, h in zip(tk, hs):
        tin, tout, tier = _addr(h[1]), _addr(h[2]), int(h[3]) if len(h) > 3 else 500
        # amount for each dust token is unknown without a balance read; quote per 1 unit is a shape,
        # so accept an optional 5th element as the amount, else 0 and report the tier.
        bal = await_bal = None
        q = _univ3_quote(tin, tout, 1, tier)
        out.append({"tokenIn": tin, "tokenOut": tout, "feeTier": tier,
                    "perUnitOut": q.get("amountOut"), "error": q.get("error")})
    return _json({"tool": "quote_sweep", "chain": {"id": spec.CHAIN_ID},
                  "dustFee": "ZERO (duster takes no fee)", "quotes": out,
                  "slippageBps": int(slippage_bps),
                  "note": "pass minOut[] to `sweep_dust`; per-token min = quoted_out*(1-slippage). "
                          "quote is per 1 base unit — multiply by the real balance for the true min",
                  "spec": spec.SPEC_URL})


@server.tool(description="SIGNED-INTENT batch on the FleetExecutor EIP-7702 delegate (the authority signs EIP-712 off-chain; ANY relayer carries it, paying the gas, while the authority's own frame runs the calls). Calls are (target,value,data). If you omit nonce/deadline/sig you get the digest() to sign; call digest() on the AUTHORITY address.")
def sponsored_call(calls, nonce: int = -1, deadline: int = 0, sig: str = "",
                   authority: str = "", dry_run: bool = True) -> str:
    """calls: JSON list of [target, value, data] OR the 3-tuple form. The emitted leg targets the
    AUTHORITY (the delegated EOA), because `execute` is called on the EOA, not the delegate address."""
    delegate = spec.ADDR["fleet-executor"]
    sig_str = spec.CALLS["sponsored_call"]["sigs"][0]
    if isinstance(calls, str):
        calls = json.loads(calls or "[]")
    norm = [[_addr(c[0]), int(c[1]), c[2]] for c in calls]
    to = _addr(authority) if authority else delegate
    args = [norm, int(nonce) if nonce >= 0 else 0, int(deadline), sig or ("0x" + "00" * 65)]
    c = _one("sponsored_call", sig_str, args, to, dry_run)
    note = (f"execute(calls,nonce,deadline,sig) ON THE AUTHORITY {to}. Sign EIP-712 over "
            f"digest(calls,nonce,deadline) computed on that same authority; nonce = nonceOf(authority)+1; "
            f"deadline = now+300. FleetExecutor {delegate} is a stateless EIP-7702 delegate — it holds no "
            f"funds and needs no approval.")
    return _result("sponsored_call", [c], note)


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
