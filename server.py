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
import os
import time
from typing import Optional

# MCP-8 lazy import: `mcp.server.mcpserver` is the ONE heavyweight dependency. The lazy surface is
# chain's (httpx/eth_abi/eth_utils load per-use — see chain.py), so `spec`/`chain` and every pure
# encoder now work with none of it installed. `server` itself is built on FIRST TOOL REGISTRATION
# rather than at module scope, so construction (and its version/instructions) no longer runs merely
# to import the module. NB: `@server.tool` still executes at import, so the MCP package is still
# needed for `import server` — this defers the object, it does not remove the dependency.
import chain
import spec


class _LazyServer:
    """Proxy so decorators can run at import time while the MCP stack loads on first real use."""

    def __init__(self):
        self._real = None

    def _load(self):
        if self._real is None:
            from mcp.server.mcpserver import MCPServer
            self._real = MCPServer(
                name="dex-fleet",
                title="DEX fleet — non-custodial payment rails on Base",
                version="0.2.0",
                instructions=(
                    "Non-custodial payment rails on Base (chainId 8453). Each tool returns the "
                    "calldata to send to a live mainnet contract — no server holds funds. Tools "
                    "simulate by default (dry_run=true). Spec: " + spec.SPEC_URL
                ),
            )
        return self._real

    def tool(self, *a, **kw):
        """Load the real server on first use, then hand back ITS decorator (applied by @syntax)."""
        return self._load().tool(*a, **kw)

    def resource(self, *a, **kw):
        """Same deferral for @server.resource (fleet://addresses, //fees, //status)."""
        return self._load().resource(*a, **kw)

    def run(self, *a, **kw):
        return self._load().run(*a, **kw)


server = _LazyServer()


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


# SPENDING GUARD (MCP-9). An agent hands these tools numbers it got from somewhere else; a decimal
# slip (5000000 vs 5000000000) is a 1000x overspend and nothing in the old surface noticed. Ceilings
# are per-call hard stops, set by env (base units), and a `max_amount` arg pins one call tighter.
# USDC is 6 dp, so the default ceilings are deliberately generous-but-real (see DEFAULT_MAX_USDC).
# MCP_MAX_USDC=0 DISABLES the ceiling (0 would otherwise flag every amount, since nothing exceeds 0).
DEFAULT_MAX_USDC = float(os.environ.get("MCP_MAX_USDC", "1000"))
_TRUSTED = {spec.CHAIN_ID}   # chainIds this server's addresses belong to


def _spend_gate(amount: int, token: str = "", max_amount: int = -1,
                chain_id: int | None = None) -> list[str]:
    """Warning list (never fatal — an agent may legitimately move more) for an amount about to move.

    Flags: a non-positive/absurd amount, an identical token==destination style swap, a decimal-class
    overspend against the ceiling, and a chain mismatch when the caller names one."""
    w = []
    a = int(amount)
    if a <= 0:
        w.append(f"amount is {a} base units — a zero/negative amount moves nothing (USDC 6 dp)")
    elif DEFAULT_MAX_USDC and token and token.lower() == spec.USDC.lower() and a > int(DEFAULT_MAX_USDC * 10 ** spec.USDC_DECIMALS):
        w.append(f"amount {a} = {a / 10 ** spec.USDC_DECIMALS:,.2f} USDC exceeds the "
                 f"{DEFAULT_MAX_USDC:,.0f} USDC per-call ceiling (MCP_MAX_USDC) — check the decimals "
                 f"(6 dp: 5 USDC is 5000000, not 5)")
    elif DEFAULT_MAX_USDC and a > int(DEFAULT_MAX_USDC * 10 ** spec.USDC_DECIMALS):
        w.append(f"amount {a} base units exceeds the {DEFAULT_MAX_USDC:,.0f}-unit ceiling "
                 f"(MCP_MAX_USDC, assumed 6 dp) — confirm the token's decimals")
    if max_amount >= 0 and a > int(max_amount):
        w.append(f"amount {a} > your max_amount {max_amount} — refusing nothing, but this exceeds "
                 f"the bound you passed")
    if chain_id is not None and int(chain_id) not in _TRUSTED:
        w.append(f"chain_id {chain_id} is not {spec.CHAIN_ID} — these addresses are Base-mainnet "
                 f"addresses; on another chain they are different contracts or empty")
    return w


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


def _result(tool: str, calls: list[dict], note: str = "", warn: Optional[list[str]] = None,
            extra: Optional[dict] = None, tip: str = "") -> str:
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
    if extra:
        o.update(extra)   # R3-4: `needs_signature` / digest / nonce ride here, not in prose
    if tip:
        # CAPABILITY CHECK (MCP-10). `read_capabilities` answers "can this succeed?" in the same
        # currency as the revert: a missing allowance, a paused factory, a zero balance. A tip names
        # the exact check for the leg about to be sent, so an agent that skips it can see what it
        # skipped rather than reading a bare revert later.
        o["tip"] = tip
    return _json(o)


def _sim(to: str, data: str, dry_run: bool, frm: Optional[str] = None,
         overrides: Optional[dict] = None) -> dict:
    if not dry_run:
        return {"simulated": False}
    frm = frm or SIM_FROM
    r = chain.eth_call(to, data, frm=frm, overrides=overrides)
    # do not raise on revert; report it honestly (the calldata may still be right). A revert here is
    # usually a TRUE STATE revert, not bad calldata: approvals are only simulated (no state change),
    # so a later pull/create reverts for lack of allowance. Say so, so an agent reads it right.
    out = {"simulated": True, "ok": r["ok"],
           "result": r.get("result") if r["ok"] else None,
           "revert": None if r["ok"] else r.get("error")}
    if frm:
        out["from"] = frm
    # MCP-3: grade it — an agreed answer is evidence, a lone one is a hint.
    if "quorum" in r:
        out["agree"] = r.get("agree")
        out["quorum"] = r.get("quorum")
        if r.get("dissent"):
            out["dissent"] = r["dissent"]
        if r.get("block"):
            out["block"] = r["block"]
    if r.get("cached"):
        out["cached"] = True
    if not r["ok"]:
        out["hint"] = ("sim is stateless: a prior approve here did not persist, so this leg reverts "
                       "for allowance/state. Send the legs in order, or pre-approve, to pass.")
    return out


def _one(tool: str, sig: str, args: list, to: str, dry_run: bool, frm: Optional[str] = None,
         overrides: Optional[dict] = None) -> dict:
    data = chain.build_call(sig, args)
    out = {"to": to, "sig": sig, "selector": chain.selector(sig), "data": data,
           "sim": _sim(to, data, dry_run, frm, overrides)}
    # MCP-3: grade the sim. A quorum-less answer is not the same evidence as an agreed one, and a
    # caller deciding whether to sign deserves to see which it has.
    sim = out["sim"]
    if sim.get("simulated") and "quorum" in sim and not sim["quorum"]:
        sim["grade"] = "UNCONFIRMED (one endpoint; no quorum)"
    return out


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


@server.tool(description="PAY: the real two-step. Leg 1 register(destination) on the p2 Registry (mints your deposit address, idempotent per nonce); Leg 2 transfer(token, depositAddr, amount) on the TOKEN (or a native value-send when token is the zero address). depositAddr is VERIFIED against registry.predict(owner, destination) before returning. WARNs if read_fee wasn't called this session.")
def pay(destination: str, token: str = spec.USDC, amount: int = 0, deposit_addr: str = "",
        owner: str = "", dry_run: bool = True, expect_fee_bps: int = -1,
        max_amount: int = -1) -> str:
    """R3-5: leg 2 pays whatever bare 20 bytes came off leg 1's return. If that decode is wrong or the
    caller pasted a stranger's deposit address, the money lands at the WRONG forwarder. So predict()
    the registry itself and ASSERT the encoded destination equals it — a real cross-check, not a
    re-derivation of our own bytes. `owner` defaults to SIM_FROM (the simulated sender == register's
    msg.sender, so predict must use the same identity)."""
    reg = spec.ADDR["p2-forwarder"]
    who = _addr(owner) if owner else SIM_FROM
    dest = _addr(destination)
    c1 = _one("pay", spec.CALLS["pay"]["sigs"][0], [dest], reg, dry_run)
    warn = list(_fee_gate("p2-forwarder", expect_fee_bps)) + _spend_gate(amount, token, max_amount)
    extra: dict = {"owner": who}
    native = (not token) or token == "0x" + "00" * 20

    # ask the REGISTRY what the deposit address is (predict binds owner+nonce+destination).
    # Gated on dry_run so the offline drift check (verify.py, dry_run=False) stays RPC-free and
    # deterministic: without it leg2's placeholder is the zero address, exactly as before.
    truth = None
    if dry_run:
        rp = chain.eth_call(reg, chain.build_call(spec.READS["p2-forwarder"][0], [who, dest]))
        if rp["ok"]:
            truth = chain.decode_addr(rp["result"])
            extra["predicted"] = truth
        else:
            warn.append(f"predict(owner,destination) read failed ({rp['error']}) — deposit address NOT "
                        f"cross-checked this call")

    if deposit_addr:
        dep = _addr(deposit_addr)
        if truth and dep.lower() != truth.lower():
            warn.append(f"DEST MISMATCH: you passed deposit_addr {dep} but registry.predict({who}, "
                        f"{dest}) = {truth} — paying {dep} sends the money to the WRONG forwarder")
    elif c1["sim"].get("result"):
        dep = chain.decode_addr(c1["sim"]["result"])
    elif truth:
        dep = truth
    else:
        dep = "0x" + "00" * 20
    # the sim's own return must ALSO agree with predict — a disagreement means the decode is wrong.
    if truth and c1["sim"].get("result") and dep.lower() != truth.lower():
        warn.append(f"DECODE MISMATCH: leg-1 sim returned {dep} but predict() says {truth}")

    if native:
        c2 = {"to": dep, "value": int(amount), "data": "0x", "sig": "(native value send)",
              "selector": "0x", "sim": c1["sim"]}
    else:
        c2 = _one("pay", spec.TRANSFER_SIG, [dep, int(amount)], _addr(token), dry_run)
    extra["deposit_addr"] = dep
    if truth:
        extra["verified"] = dep.lower() == truth.lower()
    return _result("pay", [c1, c2],
                   "leg1 mints your deposit address (Registry); leg2 sends the token to it (token. "
                   "transfer) — or native value to that address when token=0x0. The forwarder then "
                   "sweeps to `destination`. Send leg1 first, substitute its return for the "
                   "placeholder in leg2.",
                   warn=warn or None, extra=extra)


@server.tool(description="Create an escrow (g2b) locked against a hashlock or arbiter; funds sit in the contract until release or refund. `hashlock` is ALREADY bytes32 — call escrow_new_secret() first and pass its `hashlock`; the matching `preimage` goes to escrow_release (never re-hash it).")
def escrow_create(counterparty: str, token: str = spec.USDC, amount: int = 0,
                  hashlock: str = "", timeout: int = 0, dry_run: bool = True,
                  max_amount: int = -1) -> str:
    sig = spec.CALLS["escrow_create"]["sigs"][0]
    to = spec.ADDR["g2b-escrow"]
    h = _hashlock_arg(hashlock)  # 32-byte hashlock straight through; a STRING is keccak'd ONCE
    c = _one("escrow_create", sig,
             [_addr(counterparty), _addr(token), int(amount), h, int(timeout)], to, dry_run)
    warn = _spend_gate(amount, token, max_amount)
    return _result("escrow_create", [c],
                   "returns an escrow address; release with the SAME secret's preimage (escrow_release), "
                   "or refund after timeout. NB: do NOT pass keccak(string) as the preimage later — the "
                   "contract checks keccak(preimage)==hashlock, so pass the raw secret.",
                   warn=warn or None)


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
    warn = []
    if which == "release":
        if not preimage:
            warn.append("empty preimage — release() sends an all-zero word and the keccak check fails; "
                        "pass the raw secret escrow_new_secret gave you")
        elif preimage.startswith("0x") and len(preimage) == 66 and preimage == "0x" + "00" * 32:
            warn.append("preimage is all-zero — that is NOT the same as omitting it, and it only works "
                        "if the hashlock was keccak(0)")
    return _result("escrow_release", [c],
                   f"{which} on {escrow}. `which`: release(preimage) / refund() / arbiterRelease() / "
                   f"arbiterRefund(). release needs the RAW preimage; refund is only valid after the "
                   f"timeout and arbiter* only for the named arbiter.",
                   warn=warn or None)


@server.tool(description="Create a payment stream (g2a): approve the factory, then createStream(recipient, token, amount, start, end); the recipient withdraw()s as it vests.")
def stream_create(recipient: str, token: str = spec.USDC, amount: int = 0,
                  start: int = 0, end: int = 0, dry_run: bool = True, max_amount: int = -1) -> str:
    factory = spec.ADDR["g2a-streams"]
    a = spec.CALLS["stream_create"]["sigs"][0]  # approve(address,uint256)
    s = spec.CALLS["stream_create"]["sigs"][1]  # createStream(...)
    calls = [
        _one("stream_create", a, [_addr(factory), int(amount)], _addr(token), dry_run),
        _one("stream_create", s, [_addr(recipient), _addr(token), int(amount), int(start), int(end)], factory, dry_run),
    ]
    return _result("stream_create", calls, "call approve on the TOKEN first, then createStream on the FACTORY",
                   warn=_spend_gate(amount, token, max_amount) or None)


@server.tool(description="Subscribe (g2a): approve(factory, ticket*periods) then setMandate(...) then createStreamFor. The MANDATE is the bounded authorization — while it is armed the factory lets ANYONE fire a lap strictly within its limits (ticket, period, laps, monotonic t0), so the keeper needs no standing grant. Also returns a `revoke` block (disarmMandate + approve(v1,0)).")
def subscribe(payer: str, recipient: str, token: str = spec.USDC, amount: int = 0,
              start: int = 0, end: int = 0, periods: int = 1, dry_run: bool = True,
              max_amount: int = -1) -> str:
    """MCP-1: the tool used to emit approve + createStreamFor and NOTHING else.

    That works today only because a fleet keeper key is globally allow-listed (`isKeeper`) — the
    HEDGE path in `_create`. It is the unbounded half: `!isKeeper` anywhere and every lap reverts
    NotAuthorized, which is the 2026-11-13 OP freeze. `setMandate` is the other half — the payer
    states the ticket, the period, the LAPS BUDGET and the first start; the contract then enforces
    all four on every lap, so the worst a stranger can do is exactly what the payer authorised, and
    the reel cannot outrun its laps. `period` is derived as `end - start` (the mandate gate compares
    it to the window every lap), and `laps = periods`.

    NB the mandate is keyed by msg.sender, so the leg MUST be signed by `payer` — notify the caller
    when the supplied payer differs from the sim sender, because an approve from one key and a
    mandate from another authorise two different accounts."""
    factory = spec.ADDR["g2a-subscriptions"]  # v2.1 (the v1 factory is paused)
    a, m, s = spec.CALLS["subscribe"]["sigs"]
    ticket, laps = int(amount), int(periods)
    period = int(end) - int(start)
    warn = _spend_gate(ticket * laps, token, max_amount)
    if period < 60:
        warn.append(f"period = end-start = {period}s is under MIN_DURATION (60s) — setMandate reverts")
    if laps < 1:
        warn.append(f"periods/laps = {laps} — setMandate reverts (ZeroArg)")
    calls = [
        _one("subscribe", a, [_addr(factory), ticket * laps], _addr(token), dry_run),
        _one("subscribe", m, [_addr(recipient), _addr(token), ticket, period, laps, int(start)], factory, dry_run),
        _one("subscribe", s, [_addr(payer), _addr(recipient), _addr(token), ticket, int(start), int(end)], factory, dry_run),
    ]
    # ORDER MATTERS: approve (leg 0) funds the allowance, setMandate (leg 1) arms the bounds, and only
    # then may a keeper fire. Simulating leg 1 offline against a stateless node shows the mandate
    # landing, but the approve itself will not have persisted — expected, and the sim hint says so.
    revoke = [
        _one("disarm_mandate", spec.CALLS["disarm_mandate"]["sigs"][0], [_addr(recipient), _addr(token)],
             factory, dry_run),
        _one("disarm_mandate", spec.V1_APPROVE_REVOKE[0]["sig"], [_addr(spec.V1_APPROVE_REVOKE[0]["to"]), 0],
             _addr(token), dry_run),
    ]
    return _result("subscribe", calls,
                   f"leg0 approve is the allowance ({ticket*laps} base units = ticket {ticket} x laps "
                   f"{laps}, NOT max-uint); leg1 setMandate is the BOUNDED authorization (laps budget "
                   f"{laps}, period {period}s); leg2 fires the first lap. All three must be signed by "
                   f"`payer` — the mandate is keyed by msg.sender.",
                   warn=warn or None,
                   # `revoke` rides as a KEY, not a second concatenated document: the tool text used to
                   # be two JSON docs back to back, so a client doing a plain json.loads got
                   # "Extra data" and had to know about raw_decode.
                   extra={"revoke": {"note": "disarm + clear the allowance; either alone leaves half "
                                             "the authorization live", "calls": revoke}},
                   tip="read_capabilities(payer, token, factory) checks balance, allowance and paused "
                       "before you sign; read_fee shows the live per-period take")


@server.tool(description="Revoke a subscription fully (g2a): disarmMandate(recipient, token) clears the armed bounds AND approve(factory, 0) clears the allowance. Either alone leaves half the authorization live — with the mandate disarmed a keeper stops, but the standing allowance would still let a createStreamFor pull.")
def disarm_mandate(recipient: str, issuer: str = "", token: str = spec.USDC,
                   dry_run: bool = True) -> str:
    """Two legs, both signed by the PAYER (the mandate and the allowance are keyed by msg.sender).

    `issuer` is only the simulated sender — pass the payer so both sims run with the right identity."""
    factory = spec.ADDR["g2a-subscriptions"]
    d, a = spec.CALLS["disarm_mandate"]["sigs"]
    frm = _addr(issuer) if issuer else None
    warn = [] if issuer else ["no `issuer` given: both legs are keyed by msg.sender, so the sim runs "
                              "as the default sender and only shows calldata shape — pass the payer"]
    calls = [
        _one("disarm_mandate", d, [_addr(recipient), _addr(token)], factory, dry_run, frm=frm),
        # the allowance was granted to the v1 factory if the client approved before the cutover, and
        # to the live one otherwise — clearing only one leaves the other live. Clear BOTH.
        _one("disarm_mandate", a, [_addr(spec.V1_APPROVE_REVOKE[0]["to"]), 0], _addr(token), dry_run, frm=frm),
        _one("disarm_mandate", a, [_addr(factory), 0], _addr(token), dry_run, frm=frm),
    ]
    return _result("disarm_mandate", calls,
                   "leg0 disarms the mandate; legs 1-2 zero the allowance on the v1 AND the live "
                   "factory (whichever one you approved). All signed by the payer.",
                   warn=warn or None,
                   tip="read_capabilities(payer, token, factory) shows the allowance you are clearing")


@server.tool(description="x402 PAY. Two modes. (a) `url=…`: the agent-native entry point — fetch the URL, and if it answers 402 parse the challenge {rail,to,token,amount,memo,facilitator} and return the settle calls for it (rail pay from `payer`, then markPaid by a writer, then the verify gate) plus the X-PAYMENT retry. (b) `payment_id=…`: the post-settlement half only — emit markPaid(paymentId,to,token,amount) and the verify(...) VIEW. Everything is simulated, nothing is signed.")
def pay_x402(url: str = "", payment_id: str = "", to: str = "", token: str = spec.USDC,
             amount: int = 0, min_amount: int = -1, dry_run: bool = True, max_amount: int = -1,
             writer: str = "", payer: str = "") -> str:
    """MCP-6: there was NO x402 tool at all despite a deployed facilitator (`0x5849eF6f…`), so the
    whole build-lane surface was reachable by MCP except this one — and the one AGENT-shaped verb (pay
    the 402 a URL hands you) had no entry point at all.

    ORDER IS pay -> markPaid -> verify. The rail settles (its `Paid` event carries the paymentId),
    markPaid writes the settlement, verify reads it. markPaid is idempotent for identical fields and
    REVERTS `ConflictingMark()` on a different (to,token,amount), so a paymentId can never quietly
    change meaning; verify() answers false on any mismatch.

    `to`/`token`/`amount` must be the SAME triple the server advertised in its 402 — verify compares
    all three, so a typo here is a permanent false at the gate, not an error. With `url` they are
    filled FROM the challenge; an explicit argument still wins (and says so), so a caller can pay a
    different amount than advertised deliberately. `min_amount` defaults to `amount` (the contract's
    own call shape).

    `writer` sets the SIMULATED SENDER for the markPaid leg. Only an isWriter key passes, and the
    default SIM_FROM is not one — so an unqualified sim of that leg ALWAYS reverts NotWriter(), which
    reads as "bad calldata" when it is only a sender artifact. Pass the writer EOA you will sign with.

    HONEST LIMIT, stated rather than implied: no `IPaymentRail` implementation is deployed, so a
    challenge that names a `rail` address with no code gets a pay leg anyway with a warning (the
    address is the server's own claim) — the markPaid/verify pair is what is live here."""
    fac = spec.ADDR["x402"]
    warn: list[str] = []
    extra: dict = {}
    ch: dict = {}

    # ---- mode (a): fetch the challenge ---------------------------------------------------------
    if url:
        g = chain.http_get(url)
        if not g["ok"]:
            return _json({"tool": "pay_x402", "url": url, "error": f"fetch failed: {g['error']}",
                          "note": "a transport failure is NOT a 402 — nothing was charged, retry the URL",
                          "spec": spec.SPEC_URL})
        extra["challenge"] = {"status": g["status"], "url": url}
        if g["status"] != 402:
            body = g.get("json", g.get("text", ""))
            extra["challenge"]["body"] = body
            extra["paid_already"] = g["status"] == 200
            return _json({"tool": "pay_x402", "url": url, "status": g["status"],
                          "note": ("not a 402 — the server answered %d. If 200 the resource is already "
                                   "served (nothing to pay); any other status is the server's, not a "
                                   "payment gate." % g["status"]),
                          "body": body, "spec": spec.SPEC_URL})
        ch = g.get("json") or {}
        if not ch:
            hdr = g["headers"].get("www-authenticate", "")
            warn.append(f"402 body is not JSON — header seam: {hdr or '(none)'}; parse the body in "
                        f"`challenge` and pass to/token/amount explicitly")
            extra["challenge"]["body"] = g.get("text", "")
        # challenge fields fill the args the caller did not give (explicit args still win)
        if ch.get("to") and not to:
            to = ch["to"]
        elif ch.get("to") and ch["to"].lower() != _addr(to).lower():
            warn.append(f"you passed to={to} but the challenge advertises {ch['to']} — verify() "
                        f"compares the triple, so a mismatch is a permanent false")
        if ch.get("token") and token == spec.USDC and ch["token"].lower() != spec.USDC.lower():
            token = ch["token"]   # default was untouched; the challenge is more specific
        elif ch.get("token") and token.lower() != ch["token"].lower():
            warn.append(f"you passed token={token} but the challenge advertises {ch['token']}")
        if ch.get("amount") and not amount:
            amount = int(ch["amount"])
        if ch.get("facilitator") and ch["facilitator"].lower() != fac.lower():
            warn.append(f"challenge names facilitator {ch['facilitator']}, not the live {fac} — "
                        f"the markPaid/verify legs here target {fac}; a different gate means a "
                        f"different verify() and this pair will not clear it")
        extra["payment_id_from"] = "the rail's Paid event on the pay leg (topics[1])"

    if not to:
        return _json({"tool": "pay_x402", "error": "need `to` (or a `url` whose 402 names one)",
                      **({"warnings": warn} if warn else {}), **extra, "spec": spec.SPEC_URL})

    # ---- the settle calls ----------------------------------------------------------------------
    amt = int(amount)
    minamt = amt if min_amount < 0 else int(min_amount)
    warn += _spend_gate(amt, token, max_amount)
    mentor = _addr(writer) if writer else ""
    calls: list[dict] = []

    rail = ch.get("rail", "")
    if rail:
        rc = chain.get_code(rail)
        if rc.get("ok") and rc.get("result") in (None, "0x"):
            warn.append(f"challenge rail {rail} has NO CODE — the pay leg is built from the "
                        f"server's claim; nothing will execute there")
        memo = _pad32(ch.get("memo", ""))
        calls.append(_one("pay_x402", spec.PAY_RAIL_SIG,
                          [_addr(to), _addr(token), amt, memo, _addr(payer)], rail, dry_run,
                          frm=_addr(payer) if payer else None))
        if token == "0x" + "00" * 20:
            calls[-1]["value"] = amt   # native: pay() is payable and the amount rides as value

    if payment_id:
        pid = _bytes32(payment_id)
    else:
        pid = ""   # only known after the pay leg lands
    if pid:
        if int(to, 16) == 0:
            warn.append("`to` is the zero address — markPaid reverts ZeroAddress")
        if minamt > amt:
            warn.append(f"min_amount {minamt} > amount {amt} — verify() can never pass")
        if mentor:
            kp = chain.eth_call(fac, chain.build_call("isWriter(address)", [mentor]))
            if kp["ok"] and kp["result"] not in (None, "0x") and not chain.decode_uint(kp["result"]):
                warn.append(f"{mentor} is NOT an isWriter key — markPaid will revert NotWriter()")
        else:
            warn.append("no `writer` given: the sim runs as the default sender, which is not a writer, "
                        "so the markPaid leg will revert NotWriter() as a SENDER artifact, not a "
                        "calldata fault. Pass the writer EOA you will sign with.")
        if dry_run:
            cur = chain.eth_call(fac, chain.build_call("settlement(bytes32)", [pid]))
            if cur["ok"]:
                have = chain.decode_uint_at(cur["result"], 2)
                if have:
                    got_to = "0x" + cur["result"][2:][24:64]
                    same = got_to.lower() == _addr(to).lower() and have == amt
                    warn.append(f"paymentId is ALREADY marked ({have} to {got_to}) — markPaid is a "
                                f"no-op if identical, ConflictingMark() if not"
                                + ("" if same else "  ** THIS ONE DIFFERS — it will revert **"))
        calls.append(_one("pay_x402", spec.CALLS["pay_x402"]["sigs"][0],
                          [pid, _addr(to), _addr(token), amt], fac, dry_run, frm=mentor or None))
        calls.append(_one("pay_x402", spec.CALLS["pay_x402"]["sigs"][1],
                          [pid, _addr(to), _addr(token), minamt], fac, dry_run))
    elif not rail:
        return _json({"tool": "pay_x402", "error": "nothing to build: no `rail` in the challenge and no "
                      "`payment_id`", "spec": spec.SPEC_URL})

    if url:
        extra["retry"] = {"header": spec.X402_HEADER, "value": "<paymentId from the pay leg's Paid event>",
                          "note": "send the SAME request again with this header; the server re-runs "
                                  "verify() and serves on true"}
    head = ("leg0 is the rail pay (settles; its Paid event's first topic IS the paymentId) — "
            if rail else "")
    return _result("pay_x402", calls,
                   head + "next leg markPaid records the settlement and MUST be sent by a writer key "
                   "(isWriter); the last leg is the server's verify() VIEW, true iff that id settled "
                   ">= min_amount of that token to that exact recipient."
                   + ("" if pid else " paymentId is unknown until the pay leg has landed — re-run with "
                      "payment_id=… to get the markPaid/verify pair."),
                   warn=warn or None, extra=extra,
                   tip="read_capabilities(payer, token, spender=x402) says whether the writer bit and "
                       "the balance are there before you sign")


@server.tool(description="READ: fetch an x402-protected URL and return its 402 challenge (rail, to, token, amount, memo, facilitator) WITHOUT paying — the discovery step before pay_x402(url=…). Reports the status honestly: a non-402 is not an error, it is an answer.")
def read_402_challenge(url: str) -> str:
    g = chain.http_get(url)
    if not g["ok"]:
        return _json({"tool": "read_402_challenge", "url": url,
                      "error": f"fetch failed: {g['error']}", "spec": spec.SPEC_URL})
    body = g.get("json")
    out = {"tool": "read_402_challenge", "url": url, "status": g["status"],
           "gated": g["status"] == 402, "spec": spec.SPEC_URL}
    if body is not None:
        out["challenge"] = body
    else:
        out["body"] = g.get("text", "")
        out["wwwAuthenticate"] = g["headers"].get("www-authenticate")
    if g["status"] == 300 + 2 and isinstance(body, dict):
        missing = [k for k in ("rail", "to", "token", "amount") if not body.get(k)]
        out["note"] = ("challenge parsed" if not missing else
                       f"challenge is missing {missing} — pay_x402 will need those explicitly")
        if body.get("facilitator") and body["facilitator"].lower() != spec.ADDR["x402"].lower():
            out["facilitatorNote"] = (f"challenge names {body['facilitator']}, not the live "
                                      f"{spec.ADDR['x402']}")
    return _json(out)


@server.tool(description="READ: the x402 facilitator's record for a paymentId — settled? to/token/amount/at, plus the verify() answer for a given triple. Mirrors what a 402 server decides on.")
def read_x402_status(payment_id: str, to: str = "", token: str = spec.USDC,
                     min_amount: int = 0) -> str:
    pid = _bytes32(payment_id)
    fac = spec.ADDR["x402"]
    out = {"tool": "read_x402_status", "paymentId": pid, "chain": {"id": spec.CHAIN_ID},
           "facilitator": fac, "spec": spec.SPEC_URL}
    r = chain.eth_call(fac, chain.build_call("settlement(bytes32)", [pid]))
    if not r["ok"]:
        out["error"] = r.get("error")
        return _json(out)
    res = r["result"]
    got_to, got_tok = "0x" + res[2:][24:64], "0x" + res[2:][64:][24:64]
    settled = int(res[2:][0:64], 16) != 0 or got_to != "0x" + "00" * 20
    out.update({"settled": settled, "to": got_to, "token": got_tok,
                "amount": chain.decode_uint_at(res, 2), "at": chain.decode_uint_at(res, 3),
                "block": r.get("block"), "quorum": r.get("quorum"), "agree": r.get("agree")})
    if to:
        v = chain.eth_call(fac, chain.build_call("verify(bytes32,address,address,uint256)",
                                                 [pid, _addr(to), _addr(token), int(min_amount)]))
        out["verify"] = (bool(int(v["result"], 16)) if v["ok"] else None)
        if not v["ok"]:
            out["verify_error"] = v.get("error")
    return _json(out)


@server.tool(description="READ: everything a money verb needs to know before it is worth signing — balance, allowance to the spender, whether `paused()` is set, and whether the key is an allow-listed keeper/writer. One pass/fail line per leg. Base mainnet only.")
def read_capabilities(payer: str, token: str = spec.USDC, spender: str = "",
                      product: str = "") -> str:
    """MCP-10: a capability check. The tools emitted calldata with no way to ask "will this work?",
    so a caller discovered a zero balance, a missing allowance, or a paused factory by paying gas
    into a revert. Every check here is a read that maps 1:1 onto a leg the money verbs emit.

    `spender` defaults to the product's contract (pass `product`), which is the allowance target the
    approve legs use. Products with no gate (pay links, x402 reads) report what exists and say so."""
    who = _addr(payer)
    tok = _addr(token)
    checks: list[dict] = []
    out = {"tool": "read_capabilities", "payer": who, "chain": {"id": spec.CHAIN_ID},
           "spec": spec.SPEC_URL}

    def _read(label: str, to: str, sig: str, args: list, want, note: str):
        r = chain.eth_call(to, chain.build_call(sig, args))
        if not r["ok"]:
            checks.append({"check": label, "ok": None, "error": r.get("error"), "note": note})
            return
        v = int(r["result"], 16) if r["result"] not in (None, "0x") else None
        checks.append({"check": label, "ok": (want(v) if v is not None else None),
                       "value": v, "note": note,
                       "quorum": r.get("quorum"), "agree": r.get("agree")})

    # native balance is eth_getBalance, not an eth_call — so it does not go through _read
    nb = chain.rpc_quorum("eth_getBalance", [who, "latest"])
    checks.append({"check": "native balance (gas)", "ok": (int(nb["result"], 16) > 0) if nb["ok"] else None,
                   "value": int(nb["result"], 16) if nb["ok"] else None,
                   "error": None if nb["ok"] else nb.get("error"),
                   "note": "needs gas for any leg", "quorum": nb.get("quorum")})
    prod = product.lower()
    # x402's money verb is markPaid — a writer RECORDS a settlement the rail already made, so it needs
    # GAS and the writer bit, but pulls no token and needs no allowance. Judging it on balance would
    # report a correct setup as blocked. Everything else pulls, so both checks block there.
    pulls = prod != "x402"
    tb = chain.eth_call(tok, chain.build_call("balanceOf(address)", [who]))
    if tb["ok"]:
        bal = chain.decode_uint(tb["result"])
        checks.append({"check": f"token balance {tok}", "ok": bal > 0 if pulls else True, "value": bal,
                       "blocking": pulls,
                       "note": "the amount is pulled from here" if pulls
                               else "informational: markPaid moves no token",
                       "quorum": tb.get("quorum")})
    else:
        checks.append({"check": f"token balance {tok}", "ok": None, "error": tb.get("error")})
    sp = _addr(spender) if spender else (spec.ADDR.get(prod) if prod else "")
    if sp:
        al = chain.eth_call(tok, chain.build_call("allowance(address,address)", [who, sp]))
        if al["ok"]:
            checks.append({"check": f"allowance -> {sp}", "ok": chain.decode_uint(al["result"]) > 0 if pulls else True,
                           "value": chain.decode_uint(al["result"]), "blocking": pulls,
                           "note": "the approve leg must land before a pull" if pulls
                                   else "informational: markPaid pulls nothing",
                           "quorum": al.get("quorum")})
        else:
            checks.append({"check": f"allowance -> {sp}", "ok": None, "error": al.get("error")})
    # paused(): only products that have it. A codeless spender answers 0x -> report that, don't guess.
    gate = sp or spec.ADDR.get(product.lower(), "")
    if gate:
        code = chain.get_code(gate)
        out["spender_code_len"] = len(code["result"] or "") // 2 - 1 if code["ok"] else None
        if code["ok"] and (not code["result"] or code["result"] == "0x"):
            checks.append({"check": f"code at {gate}", "ok": False, "note": "no contract — wrong chain?"})
        else:
            pz = chain.eth_call(gate, chain.build_call("paused()", []))
            if pz["ok"]:
                checks.append({"check": f"paused() on {gate}", "ok": chain.decode_uint(pz["result"]) == 0,
                               "value": chain.decode_uint(pz["result"]), "note": "true = factory halted",
                               "quorum": pz.get("quorum")})
            for sig, label, blocks in (("isKeeper(address)", "isKeeper", False),
                                       ("isWriter(address)", "isWriter", product.lower() == "x402")):
                kp = chain.eth_call(gate, chain.build_call(sig, [who]))
                if kp["ok"] and kp["result"] not in (None, "0x"):
                    checks.append({"check": f"{label}({who})", "ok": bool(chain.decode_uint(kp["result"])),
                                   "blocking": blocks,
                                   "note": "allowlist needed on the keeper/writer paths"
                                           + ("" if blocks else " (optional here)"),
                                   "quorum": kp.get("quorum")})
    out["checks"] = checks
    # A failed OPTIONAL check is not a block: isKeeper is only the hedge path (a published mandate
    # fires without it), and isWriter is only required where the verb is writer-gated (x402 markPaid).
    out["verdict"] = ("ready" if all(c["ok"] is not False for c in checks if c.get("blocking", True))
                      else "BLOCKED: " + ", ".join(c["check"] for c in checks
                                                    if c["ok"] is False and c.get("blocking", True)))
    out["note"] = ("quorum=false means one endpoint answered and no majority agreed — re-read before "
                   "trusting a lucky value")
    return _json(out)


@server.tool(description="Swap (p3 router). Hops are handed in; the router takes a 5 bps fee on INPUT to treasury. amount_out_min is your slippage guard.")
def swap(amount_in: int, amount_out_min: int, hops, recipient: str,
         deadline: int = 0, token_in: str = "", dry_run: bool = True,
         max_amount: int = -1) -> str:
    sig = spec.CALLS["swap"]["sigs"][0]
    to = spec.ADDR["p3-router"]
    hs = _hops_obj(hops)
    params = [int(amount_in), int(amount_out_min), hs, _addr(recipient), int(deadline)]
    c = _one("swap", sig, [params], to, dry_run)
    # token_in is optional; the first hop's tokenIn is the token actually being spent, so fall back to
    # it rather than leaving the spend guard blind to which token's decimals it is judging.
    tok = token_in or (hs[0][1] if hs else "")
    warn = _fee_gate("p3-router") + _spend_gate(amount_in, tok, max_amount)
    if int(amount_out_min) <= 0:
        warn.append("amount_out_min is 0 — no slippage guard at all; quote_swap suggests one")
    return _result("swap", [c],
                   "hop = [venue,tokenIn,tokenOut,feeTier,stable,venueRouter,factory]; fee is taken on INPUT "
                   "(read_fee(p3-router) for the live bps). Approve the router for amount_in.",
                   warn=warn or None)


@server.tool(description="Sweep dust to USDC (f1c). One tx: pull balances via Permit2, one-hop each token to USDC, deliver to you. Needs Permit2 approvals first.")
def sweep_dust(tokens, hops, min_out, dry_run: bool = True, max_amount: int = -1) -> str:
    sig = spec.CALLS["sweep_dust"]["sigs"][0]
    to = spec.ADDR["f1c-duster"]
    tk = json.loads(tokens) if isinstance(tokens, str) else tokens
    mo = json.loads(min_out) if isinstance(min_out, str) else min_out
    c = _one("sweep_dust", sig, [list(tk), _hops_obj(hops), [int(x) for x in mo]], to, dry_run)
    warn = []
    if len(mo) != len(tk):
        warn.append(f"{len(mo)} min_out values for {len(tk)} tokens — sweep() reverts on a length "
                    f"mismatch (as does a hops mismatch)")
    zero = [i for i, x in enumerate(mo) if int(x) == 0]
    if zero:
        warn.append(f"min_out is 0 at index {zero} — no slippage guard for those tokens")
    # the per-token spend is the dust balance, which the caller does not pass; the ceiling can only be
    # applied to a single-token sweep, where that token's total is unambiguous.
    if max_amount >= 0 and len(tk) == 1:
        warn += _spend_gate(int(mo[0]) if mo else 0, tk[0], max_amount)
    return _result("sweep_dust", [c],
                   "hop = [venue,tokenIn,tokenOut,feeTier,venueRouter]; zero fee by design. Approve Permit2 first.",
                   warn=warn or None)


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
    # MCP-5: the fee is STATE (feeBps is owner-settable, 5 -> 25 -> 500 observed), so a quote that
    # reports only the absolute fee can be read as "5 bps forever". Read BOTH the live bps AND the
    # contract's own previewFee(url-amended arithmetic) and report them together; if they disagree the
    # bps read is stale/wrong and the preview wins (it is what the swap actually charges).
    bps_r = chain.eth_call(router, chain.build_call("feeBps()", []))
    live_bps = chain.decode_uint(bps_r["result"]) if bps_r["ok"] else None
    fee_r = chain.eth_call(router, chain.build_call("previewFee(uint256)", [amt]))
    fee = chain.decode_uint_at(fee_r["result"], 0) if fee_r["ok"] else None
    fee_src = "previewFee"
    if fee is None and live_bps is not None:
        fee = amt * live_bps // 10_000   # previewFee unreadable: derive, and say so
        fee_src = "derived from feeBps (previewFee unreadable)"
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
    out = {"tool": "quote_swap", "chain": {"id": spec.CHAIN_ID}, "router": router,
           "amountIn": amt, "feeBps": live_bps, "routerFee": fee, "fee_amount": fee,
           "routerFeeSource": fee_src,
           "routerFeePct": (f"{live_bps/100:.4f}%" if live_bps is not None else None),
           "routerFeeUnit": "token-in base units",
           "hops": steps, "amountOut": cur if steps and "amountOut" in steps[-1] else None,
           "slippageBps": int(slippage_bps), "suggested_amount_out_min": sugg,
           "note": ("feeBps is LIVE state, not a constant — re-quote if time has passed. Fee is taken "
                    "on INPUT to treasury; pass suggested_amount_out_min to `swap`."),
           "spec": spec.SPEC_URL}
    if live_bps is None:
        out["warn"] = "feeBps() unreadable — the take is unknown; treat routerFee as a lower bound"
    if fee is None:
        out["warn"] = "fee unknown (previewFee and feeBps both unreadable) — quote is on the gross amount"
    return _json(out)


@server.tool(description="READ: same UniV3 quote as quote_swap but the f1c duster takes ZERO fee, so minOut == the quoted out minus slippage. hops are `sweep_dust`'s shape ([venue,tokenIn,tokenOut,feeTier]). Pass `payer` and each token's real balance is read and quoted, so suggestedMinOut[] is usable directly; without it each token is quoted per one whole token.")
def quote_sweep(tokens, hops, slippage_bps: int = 50, payer: str = "",
                dry_run: bool = True) -> str:
    tk = json.loads(tokens) if isinstance(tokens, str) else tokens
    hs = json.loads(hops) if isinstance(hops, str) else hops
    duster = spec.ADDR["f1c-duster"]
    # MCP-5: report the fee as STATE, not a claim. The duster has no feeBps getter BY DESIGN — so
    # prove it (selector on a codeless getter returns 0x) rather than asserting "zero" from prose.
    bps_r = chain.eth_call(duster, chain.build_call("feeBps()", []))
    live_bps = chain.decode_uint(bps_r["result"]) if bps_r["ok"] and bps_r["result"] not in (None, "0x") else 0
    who = _addr(payer) if payer else ""
    out, mins = [], []
    for tok, h in zip(tk, hs):
        # sweep hop = [venue, tokenIn, tokenOut, feeTier, amount?] — venue is h[0], NOT the token.
        if len(h) < 4:
            out.append({"hop": h, "error": "hop needs [venue,tokenIn,tokenOut,feeTier]; "
                                           "quote_swap's 3-element [tokenIn,tokenOut,feeTier] is a "
                                           "different shape"})
            mins.append(None)
            continue
        tin, tout, tier = _addr(h[1]), _addr(h[2]), int(h[3])
        row = {"tokenIn": tin, "tokenOut": tout, "feeTier": tier}
        # NB: a 5-field duster hop's h[4] is the venueRouter ADDRESS, not an amount — an amount is
        # only an optional 6th element. (Reading h[4] as int crashed on every real hop.)
        amt = int(h[5]) if len(h) > 5 and str(h[5]).lstrip("-").isdigit() else None
        if amt is None and who:
            br = chain.eth_call(tin, chain.build_call("balanceOf(address)", [who]))
            if br["ok"]:
                amt = chain.decode_uint(br["result"])
                row["balance"] = amt
            else:
                row["balance_error"] = br.get("error")
        if amt is None:
            # 1 base unit is 0 out on a high-decimals token (1 wei WETH -> 0 USDC), which reads as a
            # broken quote. Use the token's OWN 10**decimals as the shape unit instead.
            dec = 18
            try:
                dc = chain.eth_call(tin, chain.build_call("decimals()", []))
                if dc["ok"] and dc["result"] not in (None, "0x"):
                    dec = min(int(dc["result"], 16), 36)
            except Exception:  # noqa: BLE001 — offline callers still get a shaped quote
                pass
            amt = 10 ** dec
            row["quoteBasis"] = f"per 1 whole token (10^{dec}; no payer/amount given)"
        if amt == 0:
            row.update({"amountIn": 0, "amountOut": 0, "suggested_minOut": 0})
            out.append(row)
            mins.append(0)
            continue
        q = _univ3_quote(tin, tout, amt, tier)
        if not q["ok"]:
            row["error"] = q.get("error")
            out.append(row)
            mins.append(None)
            continue
        row["amountIn"] = amt
        row["fee_amount"] = amt * live_bps // 10_000
        row["amountOut"] = q["amountOut"]
        row["suggested_minOut"] = q["amountOut"] - (q["amountOut"] * int(slippage_bps)) // 10_000
        mins.append(row["suggested_minOut"])
        out.append(row)
    return _json({"tool": "quote_sweep", "chain": {"id": spec.CHAIN_ID}, "duster": duster,
                  "feeBps": live_bps, "feeBpsEvidence": (
                      "no feeBps() getter on the duster (0x return) — zero by design"
                      if live_bps == 0 else "feeBps() returned non-zero"),
                  "quotes": out, "suggested_minOut": mins,
                  "slippageBps": int(slippage_bps),
                  "note": "pass suggested_minOut[] to `sweep_dust`; tokenIn==tokenOut has no pool and "
                          "reverts (drop that hop). A null min is an unquotable hop — sweep with 0 "
                          "for it only if you accept any output.",
                  "spec": spec.SPEC_URL})


@server.tool(description="SIGNED-INTENT batch on the FleetExecutor EIP-7702 delegate (the authority signs EIP-712 off-chain; ANY relayer carries it, paying the gas, while the authority's own frame runs the calls). Calls are (target,value,data). If you omit nonce/deadline/sig you get `needs_signature: true` + the digest() to sign — the returned calldata alone is NOT sendable. Call digest() on the AUTHORITY address.")
def sponsored_call(calls, nonce: int = -1, deadline: int = 0, sig: str = "",
                   authority: str = "", dry_run: bool = True) -> str:
    """calls: JSON list of [target, value, data] OR the 3-tuple form. The emitted leg targets the
    AUTHORITY (the delegated EOA), because `execute` is called on the EOA, not the delegate address.

    R3-4: unsigned => the calldata carries a 65-zero placeholder signature and a made-up nonce, so a
    client that forwards it unchanged sends a tx that REVERTS (BadSignature/ECDSA_ZERO or BadNonce)
    and still pays gas. So when `sig` is empty we mark the result `needs_signature: true`, fill nonce
    with the REAL next value (nonceOf(authority)+1) and return the exact `digest` to sign."""
    delegate = spec.ADDR["fleet-executor"]
    sig_str = spec.CALLS["sponsored_call"]["sigs"][0]
    if isinstance(calls, str):
        calls = json.loads(calls or "[]")
    norm = [[_addr(c[0]), int(c[1]), c[2]] for c in calls]
    to = _addr(authority) if authority else delegate

    warn: list[str] = []
    extra: dict = {}
    n = int(nonce) if nonce >= 0 else 0   # 0 is the PRIOR behaviour when unsigned+unreadable
    dl = int(deadline)
    if not sig:
        extra["needs_signature"] = True
        extra["digest_hint"] = ("sign EIP-712 digest(calls,nonce,deadline) ON the authority; "
                               "nonce = nonceOf(authority)+1; then re-call with that sig")
        if authority and dry_run:
            # nonceOf/digest live on the AUTHORITY (verifyingContract == address(this) == the EOA);
            # reading them on the delegate address would bind the WRONG verifyingContract.
            rn = chain.eth_call(to, chain.build_call("nonceOf(address)", [to]))
            if rn["ok"]:
                n = chain.decode_uint(rn["result"]) + 1
                dl = dl or (int(time.time()) + 300)
                rd = chain.eth_call(to, chain.build_call(
                    "digest((address,uint256,bytes)[],uint256,uint256)", [norm, n, dl]))
                if rd["ok"]:
                    extra["digest"] = rd["result"]
                    extra["nonce"] = n
                    extra["deadline"] = dl
            if "digest" not in extra:
                warn.append("could not read digest() on the authority (RPC fault) — read it yourself")
        elif not authority:
            warn.append("unsigned and no `authority` given: digest()/nonceOf() live on the delegated "
                        "EOA, so re-call with authority=<EOA> to get the real digest and nonce")
        warn.append("UNSIGNED: the emitted calldata is NOT sendable as-is — sign `digest`, put the "
                    "65-byte sig in `sig`, and rebuild. Sending it unchanged reverts and burns gas.")

    args = [norm, n, dl, sig or ("0x" + "00" * 65)]
    c = _one("sponsored_call", sig_str, args, to, dry_run)
    note = (f"execute(calls,nonce,deadline,sig) ON THE AUTHORITY {to}. Sign EIP-712 over "
            f"digest(calls,nonce,deadline) computed on that same authority; nonce = nonceOf(authority)+1; "
            f"deadline = now+300. FleetExecutor {delegate} is a stateless EIP-7702 delegate — it holds no "
            f"funds and needs no approval.")
    return _result("sponsored_call", [c], note, warn=warn or None, extra=extra)


@server.tool(description="Mint the one proof-of-payment receipt NFT (g4b) for a SETTLED escrow, to the payer. Payable: send mintFeeWei.")
def mint_receipt(escrow: str, dry_run: bool = True, value_wei: int = -1) -> str:
    """The mint is PAYABLE, and the old body read mintFeeWei() into a local it never used — so the one
    number the caller has to send was fetched and thrown away. It is now put in the output: the live
    fee, and a `value_wei` to send. An underpaid mint reverts, so a missing value is flagged."""
    sig = spec.CALLS["mint_receipt"]["sigs"][0]
    to = spec.ADDR["g4b-receipts"]
    c = _one("mint_receipt", sig, [_addr(escrow)], to, dry_run)
    fr = chain.eth_call(to, chain.build_call("mintFeeWei()", []))
    fee = chain.decode_uint(fr["result"]) if fr["ok"] else None
    warn = [] if fr["ok"] else [f"mintFeeWei() unreadable ({fr.get('error')}) — read_fee('g4b-receipts')"]
    if fee is not None:
        if value_wei < 0 and fee > 0:
            warn.append(f"send value_wei = {fee} (the live mintFeeWei) — this call is payable and an "
                        f"underpaid mint reverts")
        elif value_wei >= 0 and int(value_wei) < fee:
            warn.append(f"value_wei {int(value_wei)} is under the live mintFeeWei {fee} — mints revert")
    return _result("mint_receipt", [c],
                   f"payable: send value_wei = mintFeeWei = {fee} with the call. "
                   f"Fee is live state (#162) — read_fee('g4b-receipts') before sending.",
                   warn=warn or None, extra={"mintFeeWei": fee, "value_wei": int(value_wei) if value_wei >= 0 else fee})


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
        "tools": list(spec.CALLS) + ["read_fee", "read_x402_status", "server_info"],
        "spec": spec.SPEC_URL, "catalog": spec.CATALOG_URL,
        "custody": "non-custodial: funds move payer -> vault/escrow, never into a server",
    })


# ---- resources -----------------------------------------------------------------------------------
# Tools are for CALLS; these three are the same facts an agent wants without burning a tool call —
# the address set, the live fee table, and "is the chain reachable / is this build current". Read-only
# and text/JSON. `fleet://addresses` deliberately serves the whole map rather than making an agent
# call server_info: an address it can read is one it will use instead of retyping (GOTCHA #73).
@server.resource(
    "fleet://addresses",
    name="addresses",
    title="Fleet contract addresses",
    description="Every product id -> live Base callee, plus the treasury and the address-book hash. "
                "These are the values the tools emit; copy from here, never from prose.",
    mime_type="application/json",
)
def res_addresses() -> str:
    return _json({
        "chain": {"name": spec.CHAIN_NAME, "id": spec.CHAIN_ID},
        "addresses": spec.ADDR,
        "treasury": spec.TREASURY,
        "book_sha256": spec._ADDR_SHA256,
        "spec": spec.SPEC_URL,
        "catalog": spec.CATALOG_URL,
    })


@server.resource(
    "fleet://fees",
    name="fees",
    title="Live fee table",
    description="feeBps/mintFeeWei read LIVE per contract. The fee is STATE (owner-settable), not a "
                "constant — re-read rather than remembering a number.",
    mime_type="application/json",
)
def res_fees() -> str:
    return read_fee()


@server.resource(
    "fleet://status",
    name="status",
    title="Server + chain reachability",
    description="Version, chain head, and whether the quorum read path currently reaches enough "
                "endpoints. A degraded status means tool answers may be single-endpoint.",
    mime_type="application/json",
)
def res_status() -> str:
    h = chain.rpc_quorum("eth_blockNumber", [])
    return _json({
        "name": "dex-fleet", "version": "0.2.0",
        "chain": {"name": spec.CHAIN_NAME, "id": spec.CHAIN_ID},
        "head": int(h["result"], 16) if h.get("ok") else None,
        "rpc_ok": bool(h.get("ok")),
        "rpc_error": None if h.get("ok") else h.get("error"),
        "quorum": h.get("quorum"), "agree": h.get("agree"), "dissent": h.get("dissent") or [],
        "degraded": not h.get("quorum", False),
        "book_sha256": spec._ADDR_SHA256,
        "spec": spec.SPEC_URL,
    })


def main() -> None:
    """Console-script entry (`dex-fleet-mcp` / `python3 server.py`). stdio transport."""
    server.run()


if __name__ == "__main__":
    main()  # stdio by default
