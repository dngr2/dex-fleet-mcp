#!/usr/bin/env python3
"""spec.py — the ONE place the MCP surface is pinned to the live products.

DISCIPLINE (why this file exists):
  * Addresses come from the SDK's address book (`products/sdk/addresses.json`), never retyped —
    GOTCHA #73. A byte copy is vendored at `fleet_addr/addresses.json` and SHA-256-PINNED; a mismatch
    fails import. PRODUCTS.json is cross-checked against it, and the `_PINNED` literal below is
    checked against it too, so all three routes must agree before a tool can emit a callee.
  * Selector strings are the EXACT `call:` signatures published in `site/llms.txt`; `chain.selector`
    derives the 4-byte value via keccak, so a typo in the sig cannot hide (GOTCHA #73/#131).
  * The MCP tool set must not drift from the published spec — GOTCHA #131 family. `selftest.py`
    asserts every sig here appears verbatim in the published llms.txt and re-derives every selector.
"""
from __future__ import annotations

import hashlib
import json
import os

from chain import selector

# Published spec (the agent-facing map). The tool surface mirrors it 1:1.
SPEC_URL = "https://dngr2.github.io/dex-products/llms.txt"
CATALOG_URL = "https://dngr2.github.io/dex-products/PRODUCTS.json"

BASE = "https://dngr2.github.io/dex-products"
CHAIN_ID = 8453
CHAIN_NAME = "Base"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # Base USDC, 6 dp (copied from llms.txt)
USDC_DECIMALS = 6
TREASURY = "0x5c0fc0917260A0656D253f1625053e3E6Dd2Ef3c"
EXPLORER = "https://basescan.org"

# --- addresses: the SDK book (hash-pinned) is the source; _PINNED is a CHECKED no-book fallback ----
_PINNED = {
    "p2-forwarder": "0x417c41d406c61E09958032Cd77338fc1F1ac7D45",
    "g2b-escrow": "0x4B05fA6aD0Ba0D0120Dce19Ce34dde6d1316C237",
    "g4b-receipts": "0xAE5951d25FEDD06aB7e124e91Dac3AC20f5e7cAF",
    "p3-router": "0x036645cA607Dc8075Ae9B12A3474C00A82c306e6",
    "f1c-duster": "0x8c38c2bbECa7575c24ACEf1d907Aa1F4f43CbFB9",
    "g2a-streams": "0x3882A049ee99B96Ea68DF317713ed76008b9A075",
    "g2a-subscriptions": "0x3882A049ee99B96Ea68DF317713ed76008b9A075",
    "f1a-payment-links": "0xeD395024Bba719564bec617b6b42CF6fDC8a252c",
    # BUILD-WAVE-1 surfaces, now LIVE on Base (was contract:null). Added so selftest #3 keeps diffing
    # the pin against PRODUCTS.json; each is a nonce-0 CREATE from its own key, cold-verified.
    "x402": "0x5849eF6f21fDC21d5194c24ED6c824965A613739",
    "settlement": "0xdDA0728Ff635B555D2Af471E2821055bE08F9127",
    "fleet-paymaster": "0x70A615dDc4cd013Cf4D569Ae3394bF4465229B95",
    "g4c-toll-registry": "0xc8319D6fbc0A8f1685Df9c567557141A289b7A1b",
    "fleet-executor": "0x410396662089a26C801c54818CCd59640eFCaf77",
}
# g2b Escrow instances are per-deal; release/refund are called on the escrow, not the factory.
# g2a StreamVault instances are per-stream; withdraw() is called on the vault.

# V1 factories — the OLD g2a StreamFactory is PAUSED (dex-critic fired setPaused(true) 2026-11-10), so
# `subscribe` now targets the LIVE factory and returns a `revoke` leg against V1' `approve(v1, 0)` to
# clear any allowance a client granted before the migration. Copied from GATE6 §1 (#73).
#
# The revoke target is the FROZEN v1 factory `0x2bB5b763…2b4F` (9,385 B runtime, keccak `0x6dfe06ec…`),
# NOT the current factory. This was wrong before 2026-11-12: V1_APPROVE_REVOKE pointed at the same
# 0x3882A049 address as `ADDR["g2a-subscriptions"]`, so the selftest's "v2 un-paused AND v1 paused"
# pair read `paused()` twice on ONE contract and could never be satisfied. An allowance is granted to
# the factory contract, so the revoke MUST name the exact v1 contract the client approved.
#
# v2.1 REPOINT (2026-11-10): the live g2a factory is now v2.1 `0x3882A049…a075` (deploy tx
# 0x5fa89c18…a97c2, blk 55483090, predicted at deployer nonce 13 — this is what the earlier
# `0x8f26d7a5…fa19` note mis-recorded as the landed address; the receipt's contractAddress is
# 0x3882A049…a075), replacing v2 `0x14bBd99B…58a0`. v2.1 adds receive()/fallback()/rescue(onlyOwner) +
# createStreamSelfFunded — the DEAD-DROP fix (a bare token/native send to the factory used to be orphan
# dust; v1 stranded 5.01 USDC that way). Same CREATE2 mint+fund shape otherwise. Cold-verified
# 2026-11-12: runtime keccak a4798afc…3a6761 == the pin, paused()==false, rescue selector 0x4fdf5d1d.
# Evidence: products/g2a-streams/V21-DEAD-DROP-FIX-EVIDENCE-2026-11-10.md.
V1_APPROVE_REVOKE = [
    {"to": "0x2bB5b763a8A85e446909674177e65cb6F1052b4F", "sig": "approve(address,uint256)"},
]

# v2.1 factory-only verbs — NOT a published `call:` on the factory's normal path, so kept here for the
# `rescue` tool/spec text. Selector re-derived by keccak at use site (never typed).
RESCUE_SIG = "rescue(address,address)"
SELFFUND_SIG = "createStreamSelfFunded(address,address,address,uint256,uint64,uint64)"

# V1 RequestRegistry (f1a) — still the emitter of every request minted BEFORE the v2 cutover, so
# resolve_pay_link must fall back to it or the on-chain links from that window resolve to nothing.
# Copied from exec3/GATE6-MIGRATION-PLAN.md §1 row B (#73). The link is always built with the REGISTRY
# THAT EMITTED, since the /p2-forwarder page re-reads the RequestCreated log from that exact emitter.
V1_F1A = "0x036645cA607Dc8075Ae9B12A3474C00A82c306e6"


# --- addresses: ONE machine-readable source, hash-pinned, checked at import ------------------------
# The pinned dict below used to be the LOAD-BEARING copy in any checkout without PRODUCTS.json, and it
# has drifted twice in two rounds — a hand-copied address that nothing diffs is just a literal with a
# comment attached (GOTCHA #73's whole family). So:
#
#   * The SOURCE OF TRUTH is the SDK's address book (`products/sdk/addresses.json`), the fleet's one
#     machine-readable multi-chain map. A byte copy of it is vendored at `fleet_addr/addresses.json`;
#     it is read through `importlib.resources`, so resolution does not depend on cwd or a relative path.
#   * The copy is HASH-PINNED (`_ADDR_SHA256`). A mismatch is a START-UP FAILURE, not a warning: an
#     address book that moved under us and was not re-vendored means every callee in this file is of
#     unknown age. `MCP_ADDR_HASH=skip` downgrades it to a warning when you are mid-repoint.
#   * PRODUCTS.json, when reachable, must AGREE with the book — a second independent tooth, because the
#     two drift by different routes (a redeploy bumps one, a hand edit bumps the other).
#   * `_PINNED` survives only as the no-book fallback, and it is now *checked* against the book on
#     every load — a stale pin can no longer sit in the file looking authoritative.
#
# Repoint procedure: `python3 tools/sync-addresses.py` (copies the SDK book + prints the new hash).
_ADDR_SHA256 = "1f2fe643fc38c2644512805fdfd8daa6583a662a45fd5f10a4391d60dd924027"
_ADDR_REL = ("fleet_addr", "addresses.json")


class SpecDrift(RuntimeError):
    """The address book does not match its pin, or PRODUCTS.json disagrees with it. Fatal at import."""


def _book_bytes() -> bytes:
    """The vendored address book, via importlib.resources (cwd-independent, works in both layouts)."""
    try:
        from importlib.resources import files
        return (files("fleet_addr") / _ADDR_REL[1]).read_bytes()
    except Exception:  # noqa: BLE001 — frozen zip / odd loader / running from a bare file
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, *_ADDR_REL), "rb") as fh:
            return fh.read()


# SDK key -> product id. ONLY the money-facing surfaces; `native`/`feeRecipient`/the 7702 pair are
# handled separately below (they are not products).
_ADDR_MAP = {
    "p2-forwarder": "paymentRail",
    "f1a-payment-links": "requestRegistry",
    "p3-router": "swapRouter",
    "g2a-streams": "streamRail",
    "g2a-subscriptions": "streamRail",     # the shared factory — same contract, two product entries
    "g2b-escrow": "escrowRail",
    "g4b-receipts": "receiptNft",
    "settlement": "settlementRegistry",
    "fleet-executor": "fleetExecutor",
    "x402": "x402Facilitator",
    "fleet-paymaster": "fleetPaymaster",
    "g4c-toll-registry": "tollRegistry",
    "f1c-duster": "v2.duster",             # duster only exists on the v2 (current) line
}
_ALIAS = {"miniapp": "p2-forwarder"}       # UI over the Registry, no address of its own


def _dig(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def _from_book(book: dict) -> dict:
    addr = {pid: _dig(book, key) for pid, key in _ADDR_MAP.items()}
    for alias, parent in _ALIAS.items():
        addr[alias] = addr[parent]
    return addr


def _locate(*cands: str) -> str | None:
    """First existing path among `cands` (relative to this file's dir), else None.

    WHY: this file ships BOTH inside the monorepo (`products/mcp-server/`, where PRODUCTS.json is at
    `../dex-site/`) AND inside the published standalone repo (`dngr2/dex-fleet-mcp`, where a vendored
    catalog sits at `catalog/`). A single hardcoded `../dex-site` path would silently drop the live
    diff — and let the pinned fallback masquerade as a check. Try monorepo first (unchanged there).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in cands:
        p = os.path.normpath(os.path.join(here, rel))
        if os.path.exists(p):
            return p
    return None


_PRODUCTS_JSON = _locate(os.path.join("..", "dex-site", "PRODUCTS.json"),
                         os.path.join("catalog", "PRODUCTS.json"))
# The SDK book itself, for the monorepo byte-identity check (absent on a standalone clone, where the
# vendored copy IS the book).
_SDK_BOOK = _locate(os.path.join("..", "sdk", "addresses.json"))


def _load_products() -> dict:
    """Book -> addresses, with the hash gate and the PRODUCTS.json cross-check. Raises SpecDrift.

    Falls back to `_PINNED` only if NO book is present at all (a hand-assembled directory), and says
    so on stderr so a green run cannot be mistaken for a checked one.
    """
    try:
        raw = _book_bytes()
    except OSError:
        import sys
        print("[spec] WARNING: no address book — falling back to the literal _PINNED map (unchecked)",
              file=sys.stderr)
        return dict(_PINNED)

    got = hashlib.sha256(raw).hexdigest()
    if got != _ADDR_SHA256:
        msg = (f"address book hash mismatch\n  have {got}\n  want {_ADDR_SHA256}\n"
               f"  fix: python3 tools/sync-addresses.py   (or MCP_ADDR_HASH=skip to run anyway)")
        if os.environ.get("MCP_ADDR_HASH", "") == "skip":
            import sys
            print(f"[spec] WARNING: {msg}", file=sys.stderr)
        else:
            raise SpecDrift(msg)

    book = json.loads(raw)["base"]
    addr = _from_book(book)

    # the pin must still agree — otherwise the fallback path is a time bomb, not a fallback
    stale = {k: (v, addr.get(k)) for k, v in _PINNED.items() if addr.get(k, "").lower() != v.lower()}
    if stale:
        raise SpecDrift(f"_PINNED disagrees with the address book (stale literal): {stale}")
    # and PRODUCTS.json, where present, must agree too (independent route to the same drift)
    if _PRODUCTS_JSON:
        for p in json.load(open(_PRODUCTS_JSON))["products"]:
            pid, want = p["id"], p.get("contract")
            have = addr.get(pid)
            if want and have and want.lower() != have.lower():
                raise SpecDrift(f"PRODUCTS.json `{pid}` = {want} but the address book says {have}")
    return addr


ADDR = _load_products()
# The treasury is not a product but is the same class of hand-copied literal, so it comes from the
# book as well (feeRecipient). `_PINNED`-only mode keeps the literal above.
_TREASURY_BOOK = None
try:
    _TREASURY_BOOK = json.loads(_book_bytes())["base"]["feeRecipient"]
except OSError:
    pass
if _TREASURY_BOOK:
    TREASURY = _TREASURY_BOOK

# --- the call table: ONE primary money verb per product, sig strings VERBATIM from llms.txt --------
# `sigs` are what the tool emits (a multi-call tool lists its prerequisite first, e.g. approve).
# `sel` still comes from chain.selector(sig) — never hand-typed (GOTCHA #17/#73).
CALLS = {
    "create_pay_link": {
        "product": "f1a-payment-links",
        "to": "f1a-payment-links",
        "sigs": ["request(address,address,uint256,bytes32)"],
        "verb": "request(destination, token, amount, memo) -> (id, depositAddr); share the PAYER link, payer sends to depositAddr",
    },
    "resolve_pay_link": {
        "product": "f1a-payment-links",
        "to": "f1a-payment-links",
        "sigs": [],
        "verb": "READ: parse a RequestCreated log from a tx receipt -> (id, depositAddr) -> the shareable payer link",
    },
    "register_deposit_address": {
        "product": "p2-forwarder",
        "to": "p2-forwarder",
        "sigs": ["register(address)"],
        "verb": "register(destination) mints YOUR deposit address (register-ONLY; use `pay` for the full two-step)",
    },
    "pay": {
        "product": "p2-forwarder",
        "to": "p2-forwarder",
        "sigs": ["register(address)", "transfer(address,uint256)"],
        "verb": "TWO-STEP: register(destination) on the Registry, then transfer(token, depositAddr, amount) on the token; the forwarder sweeps to destination",
    },
    "escrow_create": {
        "product": "g2b-escrow",
        "to": "g2b-escrow",
        "sigs": ["create(address,address,uint256,bytes32,uint64)"],
        "verb": "create(counterparty, token, amount, hashlock, timeout) -> escrow address (hashlock is already bytes32; see escrow_new_secret)",
    },
    "escrow_new_secret": {
        "product": "g2b-escrow",
        "to": "g2b-escrow",
        "sigs": [],
        "verb": "OFFLINE helper: returns {preimage: bytes32, hashlock: keccak(preimage)}; pass hashlock to escrow_create, preimage to escrow_release",
    },
    "escrow_release": {
        "product": "g2b-escrow",
        "to": "g2b-escrow",  # NB: release/refund are called on the ESCROW, not the factory
        "sigs": ["release(bytes32)", "refund()", "arbiterRelease()", "arbiterRefund()"],
        "verb": "on the escrow contract: release(preimage) / refund() / arbiterRelease() / arbiterRefund() — preimage is the RAW bytes32, never a re-hash",
    },
    "stream_create": {
        "product": "g2a-streams",
        "to": "g2a-streams",
        "sigs": ["approve(address,uint256)", "createStream(address,address,uint256,uint64,uint64)"],
        "verb": "approve(factory, amount) then createStream(recipient, token, amount, start, end); recipient withdraw()s as it vests",
    },
    "subscribe": {
        "product": "g2a-subscriptions",
        "to": "g2a-subscriptions",
        "sigs": ["approve(address,uint256)", "setMandate(address,address,uint256,uint64,uint32,uint64)",
                 "createStreamFor(address,address,address,uint256,uint64,uint64)"],
        "verb": "bounded path: approve(factory, ticket*periods) is the allowance, setMandate(recipient, token, ticket, period, laps, t0) is the on-chain authorization. A keeper then fires createStreamFor once per period; without a mandate the keeper only works while isKeeper is true (the hedge path). `revoke` also emits disarmMandate + approve(v1,0)",
    },
    "disarm_mandate": {
        "product": "g2a-subscriptions",
        "to": "g2a-subscriptions",
        "sigs": ["disarmMandate(address,address)", "approve(address,uint256)"],
        "verb": "clear a published mandate (disarmMandate(recipient, token)) AND the allowance (approve(factory, 0)); either alone leaves half the authorization live",
    },
    "pay_x402": {
        "product": "x402",
        "to": "x402",
        "sigs": ["markPaid(bytes32,address,address,uint256)", "verify(bytes32,address,address,uint256)"],
        "verb": "the gated-writer half of an HTTP-402 flow: markPaid(paymentId, to, token, amount) after the rail settles, and the server's verify(paymentId, to, token, minAmount) VIEW that gates the resource",
    },
    "read_402_challenge": {
        "product": "x402",
        "to": "",
        "sigs": [],
        "verb": "READ: fetch an x402-protected URL and return its 402 challenge (rail, to, token, amount, memo, facilitator) without paying — the discovery step before pay_x402(url=…)",
    },
    "read_capabilities": {
        "product": "",
        "to": "",
        "sigs": [],
        "verb": "READ: for a payer+token+spender, the balance / allowance / isKeeper / paused state a money verb needs, plus a pass/fail line per leg",
    },
    "swap": {
        "product": "p3-router",
        "to": "p3-router",
        "sigs": ["swapExactTokensForTokens((uint256,uint256,(uint8,address,address,uint24,bool,address,address)[],address,uint256))"],
        "verb": "swapExactTokensForTokens(ExactInputParams) — hops are handed in; quote_swap computes amount_out_min",
    },
    "quote_swap": {
        "product": "p3-router",
        "to": "p3-router",
        "sigs": [],
        "verb": "READ: QuoterV2 amountOut per univ3 hop + router previewFee -> net out; suggests amount_out_min for `swap`",
    },
    "sweep_dust": {
        "product": "f1c-duster",
        "to": "f1c-duster",
        "sigs": ["sweep(address[],(uint8,address,address,uint24,address)[],uint256[])"],
        "verb": "sweep(tokens, hops, minOut) funnels scattered dust to USDC in one tx (needs Permit2 approvals)",
    },
    "quote_sweep": {
        "product": "f1c-duster",
        "to": "f1c-duster",
        "sigs": [],
        "verb": "READ: same quoter as quote_swap but zero router fee (the duster takes no fee); suggests minOut for `sweep_dust`",
    },
    "sponsored_call": {
        "product": "fleet-executor",
        "to": "fleet-executor",
        "sigs": ["execute((address,uint256,bytes)[],uint256,uint256,bytes)"],
        "verb": "SIGNED-INTENT batch on the FleetExecutor EIP-7702 delegate: the authority signs EIP-712 off-chain, any relayer carries execute(calls,nonce,deadline,sig); the actor's frame, the relayer's gas",
    },
    "mint_receipt": {
        "product": "g4b-receipts",
        "to": "g4b-receipts",
        "sigs": ["mintForEscrow(address)"],
        "verb": "mintForEscrow(escrow) — mint the one proof-of-payment NFT to the payer of a SETTLED escrow",
    },
}

# --- READ-ONLY helpers: emitted as views, so not every one is a published `call:` ------------------
# sigs here are CALLED (via eth_call) but are reads/ERC20 primitives a quote/resolve needs; the tool
# surface still re-derives each selector by keccak (selector is never typed). `selftest` asserts every
# CALLS sig is either live-published or one of these (or a g2b escrow-instance verb).
READS = {
    "f1a-payment-links": ["nextId()", "predictDepositFor(address)", "request_(uint256)"],
    "p2-forwarder": ["predict(address,address)"],
    "p3-router": ["previewFee(uint256)"],
    "fleet-executor": ["nonceOf(address)", "digest((address,uint256,bytes)[],uint256,uint256)"],
}

# The real venue quoter (Uniswap V3 QuoterV2) on Base — for quote_swap/quote_sweep. Copied from
# p3-router/keeper/quote.py (never retyped, #73). `transfer` is plain ERC20.
QUOTER = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a"
QUOTER_SIG = "quoteExactInputSingle((address,address,uint256,uint24,uint160))"
TRANSFER_SIG = "transfer(address,uint256)"

# IPaymentRail.pay — the CLIENT leg of a 402 (products/rails/src/IPaymentRail.sol:37, verbatim). No
# implementation is deployed yet, so it is NOT a published `call:` on any product row; a challenge
# names its own `rail` and this sig is emitted only against THAT address. The selector is still
# keccak-derived at the use site (0x68abdc82), never typed. x402 README §"pay_for_402" is the flow.
PAY_RAIL_SIG = "pay(address,address,uint256,bytes32,address)"
# The header the retry carries (x402 README step 4) — named so a client does not have to re-read prose.
X402_HEADER = "X-PAYMENT"

# --- fee getters: the LIVE read per product, with the #144 hazard named explicitly ------------------
# p3 ships BOTH `feeBps` (the take, immutable=5) AND `MAX_FEE_BPS` (=10000, a DENOMINATOR). Never
# cross-read: MAX_FEE_BPS is a CEILING in some products and a DENOMINATOR here (GOTCHA #144).
FEE_GETTERS = {
    "p2-forwarder": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the Registry; per forwarded payment"},
    "g2b-escrow": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the factory; release only, 0 on refund"},
    "g4b-receipts": {"sig": "mintFeeWei()(uint256)", "unit": "wei", "note": "flat mint fee, payable in the {value}"},
    "p3-router": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "immutable take on INPUT; do NOT read MAX_FEE_BPS (that is 10000, a denominator)"},
    "f1c-duster": {"sig": None, "unit": "bps", "note": "ZERO by design — no getter, the sweep takes no fee"},
    "g2a-streams": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the factory; charged on withdraw only"},
    "g2a-subscriptions": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the shared factory; per-period fee"},
    "f1a-payment-links": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "the P2 Registry's fee, paid by the derived forwarder",
                           "contract": "p2-forwarder"},
}


def sig_selectors() -> dict:
    """{tool: [(sig, selector), ...]} — every selector derived, nothing typed."""
    return {tool: [(s, selector(s)) for s in c["sigs"]] for tool, c in CALLS.items()}


if __name__ == "__main__":
    import json as _j
    print(_j.dumps({"addr": ADDR, "selectors": sig_selectors()}, indent=2))
