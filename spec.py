#!/usr/bin/env python3
"""spec.py — the ONE place the MCP surface is pinned to the live products.

DISCIPLINE (why this file exists):
  * Addresses are COPIED from `products/dex-site/PRODUCTS.json` (the repo's one edit point), never
    retyped — GOTCHA #73. When that file is reachable it is read live; the pinned fallback below is
    only for a machine without the repo checkout, and `selftest.py` diffs the two.
  * Selector strings are the EXACT `call:` signatures published in `site/llms.txt`; `chain.selector`
    derives the 4-byte value via keccak, so a typo in the sig cannot hide (GOTCHA #73/#131).
  * The MCP tool set must not drift from the published spec — GOTCHA #131 family. `selftest.py`
    asserts every sig here appears verbatim in the published llms.txt and re-derives every selector.
"""
from __future__ import annotations

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
TREASURY = "0xe218E382F28A094f9f64E903ee3cb1750A7f204B"
EXPLORER = "https://basescan.org"

# --- addresses: read live from PRODUCTS.json when present, else the pinned copy -------------------
_PINNED = {
    "p2-forwarder": "0xe9515881fe6976eD9CB55328B8308F6eF7c311a8",
    "g2b-escrow": "0x80793a7d35f735bc76BeAf22B1f413926818f410",
    "g3a-sponsorship": "0x83303e59d4F9798C3B49f9D4C6E522FfeC05f2A5",
    "g4b-receipts": "0x6d140b934a06410a8C36eEe926c967467ab6d46f",
    "p3-router": "0xEB28D5cA0783D01dd2E4bF86AD7024ca156aB047",
    "f1c-duster": "0x5F6f5dee0c371ed13D9151B9C64d9fBf30245800",
    "g2a-streams": "0x2bB5b763a8A85e446909674177e65cb6F1052b4F",
    "g2a-subscriptions": "0x2bB5b763a8A85e446909674177e65cb6F1052b4F",
    "f1a-payment-links": "0x9651cD591cFe33E1b684e5d8541940e78724c749",
}
# g2b Escrow instances are per-deal; release/refund are called on the escrow, not the factory.
# g2a StreamVault instances are per-stream; withdraw() is called on the vault.


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


def _load_products() -> dict:
    """Live-copy ADDRESS-BEARING products; fall back to the pin only if the repo file is absent.

    PRODUCTS.json also lists source-only surfaces (sdk, mcp-server, x402, …) whose `contract` is
    null — they carry no callee, so they must NOT enter ADDR (else downstream `.lower()` on None).
    """
    try:
        d = json.load(open(_PRODUCTS_JSON))
        return {p["id"]: p["contract"] for p in d["products"] if p.get("contract")}
    except Exception:
        return dict(_PINNED)


ADDR = _load_products()

# --- the call table: ONE primary money verb per product, sig strings VERBATIM from llms.txt --------
# `sigs` are what the tool emits (a multi-call tool lists its prerequisite first, e.g. approve).
# `sel` still comes from chain.selector(sig) — never hand-typed (GOTCHA #17/#73).
CALLS = {
    "create_pay_link": {
        "product": "f1a-payment-links",
        "to": "f1a-payment-links",
        "sigs": ["request(address,address,uint256,bytes32)"],
        "verb": "request(destination, token, amount, memo) -> (id, depositAddr); share the link, payer sends to depositAddr",
    },
    "pay": {
        "product": "p2-forwarder",
        "to": "p2-forwarder",
        "sigs": ["register(address)", "forward(address,address)"],
        "verb": "register(destination) mints your deposit address; a payer transfers the token to it and the forwarder sweeps to destination",
    },
    "escrow_create": {
        "product": "g2b-escrow",
        "to": "g2b-escrow",
        "sigs": ["create(address,address,uint256,bytes32,uint64)"],
        "verb": "create(counterparty, token, amount, hashlock, timeout) -> escrow address",
    },
    "escrow_release": {
        "product": "g2b-escrow",
        "to": "g2b-escrow",  # NB: release/refund are called on the ESCROW, not the factory
        "sigs": ["release(bytes32)", "refund()", "arbiterRelease()", "arbiterRefund()"],
        "verb": "on the escrow contract: release(preimage) / refund() / arbiterRelease() / arbiterRefund()",
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
        "sigs": ["approve(address,uint256)", "createStreamFor(address,address,address,uint256,uint64,uint64)"],
        "verb": "approve(factory, ticket*periods) is the whole mandate; a keeper calls createStreamFor once per period",
    },
    "swap": {
        "product": "p3-router",
        "to": "p3-router",
        "sigs": ["swapExactTokensForTokens((uint256,uint256,(uint8,address,address,uint24,bool,address,address)[],address,uint256))"],
        "verb": "swapExactTokensForTokens(ExactInputParams) — hops are handed in; quotes are chosen off-chain",
    },
    "sweep_dust": {
        "product": "f1c-duster",
        "to": "f1c-duster",
        "sigs": ["sweep(address[],(uint8,address,address,uint24,address)[],uint256[])"],
        "verb": "sweep(tokens, hops, minOut) funnels scattered dust to USDC in one tx (needs Permit2 approvals)",
    },
    "sponsored_call": {
        "product": "g3a-sponsorship",
        "to": "g3a-sponsorship",
        "sigs": ["sponsoredCall(address,bytes)"],
        "verb": "sponsoredCall(target, data) — the relay pays gas; the actor EOA does not (EIP-7702 delegate)",
    },
    "mint_receipt": {
        "product": "g4b-receipts",
        "to": "g4b-receipts",
        "sigs": ["mintForEscrow(address)"],
        "verb": "mintForEscrow(escrow) — mint the one proof-of-payment NFT to the payer of a SETTLED escrow",
    },
}

# --- fee getters: the LIVE read per product, with the #144 hazard named explicitly ------------------
# p3 ships BOTH `feeBps` (the take, immutable=5) AND `MAX_FEE_BPS` (=10000, a DENOMINATOR). Never
# cross-read: MAX_FEE_BPS is a CEILING in some products and a DENOMINATOR here (GOTCHA #144).
FEE_GETTERS = {
    "p2-forwarder": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the Registry; per forwarded payment"},
    "g2b-escrow": {"sig": "feeBps()(uint256)", "unit": "bps", "note": "on the factory; release only, 0 on refund"},
    "g3a-sponsorship": {"sig": None, "unit": "per-tx", "note": "no bps getter — fee is per sponsored tx (>=1.5x gas floor)"},
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
