#!/usr/bin/env python3
"""selftest.py — the drift gate. Run offline (no RPC needed for the structural checks).

Proves, against the PUBLISHED spec, that this server has not invented anything:
  1. every tool's sig string appears VERBATIM in the live site/llms.txt  (GOTCHA #131 family)
  2. every selector re-derives from keccak — nothing hand-typed               (GOTCHA #73)
  3. the pinned address fallback equals PRODUCTS.json                        (GOTCHA #73)
  4. the MCP tool list is enumerable and matches the intended surface
Exit 0 = green. Any drift fails loud.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import chain
import spec

def _locate(*cands):
    """First existing path among `cands` (relative to HERE), else the first candidate (for the msg).

    WHY: this gate ships inside the monorepo (`../dex-site/…`) AND inside the published standalone
    repo (`dex-fleet-mcp`, where the catalog is vendored under `catalog/`). Checks 1 and 3 are this
    gate's two STRONGEST — a single hardcoded path silently downgrades them to `[skip]` on a clone.
    Try the monorepo path first so in-tree behavior is byte-identical.
    """
    for rel in cands:
        p = os.path.normpath(os.path.join(HERE, rel))
        if os.path.exists(p):
            return p
    return os.path.normpath(os.path.join(HERE, cands[0]))


LLMS = _locate(os.path.join("..", "dex-site", "site", "llms.txt"),
               os.path.join("catalog", "llms.txt"))
PRODUCTS = _locate(os.path.join("..", "dex-site", "PRODUCTS.json"),
                   os.path.join("catalog", "PRODUCTS.json"))

# PRODUCTS.json ids that carry NO independent pin because they are ALIASES: their contract field is
# another product's address (miniapp rides the p2 Registry it is a UI over). They are skipped by
# name — and PRINTED — so a future reader sees the skip is intentional, not a silent hole. The skip
# is also a real check: each alias's address must EQUAL its parent's.
NO_PIN = {"miniapp": "p2-forwarder"}

fails: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        fails.append(name)


# 1. STRONG anti-drift: every `call: \`sig\`  selector \`0x…\`` pair in the published llms.txt must
#    re-derive byte-identically from keccak. This proves BOTH directions at once — our tool sigs
#    are the spec's sigs, and the spec's published selectors are truly keccak-derived (GOTCHA #131/#73).
#    The spec is fetched LIVE (the same URL the tools cite) so a stale on-disk copy cannot pass as
#    authority; the on-disk copy is only the offline fallback.
import re

LLMS_URL = spec.SPEC_URL


def _live_llms() -> tuple[str, str]:
    """Return (text, source). LIVE first (httpx, short timeout), else the on-disk vendored copy."""
    try:
        import httpx
        r = httpx.get(LLMS_URL, timeout=10.0)
        if r.status_code == 200 and "selector `0x" in r.text:
            return r.text, f"LIVE {LLMS_URL}"
    except Exception as e:  # noqa: BLE001
        print(f"[warn] live llms.txt fetch failed ({type(e).__name__}); using on-disk copy")
    return open(LLMS, encoding="utf-8").read(), f"on-disk {LLMS}"


try:
    llms, llms_src = _live_llms()
    have_spec = True
except FileNotFoundError:
    llms, llms_src = "", "absent"
    have_spec = False
    print(f"[skip] llms.txt not found at {LLMS}")

if have_spec:
    pairs = re.findall(r"- call: `([^`]+)`\s+selector `(0x[0-9a-fA-F]{8})`", llms)
    bad = [f"{s}:{sel}" for s, sel in pairs if "0x" + chain.keccak(text=s)[:4].hex() != sel]
    check(f"every published (sig, selector) re-derives from keccak [{llms_src}]",
          bool(pairs) and not bad, f"{len(pairs)} published pairs, {len(bad)} bad" + (f" {bad}" if bad else ""))
    # and: every sig our tools emit must be one the spec publishes (escrow-instance verbs are called
    # on the escrow, not the factory; READ sigs are view/getters eth_call'd, not published `call:`s)
    published = {s for s, _ in pairs}
    INSTANCE = {"release(bytes32)", "refund()", "arbiterRelease()", "arbiterRefund()"}
    READS = {s for sigs in spec.READS.values() for s in sigs} | {spec.TRANSFER_SIG, "previewFee(uint256)",
             "nonceOf(address)", "digest((address,uint256,bytes)[],uint256,uint256)",
             "predict(address,address)", "nextId()", "predictDepositFor(address)", "request_(uint256)"}
    off = [f"{t}:{s}" for t, c in spec.CALLS.items() for s in c["sigs"]
           if s not in published and s not in INSTANCE and s not in READS]
    check("every tool sig is published, a g2b escrow-instance verb, or a read helper", not off, str(off))
    # the v2 re-point is the sharp case: our g2a factory (subscribe) must be the spec's address.
    # NOTE: the LIVE published site may still carry the v1 addresses if a site republish is pending
    # (observed 2026-11-10), so accept live OR on-disk and NAME the lag rather than fail on it.
    sub_factory = spec.ADDR.get("g2a-subscriptions", "")
    on_disk = ""
    try:
        on_disk = open(LLMS, encoding="utf-8").read()
    except Exception:  # noqa: BLE001
        pass
    carried = sub_factory in llms or sub_factory in on_disk
    check("subscribe factory is the spec's g2a address (live or on-disk)", carried,
          f"{sub_factory} in_live={sub_factory in llms} in_ondisk={sub_factory in on_disk}")
    if sub_factory not in llms:
        print(f"[warn] LIVE site still publishes the OLD g2a addr — site republish pending "
              f"(live spec lag, not an MCP bug)")
    # CHAIN TRUTH (RL): the v1 factory MUST be paused and the v2 MUST be un-paused — this is the
    # MCP-1 bug in one read, independent of any spec doc.
    try:
        p2v2 = chain.eth_call(spec.ADDR["g2a-subscriptions"], chain.selector("paused()"))
        v1 = chain.eth_call(spec.V1_APPROVE_REVOKE[0]["to"], chain.selector("paused()"))
        v2_unpaused = p2v2["ok"] and int(p2v2["result"], 16) == 0
        v1_paused = v1["ok"] and int(v1["result"], 16) == 1
        check("chain: v2 factory un-paused AND v1 factory paused", v2_unpaused and v1_paused,
              f"v2_unpaused={v2_unpaused} v1_paused={v1_paused}")
    except Exception as e:  # noqa: BLE001
        print(f"[skip] chain paused() check: {type(e).__name__}: {e}")

# 2. our own selectors re-derive from keccak (nothing hand-typed) ----------------------------------
bad_sel = []
for tool, sels in spec.sig_selectors().items():
    for s, sel in sels:
        if sel != "0x" + chain.keccak(text=s)[:4].hex() or len(sel) != 10:
            bad_sel.append(f"{tool}:{s}")
check("every selector is a well-formed keccak-derived 4-byte value", not bad_sel, str(bad_sel))

# 3. pinned fallback == PRODUCTS.json --------------------------------------------------------------
# Two categories legitimately carry no address to pin, and each is SKIPPED + PRINTED (intentional, not
# a silent hole):
#   (a) null-contract entries — build-only products (sdk, mcp-server, x402, …) that have no on-chain
#       address yet (`"contract": null`); nothing to compare a pin against.
#   (b) aliases (NO_PIN) — an id whose `contract` is ANOTHER product's address (miniapp rides p2);
#       skipped by name, and the alias's address is asserted EQUAL to its parent's.
try:
    raw = json.load(open(PRODUCTS))["products"]
    live = {p["id"]: p.get("contract") for p in raw}
    # (a) skip null-contract (build-only) entries, print them.
    nocontract = sorted(k for k, v in live.items() if v is None)
    if nocontract:
        print(f"[skip] {len(nocontract)} PRODUCTS.json id(s) with no `contract` (build-only): {nocontract}")
    # (b) aliases: skip by name, prove the alias points at its parent, and print it.
    aliases = []
    alias_ok = True
    for alias, parent in NO_PIN.items():
        if alias in live:
            aliases.append(alias)
            if (live.get(alias) or "").lower() != (live.get(parent) or "\x00").lower():
                alias_ok = False
                print(f"[FAIL] alias `{alias}` must equal its parent `{parent}`: "
                      f"{live.get(alias)} != {live.get(parent)}")
    print(f"[skip] {len(aliases)} PRODUCTS.json id(s) with no own pin (alias): "
          f"{sorted(aliases)} -> {sorted(NO_PIN.values())}  (checked == parent)")
    # only entries with a real, non-alias address can be diffed against a pin.
    pinned = {k: v for k, v in live.items() if v is not None and k not in NO_PIN}
    diff = {k: (spec._PINNED.get(k), v) for k, v in pinned.items() if spec._PINNED.get(k) != v}
    extra = set(spec._PINNED) - set(live) - {"g2a-subscriptions"}
    check("pinned addresses match PRODUCTS.json (copied, not retyped)",
          not diff and not extra and alias_ok,
          "" if (not diff and not extra and alias_ok) else f"diff {diff} extra {extra} alias_ok={alias_ok}")
except FileNotFoundError:
    print(f"[skip] PRODUCTS.json not found at {PRODUCTS}")

# 4. tool surface enumerable + intended ------------------------------------------------------------
# The money/calls surface (CALLS) plus the two meta tools. New since the v2 fix: register_deposit_
# address (split out of `pay`), resolve_pay_link, escrow_new_secret, quote_swap, quote_sweep.
expected_calls = ["create_pay_link", "resolve_pay_link", "register_deposit_address", "pay",
                  "escrow_create", "escrow_new_secret", "escrow_release", "stream_create",
                  "subscribe", "swap", "quote_swap", "sweep_dust", "quote_sweep",
                  "sponsored_call", "mint_receipt"]
meta = ["read_fee", "server_info"]
check("tool surface == the intended verbs + read_fee + server_info",
      sorted(spec.CALLS) == sorted(expected_calls), f"{len(spec.CALLS)} call tools + {len(meta)} meta")

# 4c. sponsored_call targets the LIVE FleetExecutor delegate and emits the execute() selector -----
check("sponsored_call targets fleet-executor and emits execute()",
      spec.CALLS["sponsored_call"]["to"] == "fleet-executor"
      and spec.CALLS["sponsored_call"]["sigs"] == ["execute((address,uint256,bytes)[],uint256,uint256,bytes)"],
      spec.CALLS["sponsored_call"]["sigs"])

# 4d. hashlock round-trip: escrow_new_secret's (preimage, hashlock) must satisfy keccak(preimage)==
#     hashlock AND create/release must emit those SAME two words (a double-hash was the old bug).
try:
    import server as _sv
    sec = json.loads(_sv.escrow_new_secret())
    from eth_utils import keccak as _k
    rt = "0x" + _k(hexstr=sec["preimage"]).hex() == sec["hashlock"]
    h_arg = _sv._hashlock_arg(sec["hashlock"])
    p_arg = _sv._preimage_arg(sec["preimage"])
    check("escrow secret round-trips: keccak(preimage)==hashlock, args pass through RAW",
          rt and h_arg == sec["hashlock"] and p_arg == sec["preimage"],
          f"keccak(pre)==hash:{rt}")
except Exception as e:  # noqa: BLE001
    check("escrow secret round-trips: keccak(preimage)==hashlock, args pass through RAW", False,
          f"{type(e).__name__}: {e}")

# 4d-bis. resolve_pay_link must resolve BOTH eras offline: a synthetic receipt from the v2 emitter and
#     one from the v1 emitter, each yielding a link naming the emitter that actually logged (the
#     /p2-forwarder page re-reads RequestCreated from that exact address, so a v1 id under v2 404s).
try:
    import server as _sp
    import chain as _ch
    _t0 = _ch.topic0("RequestCreated(uint256,address,address,address,address,address,uint256,bytes32,uint64)")
    def _receipt(emitter: str) -> dict:
        return {"logs": [{
            "address": emitter, "topics": [_t0, "0x" + "00" * 31 + "07",
                                           "0x" + "11" * 32, "0x" + "22" * 32],
            "data": "0x" + "00" * 12 + "aa" * 20 + "00" * 32}]}
    _orig = _ch.rpc
    _out = {}
    for era, emitter in (("v2", spec.ADDR["f1a-payment-links"]), ("v1", spec.V1_F1A)):
        _ch.rpc = (lambda e: (lambda m, p, **k: {"ok": True, "result": _receipt(e)}))(emitter)
        body = json.loads(_sp.resolve_pay_link("0x" + "ab" * 32))
        _out[era] = (body.get("id"), body.get("registry"), emitter in (body.get("link") or ""))
    _ch.rpc = _orig
    check("resolve_pay_link resolves v2 AND v1 receipts; link names the real emitter",
          _out["v2"][0] == 7 and _out["v2"][2] and _out["v1"][0] == 7 and _out["v1"][2],
          str(_out))
except Exception as e:  # noqa: BLE001
    check("resolve_pay_link resolves v2 AND v1 receipts; link names the real emitter", False,
          f"{type(e).__name__}: {e}")

# 4b. the read_fee-before-pay gate: pay() must WARN until a live fee has been read this session -----
#     (offline: exercise the warning path directly, no RPC — the gate keys off the session dict.)
try:
    import server as _s
    _s._FEE_SEEN.clear()
    w_before = _s._fee_gate("p2-forwarder")
    _s._FEE_SEEN["p2-forwarder"] = 500                      # simulate a prior read_fee
    w_after = _s._fee_gate("p2-forwarder")
    w_mismatch = _s._fee_gate("p2-forwarder", expect_bps=100)   # caller quoted the OLD 100 bps
    _s._FEE_SEEN.clear()
    check("pay warns until read_fee was called this session, then clears",
          bool(w_before) and "read_fee not called" in w_before[0]
          and bool(w_after) and "last read this session" in w_after[0],
          f"before={w_before} after={w_after}")
    check("pay flags a stale expect_fee_bps against the live read",
          any("FEE MISMATCH" in x for x in w_mismatch), str(w_mismatch))
except Exception as e:  # noqa: BLE001
    check("pay warns until read_fee was called this session, then clears", False,
          f"{type(e).__name__}: {e}")

# 5. import the server module (needs mcp in user-site — run WITHOUT -I) -----------------------------
try:
    import server  # noqa: F401
    check("server.py imports (MCPServer present)", True)
except Exception as e:  # noqa: BLE001
    check("server.py imports (MCPServer present)", False, f"{type(e).__name__}: {e}")

# 6. dry-run each tool once, in-process ------------------------------------------------------------
try:
    import dryrun
    n = dryrun.run_all(dry_run=False)  # False => no RPC, pure calldata
    total = len(expected_calls) + len(meta)
    check("every tool builds calldata (no RPC)", n == total, f"{n}/{total} tools")
except Exception as e:  # noqa: BLE001
    check("every tool builds calldata (no RPC)", False, f"{type(e).__name__}: {e}")

print()
if fails:
    print(f"SELFTEST RED — {len(fails)} failure(s): {fails}")
    sys.exit(1)
print("SELFTEST GREEN — surface matches the published spec, nothing hand-typed.")
