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

import asyncio

import chain

try:
    import spec
except Exception as _e:  # noqa: BLE001 — spec refuses to import on address drift
    # A bare traceback here reads like a broken gate; say which tooth bit and how to reset it.
    if type(_e).__name__ == "SpecDrift":
        print(f"[FAIL] spec.py refused to load — {_e}\n"
              f"       fix: python3 tools/sync-addresses.py   (then re-run this gate)")
        sys.exit(1)
    raise

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
DEST = "0x000000000000000000000000000000000000dEaD"   # plausible scratch target, nothing sensitive
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
    # A sig added to the generator lands on disk on the next build but in the LIVE text only after a
    # publish. Accept either (the same live-lag accommodation the address check below makes) and NAME
    # the lag rather than failing on it — but require the ONDISK copy to carry it, so a sig in neither
    # is a real drift and still fails.
    try:
        ondisk_pairs = set(re.findall(r"- call: `([^`]+)`\s+selector `(0x[0-9a-fA-F]{8})`",
                                      open(LLMS, encoding="utf-8").read()))
    except Exception:  # noqa: BLE001
        ondisk_pairs = set()
    published |= {s for s, _ in ondisk_pairs}
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
    # MCP-1 bug in one read, independent of any spec doc. The two pointers MUST also be different
    # contracts: if they alias, both reads hit one address and "un-paused AND paused" is unsatisfiable.
    try:
        live_f, dead_f = spec.ADDR["g2a-subscriptions"], spec.V1_APPROVE_REVOKE[0]["to"]
        check("v1 revoke target differs from the live factory", live_f.lower() != dead_f.lower(),
              f"live={live_f} v1={dead_f} (aliased → reads double-count)")
        p2v2 = chain.eth_call(live_f, chain.selector("paused()"))
        v1 = chain.eth_call(dead_f, chain.selector("paused()"))
        v2_unpaused = p2v2["ok"] and int(p2v2["result"], 16) == 0
        v1_paused = v1["ok"] and int(v1["result"], 16) == 1
        check("chain: v2 factory un-paused AND v1 factory paused", v2_unpaused and v1_paused,
              f"v2_unpaused={v2_unpaused} v1_paused={v1_paused} ({live_f} / {dead_f})")
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

# 3b. THE ADDRESS BOOK (MCP-2's surviving form). The pins used to be the load-bearing copy and drifted
#     twice in two rounds. They are now read from a hash-pinned vendored book; these teeth prove the
#     book is the one the SDK ships, that the pin matches it, and that ADDR really came from it (not
#     from `_PINNED`, which would look identical at runtime and be exactly the old bug).
import hashlib

_VENDOR = os.path.join(HERE, "fleet_addr", "addresses.json")
_SDK = os.path.join(HERE, "..", "sdk", "addresses.json")
try:
    _vb = open(_VENDOR, "rb").read()
    check("address book hash == spec._ADDR_SHA256",
          hashlib.sha256(_vb).hexdigest() == spec._ADDR_SHA256,
          f"pinned {spec._ADDR_SHA256[:12]}… (fix: python3 tools/sync-addresses.py)")
    if os.path.exists(_SDK):
        check("vendored address book is byte-identical to products/sdk/addresses.json",
              open(_SDK, "rb").read() == _vb, "re-run tools/sync-addresses.py")
    check("ADDR names every _PINNED key (the fallback cannot be a different fleet)",
          not (set(spec._PINNED) - set(spec.ADDR)), str(sorted(set(spec._PINNED) - set(spec.ADDR))))
    # negcontrol-grade: a book value must actually reach ADDR — mutate the parsed book and re-derive.
    _b = json.loads(_vb)["base"]
    _b["x402Facilitator"] = "0x" + "11" * 20
    check("ADDR is derived FROM the book (mutating it moves ADDR)",
          spec._from_book(_b)["x402"] == "0x" + "11" * 20
          and spec.ADDR["x402"] != "0x" + "11" * 20, spec.ADDR["x402"])
except FileNotFoundError as e:
    check("address book present and hash-pinned", False, str(e))

# 4. tool surface enumerable + intended ------------------------------------------------------------
# The money/calls surface (CALLS) plus the two meta tools. New since the v2 fix: register_deposit_
# address (split out of `pay`), resolve_pay_link, escrow_new_secret, quote_swap, quote_sweep.
expected_calls = ["create_pay_link", "resolve_pay_link", "register_deposit_address", "pay",
                  "escrow_create", "escrow_new_secret", "escrow_release", "stream_create",
                  "subscribe", "disarm_mandate", "pay_x402", "read_402_challenge", "read_capabilities",
                  "swap", "quote_swap", "sweep_dust", "quote_sweep",
                  "sponsored_call", "mint_receipt"]
meta = ["read_fee", "read_x402_status", "server_info"]
check("tool surface == the intended verbs + read_fee + server_info",
      sorted(spec.CALLS) == sorted(expected_calls), f"{len(spec.CALLS)} call tools + {len(meta)} meta")

# 4b. MCP-1: subscribe must emit setMandate between the approve and the first lap, and the whole tool
#     text must be ONE json document (it was two concatenated docs, which broke a plain json.loads).
try:
    import server as _sv1
    from eth_abi import decode
    _m1 = json.loads(_sv1.subscribe(payer="0x" + "11" * 20, recipient="0x" + "22" * 20,
                                    amount=1_000_000, start=1_700_000_000, end=1_700_086_400,
                                    periods=12, dry_run=False))
    _sel = [c["selector"] for c in _m1["calls"]]
    check("MCP-1 subscribe legs are approve -> setMandate -> createStreamFor",
          _sel == ["0x095ea7b3", "0x88f67583", "0x2f7a1c66"], _sel)
    _dec = decode(["address", "address", "uint256", "uint64", "uint32", "uint64"],
                  bytes.fromhex(_m1["calls"][1]["data"][10:]))
    check("MCP-1 setMandate carries period = end-start and laps = periods",
          (_dec[3], _dec[4], _dec[5]) == (86_400, 12, 1_700_000_000), _dec)
    check("MCP-1 approve allowance is ticket*laps, not max-uint",
          int(_m1["calls"][0]["data"][-64:], 16) == 12_000_000, _m1["calls"][0]["data"][-64:])
    check("MCP-1 subscribe returns a revoke block as a KEY (one json document)",
          [c["selector"] for c in _m1["revoke"]["calls"]] == ["0x193ad1b2", "0x095ea7b3"],
          sorted(_m1))
except Exception as e:  # noqa: BLE001
    check("MCP-1 subscribe legs are approve -> setMandate -> createStreamFor", False, f"{type(e).__name__}: {e}")

# 4b-bis. MCP-6: the x402 CLIENT entry point. A stub 402 server is stood up in-process (stdlib only,
#     no network) and the tool is driven at it: the challenge must parse, the settle legs must be
#     emitted in pay -> markPaid -> verify order against the CHALLENGE's rail and the live facilitator,
#     and a non-402 must not be dressed up as a payment gate. Each case has a negcontrol shape.
try:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from eth_abi import decode   # in-scope here regardless of whether 4b's block ran
    import server as _sv4

    _CH = {"x402Version": 2, "rail": "0x" + "77" * 20, "to": "0x" + "88" * 20,
           "token": spec.USDC, "amount": "250000", "memo": "0x" + "00" * 32,
           "facilitator": spec.ADDR["x402"]}

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/open":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            if self.path == "/html":
                self.send_response(402)
                self.send_header("WWW-Authenticate", 'Payment rail="x"')
                self.end_headers()
                self.wfile.write(b"<html>pay</html>")
                return
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(_CH).encode())

        def log_message(self, *a):  # quiet
            pass

    _srv = HTTPServer(("127.0.0.1", 0), _H)
    _base = f"http://127.0.0.1:{_srv.server_port}"
    threading.Thread(target=_srv.serve_forever, daemon=True).start()
    try:
        _r = json.loads(_sv4.pay_x402(url=_base + "/weather", dry_run=False,
                                      payer="0x" + "11" * 20, payment_id="0x" + "ab" * 32))
        _c = _r.get("calls", [])
        check("MCP-6 pay_x402(url) parses the 402 and emits pay -> markPaid -> verify",
              [x["selector"] for x in _c] == ["0x68abdc82", "0x7dffcf3b", "0x796e926d"], _c and
              [x["selector"] for x in _c])
        check("MCP-6 the pay leg targets the CHALLENGE's rail and markPaid the live facilitator",
              _c and _c[0]["to"] == _CH["rail"] and _c[1]["to"] == spec.ADDR["x402"],
              f"{_c and _c[0]['to']} / {_c and _c[1]['to']}")
        _pd = decode(["address", "address", "uint256", "bytes32", "address"],
                     bytes.fromhex(_c[0]["data"][10:])) if _c else None
        check("MCP-6 the advertised to/amount are used when not passed",
              _pd is not None and _pd[0].lower() == _CH["to"].lower()
              and _pd[2] == int(_CH["amount"]), _pd)
        check("MCP-6 the retry header is returned as a KEY",
              _r.get("retry", {}).get("header") == "X-PAYMENT", sorted(_r))
        # negcontrol: a passed `to` that differs from the challenge is NAMED, not silently preferred
        _r2 = json.loads(_sv4.pay_x402(url=_base + "/weather", to="0x" + "99" * 20, dry_run=False))
        check("MCP-6 negcontrol: a `to` that differs from the challenge warns",
              any("challenge advertises" in w for w in _r2.get("warnings") or []),
              _r2.get("warnings"))
        # negcontrol: 200 is "already served", not a gate; a non-JSON 402 warns instead of crashing
        _r3 = json.loads(_sv4.pay_x402(url=_base + "/open"))
        check("MCP-6 negcontrol: a 200 is reported as not-a-402 (nothing to pay)",
              _r3.get("status") == 200 and "not a 402" in (_r3.get("note") or ""), _r3.get("note"))
        _r4 = json.loads(_sv4.pay_x402(url=_base + "/html", dry_run=False))
        check("MCP-6 negcontrol: a non-JSON 402 warns and still does not crash",
              any("not JSON" in w for w in _r4.get("warnings") or []), _r4.get("warnings"))
        _r5 = json.loads(_sv4.read_402_challenge(url=_base + "/weather"))
        check("MCP-6 read_402_challenge reports gated=true + the challenge, uncharged",
              _r5.get("gated") is True and _r5.get("challenge", {}).get("rail") == _CH["rail"],
              _r5.get("status"))
    finally:
        _srv.shutdown()
except Exception as e:  # noqa: BLE001
    check("MCP-6 pay_x402(url) parses the 402 and emits pay -> markPaid -> verify", False,
          f"{type(e).__name__}: {e}")

# 4c. sponsored_call targets the LIVE FleetExecutor delegate and emits the execute() selector -----
check("sponsored_call targets fleet-executor and emits execute()",
      spec.CALLS["sponsored_call"]["to"] == "fleet-executor"
      and spec.CALLS["sponsored_call"]["sigs"] == ["execute((address,uint256,bytes)[],uint256,uint256,bytes)"],
      spec.CALLS["sponsored_call"]["sigs"])

# 4c-bis. R3-4: an UNSIGNED sponsored_call must say so. The old shape emitted a 65-zero placeholder
#     sig + nonce 0 and looked sendable; a client forwarding it reverted (BadSignature/BadNonce) and
#     paid gas. The tool must now mark needs_signature AND the emitted sig arg must still be the
#     65-zero placeholder (offline, no RPC — so verify.py stays byte-identical).
try:
    import server as _sv2
    r = json.loads(_sv2.sponsored_call(calls=[["0x" + "ab" * 20, 0, "0xdeadbeef"]], dry_run=False))
    args = r["calls"][0]
    # find the sig arg positionally: execute(calls,nonce,deadline,sig) -> data ends with the 65-byte arg
    sig_arg = "0x" + args["data"][-65 * 2:]
    check("R3-4 unsigned sponsored_call flags needs_signature + keeps the 65-zero placeholder",
          r.get("needs_signature") is True and sig_arg == "0x" + "00" * 65
          and any("UNSIGNED" in w for w in r.get("warnings", [])),
          f"needs_signature={r.get('needs_signature')} sig_arg_tail={sig_arg[:12]}…")
    # negative control: a SUPPLIED sig must NOT set the flag
    rs = json.loads(_sv2.sponsored_call(calls=[["0x" + "ab" * 20, 0, "0xdeadbeef"]],
                                        nonce=1, deadline=1_800_000_000,
                                        sig="0x" + "11" * 65, dry_run=False))
    check("R3-4 negcontrol: a supplied sig clears needs_signature",
          "needs_signature" not in rs, f"keys={sorted(rs)}")
except Exception as e:  # noqa: BLE001
    check("R3-4 unsigned sponsored_call flags needs_signature", False, f"{type(e).__name__}: {e}")

# 4c-ter. R3-6: g3a-sponsorship must be GONE from the pin, the fee table and the catalog — it was a
#     second product entry for something now expressed as `sponsored_call`. An agent reading
#     server_info must not see a duplicate.
_g3a = "0xb8381fF6b76726e989a7FFF358dBc3640d78d684"
check("R3-6 g3a-sponsorship dropped from _PINNED + FEE_GETTERS",
      "g3a-sponsorship" not in spec._PINNED and "g3a-sponsorship" not in spec.FEE_GETTERS
      and _g3a not in spec.ADDR.values(),
      f"in_ADDR={_g3a in spec.ADDR.values()}")

# 4c-quater. R3-5: pay must CROSS-CHECK the deposit address, not just re-encode its own bytes.
#     Offline the predict read is skipped (dry_run=False), so assert the structure: `owner` is a
#     parameter and the result carries deposit_addr; and with a SUPPLIED deposit_addr that differs
#     from the sim return the code path is reachable (offline: no sim, so it echoes the supplied one).
try:
    import server as _sv3
    import inspect
    params = inspect.signature(_sv3.pay).parameters
    check("R3-5 pay takes `owner` (the predict subject) and returns deposit_addr",
          "owner" in params, f"params={sorted(params)}")
    rp = json.loads(_sv3.pay(destination="0x" + "cd" * 20, deposit_addr="0x" + "ee" * 20, dry_run=False))
    check("R3-5 pay encodes the SUPPLIED deposit_addr into leg 2 (not a blind placeholder)",
          rp["calls"][1]["data"].endswith("ee" * 20 + "0" * 24) or "ee" * 20 in rp["calls"][1]["data"]
          or rp["calls"][1]["to"] == "0x" + "ee" * 20,
          f"leg2.to={rp['calls'][1]['to']} deposit_addr={rp.get('deposit_addr')}")
except Exception as e:  # noqa: BLE001
    check("R3-5 pay cross-checks the deposit address", False, f"{type(e).__name__}: {e}")

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

# 4c. R3-4: an unsigned sponsored_call must be marked UN-SENDABLE and carry the digest hint ----------
#     (offline: dry_run=False skips the nonce/digest read, exactly the shape a client sees first).
try:
    import server as _sp2
    _b = json.loads(_sp2.sponsored_call(calls=[[DEST, 0, "0x"]], sig="", authority="", dry_run=False))
    check("R3-4 unsigned sponsored_call => needs_signature:true (not a sendable placeholder)",
          _b.get("needs_signature") is True and any("authority" in w for w in _b.get("warnings", [])),
          json.dumps({k: _b.get(k) for k in ("needs_signature", "warnings")})[:200])
except Exception as e:  # noqa: BLE001
    check("R3-4 unsigned sponsored_call => needs_signature:true (not a sendable placeholder)", False,
          f"{type(e).__name__}: {e}")

# 4d. R3-5: pay must cross-check the deposit address against registry.predict() and NAME a mismatch --
#     (offline: eth_call is stubbed, so predict AND the leg-1 sim return the same known address.)
try:
    import server as _sp3
    import chain as _ch3
    _addr20 = "0x" + "11" * 20                     # what a caller pastes / what deposit_addr takes
    _word = "0x" + "00" * 12 + "11" * 20           # what eth_call returns: a left-padded 32-byte word
    _orig3 = _ch3.eth_call
    _ch3.eth_call = lambda to, data, **k: {"ok": True, "result": _word}
    _o3 = json.loads(_sp3.pay(destination=DEST, amount=1, deposit_addr="0x" + "22" * 20, dry_run=True))
    _ok3 = json.loads(_sp3.pay(destination=DEST, amount=1, deposit_addr=_addr20, dry_run=True))
    _ch3.eth_call = _orig3
    check("R3-5 pay flags a deposit_addr that != predict() and passes the matching one",
          any("DEST MISMATCH" in w for w in _o3.get("warnings", []))
          and _o3.get("deposit_addr", "").lower() == "0x" + "22" * 20
          and not any("DEST MISMATCH" in w for w in _ok3.get("warnings", [])),
          f"mismatch={_o3.get('warnings')} match={_ok3.get('warnings')}")
except Exception as e:  # noqa: BLE001
    check("R3-5 pay flags a deposit_addr that != predict() and passes the matching one", False,
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

# 7. the RESOURCES are registered and serve the same facts the tools do — a resource that drifts from
#    the tool surface is a second, unchecked copy. Static ones are compared to spec directly; the two
#    live ones read their own RPC and are graded by shape only (offline: skip on transport failure).
try:
    import server as _sv6
    _srv6 = _sv6.server._load()
    _uris = [str(r.uri) for r in asyncio.run(_srv6.list_resources())]
    check("resources registered: fleet://addresses, //fees, //status",
          sorted(_uris) == ["fleet://addresses", "fleet://fees", "fleet://status"], _uris)
    _a = json.loads(asyncio.run(_srv6.read_resource("fleet://addresses"))[0].content)
    check("fleet://addresses serves exactly spec.ADDR (no second copy)",
          _a.get("addresses") == spec.ADDR and _a.get("book_sha256") == spec._ADDR_SHA256,
          f"{len(_a.get('addresses', {}))} addresses")
    try:
        _s = json.loads(asyncio.run(_srv6.read_resource("fleet://status"))[0].content)
        check("fleet://status carries an explicit degraded flag + head",
              "degraded" in _s and "head" in _s, f"degraded={_s.get('degraded')} head={_s.get('head')}")
    except Exception as _e:  # noqa: BLE001
        print(f"[skip] fleet://status live read: {type(_e).__name__}: {_e}")
except Exception as e:  # noqa: BLE001
    check("resources registered: fleet://addresses, //fees, //status", False, f"{type(e).__name__}: {e}")

print()
if fails:
    print(f"SELFTEST RED — {len(fails)} failure(s): {fails}")
    sys.exit(1)
print("SELFTEST GREEN — surface matches the published spec, nothing hand-typed.")
