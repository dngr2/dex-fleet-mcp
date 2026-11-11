#!/usr/bin/env python3
"""verify.py — the A4 drift gate.

Two proofs, both read-only:

  (1) DRIFT: every generated tool's calldata must equal what A1's OWN server.py builds for the
      same args. We call A1's server functions (dry_run=False, so no RPC) and A4's generated
      wrappers with identical inputs and diff `calls[i].data` byte-for-byte. A selector typo, an
      arg reorder, or a wrong callee anywhere in A4 fails here.

  (2) NO-HAND-TYPING: the openai/tools.json selector for each tool re-derives from keccak of A1's
      pinned sig, and every `x-callee` equals A1's spec address. So the JSON schema is generated,
      not transcribed.

  (3) STALENESS: `gen.py --check` must report the four files in sync with A1.

Exit non-zero on any miss. No RPC required (dry_run=False).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# A1 is `../mcp-server` in the monorepo; this dir is the published repo's `plugins/`, where A1 is
# the repo ROOT. Same resolution as gen.py, so the gate runs unchanged on a standalone clone.
def _find_a1() -> str:
    for rel in (os.path.join("..", "mcp-server"), ".."):
        p = os.path.normpath(os.path.join(HERE, rel))
        if os.path.exists(os.path.join(p, "spec.py")) and os.path.exists(os.path.join(p, "chain.py")):
            return p
    return os.path.normpath(os.path.join(HERE, "..", "mcp-server"))


A1 = _find_a1()
sys.path.insert(0, A1)
sys.path.insert(0, os.path.join(HERE, "langchain"))

import spec  # noqa: E402  (A1)
from chain import selector  # noqa: E402  (A1)
import fleet_tools as A4  # noqa: E402  generated

fails = 0
checks = 0


def ok(m):
    global checks
    checks += 1
    print("  ok   " + m)


def bad(m):
    global checks, fails
    checks += 1
    fails += 1
    print("  FAIL " + m)


A = "0x" + "ab" * 20
B = "0x" + "cd" * 20
MEMO = "0x" + "11" * 32
HASH = "0x" + "22" * 32
HOPS7 = [[1, A, B, 3000, False, A, B]]
HOPS5 = [[1, A, B, 3000, A]]

# tool -> (A1 kwargs, A4 kwargs) — identical inputs both sides
CASES = {
    "create_pay_link": (dict(destination=A, token=spec.USDC, amount=1_000_000, memo=MEMO, dry_run=False),
                        dict(destination=A, token=spec.USDC, amount=1_000_000, memo=MEMO, dry_run=False)),
    "pay": (dict(destination=A, dry_run=False), dict(destination=A, dry_run=False)),
    "escrow_create": (dict(counterparty=A, token=spec.USDC, amount=5, hashlock=HASH, timeout=9, dry_run=False),
                      dict(counterparty=A, token=spec.USDC, amount=5, hashlock=HASH, timeout=9, dry_run=False)),
    "escrow_release": (dict(escrow=A, which="release", preimage="0x" + "33" * 32, dry_run=False),
                       dict(escrow=A, which="release", preimage="0x" + "33" * 32, dry_run=False)),
    "stream_create": (dict(recipient=A, token=spec.USDC, amount=7, start=1, end=2, dry_run=False),
                      dict(recipient=A, token=spec.USDC, amount=7, start=1, end=2, dry_run=False)),
    "subscribe": (dict(payer=A, recipient=B, token=spec.USDC, amount=3, start=1, end=2, periods=4, dry_run=False),
                  dict(payer=A, recipient=B, token=spec.USDC, amount=3, start=1, end=2, periods=4, dry_run=False)),
    "swap": (dict(amount_in=100, amount_out_min=90, hops=HOPS7, recipient=A, deadline=5, dry_run=False),
             dict(amount_in=100, amount_out_min=90, hops=HOPS7, recipient=A, deadline=5, dry_run=False)),
    "sweep_dust": (dict(tokens=[A, B], hops=HOPS5, min_out=[1, 2], dry_run=False),
                   dict(tokens=[A, B], hops=HOPS5, min_out=[1, 2], dry_run=False)),
    "sponsored_call": (dict(calls=[[A, 0, "0xdeadbeef"]], dry_run=False),
                       dict(calls=[[A, 0, "0xdeadbeef"]], dry_run=False)),
    "mint_receipt": (dict(escrow=A, dry_run=False), dict(escrow=A, dry_run=False)),
}


def _a1_docs(raw: str) -> list:
    """A1 returns ONE json doc for most tools, but TWO concatenated docs for `subscribe`
    (the second is `subscribe.revoke`). Split them without assuming json.loads sees the whole string."""
    dec, i, out = json.JSONDecoder(), 0, []
    while i < len(raw):
        while i < len(raw) and raw[i] in " \t\r\n":
            i += 1
        if i >= len(raw):
            break
        obj, j = dec.raw_decode(raw, i)
        out.append(obj)
        i = j
    return out


def _a1_legs(raw: str) -> list:
    """Every leg A1 emits, across ALL its docs (so a 2-doc tool still diffs 1:1 against a flattened
    multi-leg consumer like the TS/crewai flavors)."""
    return [c for d in _a1_docs(raw) for c in d.get("calls", [])]

print("§1 generated calldata == A1's own server output")
for name, (a1kw, a4kw) in CASES.items():
    import server  # A1's server module (imported once)
    a1_calls = _a1_legs(getattr(server, name)(**a1kw))  # ALL docs (subscribe emits 2)
    a4_calls = _a1_legs(getattr(A4, name)(**a4kw))       # A4 mirrors the same concatenation
    if len(a1_calls) != len(a4_calls):
        bad(f"{name}: call count {len(a4_calls)} != A1 {len(a1_calls)}")
        continue
    drift = []
    for i, (x, y) in enumerate(zip(a1_calls, a4_calls)):
        for k in ("to", "data", "selector", "sig"):
            if k in x and x.get(k) != y.get(k):
                drift.append(f"call[{i}].{k}: A4={y.get(k)} A1={x.get(k)}")
    if drift:
        bad(f"{name}: " + "; ".join(drift))
    else:
        ok(f"{name}: {len(a4_calls)} call(s) byte-identical to A1")

print("§2 openai/tools.json selectors re-derive from A1 sig, callees match A1 addr")
oj = json.load(open(os.path.join(HERE, "openai", "tools.json")))
by_name = {t["name"]: t for t in oj["tools"]}
# NB: spec.CALLS is BROADER than the published set. It also carries five DELIBERATELY-unpublished
# entries: the four read-only helpers (empty `sigs`) PLUS register_deposit_address (register-only
# companion to `pay`). Assert over what is PUBLISHED, and pin the complement by name so a helper that
# gains a sig — or a published tool that loses one — is caught, not silently skipped.
UNPUBLISHED = {"resolve_pay_link", "register_deposit_address", "escrow_new_secret",
               "quote_swap", "quote_sweep"}
for name in by_name:
    if name in ("read_fee", "server_info"):
        continue
    c = spec.CALLS.get(name)
    if c is None:
        bad(f"{name}: published tool with no spec.CALLS entry")
        continue
    want = [{"sig": s, "selector": selector(s)} for s in c["sigs"]]
    if t := by_name[name]:
        if t.get("x-calls") != want:
            bad(f"{name}: x-calls {t.get('x-calls')} != derived {want}")
        elif t.get("x-callee") != spec.ADDR[c["to"]]:
            bad(f"{name}: x-callee != A1 addr")
        else:
            ok(f"{name}: selector(s) + callee derived")
_drift_set = set(spec.CALLS) - set(by_name)
if _drift_set == UNPUBLISHED:
    ok(f"{len(UNPUBLISHED)} deliberately-unpublished spec entr(ies) accounted for")
else:
    bad(f"unpublished-set drift: unexpected={sorted(_drift_set - UNPUBLISHED)} "
        f"missing={sorted(UNPUBLISHED - _drift_set)}")


print("§3 gen.py --check (files in sync with A1)")
r = subprocess.run([sys.executable, os.path.join(HERE, "gen.py"), "--check"],
                   capture_output=True, text=True)
if r.returncode == 0 and r.stdout.startswith("OK"):
    ok("generated files in sync")
else:
    bad("stale: " + (r.stdout + r.stderr).strip())

print("§3b STALENESS GUARD has teeth — the p2→g2b class must FAIL, not silently ship")
# The class that shipped: an artifact carrying a WRONG-BUT-KNOWN address (pay → g2b factory, both
# real). Reproduce by rewriting pay.x-callee to g2b in tools.json; `gen.py --check` must redden; a
# regen must fix it. Then confirm and leave the tree clean.
import tempfile
_oj = os.path.join(HERE, "openai", "tools.json")
_orig = open(_oj).read()
try:
    _d = json.loads(_orig)
    _g2b = spec.ADDR["g2b-escrow"]
    for _t in _d["tools"]:
        if _t["name"] == "pay":
            _t["x-callee"] = _g2b
    open(_oj, "w").write(json.dumps(_d, indent=2) + "\n")
    _r = subprocess.run([sys.executable, os.path.join(HERE, "gen.py"), "--check"],
                        capture_output=True, text=True)
    if _r.returncode == 1 and _r.stdout.startswith("STALE"):
        ok("wrong-but-known callee → gen.py --check reddens (guard has teeth)")
    else:
        bad(f"guard missed a wrong callee: rc={_r.returncode} out={_r.stdout.strip()[:80]}")
    subprocess.run([sys.executable, os.path.join(HERE, "gen.py")], capture_output=True)
    _back = json.loads(open(_oj).read())
    _paycallee = [t for t in _back["tools"] if t["name"] == "pay"][0]["x-callee"]
    if _paycallee.lower() == spec.ADDR["p2-forwarder"].lower():
        ok("regen restores pay.x-callee = p2 Registry (not g2b)")
    else:
        bad(f"regen left pay.x-callee = {_paycallee}")
finally:
    pass

print("§4 vercel-ai/fleet.ts — every selector literal is an A1-derived keccak; addrs are A1 addrs")
ts = open(os.path.join(HERE, "vercel-ai", "fleet.ts")).read()
import re
# every sig-derived selector A1 knows (all tools, all sigs)
A1_SEL = {selector(s) for c in spec.CALLS.values() for s in c["sigs"]}
A1_ADDR = set(spec.ADDR.values())
lits = set(re.findall(r"['\"](0x[0-9a-f]{8})['\"]", ts))
if lits and lits <= A1_SEL:
    ok(f"all {len(lits)} selector literal(s) derive from A1 sigs")
else:
    bad(f"stray selector literal(s): {sorted(lits - A1_SEL)}")
taddrs = set(re.findall(r"['\"](0x[0-9a-fA-F]{40})['\"]", ts))
# allowed address literals = A1's ADDR map ∪ USDC ∪ the DELIBERATE v1 constants spec pins
# (V1_APPROVE_REVOKE[].to is the PAUSED v1 factory the revoke leg targets; V1_F1A). Same allowlist
# as gen.py's own guard, so the two guards agree and neither hides a real stale callee.
A1_ADDR = set(spec.ADDR.values()) | {spec.USDC}
A1_ADDR |= {r["to"] for r in getattr(spec, "V1_APPROVE_REVOKE", [])}
if getattr(spec, "V1_F1A", ""):
    A1_ADDR.add(spec.V1_F1A)
if taddrs and taddrs <= A1_ADDR:
    ok(f"all {len(taddrs)} address literal(s) are A1 addrs")
else:
    bad(f"stray address literal(s): {sorted(taddrs - A1_ADDR)}")
# the per-leg shape must be present: mkLeg(to, sig, selector, args)
if ts.count("mkLeg(") >= len(CASES) + 2:
    ok(f"{ts.count('mkLeg(')} mkLeg leg(s) emitted (multi-call tools emit >1)")
else:
    bad(f"too few mkLeg legs: {ts.count('mkLeg(')}")

print("§5 selector PROVENANCE via `cast sig` — every emitted selector re-derived by an outside tool")
# `cast sig` is the external authority (foundry), NOT the eth_utils keccak that gen.py uses. If the two
# ever disagree, the emitted selector is wrong for a real node. Also re-derives each sig FROM the source
# in openai/tools.json so a retype (e.g. setFeeBps(uint16) vs uint256 -> 0x023b1fc9 vs 0x72c27b62)
# cannot hide. Skips (not fails) if `cast` is absent.
import shutil
CAST = shutil.which("cast")
def cast_sig(sig: str) -> str:
    return subprocess.run([CAST, "sig", sig], capture_output=True, text=True).stdout.strip()

if not CAST:
    ok("cast not found — provenance skipped (eth_utils keccak only)")
else:
    pairs = [(s, selector(s)) for c in spec.CALLS.values() for s in c["sigs"]]
    mism = []
    for s, sel in pairs:
        cs = cast_sig(s)
        if cs != sel:
            mism.append(f"{s}: cast={cs} keccak={sel}")
    if mism:
        bad("keccak != cast sig for: " + "; ".join(mism))
    else:
        ok(f"all {len(pairs)} A1 sig(s): keccak(eth_utils) == `cast sig`")

    # every selector literal in the TS must be `cast sig` of a sig A1 actually pins
    exp = {cast_sig(s) for s in {s for c in spec.CALLS.values() for s in c["sigs"]}}
    stray = lits - exp
    if stray:
        bad(f"TS selector literal(s) not a cast-derived A1 sig: {sorted(stray)}")
    else:
        ok(f"all {len(lits)} TS selector literal(s) match a `cast sig` of an A1 sig")

    # the three deploy-preserved setters the critic named — pin them VERBATIM here so the README claim
    # ("selectors unchanged across deploy") is a checked fact, not prose. NB the arg WIDTH matters:
    # setFeeBps is uint16 (0x023b1fc9); the same name at uint256 is 0x72c27b62.
    PRESERVED = {
        "setFeeBps(uint16)": "0x023b1fc9",
        "setMinFee(uint256)": "0x31ac9920",
        "setFeeRecipient(address)": "0xe74b981b",
    }
    pm = [f"{s}: want {w} got {cast_sig(s)}" for s, w in PRESERVED.items() if cast_sig(s) != w]
    if pm:
        bad("deploy-preserved setter drift: " + "; ".join(pm))
    else:
        ok(f"all {len(PRESERVED)} deploy-preserved setter selectors re-derive (cast sig)")

print("§6 vercel-ai/fleet.ts transpiles, and its OWN emitted args re-encode to A1 byte-identical")
TS_HARNESS = r"""
import * as F from './out/fleet.js';
const A='0x'+'ab'.repeat(20), B='0x'+'cd'.repeat(20);
const MEMO='0x'+'11'.repeat(32), HASH='0x'+'22'.repeat(32);
const HOPS7=[[1,A,B,3000,false,A,B]], HOPS5=[[1,A,B,3000,A]];
const USDC='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
F.useEncoder(({sig,args})=>'0x');
const out={};
out.create_pay_link=F.create_pay_link(A,USDC,1000000,MEMO);
out.pay=F.pay(A);
out.escrow_create=F.escrow_create(A,USDC,5,HASH,9);
out.escrow_release=F.escrow_release(A,'release','0x'+'33'.repeat(32));
out.stream_create=F.stream_create(A,USDC,7,1,2);
out.subscribe=F.subscribe(A,B,USDC,3,1,2,4);
out.swap=F.swap(100,90,HOPS7,A,5);
out.sweep_dust=F.sweep_dust([A,B],HOPS5,[1,2]);
out.sponsored_call=F.sponsored_call([[A,0,'0xdeadbeef']]);
out.mint_receipt=F.mint_receipt(A);
// keccak string-path vectors: the memo/hashlock coercion when handed a utf-8 string
out.__kek={}; for (const s of ['', 'abc', 'hello world', 'invoice #42']) out.__kek[s]=F._bytes32(s);
process.stdout.write(JSON.stringify(out,(k,v)=>typeof v==='bigint'?{__big:v.toString()}:v));
"""

def _flatten(x):
    if isinstance(x, dict) and "__big" in x:
        return int(x["__big"])
    if isinstance(x, dict):
        return {k: _flatten(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_flatten(v) for v in x]
    return x

from chain import build_call  # A1's encoder — the authority

have_node = shutil.which("node") and shutil.which("tsc")
if not have_node:
    ok("node/tsc not found — TS compile+roundtrip skipped")
else:
    work = "/tmp/a4ts"
    subprocess.run(["rm", "-rf", work]); os.makedirs(work + "/node_modules/ai", exist_ok=True)
    shutil.copy(os.path.join(HERE, "vercel-ai", "fleet.ts"), work + "/fleet.ts")
    open(work + "/node_modules/ai/index.js", "w").write(
        "export const jsonSchema=(x)=>x;\nexport const tool=(x)=>x;\n")
    open(work + "/node_modules/ai/index.d.ts", "w").write(
        "export declare function jsonSchema(x:any):any;\nexport declare function tool(x:any):any;\n")
    open(work + "/node_modules/ai/package.json", "w").write('{"name":"ai","type":"module","main":"index.js"}')
    comp = subprocess.run([shutil.which("tsc"), "fleet.ts", "--module", "esnext", "--target", "es2022",
                           "--moduleResolution", "bundler", "--outDir", "out", "--skipLibCheck"],
                          cwd=work, capture_output=True, text=True)
    if comp.returncode != 0:
        bad("tsc: " + comp.stdout.strip()[:300])
    else:
        ok("vercel-ai/fleet.ts transpiles clean (tsc rc 0)")
        open(work + "/run.mjs", "w").write(TS_HARNESS)
        run = subprocess.run(["node", "run.mjs"], cwd=work, capture_output=True, text=True)
        if run.returncode != 0:
            bad("node run: " + run.stderr.strip()[:300])
        else:
            legs = _flatten(json.loads(run.stdout))
            for name, (a1kw, _a4kw) in CASES.items():
                a1_calls = _a1_legs(getattr(server, name)(**a1kw))
                got = legs[name]
                drift = []
                if len(got) != len(a1_calls):
                    drift.append(f"leg count {len(got)} != A1 {len(a1_calls)}")
                else:
                    for i, (g, x) in enumerate(zip(got, a1_calls)):
                        # rebuild calldata from the TS-emitted args using A1's own encoder
                        try:
                            data = build_call(g["sig"], g["args"])
                        except Exception as e:
                            drift.append(f"call[{i}] TS args don't encode: {e}"); continue
                        if data != "0x" + x["data"][2:] and data != x["data"]:
                            drift.append(f"call[{i}] TS-args calldata != A1: {data} vs {x['data']}")
                        if g["selector"] != x["selector"]:
                            drift.append(f"call[{i}] selector {g['selector']} != A1 {x['selector']}")
                        if g["to"].lower() != x["to"].lower():
                            drift.append(f"call[{i}] to {g['to']} != A1 {x['to']}")
                if drift:
                    bad(f"TS/{name}: " + "; ".join(drift))
                else:
                    ok(f"TS/{name}: {len(got)} leg(s) → A1 encoder byte-identical")

            # keccak string path: TS _bytes32(str) must equal eth_utils.keccak — the hand-rolled
            # KEK must be a real keccak, not just "some hash", or every string memo silently differs.
            from eth_utils import keccak
            kmis = []
            for s, got in legs["__kek"].items():
                # A1._bytes32 maps an empty string to ZERO32 (not keccak("")); the TS mirrors that.
                want = "0x" + "00" * 32 if s == "" else "0x" + keccak(text=s).hex()
                if got != want:
                    kmis.append(f"{s!r}: {got} != {want}")
            if kmis:
                bad("TS keccak string path != eth_utils: " + "; ".join(kmis))
            else:
                ok(f"TS _bytes32(str) == eth_utils.keccak on {len(legs['__kek'])} string(s)")

print("§7 the other two front doors load and agree (crewai import; openai schema shape)")
ALL_EXPECT = [t for t in json.load(open(os.path.join(HERE, "openai", "tools.json")))["tools"]]
ALL_EXPECT = [t["name"] for t in ALL_EXPECT]
sys.path.insert(0, os.path.join(HERE, "crewai"))
try:
    import fleet_tools as CREW  # noqa: E402
    cdrift = []
    for name, (a1kw, _a4kw) in CASES.items():
        a1_calls = _a1_legs(getattr(server, name)(**a1kw))
        cr_calls = _a1_legs(getattr(CREW, name)(**_a4kw))
        if [c.get("data") for c in cr_calls] != [c.get("data") for c in a1_calls]:
            cdrift.append(name)
    if cdrift:
        bad("crewai flavor drift: " + ", ".join(cdrift))
    else:
        ok(f"crewai/fleet_tools.py: all {len(CASES)} tool(s) import + byte-identical to A1")
    if [getattr(f, "__name__", None) for f in getattr(CREW, "TOOLS", [])] == ALL_EXPECT:
        ok(f"crewai TOOLS registry = {len(ALL_EXPECT)} tools")
    else:
        bad("crewai TOOLS registry mismatch")
except Exception as e:
    bad(f"crewai import: {e}")

# openai/tools.json must be a real function-calling schema: name/description/parameters + callee pins
oj2 = json.load(open(os.path.join(HERE, "openai", "tools.json")))
ojfail = []
for t in oj2.get("tools", []):
    if not all(k in t for k in ("name", "description", "parameters")):
        ojfail.append(f"{t.get('name')}: missing required key")
    if t["name"] in spec.CALLS and "x-callee" not in t:
        ojfail.append(f"{t['name']}: money tool missing x-callee pin")
if ojfail:
    bad("openai schema: " + "; ".join(ojfail))
else:
    ok(f"openai/tools.json: {len(oj2['tools'])} tool(s), all well-formed with callee pins")

print(f"\n{checks} checks, {fails} failed")
sys.exit(1 if fails else 0)
