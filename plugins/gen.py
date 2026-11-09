#!/usr/bin/env python3
"""gen.py — generate the A4 framework plugins FROM A1 (products/mcp-server).

Catalog A4: "LangChain tool, CrewAI tool, Vercel AI SDK tool, OpenAI function schema, all thin
wrappers over A1 or the SDK; generate A4 from A1." So nothing here is hand-typed: this reads

  * products/mcp-server/server.py  — tool NAMES + PARAMS (name/type/default) + descriptions, via AST
  * products/mcp-server/spec.py    — the pinned SELECTORS + CALLEE address per tool, via import

and emits four artifacts sharing ONE JSON schema:
  openai/tools.json          the OpenAI function-calling schema (the shared wire contract)
  langchain/fleet_tools.py   StructuredTool wrappers calling A1's chain.build_call
  crewai/fleet_tools.py      CrewAI @tool wrappers (same bodies, different decorator)
  vercel-ai/fleet.ts         AI-SDK `tool({...})` wrappers + plain fns

The calldata is ALWAYS built by A1's `chain.build_call` (keccak selector + eth_abi) — this script
re-implements no encoding, so A4 cannot drift from A1. A `--check` mode is the staleness gate.

Run:    python3 gen.py            # write in place
        python3 gen.py --check    # exit 1 if any generated file is stale
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# A1 lives at `../mcp-server` INSIDE the monorepo, but this dir is published as the standalone repo's
# `plugins/` subdir, where A1 is the repo ROOT (`plugins/..`). Try monorepo first (byte-identical
# in-tree); the co-located fallback is what makes the published clone's `gen.py`/`verify.py` run.
def _find_a1() -> str:
    for rel in (os.path.join("..", "mcp-server"), ".."):
        p = os.path.normpath(os.path.join(HERE, rel))
        if os.path.exists(os.path.join(p, "server.py")) and os.path.exists(os.path.join(p, "spec.py")):
            return p
    return os.path.normpath(os.path.join(HERE, "..", "mcp-server"))


A1 = _find_a1()
SERVER = os.path.join(A1, "server.py")


def _products_json() -> str | None:
    """PRODUCTS.json: `../dex-site/` in the monorepo, `catalog/` beside A1 in the published clone."""
    for rel in (os.path.join(A1, "..", "dex-site", "PRODUCTS.json"),
                os.path.join(A1, "catalog", "PRODUCTS.json")):
        p = os.path.normpath(rel)
        if os.path.exists(p):
            return p
    return os.path.normpath(os.path.join(A1, "..", "dex-site", "PRODUCTS.json"))

MONEY_TOOLS = [
    "create_pay_link", "pay", "escrow_create", "escrow_release", "stream_create",
    "subscribe", "swap", "sweep_dust", "sponsored_call", "mint_receipt",
]
META_TOOLS = ["read_fee", "server_info"]
ALL_TOOLS = MONEY_TOOLS + META_TOOLS

# per-tool positional arg expression, taken from A1's server.py call sites (the ONE place these
# arg lists are fixed; verified against A1 output by verify.py).
ARG_EXPR = {
    "create_pay_link": "[destination, token, int(amount), _memo(memo)]",
    "pay": "[destination]",
    "escrow_create": "[counterparty, token, int(amount), _hash(hashlock), int(timeout)]",
    "escrow_release": "[_hash(preimage)] if which == 'release' else []",
    "swap": "[[int(amount_in), int(amount_out_min), _hops7(hops), recipient, int(deadline)]]",
    "sweep_dust": "[_tokens(tokens), _hops5(hops), [int(x) for x in _aslist(min_out)]]",
    "sponsored_call": "[target, data]",
    "mint_receipt": "[escrow]",
}


# --------------------------------------------------------------------------- A1 introspection

def _load_spec():
    sys.path.insert(0, A1)
    import spec  # noqa: E402

    # STALENESS GUARD (why this exists): spec.ADDR is resolved at IMPORT from PRODUCTS.json; a stale
    # __pycache__/spec.pyc (or a shadowing module) can hand back an OLD address map while a later
    # import in verify.py sees the fresh one — so the artifact lands with a wrong callee and the gate
    # still passes on the artifact that was never written. Assert, at emit time, that spec.ADDR agrees
    # with PRODUCTS.json read DIRECTLY right now. Any disagreement = fail loud, never emit.
    import json as _json
    pjson = _products_json()
    if os.path.exists(pjson):
        live = {p["id"]: p["contract"] for p in _json.load(open(pjson))["products"]}
        for pid, addr in spec.ADDR.items():
            if pid in live and live[pid].lower() != addr.lower():
                raise SystemExit(
                    f"gen: STALE spec.ADDR[{pid}]={addr} != PRODUCTS.json {live[pid]} "
                    f"(spec module from {spec.__file__}; clear mcp-server/__pycache__ and rerun)")
    else:
        # no repo checkout → spec falls back to _PINNED; the pin IS the authority then.
        for pid, addr in spec.ADDR.items():
            if spec._PINNED.get(pid) and spec._PINNED[pid].lower() != addr.lower():
                raise SystemExit(f"gen: STALE spec.ADDR[{pid}]={addr} != _PINNED {spec._PINNED[pid]}")
    return spec


def _server_sources() -> dict:
    tree = ast.parse(open(SERVER).read())
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if not any("server.tool" in ast.unparse(d) for d in node.decorator_list):
            continue
        defaults = list(node.args.defaults)
        pad = [None] * (len(node.args.args) - len(defaults))
        params = []
        for a, d in zip(node.args.args, pad + defaults):
            ty = ast.unparse(a.annotation) if a.annotation else "any"
            params.append((a.arg, ty, ast.unparse(d) if d is not None else None))
        desc = ""
        for d in node.decorator_list:
            if isinstance(d, ast.Call):
                for kw in d.keywords:
                    if kw.arg == "description":
                        desc = ast.literal_eval(kw.value)
        out[node.name] = {"params": params, "doc": ast.get_docstring(node) or "", "description": desc}
    return out


# --------------------------------------------------------------------------- descriptor

_USDC_SENTINEL = "\x00USDC"


def _default_value(raw: str | None):
    """python-literal default → JSON value; spec.USDC → sentinel (resolved to the const in code)."""
    if raw is None:
        return None
    if raw == "spec.USDC":
        return _USDC_SENTINEL
    if raw in ("True", "False"):
        return raw == "True"
    try:
        return ast.literal_eval(raw)
    except Exception:
        return None


def _json_type(t: str) -> str | list:
    if t == "int":
        return "integer"
    if t == "bool":
        return "boolean"
    return ["string", "array", "object"]  # str, or un-annotated (hops/tokens/min_out) → union


def descriptor(name: str, info: dict, spec) -> dict:
    props, required = {}, []
    for pname, ptype, praw in info["params"]:
        prop = {"type": _json_type(ptype)}
        d = _default_value(praw)
        if pname == "token":
            prop["type"] = "string"
            prop["default"] = spec.USDC
        elif d is not None and d is not _USDC_SENTINEL:
            prop["default"] = d
        props[pname] = prop
        if praw is None and pname != "dry_run":
            required.append(pname)
    if "dry_run" not in props:
        props["dry_run"] = {"type": "boolean", "default": True}
    desc = info["description"] or info["doc"].split("\n")[0]
    return {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required}}


# --------------------------------------------------------------------------- helpers (generated once)

_PY_HELPERS = '''
def _aslist(x):
    if isinstance(x, str):
        return json.loads(x or "[]")
    return x


def _addr(v):
    return v or "0x" + "00" * 20


def _memo(v):
    """bytes32 from a 0x-hex word or a utf-8 string (keccak), matching A1."""
    if not v:
        return "0x" + "00" * 32
    if isinstance(v, str) and v.startswith("0x") and len(v) == 66:
        return v
    if isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "0x" + v
    from eth_utils import keccak
    return "0x" + keccak(text=v).hex()


_hash = _memo  # the hashlock param is the same bytes32 coercion


def _hops7(hops):
    """Router hop: [venue,tokenIn,tokenOut,feeTier,stable,venueRouter,factory]."""
    return [[h[0], _addr(h[1]), _addr(h[2]), h[3], bool(h[4]), _addr(h[5]), _addr(h[6])]
            for h in _aslist(hops)]


def _hops5(hops):
    """Duster hop: [venue,tokenIn,tokenOut,feeTier,venueRouter]."""
    return [[h[0], _addr(h[1]), _addr(h[2]), h[3], _addr(h[4])] for h in _aslist(hops)]


def _tokens(t):
    return [x for x in _aslist(t)]
'''


def _py_prelude(flavor: str) -> str:
    deco_import = (
        "try:\n    from langchain_core.tools import StructuredTool\n    _HAS_FW = True\n"
        "except Exception:\n    StructuredTool = None\n    _HAS_FW = False\n"
        if flavor == "langchain" else
        "try:\n    from crewai.tools import tool as _fw_decorator\n    _HAS_FW = True\n"
        "except Exception:\n    def _fw_decorator(fn=None, **_):\n        return fn if fn is not None else (lambda f: f)\n"
        "    _HAS_FW = False\n"
    )
    return (
        '"""GENERATED by products/framework-plugins/gen.py from products/mcp-server (A1) — do not hand-edit.\n\n'
        "Regenerate:  python3 products/framework-plugins/gen.py\n"
        'Verify:      python3 products/framework-plugins/gen.py --check\n"""\n'
        "from __future__ import annotations\n\n"
        "import json, os, sys\n\n"
        "# A1 is the calldata authority — import its spec/chain; re-encode nothing here. A1 is\n"
        "# `../../mcp-server` in the monorepo and `../..` (repo root) in the published standalone repo\n"
        "# (this file lands at plugins/<flavor>/). Resolve to whichever exists so a clone just works.\n"
        "_ROOT = os.path.dirname(os.path.abspath(__file__))\n"
        "_A1 = next((p for p in (os.path.normpath(os.path.join(_ROOT, '..', '..', 'mcp-server')),\n"
        "                        os.path.normpath(os.path.join(_ROOT, '..', '..')))\n"
        "            if os.path.exists(os.path.join(p, 'chain.py'))), None)\n"
        "if _A1 and _A1 not in sys.path:\n    sys.path.insert(0, _A1)\n"
        "import chain  # noqa: E402\nimport spec   # noqa: E402\n\n"
        + deco_import + "\n"
        + _PY_HELPERS + "\n"
        "\ndef _build(tool: str, args: list) -> dict:\n"
        "    c = spec.CALLS[tool]; sig = c['sigs'][0]; to = spec.ADDR[c['to']]\n"
        "    return {'tool': tool, 'product': c['product'], 'to': to,\n"
        "            'sig': sig, 'selector': chain.selector(sig), 'data': chain.build_call(sig, args)}\n\n\n"
        "def _build_sig(tool: str, sig: str, to: str, args: list) -> dict:\n"
        "    return {'tool': tool, 'to': to, 'sig': sig,\n"
        "            'selector': chain.selector(sig), 'data': chain.build_call(sig, args)}\n\n\n"
        "def _result(tool: str, calls: list) -> str:\n"
        "    return json.dumps({'tool': tool, 'chain': {'id': spec.CHAIN_ID}, 'calls': calls}, indent=2)\n\n"
    )


def _py_fn(name: str, d: dict, spec, flavor: str) -> str:
    params = d["parameters"]["properties"]
    sig_parts, define = [], []
    for p, prop in params.items():
        if "default" in prop:
            dv = "spec.USDC" if (p == "token" and prop["default"] == spec.USDC) else repr(prop["default"])
            sig_parts.append(f"{p}=_D_{name}_{p}")
            define.append(f"_D_{name}_{p} = {dv}")
        else:
            sig_parts.append(p)
    deco = "_deco" if flavor == "langchain" else "_fw_decorator"
    # bodies
    if name == "escrow_release":
        # A1 dispatches the sig by `which` and targets the ESCROW, not the factory.
        body = [
            '    _WHICH = {"release": "release(bytes32)", "refund": "refund()",',
            '              "arbiterRelease": "arbiterRelease()", "arbiterRefund": "arbiterRefund()"}',
            "    sig = _WHICH[which]",
            "    args = [_hash(preimage)] if which == 'release' else []",
            "    return _result('escrow_release', [_build_sig('escrow_release', sig, escrow, args)])",
        ]
    elif name in ("stream_create", "subscribe"):
        fac = "g2a-streams" if name == "stream_create" else "g2a-subscriptions"
        name_fn = "createStream" if name == "stream_create" else "createStreamFor"
        sig2 = ("createStream(address,address,uint256,uint64,uint64)" if name == "stream_create"
                else "createStreamFor(address,address,address,uint256,uint64,uint64)")
        args2 = ("[recipient, token, int(amount), int(start), int(end)]" if name == "stream_create"
                 else "[payer, recipient, token, int(amount), int(start), int(end)]")
        amt2 = "int(amount)" if name == "stream_create" else "int(amount) * int(periods)"
        body = [
            f"    factory = spec.ADDR['{fac}']",
            f"    approve = _build_sig('{name}', 'approve(address,uint256)', token, [factory, {amt2}])",
            f"    create = _build_sig('{name}', '{sig2}', factory, {args2})",
            f"    return _result('{name}', [approve, create])",
        ]
    else:
        body = [f"    return _result('{name}', [_build('{name}', {ARG_EXPR[name]})])"]
    doc = d["description"] + f"\n\ncallee: {spec.ADDR[spec.CALLS[name]['to']]}"
    if name == "escrow_release":
        doc += "  (factory shown; the call targets the per-deal ESCROW address)"
    lines = define + [f"@{deco}", f"def {name}({', '.join(sig_parts)}) -> str:",
                      f'    """{doc}"""', *body, ""]
    return "\n".join(lines)


def _py_meta(spec) -> str:
    return '''
def read_fee(product: str = "") -> str:
    """Live fee per product (on-chain). p3's MAX_FEE_BPS is a DENOMINATOR (GOTCHA #144)."""
    items = {product: spec.FEE_GETTERS[product]} if product in spec.FEE_GETTERS else spec.FEE_GETTERS
    out = {}
    for pid, g in items.items():
        e = {"unit": g["unit"], "note": g["note"], "live": None}
        if g["sig"]:
            who = spec.ADDR.get(g.get("contract", pid))
            r = chain.eth_call(who, chain.selector(g["sig"].split("(")[0] + "()"))
            e["live"] = chain.decode_uint(r["result"]) if r["ok"] else None
        out[pid] = e
    return json.dumps({"tool": "read_fee", "fees": out}, indent=2)


def server_info() -> str:
    """Product map + addresses (from A1 spec, itself copied from PRODUCTS.json)."""
    return json.dumps({"name": "dex-fleet", "chain": {"id": spec.CHAIN_ID},
                       "products": [{"id": k, "contract": v} for k, v in spec.ADDR.items()],
                       "spec": spec.SPEC_URL}, indent=2)


TOOLS = [''' + ", ".join(ALL_TOOLS) + ''']


def get_tools():
    return TOOLS
'''


def gen_python(tools: dict, spec, flavor: str) -> str:
    deco_def = (
        "\ndef _deco(fn):\n    return StructuredTool.from_function(fn) if _HAS_FW else fn\n"
        if flavor == "langchain" else ""
    )
    parts = [_py_prelude(flavor)]
    if flavor == "langchain":
        parts.append(deco_def)
    for n in MONEY_TOOLS:
        parts.append(_py_fn(n, tools[n], spec, flavor))
    parts.append(_py_meta(spec))
    return "".join(parts)


# --------------------------------------------------------------------------- vercel-ai TS

_TS_HELPERS = '''
type Leg = { to: string; sig: string; selector: string; args: unknown[]; data: string | null; note?: string };
type Encode = (x: { sig: string; args: unknown[] }) => `0x${string}`;

const ZERO32 = '0x' + '00'.repeat(32);
const ZERO20 = '0x' + '00'.repeat(20);

// calldata is produced by a caller-supplied encoder so this file pulls no ABI dependency;
// pass `encode({sig, args})` from your viem client (encodeFunctionData, abi = [sig]) — or leave it
// and read `.data` as null, `.sig`/`.args` are always present. Selectors are keccak-derived by
// gen.py, never hand-typed.
let encodeFn: Encode | null = null;
export function useEncoder(e: Encode) { encodeFn = e; }

function mkLeg(to: string, sig: string, selector: string, args: unknown[], note?: string): Leg {
  return { to, sig, selector, args, data: encodeFn ? encodeFn({ sig, args }) : null, note };
}

function _addr(v: unknown): string { return (v as string) || ZERO20; }
function _aslist(x: unknown): any[] { return typeof x === 'string' ? JSON.parse(x || '[]') : (x as any[]); }

// bytes32 from a 0x-hex word; a bare 64-hex string; or a utf-8 string (keccak). Mirror of A1._bytes32.
export function _bytes32(v: unknown): string {
  const s = (v as string) || '';
  if (!s) return ZERO32;
  if (s.startsWith('0x') && s.length === 66) return s;
  if (s.length === 64 && /^[0-9a-fA-F]+$/.test(s)) return '0x' + s;
  return keccak256Hex(s);
}
const _hash = _bytes32;

// Minimal keccak-256 over utf-8 — avoids pulling a dep for the memo/hashlock string path.
function keccak256Hex(s: string): string { return KEK(s); }

// hops7: [venue,tokenIn,tokenOut,feeTier,stable,venueRouter,factory]
function _hops7(hops: unknown): any[] {
  return _aslist(hops).map((h: any[]) => [h[0], _addr(h[1]), _addr(h[2]), h[3], !!h[4], _addr(h[5]), _addr(h[6])]);
}
// hops5: [venue,tokenIn,tokenOut,feeTier,venueRouter]
function _hops5(hops: unknown): any[] {
  return _aslist(hops).map((h: any[]) => [h[0], _addr(h[1]), _addr(h[2]), h[3], _addr(h[4])]);
}
function _hexToBig(x: unknown): bigint { return BigInt(x == null || x === '' ? 0 : (x as any)); }
'''

# keccak-256 over utf-8 — hand-rolled so the TS file pulls no crypto dep for the memo/hashlock
# string path. Vector-tested by verify.py §5 (keccak('') / keccak('abc') / keccak('hello')).
_TS_KEK = '''// keccak-256 (original padding, rate 136, 24 rounds) over utf-8 — no crypto dep needed.
const KEK_RC: bigint[] = [
  1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an,
  0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n,
];
const KEK_R: number[][] = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const KEK_M = 0xffffffffffffffffn;
function rotl(x: bigint, n: number): bigint {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & KEK_M;
}
function KEK(s: string): string {
  const bytes = new TextEncoder().encode(s);
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = 0x01;
  padded[padded.length - 1] |= 0x80;
  const st: bigint[] = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let v = 0n;
      for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(padded[off + i * 8 + b]);
      st[i] ^= v;
    }
    for (let round = 0; round < 24; round++) {
      const C: bigint[] = new Array(5);
      for (let x = 0; x < 5; x++) C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
      const D: bigint[] = new Array(5);
      for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] ^= D[x];
      const B: bigint[] = new Array(25).fill(0n);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[x + 5 * y], KEK_R[x][y]);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
      st[0] ^= KEK_RC[round];
    }
  }
  let out = '0x';
  for (let i = 0; i < 4; i++) {
    let v = st[i];
    for (let b = 0; b < 8; b++) { out += (v & 0xffn).toString(16).padStart(2, '0'); v >>= 8n; }
  }
  return out;
}'''


def _ts_fn(name: str, d: dict, spec, tools) -> str:
    params = d["parameters"]["properties"]
    # signature with defaults, matching the descriptor; params are `any` (JSON-schema types are loose)
    sig_parts = []
    for p, prop in params.items():
        if p == "token":
            sig_parts.append(f"{p}: any = USDC")
        elif "default" in prop:
            sig_parts.append(f"{p}: any = {json.dumps(prop['default'])}")
        else:
            sig_parts.append(f"{p}: any")
    c = spec.CALLS[name]

    if name == "escrow_release":
        seg = [
            "  const WHICH: Record<string, string> = {",
            "    release: 'release(bytes32)', refund: 'refund()',",
            "    arbiterRelease: 'arbiterRelease()', arbiterRefund: 'arbiterRefund()',",
            "  };",
            "  const s = WHICH[which] ?? WHICH.release;",
            "  const args: unknown[] = which === 'release' ? [_hash(preimage)] : [];",
            f"  const legs: Leg[] = [mkLeg(_addr(escrow), s, SEL_{name}[which] ?? SEL_{name}.release, args,",
            "                       'called on the ESCROW, not the factory')];",
        ]
        sels = {w: chain_sel(spec, s) for w, s in
                {"release": "release(bytes32)", "refund": "refund()",
                 "arbiterRelease": "arbiterRelease()", "arbiterRefund": "arbiterRefund()"}.items()}
        sel_decl = f"const SEL_{name}: Record<string, string> = {json.dumps(sels)};"
    elif name in ("stream_create", "subscribe"):
        fac = "g2a-streams" if name == "stream_create" else "g2a-subscriptions"
        sig2 = ("createStream(address,address,uint256,uint64,uint64)" if name == "stream_create"
                else "createStreamFor(address,address,address,uint256,uint64,uint64)")
        args2 = ("[recipient, token, _hexToBig(amount), _hexToBig(start), _hexToBig(end)]"
                 if name == "stream_create"
                 else "[payer, recipient, token, _hexToBig(amount), _hexToBig(start), _hexToBig(end)]")
        amt2 = "amount" if name == "stream_create" else "BigInt(amount) * BigInt(periods)"
        seg = [
            f"  const factory = ADDR['{fac}'];",
            f"  const approve = mkLeg(_addr(token), 'approve(address,uint256)', SEL_{name}_a, [factory, {amt2}]);",
            f"  const create = mkLeg(factory, {json.dumps(sig2)}, SEL_{name}_c, {args2});",
            "  const legs: Leg[] = [approve, create];",
        ]
        sel_decl = (f"const SEL_{name}_a = {json.dumps(chain_sel(spec, 'approve(address,uint256)'))};\n"
                    f"const SEL_{name}_c = {json.dumps(chain_sel(spec, sig2))};")
    elif name == "swap":
        seg = [
            "  const params = [_hexToBig(amount_in), _hexToBig(amount_out_min), _hops7(hops), _addr(recipient), _hexToBig(deadline)];",
            f"  const legs: Leg[] = [mkLeg(ADDR['p3-router'], {json.dumps(c['sigs'][0])}, {json.dumps(chain_sel(spec, c['sigs'][0]))}, [params],",
            "                       'fee is taken on INPUT; approve the router for amount_in')];",
        ]
        sel_decl = ""
    elif name == "sweep_dust":
        seg = [
            "  const mo = _aslist(min_out).map((x: any) => BigInt(x));",
            f"  const legs: Leg[] = [mkLeg(ADDR['f1c-duster'], {json.dumps(c['sigs'][0])}, {json.dumps(chain_sel(spec, c['sigs'][0]))}, [_aslist(tokens), _hops5(hops), mo],",
            "                       'zero fee by design; approve Permit2 first')];",
        ]
        sel_decl = ""
    else:
        # simple one-leg tools
        args = {
            "create_pay_link": "[_addr(destination), _addr(token), _hexToBig(amount), _bytes32(memo)]",
            "pay": "[_addr(destination)]",
            "escrow_create": "[_addr(counterparty), _addr(token), _hexToBig(amount), _bytes32(hashlock), _hexToBig(timeout)]",
            "sponsored_call": "[_addr(target), data]",
            "mint_receipt": "[_addr(escrow)]",
        }[name]
        seg = [f"  const legs: Leg[] = [mkLeg(ADDR['{c['to']}'], {json.dumps(c['sigs'][0])}, {json.dumps(chain_sel(spec, c['sigs'][0]))}, {args})];"]
        sel_decl = ""
    body = "\n".join(seg) + "\n  return legs;"
    doc = d["description"]
    # tool wrapper calls the plain fn with explicit named args (avoids the untyped-spread error)
    call_args = ", ".join(f"a.{p}" for p in params)
    return (
        f"// {name}: {c['verb']}\n"
        + (f"{sel_decl}\n" if sel_decl else "")
        + f"/** {doc} */\n"
        + f"export function {name}({', '.join(sig_parts)}): Leg[] {{\n{body}\n}}\n\n"
        + f"export const {name}_tool = tool({{\n"
        + f"  description: {json.dumps(doc)},\n"
        + f"  parameters: jsonSchema({json.dumps(d['parameters'])}),\n"
        + f"  execute: (a: any) => {name}({call_args}),\n"
        + "});\n"
    )


def gen_ts(tools: dict, spec) -> str:
    parts = [
        "// GENERATED by products/framework-plugins/gen.py from products/mcp-server (A1).\n"
        "// Regenerate: python3 products/framework-plugins/gen.py\n"
        "// Verify:     python3 products/framework-plugins/verify.py\n"
        "//\n"
        "// Thin Vercel-AI-SDK wrappers. Each money tool returns Leg[] — {to, sig, selector, args, data}\n"
        "// exactly like A1's server output (multi-leg tools emit their prerequisite first). `data` is\n"
        "// filled by a caller-supplied encoder (viem's encodeFunctionData with abi=[sig]); selectors are\n"
        "// keccak-derived by gen.py. `*_tool` is the AI-SDK tool(); `*` is the plain fn.\n"
        "import { jsonSchema, tool } from 'ai';\n\n"
        + _TS_HELPERS + "\n\n"
        "const ADDR: Record<string, string> = " + json.dumps(spec.ADDR, indent=2) + ";\n"
        "const USDC = " + json.dumps(spec.USDC) + ";\n\n"
        + _TS_KEK + "\n\n"
    ]
    for n in MONEY_TOOLS:
        parts.append(_ts_fn(n, tools[n], spec, tools))
    parts.append("export const TOOLS = { " + ", ".join(MONEY_TOOLS) + " };\n")
    parts.append("export const TOOLS_AI = { " + ", ".join(f"{n}_tool" for n in MONEY_TOOLS) + " };\n")
    return "".join(parts)


def chain_sel(spec, sig):
    from chain import selector
    return selector(sig)


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    spec = _load_spec()
    srv = _server_sources()
    tools = {}
    for n in ALL_TOOLS:
        if n not in srv:
            raise SystemExit(f"gen: tool {n} missing from A1 server.py")
        tools[n] = descriptor(n, srv[n], spec)
    for n in MONEY_TOOLS:
        c = spec.CALLS[n]
        tools[n]["x-callee"] = spec.ADDR[c["to"]]
        tools[n]["x-calls"] = [{"sig": s, "selector": chain_sel(spec, s)} for s in c["sigs"]]

    openai_obj = {
        "name": "dex-fleet",
        "description": "Non-custodial payment rails on Base (8453). Generated from products/mcp-server (A1).",
        "chain": {"name": "Base", "id": 8453},
        "usdc": spec.USDC,
        "tools": [tools[n] for n in ALL_TOOLS],
        "addresses": spec.ADDR,
        "spec": spec.SPEC_URL,
    }
    outputs = {
        "openai/tools.json": json.dumps(openai_obj, indent=2) + "\n",
        "langchain/fleet_tools.py": gen_python(tools, spec, "langchain"),
        "crewai/fleet_tools.py": gen_python(tools, spec, "crewai"),
        "vercel-ai/fleet.ts": gen_ts(tools, spec),
    }

    stale = []
    for rel, content in outputs.items():
        path = os.path.join(HERE, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        cur = open(path).read() if os.path.exists(path) else None
        if cur != content:
            stale.append(rel)
            if not args.check:
                open(path, "w").write(content)

    # POST-EMIT CALLEE GUARD. Two failures to catch, and they need DIFFERENT checks:
    #   (a) an UNKNOWN address literal (a typo, a foreign addr) → membership scan.
    #   (b) a WRONG-BUT-KNOWN address: e.g. pay pointing at g2b's factory (both are real addrs, so a
    #       membership scan alone MISSES it). That needs a POSITIONAL check: each money tool's emitted
    #       callee must equal the address its own `to` resolves to. This is the class that shipped.
    # Resolve ADDR ONCE here and assert the artifact carries exactly that, per tool.
    import re as _re
    resolved = dict(spec.ADDR)                      # frozen at emit time
    for n in MONEY_TOOLS:                           # 1) positional: tool → its own callee
        want = resolved[spec.CALLS[n]["to"]]
        got = tools[n].get("x-callee")
        if got is None or got.lower() != want.lower():
            raise SystemExit(f"gen: {n}.x-callee={got} != resolved {want} (stale callee)")
    # 2) the emitted ADDR map must be exactly the resolved map (no missing/extra/moved entry)
    if openai_obj["addresses"] != resolved:
        raise SystemExit("gen: tools.json addresses != resolved ADDR map")
    # 3) membership: no address literal anywhere may be outside {resolved values} ∪ {USDC}
    known = {a.lower() for a in resolved.values()} | {spec.USDC.lower()}
    bad = []
    for rel, content in outputs.items():
        for lit in set(_re.findall(r"0x[0-9a-fA-F]{40}", content)):
            if lit.lower() not in known:
                bad.append(f"{rel}: {lit}")
    if bad:
        raise SystemExit("gen: UNKNOWN address literal(s) in output (stale callee?): " + "; ".join(bad))
    # 4) the vercel-ai ADDR const must re-parse to the resolved map (positional, not just membership)
    import json as _json
    m = _re.search(r"const ADDR: Record<string, string> = (\{.*?\});", outputs["vercel-ai/fleet.ts"], _re.S)
    if not m or _json.loads(m.group(1)) != resolved:
        raise SystemExit("gen: vercel-ai ADDR const != resolved ADDR map")

    if args.check:
        print(("STALE: " + ", ".join(stale)) if stale else f"OK: {len(outputs)} files in sync with A1")
        return 1 if stale else 0
    print(f"wrote {len(outputs)} files" + (f" (changed: {', '.join(stale)})" if stale else " (no change)"))
    # INPUT FINGERPRINT: A1 is a shared, LIVE-edited surface (lane 2 extends server.py; the site owns
    # PRODUCTS.json). Print the md5 of the exact inputs this run consumed so a report can pin "generated
    # from THIS server.py/spec.py/PRODUCTS.json" — the artifacts' bytes alone can't show the input state.
    import hashlib as _h
    def _fh(p):
        return _h.md5(open(p, "rb").read()).hexdigest()[:12] if os.path.exists(p) else "absent"
    print("inputs: server.py=%s spec.py=%s PRODUCTS.json=%s"
          % (_fh(SERVER), _fh(os.path.join(A1, "spec.py")),
             _fh(_products_json())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
