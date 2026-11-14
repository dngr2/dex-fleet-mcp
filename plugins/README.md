# A4 — framework plugins, generated FROM A1

Four front doors to the same payment surface, **generated** from `products/mcp-server` (A1) so they
cannot drift from the agent protocol or the contracts. Nothing here is hand-typed: `gen.py` reads
A1's `server.py` (tool names, params, descriptions — via AST) and `spec.py` (pinned sigs + addresses),
and emits all four. The calldata is always built the same way A1 builds it.

```
python3 gen.py           # regenerate all four artifacts
python3 gen.py --check   # exit 1 if any is stale (staleness gate)
python3 verify.py        # the drift gate — 46 checks, 0 failed
```

## What it emits

| file | framework | shape |
|---|---|---|
| `vercel-ai/fleet.ts` | Vercel AI SDK | `tool({...})` wrappers **+ plain functions** returning `Leg[]` |
| `langchain/fleet_tools.py` | LangChain | `StructuredTool` wrappers |
| `crewai/fleet_tools.py` | CrewAI | `@tool` wrappers |
| `openai/tools.json` | OpenAI function-calling | the shared wire schema (+ `x-callee` / `x-calls` pins) |

The four share ONE descriptor. A stranger copies **one file** — `vercel-ai/fleet.ts` — points it at
their rail, and gets a tolled call: each money tool returns the exact legs to send, prerequisite first
(e.g. `stream_create` emits `approve` then `createStream`). `subscribe` emits **three**: allowance →
`setMandate` (the bounded authorization) → first lap, and hangs the undo off `revoke`.

## The one plugin — `vercel-ai/fleet.ts`

Self-contained (one import, `ai`; no crypto dep). `useEncoder(encodeFunctionData)` from your own
viem client fills `.data`; without it `.to / .sig / .selector / .args` are still present. Every tool
mirrors A1's output leg-for-leg — `data` omitted only because the encoder is caller-supplied.

## Selector provenance — how the plugin stays valid across the v2 deploy

**Every selector is derived, never retyped.** `gen.py` derives each from the sig with `eth_utils.keccak`;
`verify.py` §5 re-derives the same selectors with an **outside authority — foundry's `cast sig`** — and
fails if the two ever disagree. So no selector in the emitted files is a transcription.

The v2 deploy **preserves selectors deliberately**, so a plugin built now stays valid through it:

```
setFeeBps(uint16)         0x023b1fc9
setMinFee(uint256)        0x31ac9920
setFeeRecipient(address)  0xe74b981b
```

`verify.py` §5 pins these three **verbatim** — the README claim is a checked fact, not prose. Note the
arg **width** matters: `setFeeBps` is `uint16`. Retyping `setFeeBps(uint256)` silently yields
`0x72c27b62` — a different selector that a node would reject. Derive, do not retype; §5 catches it.

The calldata authority is the SDK (`products/sdk/src`) / A1's `chain.build_call`; the plugin re-encodes
nothing. Lane-10 rule applies: settled predicate is `paid(id).at != 0` / `isPaid()`, never `amount>0`.

## What the gate proves (`verify.py`, 46 checks)

1. Every generated tool's calldata == A1's own `server.py` output — byte-for-byte, all 10 tools,
   with `subscribe.revoke` compared separately (it rides outside `calls` on both sides).
2. Every `openai/tools.json` selector re-derives from the A1 sig (keccak) + callee == A1 address.
3. `gen.py --check` — files in sync with A1.
3b. **Staleness guard has teeth** — a wrong-but-known callee (the p2→g2b class) makes `gen.py --check`
   redden; a regen restores it. The guard is `gen.py`'s own, proven by this negative test.
4. Every selector/address literal in `fleet.ts` is A1-derived.
5. **Provenance** — every A1 sig's keccak == `cast sig`; every TS literal == a `cast sig`; the three
   deploy-preserved setters re-derive.
6. **Cross-language** — `fleet.ts` transpiles (`tsc` rc 0); its OWN emitted args re-encode through A1's
   encoder to **byte-identical** calldata for all 10 tools; `_bytes32(str)` == `eth_utils.keccak`
   (the hand-rolled KEK is real keccak, so string memos hash right).
7. The crewai flavor imports and agrees with A1; `openai/tools.json` is well-formed with callee pins.

## Callee integrity (why a wrong address can't ship)

A generated artifact once mapped `p2-forwarder` to the **g2b EscrowFactory** address — both are real
A1 addresses, so a naive "is every literal a known address?" scan misses it. `gen.py` now fails at emit
time on three independent checks, all positional (not just membership):

- each money tool's `x-callee` must equal the address its own `to` resolves to;
- the emitted `addresses` map must equal the resolved map exactly (no missing/extra/moved entry);
- the vercel-ai `ADDR` const must re-parse to that same map.

Plus a membership scan (unknown literal = fail) and an outer guard that `spec.ADDR` agrees with
`PRODUCTS.json` read directly, so a stale module can't silently hand back an old map. `gen.py` prints
an **input fingerprint** (md5 of `server.py`/`spec.py`/`PRODUCTS.json`) so a report can name the exact
A1 state an artifact came from — A1 is a shared surface edited by other lanes.

## Limits

`vercel-ai/fleet.ts` needs `ai` + a `jsonSchema` at the call site (AI SDK ≥ v4). The other three are
import-time-safe without the framework (they degrade to plain functions if it's absent). Nothing
deployed. Owner addresses are A1's `spec.ADDR`, resolved from the hash-pinned SDK address book.
