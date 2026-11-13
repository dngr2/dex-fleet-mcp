<!-- published as dngr2/dex-fleet-mcp — a copy of products/mcp-server (+ generated products/framework-plugins) -->

> **Source-only — nothing here is deployed.** The server is a thin, read-only MCP wrapper: it builds
> calldata for the **LIVE Base mainnet** contracts and (by default) *simulates* it. Addresses live in
> `spec.py`, copied from the vendored `catalog/PRODUCTS.json` — never retyped.
>
> **`plugins/` is GENERATED from this repo's `mcp-server` (AKA "A1").** Do not hand-edit it — run
> `python3 plugins/gen.py`; the drift gate is `python3 plugins/verify.py`. Generation is what keeps
> the four framework front-doors from drifting off the agent protocol.
>
> **`catalog/` is a POINT-IN-TIME copy of the live spec (taken 2026-11-13), NOT a live fetch** — see
> `catalog/README.md`. The gates prove agreement with that snapshot, so a redeploy that moves
> addresses can leave this repo green against a stale copy (GOTCHA #208). When addresses change, bump
> `spec.py`'s pins **and** `catalog/` in the same commit, then re-push.

# dex-fleet MCP server

**An agent gets live, non-custodial payment rails on Base in one line of config. No API key, no account, no server holding funds.**

This is a thin, read-only MCP wrapper over the live fleet products — the nine money rails plus five
read-only helpers. Each tool builds the exact calldata for the product's ONE money verb and, by
default, **simulates it** (`eth_call`) so the agent sees the result before anything is signed.
Nothing here signs or broadcasts — a wallet layer does that.

**Addresses track the LIVE v2 line** (Base): the v2.1 g2a StreamFactory `0x8f26d7a5…fa19`, the v2
g2b EscrowFactory / p2 Registry / p3 Router / f1a RequestRegistry. `subscribe` also returns a
`revoke` leg against the **PAUSED** v1 factory so a pre-migration allowance can be cleared.

Spec: <https://dngr2.github.io/dex-products/llms.txt> · catalog: <https://dngr2.github.io/dex-products/PRODUCTS.json>

## Install (one line)

```jsonc
// ~/.config/claude/claude_desktop_config.json  (or any MCP client config)
{ "mcpServers": { "dex-fleet": {
  "command": "python3",
  "args": ["/home/toor/dex/products/mcp-server/server.py"] } } }
```

> Run with plain `python3` (NOT `python3 -I`): the `mcp` package lives in user-site, which `-I` excludes.

Deps: `mcp`, `eth_abi`, `eth_utils`, `httpx` (all already present in this environment).

## Tools (mirror llms.txt 1:1)

| tool | product | does |
|---|---|---|
| `create_pay_link` | f1a-payment-links | mint a request → deposit address + shareable PAYER link |
| `resolve_pay_link` | f1a-payment-links | READ a receipt → real link (if you didn't capture the return) |
| `register_deposit_address` | p2-forwarder | register-only: your personal auto-forward deposit address |
| `pay` | p2-forwarder | the real two-step: register(destination) then transfer(token, deposit, amount) |
| `escrow_create` | g2b-escrow | lock funds against a hashlock/arbiter |
| `escrow_new_secret` | g2b-escrow | OFFLINE: fresh {preimage, hashlock} — pass hashlock to create, preimage to release |
| `escrow_release` | g2b-escrow (instance) | release / refund / arbiterRelease / arbiterRefund |
| `stream_create` | g2a-streams | approve + createStream (vesting payment) |
| `subscribe` | g2a-subscriptions | one bounded approve = the whole mandate (+ v1 revoke leg) |
| `swap` | p3-router | swapExactTokensForTokens (hops handed in) |
| `quote_swap` | p3-router | READ: UniV3 amountOut per hop + fee → pick amount_out_min |
| `sweep_dust` | f1c-duster | funnel scattered dust → USDC in one tx |
| `quote_sweep` | f1c-duster | READ: same quote, zero-fee duster → minOut |
| `sponsored_call` | fleet-executor | signed-intent EIP-7702 batch (relay pays gas) |
| `mint_receipt` | g4b-receipts | mint the proof-of-payment NFT for a settled escrow |
| `read_fee` | all | **live** fee per contract |
| `server_info` | — | product map, addresses, spec URL |

Every money tool takes `dry_run` (default `true`). `read_fee` always reads live `feeBps()` per contract
and never cross-reads p3's `MAX_FEE_BPS` (which is `10000`, a denominator — GOTCHA #144).

## Prove it locally

```bash
cd products/mcp-server
python3 selftest.py          # offline drift gate: every published selector re-derives from keccak
python3 dryrun.py            # simulate every tool (needs RPC)
python3 dryrun.py --nosim    # build calldata only, offline
```

`selftest.py` is the anti-drift gate (GOTCHA #131 family): it re-derives **every** published
`(sig, selector)` pair from `site/llms.txt` via keccak and diffs the pinned addresses against
`PRODUCTS.json`. Nothing in the tool surface is hand-typed.

## Files

| file | role |
|---|---|
| `chain.py` | selector + ABI encoding + one read-only `eth_call` (offline-tolerant; a dead RPC is an ERROR, never a silent 0) |
| `spec.py` | the ONE pin point: addresses COPIED from `PRODUCTS.json` (GOTCHA #73), sig strings verbatim from `llms.txt` |
| `server.py` | the MCPServer + 17 tools |
| `dryrun.py` | call every tool once |
| `selftest.py` | drift gate |
