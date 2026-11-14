<!-- published from products/mcp-server — DO NOT EDIT HERE; edit the monorepo and re-run publish.sh -->

# dex-fleet MCP server

**An agent gets live, non-custodial payment rails on Base in one line of config. No API key, no account, no server holding funds.**

This is a thin, read-only MCP wrapper over the live fleet products — 13 money verbs across the rails
plus 7 read-only helpers. A money tool builds the exact calldata for the product's money verb and, by
default, **simulates it** (`eth_call`) so the agent sees the result before anything is signed.
Nothing here signs or broadcasts — a wallet layer does that. 22 tools total.

State reads go through a **quorum**: the same call at several endpoints, and only a JSON-identical
`QUORUM` (default 2) is an answer — a single endpoint's lie or a bare 429 body is never taken as truth,
and a split answer comes back flagged `ambiguous` rather than silently resolved. Immutable reads are
cached 8 s; a call carrying a state override never is.

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

Deps: `mcp`, `eth_abi`, `eth_utils`, `httpx` (all already present in this environment). Or install the
package instead of pointing at a checkout — `uvx dex-fleet-mcp`, or `pip install dex-fleet-mcp` then
`dex-fleet-mcp`. The generated framework front doors live in `plugins/`; the registry manifest is
`server.json`.

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
| `subscribe` | g2a-subscriptions | approve + **setMandate** (the bounded authorization: ticket, period, laps, t0) + first lap, all signed by the payer; returns a `revoke` block |
| `disarm_mandate` | g2a-subscriptions | full undo: disarmMandate + approve(0) on the old **and** live factory |
| `pay_x402` | x402 | **the agent entry point**: `url=` fetches the 402, parses the challenge and returns rail `pay` → `markPaid` → `verify` + the `X-PAYMENT` retry; `payment_id=` gives the post-settlement pair alone |
| `read_402_challenge` | x402 | READ: fetch a URL and show its 402 challenge, nothing paid |
| `read_capabilities` | all | READ: balance / allowance / paused / isKeeper / isWriter per leg, with a verdict |
| `swap` | p3-router | swapExactTokensForTokens (hops handed in) |
| `quote_swap` | p3-router | READ: UniV3 amountOut per hop + fee → pick amount_out_min |
| `sweep_dust` | f1c-duster | funnel scattered dust → USDC in one tx |
| `quote_sweep` | f1c-duster | READ: same quote, zero-fee duster → minOut |
| `sponsored_call` | fleet-executor | signed-intent EIP-7702 batch (relay pays gas) |
| `mint_receipt` | g4b-receipts | mint the proof-of-payment NFT for a settled escrow |
| `read_fee` | all | **live** fee per contract |
| `read_x402_status` | x402 | READ: is a paymentId settled, to whom, how much |
| `server_info` | — | product map, addresses, spec URL |

Every money tool takes `dry_run` (default `true`). `read_fee` always reads live `feeBps()` per contract
and never cross-reads p3's `MAX_FEE_BPS` (which is `10000`, a denominator — GOTCHA #144).

## Resources

Three MCP resources, so an agent can pull state without burning a tool call: `fleet://addresses` (the
whole pinned book + treasury + its hash), `fleet://fees` (live `feeBps()` per contract) and
`fleet://status` (head, RPC health, quorum/dissent, and an explicit `degraded` flag).

Money tools carry a **spending guard**: an amount far outside the expected decimal class, an amount over
your own `max_amount`, or a zero/absurd amount comes back in `warnings` (never a hard stop). The per-call
ceiling is `MCP_MAX_USDC` (default 1000 USDC; `0` disables it). `read_capabilities` is the matching
pre-flight — it answers "will this leg revert?" in the same currency as the revert.

## Install (pinned) and prove it locally

```bash
python3 -m venv .venv && .venv/bin/pip install -e .   # exact pins from pyproject.toml
.venv/bin/python selftest.py          # offline drift gate: every selector re-derives, book hash matches
.venv/bin/python dryrun.py --nosim    # build calldata for every tool, offline
.venv/bin/python dryrun.py            # simulate every tool (needs RPC)
```

Dependencies are pinned exactly (a silent `eth_abi` bump changes encoded bytes) and CI runs this gate
on 3.11 and 3.12 with a PASS-count floor. `selftest.py` is the anti-drift gate (GOTCHA #131 family): it
re-derives **every** published `(sig, selector)` pair from `site/llms.txt` via keccak, checks the
vendored address book against its SHA-256 pin, and cross-checks it against `PRODUCTS.json`. Nothing in
the tool surface or the address set is hand-typed.

**Addresses.** `spec.py` reads the SDK's address book (`products/sdk/addresses.json`), vendored at
`fleet_addr/addresses.json` and hash-pinned. A mismatch REFUSES to import. After a redeploy:
`python3 tools/sync-addresses.py` (monorepo) or edit nothing by hand.

## Files

| file | role |
|---|---|
| `chain.py` | selector + ABI encoding + quorum `eth_call` with the TTL cache and state-override support (offline-tolerant; a dead RPC is an ERROR, never a silent 0) |
| `spec.py` | the ONE pin point: addresses from the hash-pinned SDK book (GOTCHA #73), sig strings verbatim from `llms.txt` |
| `fleet_addr/addresses.json` | vendored, SHA-256-pinned address book (regenerate: `tools/sync-addresses.py`) |
| `server.py` | the MCPServer + 22 tools |
| `dryrun.py` | call every tool once |
| `selftest.py` | drift gate |
| `publish.sh` | stage + gate + force-push the public mirror (`--dry-run` to stop before the push) |
| `server.json` | MCP registry manifest (PyPI package, stdio transport) |
| `fleet://addresses` · `fleet://fees` · `fleet://status` | resources: the pinned address book, live fees, head/quorum health |
