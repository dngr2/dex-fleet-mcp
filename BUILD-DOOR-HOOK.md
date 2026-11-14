# /build/ — Door 3 hook (drop-in for the developer/agent door)

The Web Upgrade Spec's **Door 3 (developers and agents)** is a `/build/` page. When exec2's data
layer lands, paste the block below into its **agent line** verbatim. Nothing here drifts: the config
is the same one in `README.md`, `MERCHANT-START.md`, and the generated `site/llms.txt`.

Source of truth for the tool list: `server.py` (22 tools). Anti-drift gate: `selftest.py`.

---

## Door-3 copy block (paste under the "Agents" line)

**Agents — one line of config, no npm, no account.** The `dex-fleet` MCP server exposes every rail as
one tool (calldata for the ONE call, simulated dry-run by default). Add to any MCP client:

```json
{ "mcpServers": { "dex-fleet": {
  "command": "python3",
  "args": ["products/mcp-server/server.py"] } } }
```

Tools: `create_pay_link · pay · pay_x402 · escrow_create · escrow_release · stream_create ·
subscribe · disarm_mandate · swap · sweep_dust · sponsored_call · mint_receipt · read_fee` (live bps per
contract) plus read-only helpers (`read_capabilities`, `read_402_challenge`, `server_info`).
Spec/agent map: `/llms.txt` · catalog: `/PRODUCTS.json` · build: `products/mcp-server/`.

---

## Build, don't retype (the door-3 constants)

| thing | value (COPY — never retype; GOTCHA #73) |
|---|---|
| chain | Base mainnet (chainId 8453) |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (6 dp) |
| treasury | `0xe218E382F28A094f9f64E903ee3cb1750A7f204B` |
| contracts / selectors | `PRODUCTS.json` + the `call:` lines in `llms.txt` (both already keccak-derived) |
| agent map | `/llms.txt` |
| Sourcify links | per-product, on each product page |

## Optional: /.well-known/ai-plugin.json (spec §"once it exists")

The spec asks for `.well-known/ai-plugin.json`-style metadata pointing at the MCP server once it
exists — **it exists now** (`products/mcp-server/`). Shape to emit at site root:

```json
{
  "schema_version": "v1",
  "name_for_human": "DEX fleet — non-custodial payment rails on Base",
  "name_for_model": "dex_fleet",
  "description_for_model": "Non-custodial payment rails on Base (chainId 8453). One MCP tool per product; each returns the calldata for the product's ONE money call and simulates it by default. No account, no API key, no server holds funds.",
  "api": { "type": "mcp", "url": "products/mcp-server/server.py" },
  "spec": "https://dngr2.github.io/dex-products/llms.txt",
  "catalog": "https://dngr2.github.io/dex-products/PRODUCTS.json"
}
```
