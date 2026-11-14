#!/usr/bin/env bash
# publish.sh — mirror THIS server to the public repo `dngr2/dex-fleet-mcp`.
#
# WHY (round-5 audit): the public repo was HAND-BUILT and had drifted six ways from the tree — 562
# lines vs 1008, no setMandate, no quorum, a hand-copied address dict, no x402 tool, no pyproject.
# Two of the four audit rows were "the published repo is not the tree", and no script existed to make
# it one. This is that script: the published tree is a BUILD of this directory, never an edit of it.
#
# LAYOUT: modules at the repo root, `catalog/` (the point-in-time spec snapshot the offline gates
# diff against) and `plugins/` (the generated A4 front doors). gen.py/verify.py resolve A1 as `..`
# from `plugins/`, so they run unchanged in the published clone — and the gate step below proves it
# before anything is pushed.
#
#   bash publish.sh              # stage, gate, commit, force-push
#   bash publish.sh --dry-run    # stage and gate, no push
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPO_SLUG="${REPO_SLUG:-dngr2/dex-fleet-mcp}"
STAGE="${STAGE:-/tmp/dex-fleet-mcp-stage}"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

[ -d "$ROOT/../fleet-shared/docs" ] || { echo "REFUSING: no fleet-shared/docs" >&2; exit 1; }

# 1. stage — an explicit file list, so a stray .venv/ or egg-info can never ride along
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp "$HERE"/{server.py,chain.py,spec.py,dryrun.py,selftest.py,README.md,LICENSE,pyproject.toml,publish.sh,server.json} "$STAGE"/
cp "$HERE"/MCP-FIX-2026-11-10.md "$HERE"/BUILD-DOOR-HOOK.md "$STAGE"/
cp -r "$HERE"/fleet_addr "$STAGE"/
mkdir -p "$STAGE/.github/workflows"
cp "$HERE"/.github/workflows/selftest.yml "$STAGE/.github/workflows/"
rm -rf "$STAGE"/fleet_addr/__pycache__

# 2. plugins/ — the generated front doors, verbatim from the generator's output dir
mkdir -p "$STAGE/plugins"
cp -r "$ROOT"/products/framework-plugins/. "$STAGE/plugins/"
find "$STAGE/plugins" -name __pycache__ -type d -prune -exec rm -rf {} +

# 3. catalog/ — the SAME files the offline gates read: the built site's llms.txt and PRODUCTS.json.
#    PRODUCTS.json is the repo's one edit point; llms.txt is the built agent map.
SITE="$ROOT/products/dex-site/site"
[ -f "$SITE/llms.txt" ] && [ -f "$ROOT/products/dex-site/PRODUCTS.json" ] || {
  echo "REFUSING: site build or PRODUCTS.json absent — catalog/ would be stale-by-construction" >&2; exit 1; }
mkdir -p "$STAGE/catalog"
cp "$SITE/llms.txt" "$STAGE/catalog/llms.txt"
cp "$ROOT/products/dex-site/PRODUCTS.json" "$STAGE/catalog/PRODUCTS.json"
cat > "$STAGE/catalog/README.md" <<EOF
# catalog/ — a POINT-IN-TIME snapshot, not a live fetch

These two files (\`PRODUCTS.json\`, \`llms.txt\`) are a **dated copy** of the site's published catalog,
vendored so the drift gates here (\`selftest.py\`, \`plugins/*\`) can diff against the spec **offline, on
a clone** without reaching the network.

**The hazard to remember:** because they are a snapshot, a redeploy that moves live addresses can
leave this repo **green against a stale catalog** while the live \`PRODUCTS.json\` has already moved —
stale-resolve-reads-as-authority (GOTCHA #208 family). The gates are real, but they prove agreement
with *this copy*, not with the live site.

**When addresses change, one command re-vendors everything:** \`python3 tools/sync-addresses.py\` in the
monorepo rewrites \`fleet_addr/addresses.json\` and its SHA-256 pin in \`spec.py\`; \`publish.sh\` refreshes
this directory in the same push. Nothing here is hand-edited.

Snapshot taken $(date -u +%Y-%m-%dT%H:%MZ), PRODUCTS.json md5 \`$(md5sum "$STAGE/catalog/PRODUCTS.json" | cut -c1-10)…\`.
EOF

# 4. repo furniture
cat > "$STAGE/.gitignore" <<'EOF'
__pycache__/
*.pyc
.venv/
*.egg-info/
EOF

HEADER='<!-- published from products/mcp-server — DO NOT EDIT HERE; edit the monorepo and re-run publish.sh -->

'
printf '%s' "$HEADER" | cat - "$STAGE/README.md" > "$STAGE/README.md.new" && mv "$STAGE/README.md.new" "$STAGE/README.md"

# 5. .env must never ship
if find "$STAGE" -name '.env' | grep -q .; then echo "REFUSING: a .env is inside the stage" >&2; exit 1; fi

# 6. secret gate over the SOURCE dirs this stage was built from
echo "— secret gate —"
bash "$ROOT/tools/secret-scan.sh" "$ROOT/products/mcp-server" "$ROOT/products/framework-plugins" || {
  echo "REFUSING: secret-scan FAILED — register with 'bash tools/secret-scan.sh --update'" >&2; exit 1; }
if command -v gitleaks >/dev/null 2>&1; then
  for d in "$HERE" "$ROOT/products/framework-plugins"; do
    gitleaks detect --no-git --source "$d" --config "$ROOT/tools/ci/gitleaks.toml" --redact >/dev/null 2>&1 \
      || { echo "REFUSING: gitleaks found a secret in $d" >&2; exit 1; }
  done
  echo "gitleaks: clean"
fi

# 7. GATE THE STAGE, IN THE STAGE — the published clone's own layout, not this one. A gate that only
#    passes from the author's tree proves nothing about what is about to be public.
echo "— gate (a) address book hash —"
( cd "$STAGE" && python3 - <<'PY'
import hashlib, re, sys
pin = re.search(r'_ADDR_SHA256 = "([0-9a-f]{64})"', open("spec.py").read()).group(1)
have = hashlib.sha256(open("fleet_addr/addresses.json", "rb").read()).hexdigest()
print(f"pin {pin}\nhave {have}")
sys.exit(0 if pin == have else 1)
PY
)  || { echo "REFUSING: vendored address book does not match its pin" >&2; exit 1; }

echo "— gate (b) selftest —"
( cd "$STAGE" && python3 selftest.py > /tmp/publish-selftest.log 2>&1 ) || {
  echo "REFUSING: selftest RED — see /tmp/publish-selftest.log" >&2; tail -20 /tmp/publish-selftest.log >&2; exit 1; }
N_PASS="$(grep -c '^\[PASS\]' /tmp/publish-selftest.log || true)"
echo "  $N_PASS PASS rows"
[ "$N_PASS" -ge 20 ] || { echo "REFUSING: only $N_PASS PASS rows (floor 20)" >&2; exit 1; }

echo "— gate (c) plugins: gen --check + verify —"
( cd "$STAGE/plugins" && python3 gen.py --check && python3 verify.py | tail -2 ) || {
  echo "REFUSING: generated plugins are stale or drift from A1 in the stage" >&2; exit 1; }

echo "— gate (d) calldata for every tool, offline —"
( cd "$STAGE" && python3 dryrun.py --nosim | tail -1 ) | tee /tmp/publish-dryrun.log
grep -q "22/22" /tmp/publish-dryrun.log || { echo "REFUSING: not every tool built calldata" >&2; exit 1; }

echo "— gate (e) the marker: the four audited fixes are IN the stage —"
for pat in 'def setMandate\|setMandate(' 'QUORUM' 'def pay_x402' 'feeBps' ; do
  grep -rq "$pat" "$STAGE"/server.py "$STAGE"/chain.py "$STAGE"/spec.py || {
    echo "REFUSING: marker pattern '$pat' absent from the stage" >&2; exit 1; }
done
echo "  setMandate / quorum / pay_x402 / live feeBps all present"

# 8. commit, then push.
#
# MIRROR SEMANTICS WITHOUT --force: `main` on this repo has branch protection with
# allow_force_pushes=false (measured 2026-11-14), so a freshly-`git init`-ed stage can never push —
# it shares no history. The stage TREE stays the whole truth; only the PARENT comes from the remote:
# fetch main, soft-reset HEAD onto it (index and worktree untouched), `git add -A` so local deletions
# are recorded too, and commit. The result is a fast-forward whose tree is exactly this stage.
cd "$STAGE"
git init -q -b main
git remote add origin "git@github.com:${REPO_SLUG}.git" 2>/dev/null || \
  git remote set-url origin "git@github.com:${REPO_SLUG}.git"
PARENT_NOTE=""
if git fetch -q origin main 2>/dev/null && git rev-parse -q --verify FETCH_HEAD >/dev/null; then
  git reset -q --soft FETCH_HEAD
  PARENT_NOTE=" (parent $(git rev-parse --short FETCH_HEAD) from origin/main)"
else
  echo "  warn: origin/main unfetched — pushing an orphan commit (needs force on a protected branch)" >&2
fi
git add -A
git -c user.name="dngr2" -c user.email="dngr2@users.noreply.github.com" commit -q -m "$(cat <<EOF
mcp: publish the tree — quorum, setMandate, live feeBps, pay_x402, pinned deps

Rebuilt from the monorepo source by products/mcp-server/publish.sh. The published copy had drifted
562 lines behind on server.py and carried a hand-copied address dict; both are now build artifacts.

- addresses come from the hash-pinned SDK book (fleet_addr/), import REFUSES on mismatch
- quorum reads (2 of 3) with agree/dissent grading; a lone answer is never an answer
- subscribe arms a setMandate with the ticket/period/laps bounds; disarm_mandate is the undo
- pay_x402(url) parses the 402 challenge and returns pay -> markPaid -> verify + the retry
- pyproject pins mcp/httpx/eth-abi; CI runs selftest on 3.11 + 3.12 with a PASS floor

Co-Authored-By: Claude Code <noreply@anthropic.com>
EOF
)"
SHA="$(git rev-parse HEAD)"
echo "staged $SHA ($(git ls-files | wc -l) files)$PARENT_NOTE"

if [ "$DRY" = 1 ]; then echo "DRY RUN — staged at $STAGE, not pushed."; exit 0; fi

gh repo view "$REPO_SLUG" >/dev/null 2>&1 || gh repo create "$REPO_SLUG" --public \
  --description "dex-fleet MCP server — non-custodial payment rails on Base for agents"
git push -q origin main
echo "pushed $REPO_SLUG@$SHA"
