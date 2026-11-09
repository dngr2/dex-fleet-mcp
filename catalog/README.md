# catalog/ — a POINT-IN-TIME snapshot, not a live fetch

These two files (`PRODUCTS.json`, `llms.txt`) are a **dated copy** of the site's published catalog,
vendored so the drift gates here (`selftest.py`, `plugins/*`) can diff against the spec **offline, on
a clone** without reaching the network.

**The hazard to remember:** because they are a snapshot, a redeploy that moves live addresses can
leave this repo **green against a stale catalog** while the live `PRODUCTS.json` has already moved —
stale-resolve-reads-as-authority (GOTCHA #208 family). The gates are real, but they prove agreement
with *this copy*, not with the live site.

**When addresses change (e.g. the v2 factories fire), bump BOTH in the same commit:**
`spec.py`'s `_PINNED` map **and** `catalog/PRODUCTS.json` (and `catalog/llms.txt` if sigs move), then
re-push. Whoever owns the redeploy should send the new addresses; re-run the cold-clone gate after.

Snapshot taken 2026-11-09 (matches `spec.py` at commit `83eed74`).
