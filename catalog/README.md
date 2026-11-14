# catalog/ — a POINT-IN-TIME snapshot, not a live fetch

These two files (`PRODUCTS.json`, `llms.txt`) are a **dated copy** of the site's published catalog,
vendored so the drift gates here (`selftest.py`, `plugins/*`) can diff against the spec **offline, on
a clone** without reaching the network.

**The hazard to remember:** because they are a snapshot, a redeploy that moves live addresses can
leave this repo **green against a stale catalog** while the live `PRODUCTS.json` has already moved —
stale-resolve-reads-as-authority (GOTCHA #208 family). The gates are real, but they prove agreement
with *this copy*, not with the live site.

**When addresses change, one command re-vendors everything:** `python3 tools/sync-addresses.py` in the
monorepo rewrites `fleet_addr/addresses.json` and its SHA-256 pin in `spec.py`; `publish.sh` refreshes
this directory in the same push. Nothing here is hand-edited.

Snapshot taken 2026-11-14T01:53Z, PRODUCTS.json md5 `70644208c4…`.
