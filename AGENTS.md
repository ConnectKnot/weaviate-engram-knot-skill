# Contributor and Agent Guide

Rules for editing this repository:

1. **Zero external dependencies:** All Python CLI scripts (`skills/engram-to-knot-migration/scripts/migrate_engram.py`), SDK adapters (`sdk/engram_knot_compat.py`), and tests (`tests/`) must use Python 3.10+ standard library only. TypeScript SDK code (`sdk/engram-knot-compat.ts`) uses zero-dependency standard `fetch`.
2. **Read-only Engram exports:** Never issue `DELETE`, `PUT`, or mutating requests against Weaviate Engram (`https://api.engram.weaviate.io`). Exports are strictly read-only (`GET /v1/groups` and `POST /v1/memories/search` with `retrieval_type: "fetch"`).
3. **Config security invariant:** Never execute `{"cmd": ...}` dynamic property sources from repo-local `./.engram.json`. Log a warning, drop the key, and continue with literal properties only.
4. **Client-side secret and PCI scrubbing:** Always scrub credentials, private keys, JWTs, and Luhn-validated payment card numbers locally before writing bundle JSON or sending data to any remote endpoint, while preserving git commit SHAs and UUIDv4 trace IDs.
5. **Formatting:** Use zero Unicode em-dashes (`\u2014`) in `.md`, `.json`, `.py`, `.ts`, or `.yml` files. Use plain sentences, colons, parentheses, or `->` for arrows.
6. **Verification:** Run the full test suite and offline bundle dry-run before every commit:
   ```bash
   python3 -m unittest discover -s tests -v
   python3 skills/engram-to-knot-migration/scripts/migrate_engram.py --from-file examples/sample-engram-export.json --dry-run --output /tmp/sample-bundle.json
   rm -f /tmp/sample-bundle.json
   ```
