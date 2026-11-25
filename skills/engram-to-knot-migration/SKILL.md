---
name: engram-to-knot-migration
description: Migrate Weaviate Engram memories into Knot safely (read-only Engram export, local secret and PCI scrubbing, chronological v1 -> v2 supersession chaining, and OAuth 2.1 MCP or REST import) or guide 1-line SDK replacement with EngramKnotCompatClient.
---

# Engram to Knot Migration

Use this skill when a user wants to export memories out of Weaviate Engram (before the December 31, 2026 sunset) and bring governed, conflict-resolved context into Knot across Claude Code, Cursor, Kiro, Codex, ChatGPT, or Gemini.

## Safety and Security Invariants

1. **Read-only on Engram:** `migrate_engram.py` only issues `GET /v1/groups` and `POST /v1/memories/search` (`retrieval_type: "fetch"`). It never calls `DELETE` on Engram.
2. **Repo-local config protection:** If `./.engram.json` contains any `{"cmd": ...}` dynamic property source, `migrate_engram.py` refuses and drops it with a clear warning so cloned repositories cannot execute arbitrary shell commands.
3. **Local scrubbing before egress:** AWS keys, OpenAI/Anthropic/Stripe keys, GitHub tokens, Slack tokens, PEM private keys, Bearer JWTs, high-entropy `SECRET`/`TOKEN`/`PASSWORD`/`API_KEY` assignments, and Luhn-valid 13-19 digit payment card PANs are redacted locally (`[REDACTED_SECRET]`, `[REDACTED_PAN]`) while keeping git commit SHAs and UUIDv4 IDs intact.

## Workflow A: Zero-Key IDE Migration via OAuth 2.1 MCP (Recommended)

When your IDE already has the Knot MCP server (`https://api.connectknot.com/mcp`) connected via OAuth 2.1, you never need to copy any Knot API keys or access tokens.

1. Run the local exporter/compiler in dry-run mode:
   - Offline sample or exported JSON/JSONL file:
     ```bash
     python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
       --from-file examples/sample-engram-export.json \
       --dry-run \
       --output engram-knot-migration-bundle.json
     ```
   - Live Weaviate Engram read-only export (reads `ENGRAM_API_KEY` or pass `--api-key`; add `--read-shell-profile` only if the user opts in to reading shell profile files):
     ```bash
     python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
       --dry-run \
       --output engram-knot-migration-bundle.json
     ```
   - Optional filters: `--group <name>`, `--topic <name>`, `--user-id <id>`, `--property KEY=VAL`, `--entity-hint <project>`, `--limit 500`, `--personal-preferences-as-project`.
2. Read `engram-knot-migration-bundle.json` and review `summary` (`compiled_records`, `v1_batch_items`, `supersession_items`, `secrets_scrubbed`, `pans_scrubbed`) and `warnings` with the user.
3. Import baseline (`v1`) items using Knot MCP `batch_propose_context`:
   - Execute each entry in `mcp_batches` in order (each batch has at most 25 items).
   - Map each returned `direct_items[i].context_id` to `item_idempotency_keys[i]`.
4. Import superseding (`v2+`) items using Knot MCP `propose_context`:
   - Execute each entry in `mcp_supersessions` in chronological order.
   - Replace the placeholder `supersedes_context_id` in `arguments` with the UUID recorded for `supersedes_idempotency_key`.
   - Store the newly returned `context_id` under `idempotency_key` in case a `v3` record supersedes `v2`.
5. Explain destination behavior clearly:
   - `fact`, `decision`, `constraint`, `goal`, and `project_state` with `entity_hint` are available immediately across connected AIs via `get_relevant_context`.
   - `preference` items enter the user's Knot pending approval queue (`Your Knot`) unless `--personal-preferences-as-project` was requested.

## Workflow B: Direct CLI Push (`--push`)

For headless scripts or Knot EnterpriseBrain self-hosted deployments:

- **Push to Knot MCP:**
  ```bash
  python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
    --from-file engram-export.json \
    --push --target mcp \
    --knot-mcp-token "$KNOT_ACCESS_TOKEN"
  ```
- **Push to Knot EnterpriseBrain REST (`POST /v1/context/upsert`):**
  ```bash
  python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
    --from-file engram-export.json \
    --push --target rest \
    --knot-api-key "$KNOT_API_KEY" \
    --knot-base-url "https://production.connectknot.com/v1"
  ```

## Workflow C: 1-Line SDK Drop-In Replacement

If the user has application code calling Weaviate Engram's `.memories` API, point them to the zero-dependency compatibility adapters:

- Python: [`sdk/engram_knot_compat.py`](../../sdk/engram_knot_compat.py) (`EngramKnotCompatClient`)
- TypeScript: [`sdk/engram-knot-compat.ts`](../../sdk/engram-knot-compat.ts) (`EngramKnotCompatClient`)

Both support `.memories.add()`, `.memories.search(..., as_of=..., scopes=..., limit=...)`, `.memories.get()`, `.memories.delete()`, `.erase_user_subject()` / `.eraseUserSubject()`, and `.lineage()` / `.getLineage()`.

## Reference

See [Engram-to-Knot Field Mapping Reference](references/engram-to-knot-mapping.md) for the complete field mapping, kind routing, and `v1 -> v2` supersession rules.
