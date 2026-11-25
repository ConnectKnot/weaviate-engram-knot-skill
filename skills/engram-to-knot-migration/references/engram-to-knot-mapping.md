# Engram-to-Knot Field Mapping and Supersession Reference

This reference documents how `skills/engram-to-knot-migration/scripts/migrate_engram.py` transforms Weaviate Engram exports into Knot MCP payloads (`batch_propose_context` / `propose_context`) and Knot EnterpriseBrain REST payloads (`POST /v1/context/upsert`).

## Field-by-Field Mapping

| Engram Field | Knot MCP (`propose_context` / `batch_propose_context`) | Knot REST (`POST /v1/context/upsert`) | Notes |
| :--- | :--- | :--- | :--- |
| `group` (and `properties.repo` / `properties.project`) | `entity_hint` | `domain` | Resolved in order: `--entity-hint`, `properties.repo` / `project` / `entity` / `service`, `group`, `"Engram Migration"`. |
| `topic` + `content` | `kind` | `category` | Personal preference topics map to `preference` unless `--personal-preferences-as-project` is set; technical topics classify into `decision`, `constraint`, `goal`, `project_state`, or `fact`. |
| `user_id` | `provenance` / personal scope | `subjectId` | REST uses `--subject-id`, else `user_id`, else `"default"`. |
| `properties` + `tags` + `content` heading | `subject_key` + `entity_hint` | `entityKey` | Explicit `properties.subject_key` / `key`, `subject:` tag, or normalized `"Heading: ..."` prefix ensures comparable claims share a `subject_key`. |
| `content` (locally scrubbed) | `statement` | `content` | Secrets and Luhn-valid card numbers are redacted locally before writing to disk or calling remote APIs. |
| `updated_at` or `created_at` | `observed_at` | `observedAt` | Records are sorted chronologically by `updated_at \|\| created_at` before compiling supersessions. |
| `id` | `idempotency_key` (`engram:<id>`) | `provenance.idempotency_key` + `provenance.source_memory_id` | Prevents duplicate imports on retry and anchors `v1 -> v2` resolution. |
| Prior matching `(entity_hint, subject_key)` | `supersedes_context_id` | `supersedes` | Chronological `v2+` updates supersede the immediately preceding version in the chain. |

## Personal Preferences vs. Project Sync

Knot separates personal profile context from shared project context so cross-AI tools stay concise and relevant:

- **Project Context (`fact`, `decision`, `constraint`, `goal`, `project_state`)**: Requires an `entity_hint` and becomes immediately readable across ChatGPT, Claude Code, Cursor, Gemini, and Kiro via `get_relevant_context`.
- **Personal Context (`preference`, `person`, `relationship`)**: Enters Knot's pending approval queue in the Knot dashboard (`Your Knot`) instead of polluting project namespaces or overwriting persona defaults automatically. Passing `--personal-preferences-as-project` converts preference topics into project-scoped `fact` records when immediate project visibility is desired.

## Chronological `v1 -> v2` Supersession

Flat vector stores return both an outdated `v1` policy and a newer `v2` override when chunks overlap semantically. During migration:

1. `migrate_engram.py` sorts every exported memory chronologically (`updated_at` fallback `created_at`).
2. Memories sharing `(entity_hint, subject_key)` are grouped into a version chain `[v1, v2, ..., vn]`.
3. `v1` entries are placed in `mcp_batches` (`batch_propose_context`, chunked at 25 items or fewer).
4. `v2+` entries are placed in `mcp_supersessions` (`propose_context`), referencing `supersedes_idempotency_key` so `--push` (or an IDE agent over OAuth 2.1 MCP) passes the exact `supersedes_context_id` UUID returned for `v1`.
5. On Knot EnterpriseBrain REST (`--target rest`), records are sent sequentially via `POST /v1/context/upsert` with `supersedes` pointing to the prior remote ID.
