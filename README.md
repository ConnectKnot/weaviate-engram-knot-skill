# Weaviate Engram to Knot Migration & Context Engine Skill

[![CI](https://github.com/ConnectKnot/weaviate-engram-knot-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/ConnectKnot/weaviate-engram-knot-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+ Stdlib](https://img.shields.io/badge/Python-3.10%2B%20stdlib%20only-3776AB.svg)](skills/engram-to-knot-migration/scripts/migrate_engram.py)
[![MCP OAuth 2.1](https://img.shields.io/badge/MCP-OAuth%202.1%20PKCE-10B981.svg)](mcp.json)

**Migrate off Weaviate Engram before December 31, 2026 and pair Weaviate's large-scale vector corpus search with Knot's temporal, conflict-resolved context governance over MCP.**

---

## TL;DR: Why Use This Skill?

1. **Weaviate Engram sunsets on December 31, 2026:** Every team storing agent memories in Engram (`https://api.engram.weaviate.io`) needs a clean, non-destructive export and continuity layer before cutoff.
2. **Flat memory vectors surface stale overrides:** When an architecture or security rule changes (`v1` -> `v2`), flat vector recall retrieves both the outdated `v1` draft and the governing `v2` rule. **Knot** compiles chronological `v1 -> v2` supersession lineage at write time so every connected tool reads only active governing truth in `<15ms` with zero read-time LLM calls.
3. **One context graph across every AI surface:** Move your Engram memories once and use them immediately across **ChatGPT**, **Claude Code**, **Cursor**, **Gemini**, and **Kiro** over user-delegated OAuth 2.1 MCP, while keeping **Weaviate** (`Query Agent` / Weaviate MCP Server) focused on what it does best: 100K to 100M+ document corpus retrieval.
4. **Zero-dependency & security-first:** Runs on Python 3.10+ stdlib only, enforces read-only Engram exports (never `DELETE`), refuses shell `cmd` execution inside repo-local `./.engram.json`, and scrubs secrets and Luhn-valid card PANs locally before anything leaves your laptop.

---

## Quickstart (Choose Your Path in 2 Minutes)

### Option A: Zero-Key IDE Migration via OAuth 2.1 MCP (Claude Code, Cursor, Kiro, Windsurf)

No Knot API keys or tokens need to be copied into files. Connect the repo plugin/MCP (`https://api.connectknot.com/mcp`) and sign in via OAuth 2.1 PKCE:

- **Claude Code:**
  ```bash
  claude plugin add https://github.com/ConnectKnot/weaviate-engram-knot-skill
  ```
- **Cursor / Windsurf / Kiro:** Import `https://github.com/ConnectKnot/weaviate-engram-knot-skill` (includes `.cursor-plugin/plugin.json`, `plugin.json`, `mcp.json`, and `skills/`).
- **Then ask your AI assistant:**
  > *"Export my Weaviate Engram memories using `skills/engram-to-knot-migration/scripts/migrate_engram.py` in `--dry-run` mode, inspect the scrubbed summary, and import the compiled batches and `v1 -> v2` supersessions into Knot."*

### Option B: Instant CLI Dry-Run & Live Migration

Try the offline sample fixture immediately with zero API keys:

```bash
python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
  --from-file examples/sample-engram-export.json \
  --dry-run \
  --output engram-knot-migration-bundle.json
```

Export live from your Weaviate Engram account (strictly read-only `GET /v1/groups` + `POST /v1/memories/search` with `retrieval_type: "fetch"`):

```bash
export ENGRAM_API_KEY="your_engram_api_key"

# 1. Local read-only export, secret/PAN scrub, and bundle inspection
python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
  --dry-run \
  --output engram-knot-migration-bundle.json

# 2a. Push over Streamable HTTP MCP (with OAuth/Bearer token)
python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
  --from-file engram-export.json \
  --push --target mcp \
  --knot-mcp-token "$KNOT_ACCESS_TOKEN"

# 2b. Or push directly to Knot EnterpriseBrain REST (/v1/context/upsert)
python3 skills/engram-to-knot-migration/scripts/migrate_engram.py \
  --from-file engram-export.json \
  --push --target rest \
  --knot-api-key "$KNOT_API_KEY" \
  --knot-base-url "https://production.connectknot.com/v1"
```

Useful CLI flags: `--group`, `--topic`, `--user-id`, `--property KEY=VAL`, `--limit 500`, `--entity-hint <name>`, `--personal-preferences-as-project`, and `--read-shell-profile` (explicit opt-in only).

### Option C: 1-Line SDK Drop-In (`EngramKnotCompatClient`)

Swap Engram calls in Python or TypeScript with zero third-party dependencies:

**Python (`sdk/engram_knot_compat.py`):**

```python
from sdk import EngramKnotCompatClient

client = EngramKnotCompatClient(
    api_key="knot_prod_...",
    base_url="https://production.connectknot.com/v1",
    domain="checkout-platform",
)

client.memories.add(
    "Webhook retry policy: max 3 exponential-backoff retries.",
    user_id="usr_dev_42",
    topic="decisions",
    entity_key="webhook_retry_policy",
)

hits = client.memories.search(
    "webhook retry",
    user_id="usr_dev_42",
    scopes=["checkout-platform"],
    as_of="2026-10-20T00:00:00Z",
    limit=10,
)
```

**TypeScript (`sdk/engram-knot-compat.ts`):**

```ts
import { EngramKnotCompatClient } from "./sdk/engram-knot-compat.js";

const client = new EngramKnotCompatClient({
  apiKey: process.env.KNOT_API_KEY,
  domain: "checkout-platform",
});

await client.memories.add("Use Postgres 16 with pgvector.", {
  userId: "usr_dev_42",
  topic: "architecture_decisions",
  entityKey: "primary_database",
});

const history = await client.getLineage("usr_dev_42", "primary_database");
await client.eraseUserSubject("usr_dev_42"); // <100ms subject crypto-erasure
```

---

## What Gets Migrated & How (`v1 -> v2` Supersession & Topic Mapping)

1. **Chronological Ordering:** Exported memories are sorted by `updated_at || created_at` before compilation so older assertions never overwrite newer ones.
2. **Deterministic Mapping:**
   - Engram `group` (or `properties.repo` / `properties.project` / `--entity-hint`) maps to Knot `entity_hint` (or REST `domain`).
   - Engram `topic` + content signals map to Knot `kind` (`decision`, `constraint`, `goal`, `project_state`, `fact`, or `preference`).
   - Engram `id` maps to `idempotency_key = "engram:<id>"` so retries never create duplicates.
3. **`v1 -> v2` Supersession Chaining:** Memories sharing `(entity_hint, subject_key)` chain chronologically. Version 1 entries batch into `mcp_batches` (`<=25` items per `batch_propose_context` call). Version `2+` entries compile into `mcp_supersessions` (`propose_context` with `supersedes_context_id`), preserving full audit lineage while hiding stale `v1` guidance from active recall.
4. **Preference Queue Isolation:** Personal preference topics (`UserKnowledge`, `preferences`) default to `kind="preference"` so they enter Knot's pending approval queue instead of polluting team or project context. Pass `--personal-preferences-as-project` if you intentionally want them synced immediately as project facts.

See [references/engram-to-knot-mapping.md](skills/engram-to-knot-migration/references/engram-to-knot-mapping.md) for the complete mapping table.

---

## Pairing Weaviate + Knot (Dev to Enterprise VPC)

| Capability | Weaviate (`Query Agent` / MCP / Enterprise) | Knot (`MCP` / `EnterpriseBrain`) |
| :--- | :--- | :--- |
| **Best suited for** | 100K to 100M+ documents, logs, PDFs, codebases | Active specs, decisions, constraints, handoffs, user state |
| **Retrieval behavior** | Hybrid BM25 + dense vector similarity | `<15ms` governed active state, zero read-time LLM calls |
| **Conflict handling** | Returns top-k matching chunks | Deterministic `v1 -> v2` supersession + `as_of` point-in-time replay |
| **Cross-tool sharing** | Single backend / query API | Live across ChatGPT, Claude Code, Cursor, Gemini, Kiro + REST |
| **Enterprise VPC** | Self-hosted Weaviate Enterprise | Self-hosted **Knot EnterpriseBrain** on your Postgres `pgvector` + KMS |

See [skills/weaviate-knot-context-engine/SKILL.md](skills/weaviate-knot-context-engine/SKILL.md) and [references/enterprise-vpc-pairing.md](skills/weaviate-knot-context-engine/references/enterprise-vpc-pairing.md) for the full VPC topology, `knot-policy.yaml` domain write authority ranks, and `HTTP 422 PCI_CDE_PAYLOAD_REJECTED` boundary architecture.

---

## FAQ: Data Privacy, Security, Governance & Pricing

### 1. Does Knot ever train AI models on my migrated memories?
**No. Never.** Knot stores only structured context you explicitly migrate or approve, and never uses customer or personal context to train foundation models.

### 2. How is my data encrypted at rest in Knot?
All context payloads, metadata, and provenance summaries are encrypted at rest with **AES-256-GCM**, and vector embeddings are tenant-rotated via orthogonal Householder transformations so cross-tenant vector inversion is prevented even at the storage layer.

### 3. Are secrets or credit card numbers scrubbed before leaving my machine?
**Yes.** Both `migrate_engram.py` and `EngramKnotCompatClient` run a deterministic local scrubber before writing bundles or making network calls. AWS keys (`AKIA...`), OpenAI/Anthropic/Stripe keys (`sk-...`, `sk_live_...`, `rk_live_...`), GitHub PATs (`ghp_...`, `github_pat_...`), Slack tokens (`xox...`), PEM private keys, Bearer JWTs, high-entropy `SECRET`/`TOKEN`/`PASSWORD`/`API_KEY` assignments, and Luhn-validated 13-19 digit card PANs are replaced with `[REDACTED_SECRET]` and `[REDACTED_PAN]`, while benign git commit SHAs and UUIDv4 IDs remain intact.

### 4. Why does `migrate_engram.py` refuse `cmd` inside `./.engram.json`?
Weaviate Engram plugins support dynamic property commands, which becomes an RCE risk if you run an exporter inside an untrusted cloned repository. `migrate_engram.py` strictly refuses and drops any `{"cmd": ...}` property source in repo-local `./.engram.json` (while still supporting literal `./.engram.json` properties and user-owned `~/.engram/config.json`).

### 5. How do MCP permissions and revocation work?
Knot MCP (`https://api.connectknot.com/mcp`) uses **OAuth 2.1 with PKCE** and scoped grants. Each connected client (Claude Code, Cursor, Kiro, ChatGPT) sees only the personal or shared knots authorized in its grant, and you can revoke any client's access in one click from your Knot dashboard.

### 6. Why do `UserKnowledge` / preference items go to a pending approval queue instead of auto-syncing?
Auto-syncing every personal style preference directly into shared project context causes persona bloat and conflicting cross-team rules. Routing `preference`, `person`, and `relationship` items to the pending approval queue keeps project context focused while letting you approve profile traits intentionally (or override with `--personal-preferences-as-project`).

### 7. Does the migration modify or delete anything in my Engram account?
**No.** Exports are strictly read-only (`GET /v1/groups` and `POST /v1/memories/search` with `retrieval_type: "fetch"`). `migrate_engram.py` contains zero `DELETE` calls against Engram, so your Engram workspace stays untouched until you choose to retire it.

### 8. Can regulated teams run everything inside a zero-egress private VPC?
**Yes.** Pair self-hosted **Weaviate Enterprise** with **Knot EnterpriseBrain** inside your AWS, GCP, Azure, or on-prem Kubernetes VPC. Knot EnterpriseBrain runs on your existing PostgreSQL `pgvector` instance, wraps 3-level HKDF keys (`K_org_root -> K_domain -> K_subject`) in your own KMS/HSM (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault), runs with `KNOT_ALLOW_REMOTE_MODELS=false`, blocks raw cardholder payloads at the write-door (`HTTP 422 PCI_CDE_PAYLOAD_REJECTED`), and supports `<100ms` subject cryptographic erasure via `DELETE /v1/subjects/{id}/key`.

### 9. How much does Knot cost?
- **Free ($0, no end date):** Up to 2 connected AIs, unlimited reading and search, and shared project Knots.
- **Knot Pro ($90/year billed annually or $9.99/month):** Unlimited connected AIs, full `v1 -> v2` version history, and 3 Golden Invite codes.
- **Knot EnterpriseBrain (Self-Hosted VPC):** Annual VPC platform fee sized by connected domains and committed capacity band, with `$0` local reads and `$0` per internal seat.

---

## Repository Layout

```text
weaviate-engram-knot-skill/
├── .claude-plugin/plugin.json
├── .cursor-plugin/plugin.json
├── .github/workflows/ci.yml
├── plugin.json
├── mcp.json
├── skills/
│   ├── engram-to-knot-migration/
│   │   ├── SKILL.md
│   │   ├── references/engram-to-knot-mapping.md
│   │   └── scripts/migrate_engram.py
│   └── weaviate-knot-context-engine/
│       ├── SKILL.md
│       └── references/enterprise-vpc-pairing.md
├── sdk/
│   ├── __init__.py
│   ├── engram_knot_compat.py
│   └── engram-knot-compat.ts
├── examples/
│   └── sample-engram-export.json
├── tests/
│   └── test_migrate_engram.py
├── AGENTS.md
├── CLAUDE.md
├── LICENSE
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE).
