---
name: weaviate-knot-context-engine
description: Pair Weaviate (100K-100M+ document corpus retrieval via Query Agent or Weaviate MCP) with Knot (sub-15ms cross-model temporal state, v1 -> v2 supersession, as_of replay, and cross-AI handoffs).
---

# Weaviate + Knot Context Engine

Use Weaviate and Knot together according to what each system does best:

- **Weaviate (`Query Agent` / Weaviate MCP Server):** Use for **100K to 100M+ document corpus retrieval** across knowledge bases, support tickets, codebase archives, PDFs, product catalogs, and hybrid BM25 + vector search.
- **Knot (`get_relevant_context`, `propose_context`, `create_handoff`):** Use for **sub-15ms cross-model temporal state** with deterministic `v1 -> v2` supersession, zero read-time LLM calls, `as_of` point-in-time replay, and live continuity across ChatGPT, Claude Code, Cursor, Gemini, and Kiro.

## Separation of Responsibilities

| Workload | Use Weaviate | Use Knot |
| :--- | :--- | :--- |
| Search 10M docs, logs, or tickets | Yes (hybrid vector + BM25) | No (never store bulk document chunks in Knot) |
| Track active architecture decisions (`v1 -> v2`) | No (flat chunks surface stale `v1` alongside `v2`) | Yes (`get_relevant_context`, `propose_context` with `supersedes_context_id`) |
| Share live state across ChatGPT, Claude, Cursor, Gemini, Kiro | Partial (single workspace/app) | Yes (user-delegated OAuth 2.1 MCP + `create_handoff`) |
| Replay exact known state at timestamp `t` (`as_of`) | Snapshot/filter dependent | Native (`as_of` / `query_mode: "trajectory"`) |

## Turn-by-Turn Agent Loop

1. **Recover live decisions first (Turn 0):**
   Call Knot `get_relevant_context` (pass `entity_hint` and `query_mode: "trajectory"` when checking whether an earlier decision was superseded). This returns only governing active state without read-time LLM latency.
2. **Retrieve deep corpus evidence when needed:**
   Query Weaviate (`Query Agent` or Weaviate MCP) for supporting documentation, historical tickets, or large knowledge-base passages.
3. **Resolve conflicts safely:**
   When a new rule updates a prior Knot item, pass `supersedes_context_id` in `propose_context`. Never overwrite silently when Knot flags a potential conflict without checking provenance.
4. **Hand off across surfaces:**
   Call `create_handoff` when handing active work from one AI tool or teammate to another.

## Enterprise VPC Deployment

For regulated or self-hosted environments pairing **Weaviate Enterprise** with **Knot EnterpriseBrain** inside your own VPC, see [Enterprise VPC Pairing Reference](references/enterprise-vpc-pairing.md).
