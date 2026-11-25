# Regulated Enterprise VPC Pairing: Weaviate Enterprise + Knot EnterpriseBrain

Organizations running **Weaviate Enterprise** inside a private VPC can deploy **Knot EnterpriseBrain** (`KNOT_DEPLOYMENT_MODE=self_hosted`, `KNOT_TENANCY_MODEL=subject_domain`) alongside it as a zero-egress stateful context layer.

## Architecture Overview

1. **Vector Corpus Layer (Weaviate Enterprise):** Stores large document corpora (100K to 100M+ chunks) with RBAC and tenant isolation inside your VPC.
2. **Temporal State Layer (Knot EnterpriseBrain):** Runs on existing **PostgreSQL with `pgvector`** (AWS Aurora/RDS, GCP AlloyDB/Cloud SQL, Azure Flexible Server) using pre-bundled local ONNX embeddings (`KNOT_ALLOW_REMOTE_MODELS=false`), zero outbound network egress, and sub-15ms read latency with zero read-time LLM calls.

## Security, Encryption, and Compliance Boundaries

- **3-Level HKDF Customer KMS Envelope Encryption:**
  - `K_org_root` remains inside Customer KMS / HSM (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault).
  - `K_domain = HKDF-SHA256(K_org_root, "domain:" + domain_id)`
  - `K_subject = HKDF-SHA256(K_domain, "subject:" + subject_id + ":v" + key_epoch)`
  - Context payloads and metadata are encrypted with `AES-256-GCM` under `K_subject`, and `pgvector` embeddings are rotated per tenant/subject via orthogonal Householder reflectors.
- **Under-100ms Subject Cryptographic Erasure:**
  - Calling `DELETE /v1/subjects/{id}/key` (or `client.erase_user_subject(user_id)`) rotates/tombstones `key_epoch` and schedules async row deletion, rendering historical ciphertext and rotated embeddings unrecoverable in under 100ms.
- **Declarative Domain Write Authority (`knot-policy.yaml`):**
  - Enforces per-domain `read`, `write`, `supersede`, and `authority_rank` policies over mTLS, OAuth2 JWKS, or service credentials so lower-authority channels (e.g., `agentic.commerce` rank `30`) cannot overwrite canonical system-of-record domains (e.g., `travel` rank `90`).
- **PCI-DSS CDE Isolation (`HTTP 422 PCI_CDE_PAYLOAD_REJECTED`):**
  - Knot EnterpriseBrain sits outside the Cardholder Data Environment (CDE). A deterministic write-door gate rejects raw PAN/CVV/account payloads with `HTTP 422 PCI_CDE_PAYLOAD_REJECTED`, while the client compatibility SDK and migration CLI also scrub secrets and Luhn-valid PANs before transmission.
- **Zero Outbound Egress & `as_of` Replay:**
  - Every state mutation records `observedAt`, `supersedes`, and `provenance` for deterministic `as_of` point-in-time auditing (`POST /v1/context/retrieve` and `GET /v1/subjects/{id}/lineage`) without contacting external LLM providers (`KNOT_ALLOW_REMOTE_MODELS=false`).
