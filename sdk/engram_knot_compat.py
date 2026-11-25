"""Drop-in Weaviate Engram compatibility client backed by Knot REST endpoints.

Zero-dependency Python 3.10+ standard library implementation.
Maps Engram .memories.add / search / get / delete operations onto Knot
EnterpriseBrain REST primitives:
  - POST /v1/context/upsert
  - POST /v1/context/retrieve
  - GET  /v1/subjects/{id}/lineage
  - DELETE /v1/subjects/{id}/key
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_KNOT_REST_URL = "https://production.connectknot.com/v1"

_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
)
_BEARER_JWT_RE = re.compile(
    r"\bBearer\s+eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH_TOKEN_RE = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b"
)
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_PROVIDER_KEY_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,})\b"
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY))"
    r"\s*([:=])\s*(['\"]?)([A-Za-z0-9_./+=~!$@#%^&*-]{12,})\3"
)
_PAN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9_])")
_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


class EngramKnotCompatError(Exception):
    """Raised on HTTP, authentication, or payload errors from Knot REST APIs."""

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _normalize_v1_base(base_url: str) -> str:
    cleaned = base_url.strip().rstrip("/")
    if not cleaned:
        return DEFAULT_KNOT_REST_URL
    if cleaned.endswith("/v1"):
        return cleaned
    return f"{cleaned}/v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _slugify(value: str, max_len: int = 120) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return (slug or "memory")[:max_len].strip("_") or "memory"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19) or len(set(digits)) <= 1:
        return False
    total = 0
    for idx, ch in enumerate(digits[::-1]):
        num = ord(ch) - ord("0")
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def _scrub_text(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in (
        _PEM_RE,
        _BEARER_JWT_RE,
        _AWS_KEY_RE,
        _GH_TOKEN_RE,
        _SLACK_TOKEN_RE,
        _PROVIDER_KEY_RE,
    ):
        out = pat.sub("[REDACTED_SECRET]", out)

    def _assign_sub(match: re.Match[str]) -> str:
        key, sep, quote, val = match.group(1), match.group(2), match.group(3), match.group(4)
        if val in ("[REDACTED_SECRET]", "[REDACTED_PAN]") or _UUID_V4_RE.match(val):
            return match.group(0)
        if _HEX_SHA_RE.match(val) and len(val) in (7, 8, 12, 40) and val.islower():
            return match.group(0)
        classes = sum(
            [
                any(c.islower() for c in val),
                any(c.isupper() for c in val),
                any(c.isdigit() for c in val),
                any(c in "_./+=~!$@#%^&*-" for c in val),
            ]
        )
        if (_entropy(val) >= 3.0 and classes >= 2) or (len(val) >= 20 and _entropy(val) >= 3.2):
            return f"{key}{sep}{quote}[REDACTED_SECRET]{quote}"
        return match.group(0)

    out = _SECRET_ASSIGN_RE.sub(_assign_sub, out)

    def _pan_sub(match: re.Match[str]) -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        return "[REDACTED_PAN]" if _is_luhn_valid(digits) else match.group(0)

    return _PAN_CANDIDATE_RE.sub(_pan_sub, out)


def _infer_category(topic: str | None, category: str | None) -> str:
    if category:
        return category
    if not topic:
        return "fact"
    t = topic.strip().lower()
    if "preference" in t or t in ("userknowledge", "user_knowledge"):
        return "preference"
    if "decision" in t or t in ("architecture", "adr"):
        return "decision"
    if "constraint" in t or t in ("security", "policy", "rules", "guardrails"):
        return "constraint"
    if "goal" in t or t in ("roadmap", "objectives"):
        return "goal"
    if "state" in t or t in ("status", "rollout"):
        return "project_state"
    return "fact"


class _MemoriesNamespace:
    """Engram-compatible `.memories` sub-API backed by Knot REST endpoints."""

    def __init__(self, client: EngramKnotCompatClient) -> None:
        self._client = client

    def add(
        self,
        content: str | None = None,
        *,
        messages: list[dict[str, Any]] | None = None,
        user_id: str | None = None,
        group: str | None = None,
        topic: str | None = None,
        entity_key: str | None = None,
        category: str | None = None,
        observed_at: str | None = None,
        supersedes: str | None = None,
        idempotency_key: str | None = None,
        properties: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store or supersede a memory via Knot POST /v1/context/upsert."""
        text = content
        if text is None and messages:
            parts = [
                f"{m.get('role', 'user')}: {m.get('content', '')}".strip()
                for m in messages
                if isinstance(m, dict) and m.get("content")
            ]
            text = "\n".join(parts)
        if not isinstance(text, str) or not text.strip():
            raise ValueError("content (or non-empty messages) is required for memories.add().")

        scrubbed = _scrub_text(text.strip())
        subject_id = user_id or self._client.default_subject_id
        domain = group or self._client.domain
        resolved_category = _infer_category(topic, category)
        resolved_key = entity_key or _slugify(
            f"{topic or 'general'}:{' '.join(scrubbed.split()[:6])}"
        )

        provenance: dict[str, Any] = {
            "source": "engram-knot-compat-py",
            "group": group,
            "topic": topic,
            "tags": tags or [],
            "properties": properties or {},
        }
        if idempotency_key:
            provenance["idempotency_key"] = idempotency_key
        if metadata:
            provenance["metadata"] = metadata

        payload: dict[str, Any] = {
            "subjectId": subject_id,
            "domain": domain,
            "category": resolved_category,
            "entityKey": resolved_key,
            "content": scrubbed,
            "observedAt": observed_at or _utc_now_iso(),
            "supersedes": supersedes,
            "provenance": provenance,
        }
        return self._client._request("POST", "/context/upsert", payload=payload)

    def search(
        self,
        query: str = "",
        *,
        user_id: str | None = None,
        group: str | None = None,
        topic: str | None = None,
        scopes: list[str] | None = None,
        as_of: str | None = None,
        limit: int = 20,
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Query current or as_of point-in-time context via POST /v1/context/retrieve."""
        subject_id = user_id or self._client.default_subject_id
        resolved_scopes = scopes if scopes is not None else [group or self._client.domain]
        payload: dict[str, Any] = {
            "subjectId": subject_id,
            "query": query,
            "scopes": resolved_scopes,
            "limit": limit,
        }
        if as_of is not None:
            payload["asOf"] = as_of
        if topic is not None:
            payload["topic"] = topic
        if properties:
            payload["properties"] = properties
        return self._client._request("POST", "/context/retrieve", payload=payload)

    def get(
        self,
        memory_id: str,
        *,
        user_id: str | None = None,
        entity_key: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch a specific memory node from GET /v1/subjects/{id}/lineage."""
        if not memory_id:
            raise ValueError("memory_id is required.")
        subject_id = user_id or self._client.default_subject_id
        params: dict[str, str] = {"memoryId": memory_id}
        if entity_key:
            params["entityKey"] = entity_key
        resp = self._client.lineage(subject_id, entity_key=entity_key, extra_query=params)

        if (
            resp.get("id") == memory_id
            or resp.get("contextId") == memory_id
            or resp.get("context_id") == memory_id
        ):
            return resp

        for list_key in ("items", "lineage", "versions", "memories", "results"):
            entries = resp.get(list_key)
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    prov = entry.get("provenance") if isinstance(entry.get("provenance"), dict) else {}
                    if (
                        entry.get("id") == memory_id
                        or entry.get("contextId") == memory_id
                        or entry.get("context_id") == memory_id
                        or prov.get("source_memory_id") == memory_id
                    ):
                        return entry
        return None

    def delete(
        self,
        memory_id: str | None = None,
        *,
        user_id: str | None = None,
        erase_subject: bool = False,
        entity_key: str | None = None,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Delete a subject cryptographically or retract a single memory item.

        When erase_subject=True (or memory_id is omitted or equals subject_id),
        calls DELETE /v1/subjects/{id}/key for <100ms cryptographic erasure.
        When deleting a single memory_id, records an immutable tombstone via
        POST /v1/context/upsert with supersedes=memory_id.
        """
        subject_id = user_id or self._client.default_subject_id
        if erase_subject or memory_id is None or memory_id == subject_id:
            return self._client.erase_user_subject(subject_id)

        payload = {
            "subjectId": subject_id,
            "domain": domain or self._client.domain,
            "category": "project_state",
            "entityKey": entity_key or f"retracted:{memory_id}",
            "content": f"[TOMBSTONED] Memory {memory_id} retracted via compatibility adapter.",
            "observedAt": _utc_now_iso(),
            "supersedes": memory_id,
            "provenance": {
                "source": "engram-knot-compat-py",
                "action": "tombstone",
                "retracted_memory_id": memory_id,
            },
        }
        resp = self._client._request("POST", "/context/upsert", payload=payload)
        return {"status": "tombstoned", "superseded_id": memory_id, "result": resp}


class EngramKnotCompatClient:
    """Drop-in replacement for Weaviate Engram clients backed by Knot REST."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        domain: str = "engram-compat",
        default_subject_id: str = "default",
        timeout_seconds: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("KNOT_API_KEY") or ""
        if not resolved_key:
            raise EngramKnotCompatError(
                "Missing Knot API key. Pass api_key=... or set KNOT_API_KEY."
            )
        self.api_key = resolved_key
        self.base_url = _normalize_v1_base(
            base_url or os.environ.get("KNOT_BASE_URL") or DEFAULT_KNOT_REST_URL
        )
        self.domain = domain
        self.default_subject_id = default_subject_id
        self.timeout_seconds = timeout_seconds
        self.extra_headers = dict(headers or {})
        self.memories = _MemoriesNamespace(self)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        query: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        if query:
            qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
            if qs:
                url = f"{url}?{qs}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.extra_headers,
        }
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url=url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:
            with err:
                raw_err = err.read().decode("utf-8", errors="replace")
            code: str | None = None
            msg = raw_err[:400]
            try:
                err_obj = json.loads(raw_err)
                if isinstance(err_obj, dict):
                    code = err_obj.get("code") or err_obj.get("error")
                    msg = err_obj.get("message") or msg
            except json.JSONDecodeError:
                pass
            raise EngramKnotCompatError(
                f"HTTP {err.code} from {method} {url}: {msg}",
                status=err.code,
                code=code,
            ) from err
        except urllib.error.URLError as err:
            raise EngramKnotCompatError(
                f"Network error calling {method} {url}: {err.reason}"
            ) from err

        if not raw.strip():
            return {}
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"data": parsed}

    def erase_user_subject(self, user_id: str) -> dict[str, Any]:
        """Cryptographically erase a subject's HKDF key epoch (<100ms)."""
        if not user_id:
            raise ValueError("user_id is required for erase_user_subject().")
        encoded = urllib.parse.quote(user_id, safe="")
        return self._request("DELETE", f"/subjects/{encoded}/key")

    def lineage(
        self,
        user_id: str,
        *,
        entity_key: str | None = None,
        extra_query: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Fetch full v1 -> v2 supersession lineage for a subject."""
        if not user_id:
            raise ValueError("user_id is required for lineage().")
        encoded = urllib.parse.quote(user_id, safe="")
        query: dict[str, str] = dict(extra_query or {})
        if entity_key:
            query["entityKey"] = entity_key
        return self._client_get_lineage(encoded, query)

    def _client_get_lineage(self, encoded_subject: str, query: dict[str, str]) -> dict[str, Any]:
        return self._request("GET", f"/subjects/{encoded_subject}/lineage", query=query)
