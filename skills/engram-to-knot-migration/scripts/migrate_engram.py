#!/usr/bin/env python3
"""Migrate Weaviate Engram memories into a Knot migration bundle or push to Knot.

Zero-dependency Python 3.10+ standard library CLI.
Performs strictly read-only exports from Weaviate Engram, enforces repo-local
.engram.json security rules (refusing dynamic 'cmd' property sources), scrubs
secrets and Luhn-valid payment card numbers locally, compiles chronological
v1 -> v2 supersession lineage, and supports dry-run bundle generation as well
as --push over Knot Streamable HTTP MCP or Knot EnterpriseBrain REST.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_ENGRAM_BASE_URL = "https://api.engram.weaviate.io"
DEFAULT_KNOT_MCP_URL = "https://api.connectknot.com/mcp"
DEFAULT_KNOT_REST_URL = "https://production.connectknot.com/v1"
DEFAULT_OUTPUT_FILE = "engram-knot-migration-bundle.json"
DEFAULT_FETCH_LIMIT = 500
MCP_BATCH_SIZE = 25
CLIENT_HEADER_VALUE = "weaviate-engram-knot-migration/1.0.0"

SHELL_PROFILE_FILES = (
    ".zshenv",
    ".zshrc",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
    ".profile",
)

PERSONAL_PREFERENCE_TOPICS = {
    "userknowledge",
    "user_knowledge",
    "user-knowledge",
    "preference",
    "preferences",
    "user_preference",
    "user_preferences",
    "user-preferences",
    "personal_preferences",
    "personal-preferences",
    "persona",
    "style_preferences",
}

DECISION_TOPICS = {
    "decision",
    "decisions",
    "architecture",
    "architecture_decisions",
    "architectural_decisions",
    "adr",
    "adrs",
    "choices",
}

CONSTRAINT_TOPICS = {
    "constraint",
    "constraints",
    "guardrail",
    "guardrails",
    "security",
    "compliance",
    "rule",
    "rules",
    "policy",
    "policies",
    "invariants",
}

GOAL_TOPICS = {
    "goal",
    "goals",
    "objective",
    "objectives",
    "roadmap",
    "milestone",
    "milestones",
    "okr",
    "okrs",
}

STATE_TOPICS = {
    "state",
    "project_state",
    "project-state",
    "status",
    "current_state",
    "incidents",
    "rollout",
}

GENERIC_SUBJECT_PREFIX_MODIFIERS = {
    "update",
    "updated",
    "revision",
    "revised",
    "new",
    "final",
    "override",
    "v1",
    "v2",
    "v3",
    "v4",
    "deprecated",
}

# Compiled scrubber regexes
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
)
BEARER_JWT_RE = re.compile(
    r"\bBearer\s+eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN_RE = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b"
)
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
PROVIDER_KEY_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,})\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY))"
    r"\s*([:=])\s*(['\"]?)([A-Za-z0-9_./+=~!$@#%^&*-]{12,})\3"
)
PAN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9_])")
UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


class MigrationError(Exception):
    """Raised when configuration, network export, or Knot push fails."""


@dataclass
class ScrubStats:
    secrets_scrubbed: int = 0
    pans_scrubbed: int = 0


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    if len(set(digits)) <= 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        num = ord(ch) - ord("0")
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def _looks_like_high_entropy_secret(value: str) -> bool:
    if value in ("[REDACTED_SECRET]", "[REDACTED_PAN]"):
        return False
    if UUID_V4_RE.match(value):
        return False
    if HEX_SHA_RE.match(value) and len(value) in (7, 8, 12, 40) and value.islower():
        return False
    classes = sum(
        [
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(c in "_./+=~!$@#%^&*-" for c in value),
        ]
    )
    entropy = _shannon_entropy(value)
    return (entropy >= 3.0 and classes >= 2) or (len(value) >= 20 and entropy >= 3.2)


def scrub_text(text: str, stats: ScrubStats) -> str:
    """Scrub credentials, private keys, JWTs, and Luhn-valid card PANs from text."""
    if not text:
        return text

    out = text

    for pattern in (
        PEM_PRIVATE_KEY_RE,
        BEARER_JWT_RE,
        AWS_KEY_RE,
        GITHUB_TOKEN_RE,
        SLACK_TOKEN_RE,
        PROVIDER_KEY_RE,
    ):
        def _replace_secret(_match: re.Match[str]) -> str:
            stats.secrets_scrubbed += 1
            return "[REDACTED_SECRET]"

        out = pattern.sub(_replace_secret, out)

    def _replace_assignment(match: re.Match[str]) -> str:
        key, sep, quote, val = match.group(1), match.group(2), match.group(3), match.group(4)
        if _looks_like_high_entropy_secret(val):
            stats.secrets_scrubbed += 1
            return f"{key}{sep}{quote}[REDACTED_SECRET]{quote}"
        return match.group(0)

    out = SECRET_ASSIGNMENT_RE.sub(_replace_assignment, out)

    def _replace_pan(match: re.Match[str]) -> str:
        raw = match.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if _is_luhn_valid(digits):
            stats.pans_scrubbed += 1
            return "[REDACTED_PAN]"
        return raw

    out = PAN_CANDIDATE_RE.sub(_replace_pan, out)
    return out


def scrub_value(value: Any, stats: ScrubStats) -> Any:
    """Recursively scrub string fields inside lists and dicts."""
    if isinstance(value, str):
        return scrub_text(value, stats)
    if isinstance(value, list):
        return [scrub_value(item, stats) for item in value]
    if isinstance(value, dict):
        return {str(k): scrub_value(v, stats) for k, v in value.items()}
    return value


def _contains_cmd_descriptor(obj: Any) -> bool:
    if isinstance(obj, dict):
        if "cmd" in obj:
            return True
        return any(_contains_cmd_descriptor(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_cmd_descriptor(item) for item in obj)
    return False


def _read_shell_profile_vars(home_dir: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    assign_re = re.compile(
        r"^\s*(?:export\s+)?(ENGRAM_API_KEY|ENGRAM_BASE_URL)\s*=\s*(.+?)\s*$"
    )
    for filename in SHELL_PROFILE_FILES:
        path = home_dir / filename
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = assign_re.match(line)
            if not m:
                continue
            var_name, raw_val = m.group(1), m.group(2)
            try:
                tokens = shlex.split(raw_val, comments=True)
                parsed = tokens[0] if tokens else ""
            except ValueError:
                parsed = raw_val.strip().strip("'\"")
            if parsed and var_name not in found:
                found[var_name] = parsed
    return found


def _execute_user_home_cmd(cmd: Any, warnings: list[str], prop_name: str) -> str | None:
    """Execute dynamic property cmd ONLY from trusted user ~/.engram/config.json."""
    try:
        if isinstance(cmd, str):
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        elif isinstance(cmd, list) and all(isinstance(arg, str) for arg in cmd):
            proc = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        else:
            warnings.append(
                f"Ignored invalid 'cmd' type for property '{prop_name}' in ~/.engram/config.json."
            )
            return None
        if proc.returncode != 0:
            warnings.append(
                f"Command for property '{prop_name}' in ~/.engram/config.json exited with {proc.returncode}."
            )
            return None
        val = proc.stdout.strip()
        return val if val else None
    except (OSError, subprocess.TimeoutExpired) as exc:
        warnings.append(
            f"Failed executing command for property '{prop_name}' in ~/.engram/config.json: {exc}"
        )
        return None


def resolve_engram_config(
    *,
    cli_api_key: str | None = None,
    cli_base_url: str | None = None,
    cli_properties: list[str] | None = None,
    read_shell_profile: bool = False,
    home_dir: Path | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Resolve Engram API key, base URL, and merged properties securely."""
    home = home_dir or Path.home()
    work_dir = cwd or Path.cwd()
    warnings: list[str] = []

    api_key = cli_api_key or os.environ.get("ENGRAM_API_KEY") or ""
    base_url = cli_base_url or os.environ.get("ENGRAM_BASE_URL") or ""
    properties: dict[str, Any] = {}

    if read_shell_profile:
        profile_vars = _read_shell_profile_vars(home)
        if not api_key and profile_vars.get("ENGRAM_API_KEY"):
            api_key = profile_vars["ENGRAM_API_KEY"]
        if not base_url and profile_vars.get("ENGRAM_BASE_URL"):
            base_url = profile_vars["ENGRAM_BASE_URL"]

    # 1. Trusted user-level config: ~/.engram/config.json
    user_cfg_path = home / ".engram" / "config.json"
    if user_cfg_path.is_file():
        try:
            user_cfg = json.loads(user_cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"Failed to parse {user_cfg_path}: {exc}")
            user_cfg = {}
        if isinstance(user_cfg, dict):
            if not api_key and isinstance(user_cfg.get("api_key"), str):
                api_key = user_cfg["api_key"].strip()
            if not base_url and isinstance(user_cfg.get("base_url"), str):
                base_url = user_cfg["base_url"].strip()
            raw_props = user_cfg.get("properties")
            if isinstance(raw_props, dict):
                for key, val in raw_props.items():
                    if isinstance(val, dict) and "cmd" in val:
                        resolved = _execute_user_home_cmd(val["cmd"], warnings, str(key))
                        if resolved is not None:
                            properties[str(key)] = resolved
                    elif isinstance(val, (str, int, float, bool)):
                        properties[str(key)] = val

    # 2. Untrusted repo-local config: ./.engram.json
    # SECURITY INVARIANT: Strictly refuse any {"cmd": ...} dynamic property source.
    repo_cfg_path = work_dir / ".engram.json"
    if repo_cfg_path.is_file():
        try:
            repo_cfg = json.loads(repo_cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"Failed to parse {repo_cfg_path}: {exc}")
            repo_cfg = {}
        if isinstance(repo_cfg, dict):
            if "cmd" in repo_cfg:
                msg = (
                    "SECURITY WARNING: Refused top-level 'cmd' entry in repo-local "
                    f"{repo_cfg_path}. Repo configs cannot execute shell commands."
                )
                print(msg, file=sys.stderr)
                warnings.append(msg)
            repo_props = repo_cfg.get("properties")
            if isinstance(repo_props, dict):
                for key, val in repo_props.items():
                    if _contains_cmd_descriptor(val):
                        msg = (
                            f"SECURITY WARNING: Refused dynamic 'cmd' property source '{key}' "
                            f"in repo-local {repo_cfg_path}; dropped."
                        )
                        print(msg, file=sys.stderr)
                        warnings.append(msg)
                        continue
                    if isinstance(val, (str, int, float, bool)):
                        properties[str(key)] = val
                    else:
                        msg = (
                            f"Ignored non-literal property '{key}' in repo-local {repo_cfg_path}."
                        )
                        print(msg, file=sys.stderr)
                        warnings.append(msg)

    # 3. CLI --property KEY=VAL overrides
    for raw_pair in cli_properties or []:
        if "=" not in raw_pair:
            raise MigrationError(
                f"Invalid --property value '{raw_pair}'. Expected KEY=VAL format."
            )
        key, val = raw_pair.split("=", 1)
        key = key.strip()
        if not key:
            raise MigrationError(f"Empty key in --property '{raw_pair}'.")
        properties[key] = val

    return {
        "api_key": api_key.strip(),
        "base_url": (base_url.strip() or DEFAULT_ENGRAM_BASE_URL).rstrip("/"),
        "properties": properties,
        "warnings": warnings,
    }


def _http_json_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
    timeout_seconds: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url=url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as err:
        with err:
            err_body = err.read().decode("utf-8", errors="replace")
        raise MigrationError(
            f"HTTP {err.code} from {method} {url}: {err_body[:400]}"
        ) from err
    except urllib.error.URLError as err:
        raise MigrationError(f"Network error calling {method} {url}: {err.reason}") from err

    if not raw.strip():
        return status, {}

    if "text/event-stream" in content_type.lower() or raw.lstrip().startswith("data:"):
        parsed = _parse_sse_json(raw)
        if parsed is not None:
            return status, parsed

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MigrationError(
            f"Invalid JSON response from {method} {url}: {raw[:200]}"
        ) from exc
    return status, data if isinstance(data, dict) else {"data": data}


def _parse_sse_json(raw: str) -> dict[str, Any] | None:
    last_obj: dict[str, Any] | None = None
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            obj = json.loads(payload)
            if isinstance(obj, dict):
                last_obj = obj
        except json.JSONDecodeError:
            continue
    return last_obj


def load_memories_from_file(path: Path) -> list[dict[str, Any]]:
    """Load Engram memories from a JSON or JSONL export file."""
    if not path.is_file():
        raise MigrationError(f"Input file not found: {path}")

    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    if path.suffix.lower() == ".jsonl":
        memories: list[dict[str, Any]] = []
        for idx, line in enumerate(raw.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise MigrationError(f"Invalid JSONL on line {idx} of {path}: {exc}") from exc
            if isinstance(obj, dict) and isinstance(obj.get("memories"), list):
                memories.extend(m for m in obj["memories"] if isinstance(m, dict))
            elif isinstance(obj, dict):
                memories.append(obj)
        return memories

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MigrationError(f"Invalid JSON in {path}: {exc}") from exc

    if isinstance(parsed, dict) and isinstance(parsed.get("memories"), list):
        return [m for m in parsed["memories"] if isinstance(m, dict)]
    if isinstance(parsed, list):
        return [m for m in parsed if isinstance(m, dict)]
    raise MigrationError(
        f"Unsupported export structure in {path}. Expected {{\"memories\": [...]}} or [...]."
    )


def fetch_engram_memories(
    *,
    api_key: str,
    base_url: str,
    groups_filter: list[str] | None = None,
    topics_filter: list[str] | None = None,
    user_ids: list[str] | None = None,
    properties: dict[str, Any] | None = None,
    limit: int = DEFAULT_FETCH_LIMIT,
    client_header: str = CLIENT_HEADER_VALUE,
    warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Read-only lossless export from Weaviate Engram via /v1/groups and /v1/memories/search."""
    if not api_key:
        raise MigrationError(
            "Missing Engram API key. Set ENGRAM_API_KEY, pass --api-key, pass --read-shell-profile, "
            "or use --from-file <export.json> for offline migration."
        )

    warn_list = warnings if warnings is not None else []
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Engram-Client": client_header,
    }

    _, groups_resp = _http_json_request(
        method="GET",
        url=f"{base_url}/v1/groups",
        headers=headers,
    )
    discovered_groups = groups_resp.get("groups", [])
    if not isinstance(discovered_groups, list):
        discovered_groups = []

    target_groups = set(groups_filter or [])
    target_topics = set(topics_filter or [])
    props = properties or {}

    selected_groups: list[dict[str, Any]] = []
    for grp in discovered_groups:
        if not isinstance(grp, dict):
            continue
        grp_name = str(grp.get("name") or "")
        if target_groups and grp_name not in target_groups:
            continue
        selected_groups.append(grp)

    if target_groups:
        found_names = {str(g.get("name") or "") for g in selected_groups}
        for missing_grp in sorted(target_groups - found_names):
            selected_groups.append(
                {
                    "group_id": missing_grp,
                    "name": missing_grp,
                    "topics": [{"topic_name": t} for t in sorted(target_topics)]
                    if target_topics
                    else [],
                    "scoping": {},
                }
            )

    deduped: dict[str, dict[str, Any]] = {}
    fallback_seq = 0

    for grp in selected_groups:
        grp_name = str(grp.get("name") or grp.get("group_id") or "")
        if not grp_name:
            continue
        grp_scoping = grp.get("scoping") if isinstance(grp.get("scoping"), dict) else {}
        raw_topics = grp.get("topics") if isinstance(grp.get("topics"), list) else []

        topic_entries: list[dict[str, Any]] = []
        for top in raw_topics:
            if not isinstance(top, dict):
                continue
            top_name = str(top.get("topic_name") or "")
            if target_topics and top_name not in target_topics:
                continue
            topic_entries.append(top)

        if target_topics:
            seen_topic_names = {str(t.get("topic_name") or "") for t in topic_entries}
            for explicit_topic in sorted(target_topics - seen_topic_names):
                topic_entries.append({"topic_name": explicit_topic, "scoping": {}})

        if not topic_entries:
            topic_entries = [{"topic_name": None, "scoping": grp_scoping}]

        for top in topic_entries:
            top_name = top.get("topic_name")
            top_scoping = top.get("scoping") if isinstance(top.get("scoping"), dict) else {}
            merged_scoping = {**grp_scoping, **top_scoping}
            user_scoped = bool(merged_scoping.get("user_scoped", False))
            scope_props = [
                str(p) for p in (merged_scoping.get("scope_properties") or []) if p
            ]

            if user_ids:
                uid_list: list[str | None] = list(user_ids)
            elif user_scoped:
                warn_list.append(
                    f"Group '{grp_name}' topic '{top_name or '*'}' is user_scoped; "
                    "pass --user-id to target specific users."
                )
                uid_list = [None]
            else:
                uid_list = [None]

            req_props: dict[str, Any] = {}
            if scope_props:
                for sp in scope_props:
                    if sp in props:
                        req_props[sp] = props[sp]
                    else:
                        warn_list.append(
                            f"Group '{grp_name}' topic '{top_name or '*'}' expects scope property '{sp}', "
                            "which was not set via config or --property."
                        )
            elif props:
                req_props = dict(props)

            for uid in uid_list:
                search_body: dict[str, Any] = {
                    "query": "",
                    "group": grp_name,
                    "retrieval_config": {
                        "retrieval_type": "fetch",
                        "limit": limit,
                    },
                }
                if top_name:
                    search_body["topics"] = [str(top_name)]
                if uid:
                    search_body["user_id"] = uid
                if req_props:
                    search_body["properties"] = req_props

                _, search_resp = _http_json_request(
                    method="POST",
                    url=f"{base_url}/v1/memories/search",
                    headers=headers,
                    payload=search_body,
                )
                memories = search_resp.get("memories", [])
                if not isinstance(memories, list):
                    memories = []
                total = search_resp.get("total")
                if isinstance(total, int) and total > len(memories):
                    warn_list.append(
                        f"Engram returned {len(memories)} of {total} memories for "
                        f"group='{grp_name}' topic='{top_name or '*'}'. Increase --limit."
                    )

                for mem in memories:
                    if not isinstance(mem, dict):
                        continue
                    mem_id = str(mem.get("id") or "")
                    if not mem_id:
                        fallback_seq += 1
                        mem_id = f"anon-{fallback_seq}"
                    if mem_id not in deduped:
                        deduped[mem_id] = mem

    return list(deduped.values())


def _parse_iso_timestamp(ts: Any) -> tuple[float, str]:
    if isinstance(ts, str) and ts.strip():
        raw = ts.strip()
        normalized = raw.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp(), dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return 0.0, now_iso


def _slugify(value: str, max_len: int = 80) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return (slug or "item")[:max_len].strip("_") or "item"


def _normalize_subject_heading(heading: str) -> str:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", heading.lower()) if w]
    filtered = [w for w in words if w not in GENERIC_SUBJECT_PREFIX_MODIFIERS]
    chosen = filtered if filtered else words
    return "_".join(chosen[:8]) or "item"


def infer_entity_hint(memory: dict[str, Any], override: str | None) -> str:
    if override and override.strip():
        return override.strip()[:200]
    props = memory.get("properties")
    if isinstance(props, dict):
        for key in ("repo", "project", "entity", "service", "workspace"):
            val = props.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    group = memory.get("group")
    if isinstance(group, str) and group.strip():
        return group.strip()[:200]
    return "Engram Migration"


def infer_knot_kind(
    *,
    topic: str,
    statement: str,
    personal_preferences_as_project: bool,
) -> tuple[str, bool]:
    """Map Engram topic/content to Knot kind and return (kind, is_personal_preference)."""
    topic_norm = re.sub(r"\s+", "_", topic.strip().lower())
    is_pref_topic = (
        topic_norm in PERSONAL_PREFERENCE_TOPICS
        or "preference" in topic_norm
        or topic_norm == "userknowledge"
    )
    if is_pref_topic:
        if personal_preferences_as_project:
            return "fact", False
        return "preference", True

    lower = statement.lower()
    if topic_norm in CONSTRAINT_TOPICS or any(
        marker in lower
        for marker in (
            "must never",
            "must not",
            "prohibited",
            "pci_cde_payload_rejected",
            "http 422",
            "hard limit",
            "cannot exceed",
            "forbidden",
            "strictly reject",
        )
    ):
        return "constraint", False

    if topic_norm in DECISION_TOPICS or any(
        marker in lower
        for marker in (
            "decided to",
            "we chose",
            "switch to",
            "switched to",
            "migrated from",
            "standardize on",
            "instead of",
            "replaced ",
            "adopt ",
        )
    ):
        return "decision", False

    if topic_norm in GOAL_TOPICS or any(
        marker in lower
        for marker in ("goal is", "target ", "aim to", "milestone", "okr")
    ):
        return "goal", False

    if topic_norm in STATE_TOPICS or any(
        marker in lower
        for marker in (
            "currently running",
            "deployed to",
            "rollout at",
            "active version",
            "in progress",
        )
    ):
        return "project_state", False

    return "fact", False


def infer_subject_key(memory: dict[str, Any], topic: str, statement: str) -> str:
    """Compute a deterministic subject_key enabling chronological v1 -> v2 matching."""
    topic_slug = _slugify(topic or "general", max_len=40)
    props = memory.get("properties")
    if isinstance(props, dict):
        for key in ("subject_key", "entity_key", "key", "slot", "topic_key"):
            val = props.get(key)
            if isinstance(val, str) and val.strip():
                return f"{topic_slug}:{_slugify(val, max_len=120)}"[:200]

    tags = memory.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.lower().startswith("subject:"):
                raw = tag.split(":", 1)[1].strip()
                if raw:
                    return f"{topic_slug}:{_slugify(raw, max_len=120)}"[:200]

    # Match "<Subject Label>: details" or "<Subject Label (v2 update)>: details"
    colon_match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9 _./()-]{2,70}):\s+\S", statement)
    if colon_match:
        heading = colon_match.group(1)
        norm_heading = _normalize_subject_heading(heading)
        if norm_heading and norm_heading != "item":
            return f"{topic_slug}:{norm_heading}"[:200]

    digest = hashlib.sha256(f"{topic_slug}:{statement}".encode("utf-8")).hexdigest()[:10]
    snippet = _slugify(" ".join(statement.split()[:6]), max_len=60)
    return f"{topic_slug}:{snippet}_{digest}"[:200]


def make_idempotency_key(memory_id: str) -> str:
    raw = f"engram:{memory_id}"
    if len(raw) <= 200:
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{raw[:183]}-{digest}"


def _build_mcp_item(rec: dict[str, Any], include_supersedes_placeholder: bool = False) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": rec["kind"],
        "statement": rec["statement"],
        "subject_key": rec["subject_key"],
        "observed_at": rec["observed_at"],
        "confidence": "high",
        "rationale": rec["rationale"],
    }
    if rec["kind"] not in ("preference", "person", "relationship"):
        item["entity_hint"] = rec["entity_hint"]
    if include_supersedes_placeholder:
        item["supersedes_context_id"] = (
            f"<resolve context_id from idempotency_key '{rec['supersedes_idempotency_key']}'>"
        )
    return item


def compile_migration_bundle(
    memories: list[dict[str, Any]],
    *,
    entity_hint_override: str | None = None,
    personal_preferences_as_project: bool = False,
    source_meta: dict[str, Any] | None = None,
    initial_warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Scrub, sort, chain v1 -> v2 supersessions, and build a Knot migration bundle."""
    warnings: list[str] = list(initial_warnings or [])
    stats = ScrubStats()

    prepared: list[tuple[tuple[float, str, str], dict[str, Any]]] = []
    skipped_empty = 0

    for idx, mem in enumerate(memories):
        mem_id = str(mem.get("id") or f"row_{idx}")
        raw_content = str(mem.get("content") or "").strip()
        scrubbed_content = scrub_text(raw_content, stats).strip()
        if not scrubbed_content:
            skipped_empty += 1
            warnings.append(f"Skipped empty memory '{mem_id}'.")
            continue

        raw_props = mem.get("properties") if isinstance(mem.get("properties"), dict) else {}
        scrubbed_props = scrub_value(raw_props, stats)
        raw_tags = mem.get("tags") if isinstance(mem.get("tags"), list) else []
        scrubbed_tags = [str(t) for t in scrub_value(raw_tags, stats) if t is not None]

        created_ts, created_iso = _parse_iso_timestamp(mem.get("created_at"))
        updated_raw = mem.get("updated_at") or mem.get("created_at")
        updated_ts, observed_iso = _parse_iso_timestamp(updated_raw)
        if not mem.get("created_at"):
            created_iso = observed_iso

        group = str(mem.get("group") or "")
        topic = str(mem.get("topic") or "general")
        user_id = str(mem.get("user_id")) if mem.get("user_id") else None

        entity_hint = infer_entity_hint(
            {"group": group, "properties": scrubbed_props},
            entity_hint_override,
        )
        kind, is_personal_pref = infer_knot_kind(
            topic=topic,
            statement=scrubbed_content,
            personal_preferences_as_project=personal_preferences_as_project,
        )
        subject_key = infer_subject_key(
            {"properties": scrubbed_props, "tags": scrubbed_tags},
            topic=topic,
            statement=scrubbed_content,
        )
        idempotency_key = make_idempotency_key(mem_id)
        rationale = (
            f"Migrated from Weaviate Engram (group={group or 'default'}, topic={topic}, id={mem_id})"
        )

        record = {
            "source_memory_id": mem_id,
            "idempotency_key": idempotency_key,
            "entity_hint": entity_hint,
            "kind": kind,
            "is_personal_preference": is_personal_pref,
            "statement": scrubbed_content,
            "subject_key": subject_key,
            "observed_at": observed_iso,
            "created_at": created_iso,
            "updated_at": observed_iso,
            "group": group,
            "topic": topic,
            "user_id": user_id,
            "tags": scrubbed_tags,
            "properties": scrubbed_props,
            "rationale": rationale,
            "version": 1,
            "supersedes_idempotency_key": None,
            "supersedes_memory_id": None,
        }
        sort_key = (updated_ts if updated_ts else created_ts, created_iso, mem_id)
        prepared.append((sort_key, record))

    prepared.sort(key=lambda pair: pair[0])
    records = [pair[1] for pair in prepared]

    # Chain v1 -> v2 -> ... supersessions chronologically per (scope, subject_key)
    chains: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for rec in records:
        if rec["kind"] in ("preference", "person", "relationship"):
            chain_key: tuple[str, ...] = (
                "__personal__",
                rec["user_id"] or "default",
                rec["subject_key"],
            )
        else:
            chain_key = ("__project__", rec["entity_hint"].lower(), rec["subject_key"])
        chains.setdefault(chain_key, []).append(rec)

    supersession_chains = 0
    for chain in chains.values():
        if len(chain) <= 1:
            continue
        supersession_chains += 1
        for pos, rec in enumerate(chain):
            rec["version"] = pos + 1
            if pos > 0:
                prev = chain[pos - 1]
                rec["supersedes_idempotency_key"] = prev["idempotency_key"]
                rec["supersedes_memory_id"] = prev["source_memory_id"]

    v1_records = [r for r in records if r["supersedes_idempotency_key"] is None]
    v2_records = [r for r in records if r["supersedes_idempotency_key"] is not None]

    # Chunk v1 records <= 25 items per batch_propose_context call
    mcp_batches: list[dict[str, Any]] = []
    for batch_idx in range(0, len(v1_records), MCP_BATCH_SIZE):
        chunk = v1_records[batch_idx : batch_idx + MCP_BATCH_SIZE]
        keys = [r["idempotency_key"] for r in chunk]
        batch_hash = hashlib.sha256("|".join(keys).encode("utf-8")).hexdigest()[:8]
        mcp_batches.append(
            {
                "batch_index": len(mcp_batches),
                "tool": "batch_propose_context",
                "item_idempotency_keys": keys,
                "arguments": {
                    "idempotency_key": f"engram-migration-batch-{len(mcp_batches)}-{batch_hash}",
                    "on_conflict": "clarify",
                    "items": [_build_mcp_item(r) for r in chunk],
                },
            }
        )

    mcp_supersessions: list[dict[str, Any]] = []
    for step_idx, rec in enumerate(v2_records):
        args_obj = _build_mcp_item(rec, include_supersedes_placeholder=True)
        args_obj["idempotency_key"] = rec["idempotency_key"]
        mcp_supersessions.append(
            {
                "step_index": step_idx,
                "tool": "propose_context",
                "idempotency_key": rec["idempotency_key"],
                "supersedes_idempotency_key": rec["supersedes_idempotency_key"],
                "supersedes_memory_id": rec["supersedes_memory_id"],
                "version": rec["version"],
                "arguments": args_obj,
            }
        )

    pref_count = sum(1 for r in records if r["kind"] in ("preference", "person", "relationship"))
    if pref_count > 0:
        warnings.append(
            f"{pref_count} personal preference record(s) use kind='preference' and enter Knot's "
            "pending approval queue unless --personal-preferences-as-project is set."
        )

    kind_counts: dict[str, int] = {}
    entities: list[str] = []
    seen_entities: set[str] = set()
    for rec in records:
        kind_counts[rec["kind"]] = kind_counts.get(rec["kind"], 0) + 1
        ent = rec["entity_hint"]
        if ent not in seen_entities:
            seen_entities.add(ent)
            entities.append(ent)

    summary = {
        "total_source_memories": len(memories),
        "compiled_records": len(records),
        "skipped_empty": skipped_empty,
        "v1_batch_items": len(v1_records),
        "supersession_items": len(v2_records),
        "supersession_chains": supersession_chains,
        "batch_call_count": len(mcp_batches),
        "preference_pending_items": pref_count,
        "project_immediate_items": len(records) - pref_count,
        "secrets_scrubbed": stats.secrets_scrubbed,
        "pans_scrubbed": stats.pans_scrubbed,
        "entities": entities,
        "kinds": kind_counts,
    }

    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source_meta or {},
        "summary": summary,
        "warnings": warnings,
        "records": records,
        "mcp_batches": mcp_batches,
        "mcp_supersessions": mcp_supersessions,
    }


def _extract_mcp_result_payload(rpc_resp: dict[str, Any]) -> dict[str, Any]:
    if "error" in rpc_resp and rpc_resp["error"]:
        err = rpc_resp["error"]
        raise MigrationError(f"Knot MCP JSON-RPC error: {err}")
    result = rpc_resp.get("result")
    if not isinstance(result, dict):
        return {}
    if result.get("isError"):
        raise MigrationError(f"Knot MCP tool returned error: {result}")
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    content = result.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                try:
                    parsed = json.loads(part["text"])
                    if isinstance(parsed, dict):
                        return parsed
                except json.JSONDecodeError:
                    continue
    return result


def push_bundle_to_mcp(
    bundle: dict[str, Any],
    *,
    mcp_url: str,
    mcp_token: str,
) -> dict[str, Any]:
    """Push compiled bundle to Knot Streamable HTTP MCP (batch_propose_context + propose_context)."""
    if not mcp_token:
        raise MigrationError(
            "Missing Knot MCP token. Pass --knot-mcp-token or set KNOT_ACCESS_TOKEN, "
            "or omit --push and let your connected IDE MCP run the bundle via OAuth 2.1."
        )

    headers = {
        "Authorization": f"Bearer {mcp_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    idempotency_to_context_id: dict[str, str] = {}
    push_warnings: list[str] = []
    rpc_id = 1
    batches_sent = 0
    supersessions_sent = 0

    for batch in bundle.get("mcp_batches", []):
        rpc_req = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {
                "name": "batch_propose_context",
                "arguments": batch["arguments"],
            },
        }
        rpc_id += 1
        _, rpc_resp = _http_json_request(
            method="POST", url=mcp_url, headers=headers, payload=rpc_req
        )
        batches_sent += 1
        payload = _extract_mcp_result_payload(rpc_resp)

        item_keys: list[str] = list(batch.get("item_idempotency_keys", []))
        direct_items = payload.get("direct_items")
        if isinstance(direct_items, list):
            for idx, outcome in enumerate(direct_items):
                if idx < len(item_keys) and isinstance(outcome, dict):
                    ctx_id = outcome.get("context_id") or outcome.get("id")
                    if isinstance(ctx_id, str) and ctx_id:
                        idempotency_to_context_id[item_keys[idx]] = ctx_id
        elif isinstance(payload.get("projects"), list):
            # Fallback if a server responds using grouped projects
            proj_outcomes: list[dict[str, Any]] = []
            for proj in payload["projects"]:
                if isinstance(proj, dict) and isinstance(proj.get("items"), list):
                    proj_outcomes.extend(o for o in proj["items"] if isinstance(o, dict))
            for idx, outcome in enumerate(proj_outcomes):
                if idx < len(item_keys):
                    ctx_id = outcome.get("context_id") or outcome.get("id")
                    if isinstance(ctx_id, str) and ctx_id:
                        idempotency_to_context_id[item_keys[idx]] = ctx_id

    for step in bundle.get("mcp_supersessions", []):
        args_copy = dict(step["arguments"])
        parent_key = step.get("supersedes_idempotency_key")
        resolved_parent_id = (
            idempotency_to_context_id.get(parent_key) if isinstance(parent_key, str) else None
        )
        if resolved_parent_id:
            args_copy["supersedes_context_id"] = resolved_parent_id
        else:
            args_copy.pop("supersedes_context_id", None)
            push_warnings.append(
                f"Could not resolve supersedes_context_id for '{step['idempotency_key']}' "
                f"(parent '{parent_key}'); sent as new context item."
            )

        rpc_req = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {
                "name": "propose_context",
                "arguments": args_copy,
            },
        }
        rpc_id += 1
        _, rpc_resp = _http_json_request(
            method="POST", url=mcp_url, headers=headers, payload=rpc_req
        )
        supersessions_sent += 1
        payload = _extract_mcp_result_payload(rpc_resp)
        ctx_id = payload.get("context_id") or payload.get("id")
        if isinstance(ctx_id, str) and ctx_id:
            idempotency_to_context_id[step["idempotency_key"]] = ctx_id

    return {
        "target": "mcp",
        "mcp_url": mcp_url,
        "batches_sent": batches_sent,
        "supersessions_sent": supersessions_sent,
        "resolved_context_ids": idempotency_to_context_id,
        "warnings": push_warnings,
    }


def push_bundle_to_rest(
    bundle: dict[str, Any],
    *,
    rest_base_url: str,
    api_key: str,
    domain_override: str | None = None,
    subject_id_override: str | None = None,
) -> dict[str, Any]:
    """Push compiled records sequentially to Knot REST POST /context/upsert."""
    if not api_key:
        raise MigrationError(
            "Missing Knot API key. Pass --knot-api-key or set KNOT_API_KEY."
        )

    upsert_url = f"{rest_base_url.rstrip('/')}/context/upsert"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    idempotency_to_remote_id: dict[str, str] = {}
    upserted = 0

    for rec in bundle.get("records", []):
        parent_key = rec.get("supersedes_idempotency_key")
        supersedes_val: str | None = None
        if isinstance(parent_key, str) and parent_key:
            supersedes_val = idempotency_to_remote_id.get(parent_key, parent_key)

        payload = {
            "subjectId": subject_id_override or rec.get("user_id") or "default",
            "domain": domain_override or rec.get("entity_hint") or "Engram Migration",
            "category": rec["kind"],
            "entityKey": rec["subject_key"],
            "content": rec["statement"],
            "observedAt": rec["observed_at"],
            "supersedes": supersedes_val,
            "provenance": {
                "source": "weaviate-engram",
                "source_memory_id": rec["source_memory_id"],
                "idempotency_key": rec["idempotency_key"],
                "group": rec.get("group") or None,
                "topic": rec.get("topic") or None,
                "user_id": rec.get("user_id"),
                "tags": rec.get("tags", []),
                "properties": rec.get("properties", {}),
                "created_at": rec.get("created_at"),
                "updated_at": rec.get("updated_at"),
            },
        }
        _, resp = _http_json_request(
            method="POST", url=upsert_url, headers=headers, payload=payload
        )
        upserted += 1
        remote_id = (
            resp.get("context_id")
            or resp.get("contextId")
            or resp.get("id")
            or (resp.get("data", {}).get("id") if isinstance(resp.get("data"), dict) else None)
        )
        if isinstance(remote_id, str) and remote_id:
            idempotency_to_remote_id[rec["idempotency_key"]] = remote_id

    return {
        "target": "rest",
        "upsert_url": upsert_url,
        "records_upserted": upserted,
        "resolved_remote_ids": idempotency_to_remote_id,
    }


def _split_csv_flags(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for part in raw.split(","):
            cleaned = part.strip()
            if cleaned:
                out.append(cleaned)
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export Weaviate Engram memories (read-only), scrub secrets/PANs locally, "
            "and compile v1 -> v2 supersession bundles for Knot MCP or EnterpriseBrain REST."
        )
    )
    parser.add_argument(
        "--from-file",
        type=str,
        default=None,
        help="Read memories from a local JSON or JSONL export file instead of calling Engram.",
    )
    parser.add_argument("--api-key", type=str, default=None, help="Engram API key.")
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help=f"Engram REST base URL (default: {DEFAULT_ENGRAM_BASE_URL}).",
    )
    parser.add_argument(
        "--client-header",
        type=str,
        default=CLIENT_HEADER_VALUE,
        help="Optional X-Engram-Client header value.",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        help="Engram group name to export (repeatable or comma-separated).",
    )
    parser.add_argument(
        "--topic",
        action="append",
        default=[],
        help="Engram topic name to export (repeatable or comma-separated).",
    )
    parser.add_argument(
        "--user-id",
        action="append",
        default=[],
        help="Engram user_id filter for user-scoped topics (repeatable or comma-separated).",
    )
    parser.add_argument(
        "--property",
        action="append",
        default=[],
        help="Engram scope property filter as KEY=VAL (repeatable).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_FETCH_LIMIT,
        help=f"Max memories per group/topic fetch call (default: {DEFAULT_FETCH_LIMIT}).",
    )
    parser.add_argument(
        "--read-shell-profile",
        action="store_true",
        help="Opt-in lookup of ENGRAM_API_KEY / ENGRAM_BASE_URL from shell profile files.",
    )
    parser.add_argument(
        "--entity-hint",
        type=str,
        default=None,
        help="Override Knot entity_hint for all exported records.",
    )
    parser.add_argument(
        "--personal-preferences-as-project",
        action="store_true",
        help="Map personal preference topics as project-scoped facts instead of pending preferences.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path to write the migration bundle JSON (default: {DEFAULT_OUTPUT_FILE}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate the local migration bundle only without pushing to Knot.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push the compiled migration bundle to Knot (--target mcp or rest).",
    )
    parser.add_argument(
        "--target",
        choices=("mcp", "rest"),
        default="mcp",
        help="Knot push target protocol when --push is set (default: mcp).",
    )
    parser.add_argument(
        "--knot-mcp-token",
        type=str,
        default=None,
        help="Knot MCP Bearer access token (or set KNOT_ACCESS_TOKEN).",
    )
    parser.add_argument(
        "--knot-mcp-url",
        type=str,
        default=None,
        help=f"Knot Streamable HTTP MCP URL (default: {DEFAULT_KNOT_MCP_URL}).",
    )
    parser.add_argument(
        "--knot-api-key",
        type=str,
        default=None,
        help="Knot REST API key (or set KNOT_API_KEY).",
    )
    parser.add_argument(
        "--knot-base-url",
        type=str,
        default=None,
        help=f"Knot REST base URL (default: {DEFAULT_KNOT_REST_URL}).",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Optional Knot EnterpriseBrain domain override for --target rest.",
    )
    parser.add_argument(
        "--subject-id",
        type=str,
        default=None,
        help="Optional Knot EnterpriseBrain subjectId override for --target rest.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.push and args.dry_run:
        print("Error: --push and --dry-run cannot be used together.", file=sys.stderr)
        return 2

    try:
        cfg = resolve_engram_config(
            cli_api_key=args.api_key,
            cli_base_url=args.base_url,
            cli_properties=args.property,
            read_shell_profile=args.read_shell_profile,
        )
        warnings: list[str] = list(cfg["warnings"])

        if args.from_file:
            source_path = Path(args.from_file)
            memories = load_memories_from_file(source_path)
            source_meta = {"mode": "file", "path": str(source_path)}
        else:
            memories = fetch_engram_memories(
                api_key=cfg["api_key"],
                base_url=cfg["base_url"],
                groups_filter=_split_csv_flags(args.group),
                topics_filter=_split_csv_flags(args.topic),
                user_ids=_split_csv_flags(args.user_id),
                properties=cfg["properties"],
                limit=args.limit,
                client_header=args.client_header,
                warnings=warnings,
            )
            source_meta = {"mode": "engram_rest", "base_url": cfg["base_url"]}

        bundle = compile_migration_bundle(
            memories,
            entity_hint_override=args.entity_hint,
            personal_preferences_as_project=args.personal_preferences_as_project,
            source_meta=source_meta,
            initial_warnings=warnings,
        )

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

        result_report: dict[str, Any] = {
            "bundle_path": str(out_path),
            "summary": bundle["summary"],
            "warnings": bundle["warnings"],
        }

        if args.push:
            if args.target == "mcp":
                mcp_url = (
                    args.knot_mcp_url
                    or os.environ.get("KNOT_MCP_URL")
                    or DEFAULT_KNOT_MCP_URL
                )
                mcp_token = (
                    args.knot_mcp_token
                    or os.environ.get("KNOT_ACCESS_TOKEN")
                    or ""
                )
                result_report["push"] = push_bundle_to_mcp(
                    bundle, mcp_url=mcp_url, mcp_token=mcp_token
                )
            else:
                rest_url = (
                    args.knot_base_url
                    or os.environ.get("KNOT_BASE_URL")
                    or DEFAULT_KNOT_REST_URL
                )
                knot_key = args.knot_api_key or os.environ.get("KNOT_API_KEY") or ""
                result_report["push"] = push_bundle_to_rest(
                    bundle,
                    rest_base_url=rest_url,
                    api_key=knot_key,
                    domain_override=args.domain,
                    subject_id_override=args.subject_id,
                )

        print(json.dumps(result_report, indent=2))
        return 0
    except MigrationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
