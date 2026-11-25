"""End-to-end tests for Engram-to-Knot migration CLI and EngramKnotCompatClient."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "skills" / "engram-to-knot-migration" / "scripts"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import migrate_engram  # noqa: E402
from sdk import EngramKnotCompatClient, EngramKnotCompatError  # noqa: E402


class _MockServer(ThreadingHTTPServer):
    allow_reuse_address = True


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[_MockServer, str]:
    server = _MockServer(("127.0.0.1", 0), handler_cls)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{host}:{port}"


class TestEngramConfigAndScrubber(unittest.TestCase):
    def test_repo_config_refuses_cmd_while_accepting_literals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home_dir = root / "home"
            cwd_dir = root / "repo"
            (home_dir / ".engram").mkdir(parents=True)
            cwd_dir.mkdir(parents=True)

            pwn_marker = root / "should_not_exist"
            (home_dir / ".engram" / "config.json").write_text(
                json.dumps(
                    {
                        "api_key": "home_key_123",
                        "properties": {
                            "org": "connectknot",
                            "home_dynamic": {"cmd": "echo home_resolved"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            (cwd_dir / ".engram.json").write_text(
                json.dumps(
                    {
                        "cmd": f"touch {pwn_marker}",
                        "properties": {
                            "repo": "checkout-platform",
                            "evil": {"cmd": f"touch {pwn_marker}"},
                            "nested": {"deep": {"cmd": f"touch {pwn_marker}"}},
                        },
                    }
                ),
                encoding="utf-8",
            )

            cfg = migrate_engram.resolve_engram_config(
                home_dir=home_dir,
                cwd=cwd_dir,
            )

            self.assertFalse(pwn_marker.exists())
            self.assertEqual(cfg["api_key"], "home_key_123")
            self.assertEqual(cfg["properties"]["org"], "connectknot")
            self.assertEqual(cfg["properties"]["home_dynamic"], "home_resolved")
            self.assertEqual(cfg["properties"]["repo"], "checkout-platform")
            self.assertNotIn("evil", cfg["properties"])
            self.assertNotIn("nested", cfg["properties"])
            self.assertGreaterEqual(len(cfg["warnings"]), 3)
            self.assertTrue(any("SECURITY WARNING" in w for w in cfg["warnings"]))

    def test_shell_profile_opt_in_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home_dir = root / "home"
            cwd_dir = root / "repo"
            home_dir.mkdir()
            cwd_dir.mkdir()
            (home_dir / ".zshrc").write_text(
                'export ENGRAM_API_KEY="profile_key_xyz"\n'
                'ENGRAM_BASE_URL=https://engram.example.internal\n',
                encoding="utf-8",
            )

            cfg_default = migrate_engram.resolve_engram_config(
                home_dir=home_dir, cwd=cwd_dir, read_shell_profile=False
            )
            self.assertEqual(cfg_default["api_key"], "")

            cfg_opt_in = migrate_engram.resolve_engram_config(
                home_dir=home_dir, cwd=cwd_dir, read_shell_profile=True
            )
            self.assertEqual(cfg_opt_in["api_key"], "profile_key_xyz")
            self.assertEqual(cfg_opt_in["base_url"], "https://engram.example.internal")

    def test_secret_and_pan_scrubbing_preserves_git_shas_and_uuids(self) -> None:
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        openai_key = "sk-test-fake-" + "0" * 24
        stripe_key = "sk_" + "live_" + "AbCdEf1234567890"
        gh_pat = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1L2"
        slack_tok = "xox" + "b-" + "1234567890-abcdef123456"
        pem_block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAtestkeymaterial\n"
            "-----END RSA PRIVATE KEY-----"
        )
        jwt_tok = "Bearer " + "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assign_secret = "DB_PASSWORD=" + "Pr0d$ecret!Pass#99"
        valid_pan_1 = "4111-1111-1111-1111"
        valid_pan_2 = "4242 4242 4242 4242"
        invalid_luhn = "4111-1111-1111-1112"
        git_sha_short = "a1b2c3d4e5f6"
        git_sha_full = "1234567890abcdef1234567890abcdef12345678"
        uuid_v4 = "550e8400-e29b-41d4-a716-446655440000"

        text = (
            f"aws={aws_key} openai={openai_key} stripe={stripe_key} gh={gh_pat} "
            f"slack={slack_tok} {pem_block} {jwt_tok} {assign_secret} "
            f"cards: {valid_pan_1} and {valid_pan_2} non_luhn={invalid_luhn} "
            f"sha={git_sha_short} full={git_sha_full} trace={uuid_v4}"
        )

        stats = migrate_engram.ScrubStats()
        scrubbed = migrate_engram.scrub_text(text, stats)

        self.assertEqual(stats.secrets_scrubbed, 8)
        self.assertEqual(stats.pans_scrubbed, 2)
        for secret in (aws_key, openai_key, stripe_key, gh_pat, slack_tok, "PRIVATE KEY", "eyJhbGciOiJIUzI1NiJ9", "Pr0d$ecret!Pass#99"):
            self.assertNotIn(secret, scrubbed)
        self.assertNotIn(valid_pan_1, scrubbed)
        self.assertNotIn(valid_pan_2, scrubbed)
        self.assertIn(invalid_luhn, scrubbed)
        self.assertIn(git_sha_short, scrubbed)
        self.assertIn(git_sha_full, scrubbed)
        self.assertIn(uuid_v4, scrubbed)


class TestEngramReadOnlyExportAndCompilation(unittest.TestCase):
    def test_live_mock_engram_readonly_export(self) -> None:
        recorded_requests: list[dict[str, Any]] = []

        class EngramHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_DELETE(self) -> None:
                recorded_requests.append({"method": "DELETE", "path": self.path})
                self.send_response(500)
                self.end_headers()

            def do_GET(self) -> None:
                recorded_requests.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "client": self.headers.get("X-Engram-Client"),
                    }
                )
                if self.path == "/v1/groups":
                    body = {
                        "groups": [
                            {
                                "group_id": "grp_1",
                                "name": "checkout-platform",
                                "scoping": {"user_scoped": True, "scope_properties": ["repo"]},
                                "topics": [
                                    {
                                        "topic_name": "architecture_decisions",
                                        "description": "ADRs",
                                        "is_bounded": False,
                                        "scoping": {"user_scoped": True, "scope_properties": ["repo"]},
                                    }
                                ],
                            }
                        ]
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(body).encode("utf-8"))
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                recorded_requests.append(
                    {
                        "method": "POST",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "payload": payload,
                    }
                )
                if self.path == "/v1/memories/search":
                    body = {
                        "memories": [
                            {
                                "id": "m_101",
                                "project_id": "p_1",
                                "group": "checkout-platform",
                                "topic": "architecture_decisions",
                                "user_id": "usr_7",
                                "content": "Storage engine: use PostgreSQL 16 with pgvector.",
                                "created_at": "2026-10-01T10:00:00Z",
                                "updated_at": "2026-10-01T10:00:00Z",
                                "tags": ["db"],
                                "score": 0.95,
                                "properties": {"repo": "checkout-platform"},
                            }
                        ],
                        "total": 1,
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(body).encode("utf-8"))
                    return
                self.send_response(404)
                self.end_headers()

        server, base_url = _start_server(EngramHandler)
        try:
            warnings: list[str] = []
            memories = migrate_engram.fetch_engram_memories(
                api_key="engram_test_token",
                base_url=base_url,
                user_ids=["usr_7"],
                properties={"repo": "checkout-platform"},
                limit=250,
                warnings=warnings,
            )
            self.assertEqual(len(memories), 1)
            self.assertEqual(memories[0]["id"], "m_101")
            self.assertFalse(any(r["method"] == "DELETE" for r in recorded_requests))

            get_reqs = [r for r in recorded_requests if r["method"] == "GET"]
            post_reqs = [r for r in recorded_requests if r["method"] == "POST"]
            self.assertEqual(len(get_reqs), 1)
            self.assertEqual(get_reqs[0]["auth"], "Bearer engram_test_token")
            self.assertTrue(get_reqs[0]["client"])
            self.assertEqual(len(post_reqs), 1)
            self.assertEqual(post_reqs[0]["payload"]["retrieval_config"]["retrieval_type"], "fetch")
            self.assertEqual(post_reqs[0]["payload"]["retrieval_config"]["limit"], 250)
            self.assertEqual(post_reqs[0]["payload"]["user_id"], "usr_7")
            self.assertEqual(post_reqs[0]["payload"]["properties"], {"repo": "checkout-platform"})
        finally:
            server.shutdown()
            server.server_close()

    def test_chronological_v1_to_v2_to_v3_supersession_chaining(self) -> None:
        memories = [
            {
                "id": "mem_v3",
                "group": "orders",
                "topic": "architecture_decisions",
                "content": "Retry limit (v3 final): max 3 retries with jitter.",
                "created_at": "2026-10-20T00:00:00Z",
                "updated_at": "2026-10-20T00:00:00Z",
            },
            {
                "id": "mem_v1",
                "group": "orders",
                "topic": "architecture_decisions",
                "content": "Retry limit: use 5 fixed retries.",
                "created_at": "2026-09-01T00:00:00Z",
                "updated_at": "2026-09-01T00:00:00Z",
            },
            {
                "id": "mem_v2",
                "group": "orders",
                "topic": "architecture_decisions",
                "content": "Retry limit update: max 4 exponential retries.",
                "created_at": "2026-10-01T00:00:00Z",
                "updated_at": "2026-10-01T00:00:00Z",
            },
        ]
        bundle = migrate_engram.compile_migration_bundle(memories)
        self.assertEqual(bundle["summary"]["v1_batch_items"], 1)
        self.assertEqual(bundle["summary"]["supersession_items"], 2)
        self.assertEqual(bundle["summary"]["supersession_chains"], 1)

        steps = bundle["mcp_supersessions"]
        self.assertEqual(steps[0]["idempotency_key"], "engram:mem_v2")
        self.assertEqual(steps[0]["supersedes_idempotency_key"], "engram:mem_v1")
        self.assertEqual(steps[0]["version"], 2)
        self.assertEqual(steps[1]["idempotency_key"], "engram:mem_v3")
        self.assertEqual(steps[1]["supersedes_idempotency_key"], "engram:mem_v2")
        self.assertEqual(steps[1]["version"], 3)

    def test_mcp_batch_chunking_at_most_25_items(self) -> None:
        memories = [
            {
                "id": f"m_{i}",
                "group": "bulk-group",
                "topic": "facts",
                "content": f"Service component {i} runs on port {8000 + i}.",
                "created_at": f"2026-10-01T00:00:{i:02d}Z",
            }
            for i in range(60)
        ]
        bundle = migrate_engram.compile_migration_bundle(memories)
        batches = bundle["mcp_batches"]
        self.assertEqual(len(batches), 3)
        self.assertEqual([len(b["arguments"]["items"]) for b in batches], [25, 25, 10])

    def test_preference_queue_vs_personal_preferences_as_project(self) -> None:
        memories = [
            {
                "id": "pref_1",
                "group": "checkout-platform",
                "topic": "UserKnowledge",
                "user_id": "usr_1",
                "content": "Prefer concise diffs.",
                "created_at": "2026-10-10T00:00:00Z",
            }
        ]
        default_bundle = migrate_engram.compile_migration_bundle(memories)
        self.assertEqual(default_bundle["summary"]["preference_pending_items"], 1)
        self.assertEqual(default_bundle["records"][0]["kind"], "preference")
        self.assertNotIn("entity_hint", default_bundle["mcp_batches"][0]["arguments"]["items"][0])

        proj_bundle = migrate_engram.compile_migration_bundle(
            memories, personal_preferences_as_project=True
        )
        self.assertEqual(proj_bundle["summary"]["preference_pending_items"], 0)
        self.assertEqual(proj_bundle["records"][0]["kind"], "fact")
        self.assertEqual(
            proj_bundle["mcp_batches"][0]["arguments"]["items"][0]["entity_hint"],
            "checkout-platform",
        )

    def test_cli_offline_sample_dry_run_bundle_json(self) -> None:
        sample_path = REPO_ROOT / "examples" / "sample-engram-export.json"
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "bundle.json"
            exit_code = migrate_engram.main(
                [
                    "--from-file",
                    str(sample_path),
                    "--dry-run",
                    "--output",
                    str(out_path),
                ]
            )
            self.assertEqual(exit_code, 0)
            bundle = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["summary"]["compiled_records"], 5)
            self.assertEqual(bundle["summary"]["secrets_scrubbed"], 1)
            self.assertEqual(bundle["summary"]["pans_scrubbed"], 1)
            self.assertEqual(bundle["summary"]["supersession_chains"], 1)
            self.assertEqual(bundle["summary"]["v1_batch_items"], 4)
            self.assertEqual(bundle["summary"]["supersession_items"], 1)
            serialized = json.dumps(bundle)
            self.assertNotIn("sk-test-fake-0000000000000000000000", serialized)
            self.assertNotIn("4111-1111-1111-1111", serialized)
            self.assertIn("a1b2c3d4e5f6", serialized)
            self.assertIn("550e8400-e29b-41d4-a716-446655440000", serialized)

    def test_cli_jsonl_input_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = Path(tmp) / "export.jsonl"
            out_path = Path(tmp) / "bundle.json"
            jsonl_path.write_text(
                json.dumps({"id": "j1", "group": "app", "topic": "facts", "content": "Fact one."})
                + "\n"
                + json.dumps({"id": "j2", "group": "app", "topic": "goals", "content": "Goal is sub-15ms reads."})
                + "\n",
                encoding="utf-8",
            )
            exit_code = migrate_engram.main(
                ["--from-file", str(jsonl_path), "--dry-run", "--output", str(out_path)]
            )
            self.assertEqual(exit_code, 0)
            bundle = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["summary"]["compiled_records"], 2)


class TestPushTargetsMcpAndRest(unittest.TestCase):
    def test_push_target_mcp_chains_supersedes_context_id(self) -> None:
        calls: list[dict[str, Any]] = []
        seq = 0

        class McpHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:
                nonlocal seq
                length = int(self.headers.get("Content-Length", "0"))
                rpc = json.loads(self.rfile.read(length).decode("utf-8"))
                calls.append({"auth": self.headers.get("Authorization"), "rpc": rpc})
                tool_name = rpc["params"]["name"]
                tool_args = rpc["params"]["arguments"]

                if tool_name == "batch_propose_context":
                    direct_items = []
                    for item in tool_args["items"]:
                        seq += 1
                        direct_items.append(
                            {
                                "statement": item["statement"],
                                "kind": item["kind"],
                                "context_id": f"00000000-0000-4000-8000-{seq:012d}",
                                "status": "pending" if item["kind"] == "preference" else "approved",
                            }
                        )
                    payload = {"direct_items": direct_items}
                else:
                    seq += 1
                    payload = {
                        "context_id": f"00000000-0000-4000-8000-{seq:012d}",
                        "status": "approved",
                    }

                resp = {
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload)}],
                        "structuredContent": payload,
                        "isError": False,
                    },
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode("utf-8"))

        server, base_url = _start_server(McpHandler)
        try:
            sample_path = REPO_ROOT / "examples" / "sample-engram-export.json"
            with tempfile.TemporaryDirectory() as tmp:
                out_path = Path(tmp) / "bundle.json"
                exit_code = migrate_engram.main(
                    [
                        "--from-file",
                        str(sample_path),
                        "--push",
                        "--target",
                        "mcp",
                        "--knot-mcp-url",
                        f"{base_url}/mcp",
                        "--knot-mcp-token",
                        "tok_mcp_123",
                        "--output",
                        str(out_path),
                    ]
                )
                self.assertEqual(exit_code, 0)
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0]["auth"], "Bearer tok_mcp_123")
                self.assertEqual(calls[0]["rpc"]["params"]["name"], "batch_propose_context")
                self.assertEqual(calls[1]["rpc"]["params"]["name"], "propose_context")
                # mem_engram_001 is chronological index 0 -> context_id ...000000000001
                self.assertEqual(
                    calls[1]["rpc"]["params"]["arguments"]["supersedes_context_id"],
                    "00000000-0000-4000-8000-000000000001",
                )
        finally:
            server.shutdown()
            server.server_close()

    def test_push_target_mcp_sse_response_parsing(self) -> None:
        class SseMcpHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                rpc = json.loads(self.rfile.read(length).decode("utf-8"))
                payload = {
                    "direct_items": [
                        {"context_id": "11111111-1111-4111-8111-111111111111", "status": "approved"}
                    ]
                }
                rpc_resp = {"jsonrpc": "2.0", "id": rpc["id"], "result": {"structuredContent": payload}}
                sse_body = f"event: message\ndata: {json.dumps(rpc_resp)}\n\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(sse_body.encode("utf-8"))

        server, base_url = _start_server(SseMcpHandler)
        try:
            bundle = migrate_engram.compile_migration_bundle(
                [{"id": "s1", "group": "app", "topic": "facts", "content": "SSE test fact."}]
            )
            res = migrate_engram.push_bundle_to_mcp(
                bundle, mcp_url=f"{base_url}/mcp", mcp_token="tok_sse"
            )
            self.assertEqual(
                res["resolved_context_ids"]["engram:s1"],
                "11111111-1111-4111-8111-111111111111",
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_push_target_rest_upserts_in_chronological_order(self) -> None:
        requests_seen: list[dict[str, Any]] = []
        seq = 0

        class RestHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:
                nonlocal seq
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                requests_seen.append(
                    {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
                )
                seq += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id": f"knot_ctx_{seq}"}).encode("utf-8"))

        server, base_url = _start_server(RestHandler)
        try:
            sample_path = REPO_ROOT / "examples" / "sample-engram-export.json"
            with tempfile.TemporaryDirectory() as tmp:
                out_path = Path(tmp) / "bundle.json"
                exit_code = migrate_engram.main(
                    [
                        "--from-file",
                        str(sample_path),
                        "--push",
                        "--target",
                        "rest",
                        "--knot-api-key",
                        "knot_test_key",
                        "--knot-base-url",
                        f"{base_url}/v1",
                        "--domain",
                        "checkout",
                        "--subject-id",
                        "subj_42",
                        "--output",
                        str(out_path),
                    ]
                )
                self.assertEqual(exit_code, 0)
                self.assertEqual(len(requests_seen), 5)
                first = requests_seen[0]
                self.assertEqual(first["path"], "/v1/context/upsert")
                self.assertEqual(first["auth"], "Bearer knot_test_key")
                self.assertEqual(first["body"]["subjectId"], "subj_42")
                self.assertEqual(first["body"]["domain"], "checkout")
                self.assertIsNone(first["body"]["supersedes"])
                self.assertEqual(first["body"]["provenance"]["source_memory_id"], "mem_engram_001")

                # mem_engram_003 is index 2 chronologically and supersedes mem_engram_001 (knot_ctx_1)
                v2_req = requests_seen[2]
                self.assertEqual(v2_req["body"]["provenance"]["source_memory_id"], "mem_engram_003")
                self.assertEqual(v2_req["body"]["supersedes"], "knot_ctx_1")
        finally:
            server.shutdown()
            server.server_close()


class TestEngramKnotCompatSdk(unittest.TestCase):
    def test_sdk_compat_memories_add_search_as_of_get_delete_and_erasure(self) -> None:
        events: list[dict[str, Any]] = []
        seq = 0

        class CompatRestHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:
                nonlocal seq
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                events.append({"method": "POST", "path": self.path, "body": body})
                if self.path == "/v1/context/upsert":
                    seq += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"id": f"ctx_{seq}", "status": "committed"}).encode("utf-8")
                    )
                    return
                if self.path == "/v1/context/retrieve":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {
                                "items": [
                                    {"id": "ctx_1", "content": "Use max 3 exponential retries."}
                                ]
                            }
                        ).encode("utf-8")
                    )
                    return
                self.send_response(404)
                self.end_headers()

            def do_GET(self) -> None:
                events.append({"method": "GET", "path": self.path})
                if self.path.startswith("/v1/subjects/usr_42/lineage"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {
                                "subjectId": "usr_42",
                                "items": [
                                    {"id": "ctx_1", "content": "Use max 3 exponential retries.", "version": 2}
                                ],
                            }
                        ).encode("utf-8")
                    )
                    return
                self.send_response(404)
                self.end_headers()

            def do_DELETE(self) -> None:
                events.append({"method": "DELETE", "path": self.path})
                if self.path == "/v1/subjects/usr_42/key":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"erased": True, "subjectId": "usr_42"}).encode("utf-8")
                    )
                    return
                self.send_response(404)
                self.end_headers()

        server, base_url = _start_server(CompatRestHandler)
        try:
            client = EngramKnotCompatClient(
                api_key="knot_compat_test",
                base_url=base_url,
                domain="checkout",
                default_subject_id="usr_42",
            )
            add_res = client.memories.add(
                "Webhook retry rule with dummy card 4111-1111-1111-1111",
                user_id="usr_42",
                topic="decisions",
                entity_key="retry_policy",
            )
            self.assertEqual(add_res["id"], "ctx_1")
            self.assertIn("[REDACTED_PAN]", events[0]["body"]["content"])
            self.assertEqual(events[0]["body"]["category"], "decision")

            search_res = client.memories.search(
                "retry policy",
                user_id="usr_42",
                scopes=["checkout", "security"],
                as_of="2026-10-15T00:00:00Z",
                limit=10,
            )
            self.assertEqual(len(search_res["items"]), 1)
            self.assertEqual(events[1]["body"]["asOf"], "2026-10-15T00:00:00Z")
            self.assertEqual(events[1]["body"]["scopes"], ["checkout", "security"])
            self.assertEqual(events[1]["body"]["limit"], 10)

            got = client.memories.get("ctx_1", user_id="usr_42", entity_key="retry_policy")
            self.assertIsNotNone(got)
            self.assertEqual(got["id"], "ctx_1")

            tombstone = client.memories.delete("ctx_1", user_id="usr_42")
            self.assertEqual(tombstone["status"], "tombstoned")
            self.assertEqual(tombstone["superseded_id"], "ctx_1")

            erased_via_memories = client.memories.delete(user_id="usr_42", erase_subject=True)
            self.assertTrue(erased_via_memories["erased"])

            erased_direct = client.erase_user_subject("usr_42")
            self.assertTrue(erased_direct["erased"])

            lineage = client.lineage("usr_42", entity_key="retry_policy")
            self.assertEqual(lineage["subjectId"], "usr_42")
        finally:
            server.shutdown()
            server.server_close()

    def test_sdk_compat_error_handling_and_base_url_normalization(self) -> None:
        class ErrHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 0:
                    self.rfile.read(length)
                self.send_response(422)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "code": "PCI_CDE_PAYLOAD_REJECTED",
                            "message": "Raw CDE payload rejected by write-door policy.",
                        }
                    ).encode("utf-8")
                )

        server, base_url = _start_server(ErrHandler)
        try:
            c1 = EngramKnotCompatClient(api_key="knot_err", base_url=f"{base_url}/v1/")
            self.assertEqual(c1.base_url, f"{base_url}/v1")
            with self.assertRaises(EngramKnotCompatError) as ctx:
                c1.memories.add("Some state payload", user_id="u_9")
            self.assertEqual(ctx.exception.status, 422)
            self.assertEqual(ctx.exception.code, "PCI_CDE_PAYLOAD_REJECTED")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
