"""The approval API: authentication, authorisation, validation, status codes, idempotency, conflicts, pagination. Framework-free (Api.dispatch) on the in-memory repository, plus the same
flows against PostgreSQL (opt-in) and a FastAPI section that runs only when fastapi and httpx are installed."""
import copy
import json
import threading
import unittest

from week4.api import auth, routes
from week4.api.handlers import Api
from week4.db.drivers import DbError
from week4.db.fake import MemoryRepository
from week4.db.repository import PgRepository

from tests.week4_support import PgHarness, driver_for, make_payload, pg_enabled, seed_analysts

_PG_OK, _PG_WHY = pg_enabled()

TOKENS = {name: auth.new_token() for name in ("alice", "dave", "bob", "carol", "erin", "root", "ghost")}


def bearer(name, token=None):
    return {"Authorization": "Bearer " + (token or TOKENS[name])}


def make_auth():
    return auth.AuthConfig("token", {name: auth.hash_token(tok) for name, tok in TOKENS.items()})


class ApiCase:
    """Mixin: self.repo is a Repository with the standard analysts; builds self.api."""

    def build(self):
        seed_analysts(self.repo)
        self.api = Api(self.repo, make_auth())

    def call(self, name, who="alice", headers=None, **kw):
        h = dict(bearer(who)) if who else {}
        h.update(headers or {})
        return self.api.dispatch(name, headers=h, **kw)

    def new_case(self, **kw):
        out = self.repo.ingest_case(make_payload(**kw))
        case = self.repo.get_case(out["case_id"])
        return case, (case["actions"][0]["action_id"] if case["actions"] else None)

    def decide(self, action_id, decision="approved", who="alice", key="key-0000-0001", reason="looks right", body=None):
        body = body if body is not None else {"decision": decision, "reason": reason}
        headers = {"Idempotency-Key": key} if key is not None else {}
        return self.call("decide", who, headers, path_params={"action_id": action_id}, body=body)


class ApiTests(ApiCase):
    # ------------------------------------------------------------------ authentication and authorisation
    def test_every_protected_route_refuses_anonymous_and_bad_credentials(self):
        case, aid = self.new_case()
        for route in routes.ROUTES:
            if route.role is None:
                continue
            for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer " + "x" * 40},
                            {"X-Dev-Analyst": "alice"}):
                with self.subTest((route.name, tuple(headers))):
                    r = self.api.dispatch(route.name, headers=headers, path_params={"case_id": case["case_id"], "action_id": aid}, body={"decision": "approved", "reason": "x"})
                    self.assertEqual(r.status, 401)
                    self.assertEqual(r.headers.get("WWW-Authenticate"), "Bearer")
                    self.assertEqual(r.body["error"]["code"], "unauthenticated")
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")

    def test_health_is_public_and_shows_no_data(self):
        r = self.api.dispatch("health")
        self.assertEqual((r.status, r.body), (200, {"status": "ok", "auth_mode": "token"}))

    def test_unknown_or_inactive_analysts_are_forbidden_even_with_a_valid_token(self):
        for who in ("ghost", "erin"):
            self.assertEqual(self.call("list_cases", who).status, 403, who)
        self.repo.upsert_analyst("dave", "approver", active=False)
        self.assertEqual(self.call("list_cases", "dave").status, 403)

    def test_read_roles_can_read_but_only_approvers_can_decide_or_execute(self):
        case, aid = self.new_case()
        for who in ("alice", "dave", "bob", "carol", "root"):
            self.assertEqual(self.call("get_case", who, path_params={"case_id": case["case_id"]}).status, 200, who)
        for who in ("bob", "carol"):
            self.assertEqual(self.decide(aid, who=who).status, 403, who)
            self.assertEqual(self.call("simulate_execution", who, path_params={"action_id": aid}).status, 403)
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")
        self.assertEqual(self.decide(aid, who="root", key="key-root-0001").status, 200)

    def test_role_changes_take_effect_immediately(self):
        _, aid = self.new_case()
        self.repo.upsert_analyst("alice", "viewer")
        self.assertEqual(self.decide(aid).status, 403)
        self.repo.upsert_analyst("alice", "approver")
        self.assertEqual(self.decide(aid).status, 200)

    def test_identity_comes_from_the_token_never_the_body(self):
        _, aid = self.new_case()
        r = self.decide(aid, body={"decision": "approved", "reason": "ok", "decided_by": "root"})
        self.assertEqual(r.status, 422)
        r = self.decide(aid, who="dave", body={"decision": "approved", "reason": "ok"})
        self.assertEqual((r.status, r.body["action"]["decided_by"]), (200, "dave"))

    def test_every_approval_route_requires_the_decide_role(self):
        self.assertEqual({r.name for r in routes.APPROVAL_ROUTES}, {"decide", "simulate_execution"})
        self.assertTrue(all(r.role == "decide" for r in routes.APPROVAL_ROUTES))
        self.assertEqual([r.name for r in routes.ROUTES if r.role is None], ["health"])

    # ------------------------------------------------------------------ reads
    def test_list_get_evidence_memory_history(self):
        case, aid = self.new_case()
        listing = self.call("list_cases").body
        self.assertEqual((listing["total"], listing["items"][0]["case_id"], listing["next_offset"]), (1, case["case_id"], None))
        got = self.call("get_case", path_params={"case_id": case["case_id"]}).body
        self.assertEqual((got["status"], got["actions"][0]["state"], got["routing"]["decision"]), ("escalated", "pending", "escalate"))
        ev = self.call("case_evidence", path_params={"case_id": case["case_id"]}).body
        self.assertEqual(ev["items"][0]["kind"], "tool_call")
        mem = self.call("case_memory", path_params={"case_id": case["case_id"]}).body
        self.assertEqual((mem["hits"][0]["source_split"], mem["hits"][0]["manifest_sha256"]), ("train", "c" * 64))
        hist = self.call("case_history", path_params={"case_id": case["case_id"]}).body
        self.assertEqual([e["event_type"] for e in hist["events"]], ["action_proposed", "case_ingested"])

    def test_unknown_ids_are_404_and_malformed_ids_are_422(self):
        missing = "00000000-0000-4000-8000-000000000000"
        for name, key in (("get_case", "case_id"), ("case_evidence", "case_id"), ("case_memory", "case_id"), ("case_history", "case_id"), ("get_action", "action_id")):
            self.assertEqual(self.call(name, path_params={key: missing}).status, 404, name)
            self.assertEqual(self.call(name, path_params={key: "not-a-uuid"}).status, 422, name)
        self.assertEqual(self.decide(missing).status, 404)
        self.assertEqual(self.decide("not-a-uuid").status, 422)

    def test_pagination_and_filters(self):
        for _ in range(5):
            self.new_case()
        r = self.call("list_cases", query={"limit": "2", "offset": "0"}).body
        self.assertEqual((r["total"], len(r["items"]), r["next_offset"]), (5, 2, 2))
        r = self.call("list_cases", query={"limit": "2", "offset": "4"}).body
        self.assertEqual((len(r["items"]), r["next_offset"]), (1, None))
        self.assertEqual(self.call("list_cases", query={"status": "resolved"}).body["total"], 0)
        self.assertEqual(self.call("pending_approvals", query={"limit": "3"}).body["total"], 5)
        for bad in ({"limit": "0"}, {"limit": "201"}, {"limit": "-1"}, {"limit": "abc"}, {"offset": "-1"}, {"offset": "1.5"}, {"status": "weird"}, {"memory_mode": "x"}, {"alert_set": "frozen"}):
            with self.subTest(bad):
                self.assertEqual(self.call("list_cases", query=bad).status, 422)
        self.assertEqual(self.call("pending_approvals", query={"limit": "999"}).status, 422)

    def test_get_action_includes_decision_execution_and_history(self):
        _, aid = self.new_case()
        self.decide(aid)
        self.call("simulate_execution", path_params={"action_id": aid})
        got = self.call("get_action", path_params={"action_id": aid}).body
        self.assertEqual((got["action"]["state"], got["decision"]["decided_by"], got["execution"]["mode"]), ("approved", "alice", "simulated"))
        self.assertEqual([e["event_type"] for e in got["history"]], ["action_approved", "execution_simulated"])

    # ------------------------------------------------------------------ decisions
    def test_approve_reject_and_pending_list(self):
        case, aid = self.new_case()
        self.assertEqual(self.call("pending_approvals").body["items"][0]["action_id"], aid)
        r = self.decide(aid)
        self.assertEqual((r.status, r.body["outcome"], r.body["replayed"], r.body["action"]["state"]), (200, "applied", False, "approved"))
        self.assertEqual(self.call("pending_approvals").body["total"], 0)
        self.assertEqual(self.call("get_case", path_params={"case_id": case["case_id"]}).body["status"], "resolved")
        _, aid2 = self.new_case()
        r = self.decide(aid2, decision="rejected", key="key-0000-0002", reason="false positive")
        self.assertEqual((r.status, r.body["action"]["state"]), (200, "rejected"))

    def test_decisions_need_an_idempotency_key(self):
        _, aid = self.new_case()
        self.assertEqual(self.decide(aid, key=None).status, 400)
        for bad in ("short", "has space in it", "x" * 201, "bad/char/in/key"):
            self.assertEqual(self.decide(aid, key=bad).status, 422, bad)
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")

    def test_invalid_bodies_are_422_and_change_nothing(self):
        _, aid = self.new_case()
        for body in (None, [], "approved", {}, {"decision": "approved"}, {"reason": "x"}, {"decision": "maybe", "reason": "x"}, {"decision": "approved", "reason": ""},
                     {"decision": "approved", "reason": "   "}, {"decision": "approved", "reason": "x" * 1001}, {"decision": "executed", "reason": "x"},
                     {"decision": "approved", "reason": "x", "extra": 1}, {"decision": ["approved"], "reason": "x"}):
            with self.subTest(body):
                r = self.decide(aid, body=body) if body is not None else self.call("decide", "alice", {"Idempotency-Key": "key-0000-0001"}, path_params={"action_id": aid}, body=None)
                self.assertEqual(r.status, 422)
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")

    def test_a_retry_with_the_same_key_is_acknowledged_and_changes_nothing(self):
        case, aid = self.new_case()
        first, again = self.decide(aid), self.decide(aid)
        self.assertEqual((first.body["outcome"], again.status, again.body["outcome"], again.body["replayed"]), ("applied", 200, "replayed", True))
        self.assertEqual(len([e for e in self.repo.case_history(case["case_id"]) if e["event_type"] == "action_approved"]), 1)

    def test_conflicting_decisions_are_409_and_the_first_decision_stands(self):
        _, aid = self.new_case()
        self.decide(aid)
        for who, decision, key in (("alice", "rejected", "key-0000-0001"), ("alice", "rejected", "key-0000-0009"), ("dave", "approved", "key-0000-0008"), ("dave", "rejected", "key-0000-0007")):
            r = self.decide(aid, decision=decision, who=who, key=key)
            self.assertEqual(r.status, 409, (who, decision, key))
            self.assertEqual(r.body["error"]["code"], "conflict")
            self.assertEqual(r.body["action"]["state"], "approved")
        self.assertEqual(self.repo.get_action(aid)["action"]["decided_by"], "alice")

    def test_simulated_execution_only_after_approval_and_never_after_rejection(self):
        _, aid = self.new_case()
        r = self.call("simulate_execution", path_params={"action_id": aid})
        self.assertEqual((r.status, r.body["error"]["code"]), (409, "not_approved"))
        self.decide(aid, decision="rejected", key="key-0000-0003")
        self.assertEqual(self.call("simulate_execution", path_params={"action_id": aid}).status, 409)
        self.assertIsNone(self.repo.get_action(aid)["execution"])
        _, a2 = self.new_case()
        self.decide(a2, key="key-0000-0004")
        r1 = self.call("simulate_execution", path_params={"action_id": a2})
        r2 = self.call("simulate_execution", path_params={"action_id": a2}, who="dave")
        self.assertEqual((r1.status, r1.body["mode"], r2.status, r2.body["outcome"]), (201, "simulated", 200, "already_simulated"))

    def test_concurrent_conflicting_decisions_have_one_winner(self):
        _, aid = self.new_case()
        results, barrier = [None] * 6, threading.Barrier(6)

        def work(i):
            barrier.wait()
            results[i] = self.decide(aid, decision="approved" if i % 2 else "rejected", who="alice" if i % 3 else "dave", key="key-race-%04d" % i)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        statuses = sorted(r.status for r in results)
        self.assertEqual(statuses, [200] + [409] * 5)

    # ------------------------------------------------------------------ errors never leak internals
    def test_a_store_failure_is_503_with_no_details_and_nothing_decided(self):
        _, aid = self.new_case()

        class Down(MemoryRepository):
            pass
        real = self.repo.decide_action

        def boom(*a, **k):
            raise DbError("connection to server at 10.1.2.3 failed: password authentication failed for user soc", "28P01")
        self.repo.decide_action = boom
        r = self.decide(aid)
        self.assertEqual((r.status, r.body["error"]["code"]), (503, "store_unavailable"))
        self.assertNotIn("10.1.2.3", json.dumps(r.body))
        self.assertNotIn("password", json.dumps(r.body))
        self.repo.decide_action = real
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")

    def test_a_store_failure_during_authentication_is_503(self):
        def boom(_):
            raise DbError("down")
        self.repo.get_analyst = boom
        self.assertEqual(self.call("list_cases").status, 503)

    def test_unknown_route_name(self):
        self.assertEqual(self.api.dispatch("launch_missiles").status, 404)

    def test_responses_are_json_serialisable(self):
        case, aid = self.new_case()
        self.decide(aid)
        for name, pp in (("list_cases", {}), ("get_case", {"case_id": case["case_id"]}), ("get_action", {"action_id": aid}), ("case_history", {"case_id": case["case_id"]})):
            json.dumps(self.call(name, path_params=pp).body)


class MemoryApiTests(ApiCase, unittest.TestCase):
    def setUp(self):
        self.repo = MemoryRepository()
        self.build()


@unittest.skipUnless(_PG_OK, _PG_WHY)
class PgApiTests(ApiCase, unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness.new_database()
        self.addCleanup(PgHarness.drop, self.dbname)
        self.repo = PgRepository(driver_for(self.dbname))
        self.build()


for _n in [n for n in dir(ApiTests) if n.startswith("test_")]:
    setattr(MemoryApiTests, _n, getattr(ApiTests, _n))
    setattr(PgApiTests, _n, getattr(ApiTests, _n))


# ------------------------------------------------------------------------------------------------ authentication configuration
class AuthConfigTests(unittest.TestCase):
    def test_no_configuration_means_no_server(self):
        with self.assertRaises(auth.ConfigError) as ctx:
            auth.from_env({})
        self.assertIn("will not start", str(ctx.exception))

    def test_token_hashes_from_the_environment_and_a_file(self):
        import os
        import tempfile
        h = auth.hash_token("t" * 40)
        cfg = auth.from_env({auth.ENV_HASHES: "alice:" + h})
        self.assertEqual((cfg.mode, cfg.authenticate({"authorization": "Bearer " + "t" * 40})), ("token", "alice"))
        d = tempfile.mkdtemp()
        path = os.path.join(d, "tokens.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# comment\nbob:" + auth.hash_token("u" * 40) + "\n")
        cfg = auth.from_env({auth.ENV_HASHES_FILE: path})
        self.assertEqual(cfg.authenticate({"authorization": "Bearer " + "u" * 40}), "bob")
        import shutil
        shutil.rmtree(d)

    def test_malformed_configuration_is_refused(self):
        good = auth.hash_token("t" * 40)
        for env in ({auth.ENV_HASHES: "alice"}, {auth.ENV_HASHES: "alice:zz"}, {auth.ENV_HASHES: "bad id:" + good}, {auth.ENV_HASHES: "a:%s,a:%s" % (good, good)},
                    {auth.ENV_HASHES: "a:%s,b:%s" % (good, good)}, {auth.ENV_HASHES_FILE: "/no/such/file"}, {auth.ENV_DEV: "yes"}):
            with self.subTest(env):
                with self.assertRaises(auth.ConfigError):
                    auth.from_env(env)

    def test_dev_mode_is_explicit_and_cannot_be_combined_with_tokens(self):
        cfg = auth.from_env({auth.ENV_DEV: "1"})
        self.assertEqual((cfg.mode, cfg.authenticate({"x-dev-analyst": "alice"}), cfg.authenticate({"x-dev-analyst": "bad id"}), cfg.authenticate({})), ("dev", "alice", None, None))
        with self.assertRaises(auth.ConfigError):
            auth.from_env({auth.ENV_DEV: "1", auth.ENV_HASHES: "alice:" + auth.hash_token("t" * 40)})

    def test_token_mode_ignores_the_dev_header_and_short_or_wrong_tokens(self):
        cfg = auth.AuthConfig("token", {"alice": auth.hash_token("t" * 40)})
        self.assertIsNone(cfg.authenticate({"x-dev-analyst": "alice"}))
        self.assertIsNone(cfg.authenticate({"authorization": "Bearer short"}))
        self.assertIsNone(cfg.authenticate({"authorization": "Bearer " + "x" * 40}))
        self.assertIsNone(cfg.authenticate({"authorization": "bearer"}))
        self.assertEqual(cfg.authenticate({"authorization": "bearer " + "t" * 40}), "alice")

    def test_the_server_never_stores_or_prints_a_token(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(auth.main(["new-token", "--analyst", "alice"]), 0)
        out = buf.getvalue().splitlines()
        token = out[1]
        self.assertGreaterEqual(len(token), 32)
        self.assertIn("alice:" + auth.hash_token(token), out)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(auth.main(["new-token", "--analyst", "bad id"]), 2)

    def test_serve_refuses_to_start_without_auth_or_with_dev_mode_on_a_public_address(self):
        from week4.api import serve
        self.assertEqual(serve.main(["--port", "1"]) if False else 0, 0)
        with self.assertRaises(auth.ConfigError):
            serve.build({"WEEK4_DATABASE_URL": "postgresql://x/y"})
        with self.assertRaises(auth.ConfigError):
            serve.build({auth.ENV_DEV: "1"})


class RouteTableTests(unittest.TestCase):
    def test_every_route_has_a_handler_and_unique_path_method(self):
        seen = set()
        for r in routes.ROUTES:
            self.assertTrue(callable(getattr(Api, "_" + r.name)), r.name)
            self.assertNotIn((r.method, r.path), seen)
            seen.add((r.method, r.path))
            self.assertIn(r.role, (None, "read", "decide"))
            self.assertTrue(r.summary)

    def test_only_post_routes_change_anything_and_both_need_decide(self):
        self.assertEqual({r.name for r in routes.ROUTES if r.method != "GET"}, {"decide", "simulate_execution"})

    def test_the_api_module_has_no_execution_capability(self):
        import ast
        import os
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "week4")
        banned = {"socket", "requests", "urllib", "http", "httpx", "paramiko", "ftplib", "smtplib", "telnetlib", "subprocess", "ctypes"}
        for rel in ("api/handlers.py", "approval.py", "policy.py", "cases.py"):
            with open(os.path.join(base, rel), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                mods = set()
                if isinstance(node, ast.Import):
                    mods = {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    mods = {(node.module or "").split(".")[0]}
                self.assertFalse(mods & banned, rel + " imports " + str(mods & banned))


# ------------------------------------------------------------------------------------------------ FastAPI wiring (runs only where fastapi and httpx are installed)
try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "fastapi and httpx are not installed here: pip install -r requirements-week4.txt. The FastAPI wrapper is untested in this environment.")
class FastApiWiringTests(ApiCase, unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from week4.api.app import create_app
        self.repo = MemoryRepository()
        self.build()
        self.client = TestClient(create_app(self.api))

    def test_health_and_openapi(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        spec = self.client.get("/openapi.json").json()
        for r in routes.ROUTES:
            self.assertIn(r.path, spec["paths"])
        self.assertIn("bearerAuth", spec["components"]["securitySchemes"])

    def test_protected_routes_and_decisions_over_http(self):
        case, aid = self.new_case()
        self.assertEqual(self.client.get("/cases").status_code, 401)
        r = self.client.get("/cases", headers=bearer("carol"))
        self.assertEqual(r.status_code, 200)
        denied = self.client.post("/actions/%s/decision" % aid, json={"decision": "approved", "reason": "x"}, headers=dict(bearer("carol"), **{"Idempotency-Key": "key-http-0001"}))
        self.assertEqual(denied.status_code, 403)
        ok = self.client.post("/actions/%s/decision" % aid, json={"decision": "approved", "reason": "fine"}, headers=dict(bearer("alice"), **{"Idempotency-Key": "key-http-0002"}))
        self.assertEqual((ok.status_code, ok.json()["action"]["state"]), (200, "approved"))
        bad = self.client.post("/actions/%s/decision" % aid, content="not json", headers=dict(bearer("alice"), **{"Idempotency-Key": "key-http-0003"}))
        self.assertEqual(bad.status_code, 422)


if __name__ == "__main__":
    unittest.main()
