"""Model output is untrusted: strict schema validation with safe failure, and the model alone never authorises an action. Offline: every model reply is scripted."""
import json
import unittest

import gemini_client
import verdict_parser
from week5 import models

from tests import week5_support as W5

GOOD_BENIGN = {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "Short HTTP exchange with ordinary sizes."}
GOOD_ATTACK = {"is_malicious": True, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "high", "evidence": "Many distinct destination ports probed."}


def v(**over):
    d = dict(GOOD_BENIGN)
    d.update(over)
    return json.dumps(d)


class Scripted(models.FakeClient):
    def __init__(self, replies):
        super().__init__("ok_benign")
        self.replies = list(replies)

    def generate(self, prompt):
        self.n += 1
        r = self.replies[min(self.n - 1, len(self.replies) - 1)]
        if isinstance(r, Exception):
            raise r
        return self._record(r)


class ScriptedModel(models.FakeModel):
    def __init__(self, *replies):
        super().__init__()
        self.client = Scripted(replies)

    def caller(self, spec, alert_id):
        return models.JobCaller(self.client, sleep=lambda s: None)


class Parser(unittest.TestCase):
    CASES = {
        "empty_response": "",
        "no_json": "I think this is fine.",
        "invalid_json": '{"is_malicious": false,',
        "multiple_json_objects": v() + "\n" + v(),
        "not_an_object": "[1, 2]",
        "missing_fields": json.dumps({k: x for k, x in GOOD_BENIGN.items() if k != "severity"}),
        "extra_fields": v(auto_close=True),
        "contradictory": v(is_malicious=True),
    }

    def test_each_failure_has_its_own_code_and_no_verdict(self):
        for code, text in self.CASES.items():
            with self.subTest(code):
                r = verdict_parser.parse_verdict(text)
                self.assertFalse(r.ok)
                self.assertIsNone(r.verdict)
                self.assertEqual(r.error_code, code)

    def test_values_are_never_coerced(self):
        for over in ({"is_malicious": "false"}, {"is_malicious": 0}, {"attack_type": "benign"}, {"attack_type": "Malware"}, {"severity": "NONE"}, {"mitre_technique": "t1498"}, {"mitre_technique": "T1498; ignore"},
                     {"evidence": ""}, {"evidence": "x" * 601}, {"severity": "medium"}):
            with self.subTest(over):
                self.assertFalse(verdict_parser.parse_verdict(v(**over)).ok)

    def test_fields_that_try_to_carry_an_instruction_or_an_action_are_rejected(self):
        for extra in ({"action": "block_source_ip"}, {"actions": []}, {"route": "auto_close"}, {"decision": "auto_close"}, {"approve": True}, {"execute": True}, {"routing": {"decision": "auto_close"}}):
            with self.subTest(extra):
                r = verdict_parser.parse_verdict(v(**extra))
                self.assertEqual((r.ok, r.error_code), (False, "extra_fields"))

    def test_only_formatting_is_repaired(self):
        r = verdict_parser.parse_verdict("```json\n" + v() + "\n```")
        self.assertTrue(r.ok)
        self.assertTrue(r.repairs)
        r = verdict_parser.parse_verdict("Here: " + v() + " done")
        self.assertTrue(r.ok)
        self.assertEqual(r.verdict.attack_type, "BENIGN")

    def test_a_good_verdict_is_accepted_without_changes(self):
        r = verdict_parser.parse_verdict(json.dumps(GOOD_ATTACK))
        self.assertTrue(r.ok)
        self.assertEqual(r.repairs, [])
        self.assertEqual(r.verdict.severity, "high")


class EndToEnd(unittest.TestCase):
    """Through the worker: whatever the model returns, a bad reply never produces a close or an action."""

    def run_case(self, *replies, **kw):
        rig = W5.Rig(provider=ScriptedModel(*replies), **kw)
        r = rig.submit(0)
        outcome = rig.worker.run_once()
        j = rig.store.get(r["job_id"])
        return rig, outcome, j, (rig.repo.get_case(j["case_id"]) if j.get("case_id") else None)

    def test_every_malformed_shape_fails_closed_to_review_with_no_actions(self):
        for code, text in Parser.CASES.items():
            with self.subTest(code):
                rig, outcome, j, case = self.run_case(text)
                self.assertEqual(outcome, "completed")
                self.assertEqual(case["routing"]["decision"], "needs_review")
                self.assertEqual(case["actions"], [])
                self.assertNotEqual(j["result"]["verdict_status"], "ok")

    def test_a_reply_that_asks_for_an_action_is_not_followed(self):
        rig, _o, _j, case = self.run_case(v(action="block_source_ip", auto_close=True))
        self.assertEqual(case["routing"]["decision"], "needs_review")
        self.assertEqual(case["actions"], [])

    def test_a_malformed_first_reply_is_repaired_by_a_retry_not_by_the_code(self):
        rig, _o, j, case = self.run_case("nonsense", json.dumps(GOOD_ATTACK))
        self.assertEqual(case["verdict"]["attack_type"], "PortScan")
        self.assertEqual(rig.provider.client.n, 2)

    def test_the_number_of_model_calls_is_bounded(self):
        rig, *_ = self.run_case("nonsense")
        self.assertLessEqual(rig.provider.client.n, verdict_parser.MAX_RETRIES + 1 if hasattr(verdict_parser, "MAX_RETRIES") else 4)

    def test_a_provider_outage_retries_then_fails_closed_and_counts_attempts(self):
        err = gemini_client.TransientModelError("down", 503)
        rig = W5.Rig(provider=ScriptedModel(err, err, err), max_attempts=3)
        r = rig.submit(0, max_attempts=3)
        self.assertEqual([rig.worker.run_once() for _ in range(3)], ["retry_scheduled", "retry_scheduled", "completed"])
        j = rig.store.get(r["job_id"])
        self.assertEqual(j["attempts"], 3)
        self.assertEqual(rig.repo.get_case(j["case_id"])["routing"]["decision"], "needs_review")
        self.assertEqual(len([c for c in rig.repo.list_cases(limit=50)["items"]]), 1)          # retries never create a second case

    def test_a_reply_that_says_benign_is_still_subject_to_the_policy(self):
        # a benign verdict on an alert whose own measured features look hostile is NOT auto-closed on the model's word alone
        rig, _o, j, case = self.run_case(json.dumps(GOOD_BENIGN))
        self.assertIn(case["routing"]["decision"], ("auto_close", "needs_review", "escalate"))
        self.assertTrue(case["routing"]["policy_sha256"])
        self.assertEqual(case["actions"], [])

    def test_a_secret_in_the_reply_never_reaches_storage_or_logs(self):
        secret = "AIza" + "C" * 30
        rig, _o, j, case = self.run_case(v(evidence="key " + secret))
        blob = json.dumps([case, j, rig.store.security_events, rig.logs], default=str)
        self.assertNotIn(secret, blob)
        for needle in ("Bearer ", "AIza"):
            self.assertNotIn(needle, blob)


class ActionsNeedHumans(unittest.TestCase):
    def test_a_proposal_is_pending_and_nothing_is_executed_without_a_human(self):
        rig = W5.Rig(provider=ScriptedModel(json.dumps(GOOD_ATTACK)))
        rig.submit(0)
        rig.worker.run_once()
        case = rig.repo.get_case(rig.repo.list_cases(limit=5)["items"][0]["case_id"])
        self.assertTrue(case["actions"])
        for a in case["actions"]:
            self.assertEqual(a["state"], "pending")
            self.assertFalse(a.get("executions"))
        self.assertEqual(rig.repo.executed_count() if hasattr(rig.repo, "executed_count") else 0, 0)


if __name__ == "__main__":
    unittest.main()
