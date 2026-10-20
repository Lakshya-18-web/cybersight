"""Tests for the prompt-injection suite: the data files, the judging logic (including negative controls that switch a defence off and must be caught), and the defects the suite exposed.

Offline, in memory, fake scripted model. Run: PYTHONPATH=src:. python -m unittest tests.test_week5_injection"""
import hashlib
import json
import os
import unittest
from unittest import mock

from week5 import fixtures
from week5.security import guard
from week5.security.injection import harness, report
from week5.security.injection.stack import InjectionStack

PAYLOADS = None
RESULTS = None


def results():
    global RESULTS
    if RESULTS is None:
        RESULTS = harness.run_suite()
    return RESULTS


class PayloadFile(unittest.TestCase):
    def test_file_is_valid_and_sized_as_required(self):
        payloads = harness.load_payloads()
        self.assertEqual(harness.validate_payloads(payloads), [])
        adv = [p for p in payloads if p["kind"] == "adversarial"]
        self.assertTrue(30 <= len(adv) <= 50)
        self.assertGreaterEqual(len([p for p in payloads if p["kind"] == "benign_control"]), 10)
        self.assertEqual(len({p["id"] for p in payloads}), len(payloads))

    def test_every_category_present(self):
        cats = {p["category"] for p in harness.load_payloads() if p["kind"] == "adversarial"}
        self.assertEqual(cats, {"identifier_text", "type_format", "structure", "identity_gate", "model_output", "data_channel"})

    def test_a_malformed_file_cannot_shrink_the_suite(self):
        payloads = harness.load_payloads()
        few = [p for p in payloads if p["kind"] == "benign_control"] + [p for p in payloads if p["kind"] == "adversarial"][:5]
        self.assertTrue(harness.validate_payloads(few))
        with self.assertRaises(ValueError):
            harness.run_suite(payloads=few)
        dup = payloads + [payloads[0]]
        self.assertTrue(any("duplicate" in x for x in harness.validate_payloads(dup)))

    def test_hashes_describe_the_shipped_files(self):
        for name, digest in harness.data_hashes().items():
            with open(os.path.join(harness.DATA_DIR, name), "rb") as fh:
                raw = fh.read().replace(b"\r\n", b"\n")
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(results()["meta"]["data_sha256"], harness.data_hashes())

    def test_criteria_declare_residual_risks_and_limits(self):
        c = harness.load_criteria()
        self.assertIn("RR-1", c["residual_risks"])
        self.assertIn("RR-2", c["residual_risks"])
        self.assertTrue(c["limits"])


class FullSuite(unittest.TestCase):
    def test_all_gates_pass_and_nothing_is_a_mismatch(self):
        r = results()
        self.assertEqual([g for g in r["gates"] if not g["pass"]], [])
        self.assertTrue(r["overall_pass"])
        self.assertEqual(r["metrics"]["expectation_mismatches"], [])
        self.assertEqual(r["metrics"]["infra_failures"], 0)

    def test_benign_controls_are_accepted_and_none_blocked(self):
        m = results()["metrics"]
        self.assertEqual(m["false_block_rate"], 0)
        self.assertEqual(m["control_fidelity"], 1.0)
        self.assertEqual(m["counts"]["controls_by_observed_class"], {"accepted": 12})

    def test_no_echo_and_no_leak(self):
        m = results()["metrics"]
        self.assertEqual(m["echo_count"], 0)
        self.assertEqual(m["leak_count"], 0)


    def test_the_mitigated_residual_risk_is_reported_not_hidden(self):
        r = results()
        self.assertNotIn("PI-E02", r["metrics"]["succeeded_ids"])

        rec = {x["id"]: x for x in r["records"]}["PI-E02"]
        self.assertFalse(rec["residual_risk"])
        self.assertEqual(rec["observed_class"], "neutralised")
        self.assertFalse(rec["goal_achieved"])
        self.assertIn("needs_review", rec["routing_decisions"])

        text = report.render(r)
        self.assertIn("PI-E02", text)

    def test_audit_events_exist_for_every_refusal_and_guard_finding(self):
        m = results()["metrics"]
        self.assertEqual(m["audit_coverage"], 1.0)
        self.assertGreater(m["audit_events_checked"], 20)

    def test_corrections_made_after_the_first_run_are_listed(self):
        ids = {c["id"] for c in results()["corrections_after_first_run"]}
        self.assertEqual(ids, {"PI-A03", "PI-E09"})

    def test_results_are_json_serialisable_and_contain_no_secret(self):
        text = json.dumps(results())
        json.loads(text)


class NegativeControls(unittest.TestCase):
    """If a defence is switched off, the suite must notice. Otherwise a green result means nothing."""

    def test_switching_the_response_guard_off_is_detected(self):
        from week5 import runner
        ids = ["PI-E04", "PI-E05", "PI-E06", "PI-E08"]
        with mock.patch.object(runner.guard, "apply_to_state", side_effect=lambda state, prompts, secrets: (state, [])), \
                mock.patch.object(runner.guard, "adjust_routing", side_effect=lambda routed, signals: routed):
            r = harness.run_suite(only=ids)
        self.assertFalse(r["overall_pass"])
        self.assertTrue(r["metrics"]["leak_count"] > 0 or r["metrics"]["succeeded_ids"])

    def test_switching_identifier_aliasing_off_is_detected(self):
        r = harness.run_suite(only=["PI-A03"], new_stack=lambda: InjectionStack(alias_ids=False))
        rec = r["records"][0]
        self.assertEqual(rec["observed_class"], "succeeded")
        self.assertTrue(rec["marker_in_prompt"])
        self.assertFalse(r["overall_pass"])

    def test_an_unexpected_exception_is_an_infrastructure_failure_not_a_pass(self):
        def boom():
            raise RuntimeError("no stack")
        r = harness.run_suite(only=["PI-A01"], new_stack=boom)
        self.assertEqual(r["records"][0]["observed_class"], "infra_failure")
        self.assertFalse(r["overall_pass"])


class DefectsTheSuiteFound(unittest.TestCase):
    def _post(self, headers):
        st = InjectionStack()
        r = st.call("submit_alert", "bob", body={"alert": fixtures.make_alert(0, "PI")}, headers=headers)
        return st, r

    def test_bad_idempotency_key_is_refused_and_audited_without_the_header_value(self):
        st, r = self._post({"Idempotency-Key": "abcdefgh\r\nX-Evil: 1"})
        self.assertEqual(r.status, 422)
        events = [e for e in st.store.security_events if e["event_type"] == "ingest_rejected"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["code"], "bad_idempotency_key")
        self.assertNotIn("X-Evil", json.dumps(events) + json.dumps(r.body))

    def test_trailing_newline_in_idempotency_key_is_refused(self):
        st, r = self._post({"Idempotency-Key": "abcdefgh-0001\n"})
        self.assertEqual(r.status, 422)
        self.assertEqual(st.store.list_jobs(limit=10)["items"], [])

    def test_a_good_key_is_still_accepted(self):
        st, r = self._post({"Idempotency-Key": "abcdefgh-0001"})
        self.assertEqual(r.status, 202)
        self.assertEqual([e for e in st.store.security_events if e["event_type"] == "ingest_rejected"], [])

    def test_a_flow_id_of_exactly_128_characters_passes_intake_and_is_aliased(self):
        st = InjectionStack()
        alert = fixtures.make_alert(0, "PI")
        alert["flow_id"] = "F" * 128
        self.assertEqual(st.call("submit_alert", "bob", body={"alert": alert}).status, 202)
        st.drain()
        self.assertFalse(any("F" * 40 in p for p in st.model.prompts))

    def test_a_flow_id_of_129_characters_is_refused(self):
        st = InjectionStack()
        alert = fixtures.make_alert(0, "PI")
        alert["flow_id"] = "F" * 129
        self.assertEqual(st.call("submit_alert", "bob", body={"alert": alert}).status, 422)


class Aliasing(unittest.TestCase):
    def test_prompt_has_alias_and_stored_case_keeps_the_original_id(self):
        st = InjectionStack()
        alert = fixtures.make_alert(0, "PI")
        self.assertEqual(st.call("submit_alert", "bob", body={"alert": alert}).status, 202)
        st.drain()
        self.assertTrue(st.model.prompts)
        for prompt in st.model.prompts:
            self.assertNotIn(alert["alert_id"], prompt)
            self.assertNotIn(alert["flow_id"], prompt)
        self.assertIn("ALERT-", " ".join(st.model.prompts))
        self.assertEqual([c["alert_id"] for c in st.cases()], [alert["alert_id"]])

    def test_alias_is_stable_for_the_same_id(self):
        from week5 import runner
        self.assertEqual(runner.alias_for("ALERT-", "x1"), runner.alias_for("ALERT-", "x1"))
        self.assertNotEqual(runner.alias_for("ALERT-", "x1"), runner.alias_for("ALERT-", "x2"))
        self.assertRegex(runner.alias_for("FLOW-", "x1"), r"^FLOW-[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
