import unittest

from week5.runner import apply_beacon_candidate_veto
from week5.runner import apply_beacon_candidate_veto, apply_scan_evidence_veto


class BeaconCandidateVetoTests(unittest.TestCase):
    def make_routed(self, decision="auto_close"):
        return {
            "routing": {
                "decision": decision,
                "risk_level": "low",
                "reasons": ["original reason"],
            },
            "actions": [{"action_type": "increase_monitoring"}],
            "inputs": {},
        }

    def test_candidate_prevents_auto_close_and_clears_actions(self):
        routed = self.make_routed()
        state = {"beacon_findings": {"beacon_candidate": True}}

        result = apply_beacon_candidate_veto(routed, state)

        self.assertEqual(result["routing"]["decision"], "needs_review")
        self.assertEqual(result["routing"]["risk_level"], "unknown")
        self.assertEqual(result["actions"], [])
        self.assertTrue(
            any("W5-RR1" in reason for reason in result["routing"]["reasons"])
        )

    def test_candidate_does_not_mutate_original_result(self):
        routed = self.make_routed()
        original = {
            "routing": dict(routed["routing"]),
            "actions": list(routed["actions"]),
            "inputs": {},
        }

        apply_beacon_candidate_veto(
            routed, {"beacon_findings": {"beacon_candidate": True}}
        )

        self.assertEqual(routed, original)

    def test_non_candidate_preserves_auto_close(self):
        routed = self.make_routed()
        result = apply_beacon_candidate_veto(
            routed, {"beacon_findings": {"beacon_candidate": False}}
        )

        self.assertEqual(result, routed)

    def test_missing_or_malformed_beacon_data_preserves_result(self):
        routed = self.make_routed()

        for state in ({}, {"beacon_findings": None}, {"beacon_findings": []}):
            with self.subTest(state=state):
                self.assertEqual(apply_beacon_candidate_veto(routed, state), routed)

    def test_candidate_does_not_change_existing_escalation(self):
        routed = self.make_routed("escalate")
        result = apply_beacon_candidate_veto(
            routed, {"beacon_findings": {"beacon_candidate": True}}
        )

        self.assertEqual(result, routed)


    def test_broad_scan_evidence_prevents_auto_close(self):
        routed = self.make_routed()
        state = {
            "traffic_findings": {
                "status": "ok",
                "findings": [{
                    "kind": "source_activity",
                    "metrics": {"distinct_destination_ports": 30},
                }],
            }
        }

        result = apply_scan_evidence_veto(routed, state)

        self.assertEqual(result["routing"]["decision"], "needs_review")
        self.assertEqual(result["routing"]["risk_level"], "unknown")
        self.assertEqual(result["actions"], [])
        self.assertTrue(
            any("W5-RR1" in reason for reason in result["routing"]["reasons"])
        )

    def test_small_port_count_preserves_auto_close(self):
        routed = self.make_routed()
        state = {
            "traffic_findings": {
                "status": "ok",
                "findings": [{
                    "kind": "source_activity",
                    "metrics": {"distinct_destination_ports": 5},
                }],
            }
        }

        self.assertEqual(apply_scan_evidence_veto(routed, state), routed)

    def test_scan_evidence_does_not_change_escalation(self):
        routed = self.make_routed("escalate")
        state = {
            "traffic_findings": {
                "status": "ok",
                "findings": [{
                    "kind": "source_activity",
                    "metrics": {"distinct_destination_ports": 30},
                }],
            }
        }

        self.assertEqual(apply_scan_evidence_veto(routed, state), routed)



if __name__ == "__main__":
    unittest.main()
