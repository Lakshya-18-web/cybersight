"""Week 4 ablation evaluation (evaluate_memory.py): comparability checks, metric definitions, paired view, outputs, reproducibility, label/frozen boundaries.
Offline and synthetic: the runs are FAKE-model runs made by the runner and then relabelled as real ONLY so the plumbing can be exercised; the labels are invented. Nothing here is a result."""
import ast
import copy
import json
import os
import unittest
from unittest import mock

import pandas as pd

import baseline_store as store
import config
import eval_labels
import triage_inputs

from week4 import evaluate_memory as E

from tests.test_week3_day5 import full_alerts_frame
from tests.test_week4_runner import RunnerBase, read_text, SRC

LABELS = {"DEV-0004": ("BENIGN", "NONE", "NONE"), "DEV-0003": ("PortScan", "T1046", "T1046"), "DEV-0002": ("PortScan", "T1046", "T1046"), "DEV-0001": ("SSH-Patator", "T1110", "T1110")}


def labels_frame():
    rows = []
    for alert_id in full_alerts_frame()["alert_id"]:
        label, primary, accepted = LABELS[alert_id]
        rows.append({"alert_id": alert_id, "label": label, "is_attack": int(label != "BENIGN"), "mitre_technique_id": primary, "mitre_accepted_ids": accepted})
    return pd.DataFrame(rows)


class EvalBase(RunnerBase):
    def setUp(self):
        super().setUp()
        self.off = self.make("off")
        self.on = self.make("on")

    def make(self, mode):
        name = "FAKE_" + mode
        self.run_main("--memory", mode, "--fake-model", "--run-name", name)
        path = os.path.join(self.runs, name)
        self.relabel(path, False)
        return path

    def relabel(self, path, fake):
        meta = store.read_json(os.path.join(path, "run_meta.json"))
        meta["fake_model"] = fake
        meta["status"] = "complete"
        meta["frozen_access_log_unchanged"] = True
        meta["week1_files_unchanged"] = True
        store.write_json_atomic(os.path.join(path, "run_meta.json"), meta)

    def edit_meta(self, path, fn):
        meta = store.read_json(os.path.join(path, "run_meta.json"))
        fn(meta)
        store.write_json_atomic(os.path.join(path, "run_meta.json"), meta)

    def compare(self, **kw):
        return E.compare_runs(self.off, self.on, full_alerts_frame(), labels_frame(), **kw)


class ComparisonTests(EvalBase):
    def test_every_ratio_has_its_denominator_and_the_populations_add_up(self):
        r = self.compare()
        for arm in r["arms"].values():
            pop = arm["population"]
            self.assertEqual(pop["alerts"], 4)
            self.assertEqual(pop["ok"] + pop["parse_failed"] + pop["model_error"] + pop["not_run"], 4)
            rt = arm["metrics"]["routing"]
            self.assertEqual(sum(rt["counts"].values()), 4)
            self.assertEqual(rt["auto_close_rate"]["denominator"], 4)
            self.assertEqual(rt["true_attacks_auto_closed"]["denominator"], pop["true_attacks"])
            self.assertEqual(rt["true_benign_auto_closed"]["denominator"], pop["true_benign"])
            self.assertEqual(arm["metrics"]["mitre"]["accepted_all_attacks_failures_wrong"]["denominator"], pop["true_attacks"])

    def test_technique_accuracy_follows_the_week2_definition_with_failures_counted_wrong(self):
        r = self.compare()
        # fake script on the 4 alerts: benign, attack(PortScan T1046), malformed-then-attack(T1046), always malformed (parse_failed).
        m = r["arms"]["memory_off"]["metrics"]["mitre"]
        self.assertEqual((m["accepted_all_attacks_failures_wrong"]["numerator"], m["accepted_all_attacks_failures_wrong"]["denominator"]), (2, 3))
        self.assertEqual((m["coverage"]["numerator"], m["coverage"]["denominator"]), (2, 3))
        self.assertEqual(r["arms"]["memory_off"]["metrics"]["population"]["parse_failed"], 1)

    def test_the_paired_view_adds_up(self):
        p = self.compare()["paired"]
        self.assertEqual(p["alerts_in_both"], 4)
        for key in ("technique_correct_on_true_attacks", "attack_type_correct_on_true_attacks"):
            c = p[key]
            self.assertEqual(c["both_correct"] + c["only_memory_off_correct"] + c["only_memory_on_correct"] + c["neither_correct"], c["true_attacks_compared"])
        self.assertEqual(p["routing"]["same_decision"] + p["routing"]["changed_decision"], 4)

    def test_the_memory_arm_reports_neighbour_agreement_and_the_off_arm_does_not(self):
        r = self.compare()
        self.assertNotIn("memory", r["arms"]["memory_off"]["metrics"])
        mem = r["arms"]["memory_on"]["metrics"]["memory"]
        self.assertEqual(mem["memory_step_status_counts"], {"ok": 4})
        self.assertEqual(mem["alerts_with_neighbours"], 4)
        self.assertEqual(mem["closest_neighbour_label_equals_true_label"]["denominator"], 4)

    def test_proposed_actions_are_counted_and_no_approval_rate_is_invented(self):
        a = self.compare()["arms"]["memory_on"]["metrics"]["actions"]
        self.assertEqual(a["executed"], 0)
        self.assertIn("no approval rate exists", a["approval_note"])
        self.assertNotIn("approval_rate", json.dumps(a))

    def test_provenance_records_the_split_the_hashes_and_the_seeds(self):
        p = self.compare()["provenance"]
        self.assertEqual(p["split"]["memory_manifest_sha256"], self.memory.manifest_sha256)
        self.assertEqual(p["split"]["train_sha256"], "e" * 64)
        self.assertEqual(p["split"]["isolation_check"]["dev_overlap"], 0)
        self.assertEqual((p["split"]["memory_seed"], p["split"]["memory_per_class_cap"], p["split"]["memory_k"]), (42, 20, 5))
        self.assertEqual(p["policy"]["sha256"], store.read_json(os.path.join(self.on, "run_meta.json"))["agent"]["policy"]["sha256"])
        self.assertIn("generation_seed", p)

    def test_the_comparison_is_reproducible(self):
        a, b = self.compare(), self.compare()
        for r in (a, b):
            r.pop("_tables")
        self.assertEqual(json.dumps(a, sort_keys=True, default=str), json.dumps(b, sort_keys=True, default=str))

    def test_the_report_states_limits_and_makes_no_improvement_or_significance_claim(self):
        text = E.render_report(self.compare())
        lowered = text.lower()
        self.assertIn("Limitations and confounders", text)
        self.assertIn("non-deterministic", text)
        self.assertNotIn("improv", lowered)
        self.assertNotIn("p-value", lowered.replace("no p-value", ""))
        self.assertNotIn("statistically significant", lowered)

    def test_outputs_are_written_and_an_existing_comparison_is_not_overwritten(self):
        out = os.path.join(self.tmp.name, "cmp")
        r = self.compare()
        E.write_outputs(r, out)
        self.assertEqual(sorted(os.listdir(out)), ["COMPARISON_REPORT.md", "comparison.json", "comparison_metrics.csv", "per_alert.csv"])
        loaded = json.loads(read_text(os.path.join(out, "comparison.json")))
        self.assertEqual(loaded["schema"], E.SCHEMA)
        self.assertNotIn("_tables", loaded)
        with self.assertRaises(E.ComparisonError):
            E.write_outputs(self.compare(), out)
        E.write_outputs(self.compare(), out, force=True)

    def test_runs_are_not_changed_by_the_evaluation(self):
        before = {n: store.file_sha256(os.path.join(self.on, n)) for n in os.listdir(self.on)}
        self.compare()
        self.assertEqual(before, {n: store.file_sha256(os.path.join(self.on, n)) for n in os.listdir(self.on)})


class RefusalTests(EvalBase):
    def refused(self, fragment, **kw):
        with self.assertRaises(E.ComparisonError) as ctx:
            self.compare(**kw)
        self.assertIn(fragment, str(ctx.exception))

    def test_a_fake_run_is_refused(self):
        self.relabel(self.on, True)
        self.edit_meta(self.on, lambda m: m.update(fake_model=True))
        self.refused("--fake-model")

    def test_arms_in_the_wrong_order_or_the_same_mode_twice_are_refused(self):
        with self.assertRaises(E.ComparisonError):
            E.compare_runs(self.on, self.off, full_alerts_frame(), labels_frame())
        with self.assertRaises(E.ComparisonError):
            E.compare_runs(self.off, self.off, full_alerts_frame(), labels_frame())

    def test_a_different_model_settings_inputs_alerts_policy_or_baseline_is_refused(self):
        cases = [("model", lambda m: m.update(model="other")), ("setting seed", lambda m: m["settings"].update(seed=1)), ("inputs", lambda m: m["inputs"].update(dev_alerts_sha256="zzz")),
                 ("selected alert list", lambda m: m.update(selected_alert_ids=m["selected_alert_ids"][:2])), ("risk policy", lambda m: m["agent"]["policy"].update(sha256="0" * 64)),
                 ("graph version", lambda m: m["agent"].update(graph_version="v9")), ("locked baseline", lambda m: m["agent"].update(baseline={"run_name": "x"}))]
        for fragment, change in cases:
            with self.subTest(fragment):
                original = store.read_json(os.path.join(self.on, "run_meta.json"))
                self.edit_meta(self.on, change)
                self.refused(fragment.split()[0])
                store.write_json_atomic(os.path.join(self.on, "run_meta.json"), original)

    def test_an_incomplete_run_needs_allow_partial(self):
        self.edit_meta(self.on, lambda m: m.update(status="incomplete"))
        self.refused("not complete")

    def test_a_memory_run_without_a_clean_isolation_check_is_refused(self):
        self.edit_meta(self.on, lambda m: m["agent"]["memory"].update(isolation_check=None))
        self.refused("isolation")

    def test_a_run_that_touched_the_frozen_log_or_week1_files_is_refused(self):
        self.edit_meta(self.off, lambda m: m.update(frozen_access_log_unchanged=False))
        self.refused("frozen-access")

    def test_a_run_with_a_wrong_prompt_is_refused(self):
        self.edit_meta(self.on, lambda m: m.update(prompt_sha256="1" * 64))
        self.refused("prompt hash")

    def test_a_result_file_with_alerts_that_are_not_dev_alerts_is_refused(self):
        path = os.path.join(self.on, "results.jsonl")
        records = store.read_jsonl(path)
        records[0]["alert_id"] = "FROZEN-0001"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in records))
        from evaluate import EvaluationInputError
        with self.assertRaises(EvaluationInputError):
            self.compare()


class MetricDefinitionTests(unittest.TestCase):
    def test_routing_metrics_by_hand(self):
        df = pd.DataFrame({"alert_id": list("abcdef"), "is_attack": [True, True, False, False, False, True],
                           "routing": ["auto_close", "escalate", "auto_close", "needs_review", "escalate", "no_routing"]})
        r = E.routing_metrics(df)
        self.assertEqual(r["counts"], {"auto_close": 2, "escalate": 2, "needs_review": 1, "no_routing": 1})
        self.assertEqual((r["auto_close_rate"]["numerator"], r["auto_close_rate"]["denominator"]), (2, 6))
        self.assertEqual((r["true_attacks_auto_closed"]["numerator"], r["true_attacks_auto_closed"]["denominator"]), (1, 3))
        self.assertEqual((r["true_benign_in_review_queue"]["numerator"], r["true_benign_in_review_queue"]["denominator"]), (2, 3))
        self.assertEqual((r["auto_closed_that_were_benign"]["numerator"], r["auto_closed_that_were_benign"]["denominator"]), (1, 2))
        self.assertEqual(r["auto_closed_attack_alert_ids"], ["a"])
        self.assertEqual((r["review_queue_rate_escalate_or_needs_review"]["numerator"]), 3)

    def test_no_auto_closed_alerts_gives_an_undefined_ratio_not_a_zero_or_a_one(self):
        df = pd.DataFrame({"alert_id": ["a", "b"], "is_attack": [True, False], "routing": ["escalate", "escalate"]})
        r = E.routing_metrics(df)["auto_closed_that_were_benign"]
        self.assertIsNone(r["value"])
        self.assertEqual(r["denominator"], 0)
        self.assertTrue(E.pct(r).startswith("n/a"))

    def test_memory_metrics_by_hand_with_a_tie_going_to_the_closest_neighbour(self):
        def state(labels):
            hits = [{"rank": i + 1, "label": lab} for i, lab in enumerate(labels)]
            counts = {}
            for lab in labels:
                counts[lab] = counts.get(lab, 0) + 1
            return {"state": {"memory": {"status": "ok", "hits": hits, "label_counts": counts}}}
        df = pd.DataFrame({"alert_id": ["a", "b", "c"], "label": ["PortScan", "BENIGN", "Bot"], "is_attack": [True, False, True]})
        states = {"a": state(["PortScan", "PortScan", "BENIGN"]), "b": state(["Bot", "BENIGN"]), "c": {"state": {"memory": {"status": "error", "error_code": "store_error", "error_detail": "x"}}}}
        m = E.memory_metrics(df, states)
        self.assertEqual(m["memory_step_status_counts"], {"error": 1, "ok": 2})
        self.assertEqual(m["alerts_with_neighbours"], 2)
        self.assertEqual((m["closest_neighbour_label_equals_true_label"]["numerator"], m["majority_neighbour_label_equals_true_label"]["numerator"]), (1, 1))
        self.assertEqual(m["mean_attack_neighbour_share_on_true_benign"], {"value": 0.5, "n": 1})

    def test_the_paired_view_counts_by_hand(self):
        def table(correct, routing):
            return pd.DataFrame({"alert_id": ["a", "b", "c"], "is_attack": [True, True, False], "has_verdict": [True, True, True], "label": ["PortScan"] * 2 + ["BENIGN"],
                                 "accepted_ids": [["T1046"]] * 2 + [[]], "pred_technique": ["T1046" if c else "NONE" for c in correct], "pred_attack_type": ["PortScan" if c else "BENIGN" for c in correct],
                                 "routing": routing})
        p = E.paired(table([True, False, True], ["escalate", "escalate", "auto_close"]), table([True, True, True], ["escalate", "escalate", "needs_review"]))
        c = p["technique_correct_on_true_attacks"]
        self.assertEqual((c["both_correct"], c["only_memory_off_correct"], c["only_memory_on_correct"], c["neither_correct"]), (1, 0, 1, 0))
        self.assertEqual(p["routing"], {"same_decision": 2, "changed_decision": 1, "changes": {"auto_close->needs_review": 1}})


class BoundaryTests(EvalBase):
    def imports(self, rel):
        tree = ast.parse(read_text(os.path.join(SRC, rel)))
        out = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                out.add((node.module or "").split(".")[0])
                out |= {a.name for a in node.names}
        return out

    def test_no_agent_side_week4_module_imports_the_evaluator_or_labels(self):
        banned = {"evaluate_memory", "eval_labels", "eval_io", "evaluate", "eval_metrics"}
        for rel in ("week4/run_memory_dev.py", "week4/ingest_cases.py", "week4/seed_memory.py", "week4/policy.py", "week4/cases.py", "week4/approval.py"):
            self.assertFalse(self.imports(rel) & banned, rel)
        for folder in ("graph", "memory", "api", "db"):
            for name in os.listdir(os.path.join(SRC, "week4", folder)):
                if name.endswith(".py"):
                    self.assertFalse(self.imports("week4/%s/%s" % (folder, name)) & banned, folder + "/" + name)

    def test_the_evaluator_reads_dev_labels_only_and_never_the_frozen_set(self):
        text = read_text(os.path.join(SRC, "week4", "evaluate_memory.py"))
        for word in ("eval_io", "frozen_alerts", "FROZEN_LABELS_PATH", "load_labels(", "SOC_FROZEN_UNLOCK", "final_test"):
            self.assertNotIn(word, text)
        self.assertIn("eval_labels.load_dev_labels()", text)
        self.assertIn("triage_inputs.load_dev_alerts()", text)

    def test_main_runs_end_to_end_on_dev_inputs_and_reports_a_clean_frozen_log(self):
        out = os.path.join(self.tmp.name, "main_out")
        with mock.patch.object(triage_inputs, "load_dev_alerts", return_value=full_alerts_frame()), mock.patch.object(eval_labels, "load_dev_labels", return_value=labels_frame()):
            code = E.main(["--runs-dir", self.runs, "--off-run", "FAKE_off", "--on-run", "FAKE_on", "--out-dir", out])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(out, "COMPARISON_REPORT.md")))

    def test_main_refuses_a_fake_run(self):
        self.relabel(self.on, True)
        with mock.patch.object(triage_inputs, "load_dev_alerts", return_value=full_alerts_frame()), mock.patch.object(eval_labels, "load_dev_labels", return_value=labels_frame()):
            code = E.main(["--runs-dir", self.runs, "--off-run", "FAKE_off", "--on-run", "FAKE_on", "--out-dir", os.path.join(self.tmp.name, "x")])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
