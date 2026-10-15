"""Week 4 Day 6: score two finished DEV runs of graph v2 (memory off, memory on) against the DEV labels and put them side by side.

  python src/week4/evaluate_memory.py --off-run dev_v2_mem_off --on-run dev_v2_mem_on

EVALUATION ONLY. This is the Week 4 place that reads labels (dev labels and the dev MITRE answer key, through eval_labels). It never calls a model, never changes a run folder, never opens the frozen
set, and no agent-side module imports it (a test checks that). Nothing here chooses a threshold or tunes anything: the routing policy and the memory settings are whatever the runs recorded.

It refuses to compare unless the two runs are comparable (same dev alerts in the same order, same model and generation settings, same input hashes, same graph version, same risk policy, same locked
baseline; both real, complete, written by run_memory_dev; one with memory off and agent_v1, one with memory on and agent_v2_memory). A partial or failed arm is never silently dropped from a denominator:
every ratio shows its numerator, denominator and population, and no-verdict alerts are counted as such.

What it reports per arm: verdict and MITRE technique accuracy (Week 2 definitions, via eval_metrics), routing decisions and rates (auto_close / escalate / needs_review), how often auto-closed alerts were
really attacks, review burden, proposed actions (all 'pending': approvals are human decisions and are not simulated here), errors, and, for the memory arm, how often the neighbours' labels matched the true label.
Then a paired view on the alerts both arms answered: counts of alerts that changed from wrong to right, right to wrong, or stayed. It states no p-value and no 'significant' result: one run per arm of a
non-deterministic model cannot support one (see the Week 2 Day 6 replicate spread for the size of run-to-run noise).

Writes reports/week4_eval/<off>_vs_<on>/  comparison.json, COMPARISON_REPORT.md, comparison_metrics.csv, per_alert.csv
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # src/

import pandas as pd

import baseline_store as store
import config
import eval_metrics as em
import evaluate as ev
from agents import verdict_prompt as VP

from week4.graph import prompt as P2

OUT_ROOT = os.path.join(config.REPORTS_DIR, "week4_eval")
RUNS_ROOT = os.path.join(config.PROJECT_ROOT, "runs", "week4_memory")
SETTING_KEYS = ["temperature", "max_output_tokens", "seed", "parse_retries"]
DECISIONS = ("auto_close", "escalate", "needs_review", "no_routing")
SCHEMA = "week4_memory_comparison_v1"
RUNNER = "run_memory_dev"


class ComparisonError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ comparability
def check_comparable(off, on, allow_partial=False):
    """Raise ComparisonError listing every reason the two run_meta records cannot be compared. Returns None when they can."""
    problems = []
    for label, m, mode, prompt in (("memory-off run", off, "off", VP.prompt_sha256()), ("memory-on run", on, "on", P2.get_prompt().sha256)):
        if m.get("runner") != RUNNER:
            problems.append(label + " was not made by " + RUNNER)
        if m.get("fake_model"):
            problems.append(label + " is a --fake-model run (plumbing only, never evaluable)")
        if m.get("set") != "dev":
            problems.append(label + " is not a dev run")
        if not allow_partial and m.get("status") != "complete":
            problems.append(label + " is not complete (status " + str(m.get("status")) + "); finish it or pass --allow-partial")
        if (m.get("agent") or {}).get("memory", {}).get("mode") != mode:
            problems.append(label + " does not say memory " + mode)
        if m.get("prompt_sha256") != prompt:
            problems.append(label + " does not carry the registered " + ("agent_v1" if mode == "off" else "agent_v2_memory") + " prompt hash")
    same = [("model", lambda m: m.get("model")), ("inputs", lambda m: m.get("inputs")), ("selected alert list", lambda m: m.get("selected_alert_ids")),
            ("graph version", lambda m: (m.get("agent") or {}).get("graph_version")), ("risk policy", lambda m: (m.get("agent") or {}).get("policy")),
            ("locked baseline", lambda m: (m.get("agent") or {}).get("baseline"))]
    for name, get in same:
        if get(off) != get(on):
            problems.append(name + " differs between the runs")
    for key in SETTING_KEYS:
        if (off.get("settings") or {}).get(key) != (on.get("settings") or {}).get(key):
            problems.append("setting " + key + " differs between the runs")
    if not (on.get("agent") or {}).get("memory", {}).get("manifest_sha256"):
        problems.append("the memory-on run has no memory manifest hash")
    if ((on.get("agent") or {}).get("memory", {}).get("isolation_check") or {}).get("dev_overlap") != 0:
        problems.append("the memory-on run has no clean train/dev isolation check")
    for label, m in (("memory-off run", off), ("memory-on run", on)):
        if m.get("frozen_access_log_unchanged") is not True or m.get("week1_files_unchanged") is not True:
            problems.append(label + " did not record unchanged frozen-access log and Week 1 files")
    if problems:
        raise ComparisonError("The two runs cannot be compared:\n- " + "\n- ".join(problems))


# ------------------------------------------------------------------------------------------------ one arm
def routing_column(results, ids):
    out = []
    for alert_id in ids:
        r = results.get(alert_id)
        rr = (r or {}).get("risk_routing")
        out.append(rr["decision"] if isinstance(rr, dict) else "no_routing")
    return out


def count_by(values):
    out = {}
    for v in values:
        out[str(v)] = out.get(str(v), 0) + 1
    return dict(sorted(out.items()))


def routing_metrics(df):
    """df needs: is_attack, routing (auto_close|escalate|needs_review|no_routing). Every denominator is shown."""
    n = len(df)
    counts = {d: int((df["routing"] == d).sum()) for d in DECISIONS}
    atk, ben = df[df["is_attack"]], df[~df["is_attack"]]
    closed = df[df["routing"] == "auto_close"]
    queue = df[df["routing"].isin(["escalate", "needs_review"])]
    return {
        "definition": "Decisions of the risk policy recorded in each run, applied identically to both arms. 'no_routing' = the graph or policy produced no decision for the alert (never counted as closed).",
        "counts": counts,
        "rates_of_all_alerts": {d: em.ratio(counts[d], n, "all alerts in the comparison") for d in DECISIONS},
        "auto_close_rate": em.ratio(counts["auto_close"], n, "all alerts in the comparison"),
        "escalation_rate_escalate_only": em.ratio(counts["escalate"], n, "all alerts in the comparison"),
        "review_queue_rate_escalate_or_needs_review": em.ratio(len(queue), n, "all alerts in the comparison"),
        "true_attacks_auto_closed": em.ratio(int((atk["routing"] == "auto_close").sum()), len(atk), "true attacks (a closed attack is a missed attack)"),
        "true_attacks_in_review_queue": em.ratio(int(atk["routing"].isin(["escalate", "needs_review"]).sum()), len(atk), "true attacks"),
        "true_benign_auto_closed": em.ratio(int((ben["routing"] == "auto_close").sum()), len(ben), "true benign alerts"),
        "true_benign_in_review_queue": em.ratio(int(ben["routing"].isin(["escalate", "needs_review"]).sum()), len(ben), "true benign alerts (analyst workload that was not needed)"),
        "auto_closed_that_were_benign": em.ratio(int((~closed["is_attack"]).sum()), len(closed), "auto-closed alerts (undefined when nothing was auto-closed)"),
        "auto_closed_attack_alert_ids": sorted(closed[closed["is_attack"]]["alert_id"]),
    }


def memory_metrics(df, states):
    """Only for the memory-on arm. states: {alert_id: state record} from states.jsonl. Uses true labels for evaluation only."""
    status = count_by([(s["state"].get("memory") or {}).get("status", "none") if s else "no_state" for s in (states.get(a) for a in df["alert_id"])])
    agree_closest, agree_majority, attack_share = [], [], {"attack": [], "benign": []}
    for _, row in df.iterrows():
        s = states.get(row["alert_id"])
        mem = (s or {}).get("state", {}).get("memory") if s else None
        if not isinstance(mem, dict) or mem.get("status") != "ok":
            continue
        hits = mem["hits"]
        counts = mem["label_counts"]
        top = max(counts.values())
        tied = [lab for lab, c in counts.items() if c == top]
        majority = next((h["label"] for h in hits if h["label"] in tied), None)   # a tie goes to the closest neighbour among the tied labels
        agree_closest.append(hits[0]["label"] == row["label"])
        agree_majority.append(majority == row["label"])
        share = sum(c for lab, c in counts.items() if lab != "BENIGN") / sum(counts.values())
        attack_share["attack" if row["is_attack"] else "benign"].append(share)
    n = len(agree_closest)

    def mean(xs):
        return (sum(xs) / len(xs)) if xs else None
    return {"memory_step_status_counts": status, "alerts_with_neighbours": n,
            "closest_neighbour_label_equals_true_label": em.ratio(sum(agree_closest), n, "alerts whose memory step returned neighbours"),
            "majority_neighbour_label_equals_true_label": em.ratio(sum(agree_majority), n, "alerts whose memory step returned neighbours"),
            "mean_attack_neighbour_share_on_true_attacks": {"value": mean(attack_share["attack"]), "n": len(attack_share["attack"])},
            "mean_attack_neighbour_share_on_true_benign": {"value": mean(attack_share["benign"]), "n": len(attack_share["benign"])},
            "note": "Descriptive only: how similar past training flows were labelled compared with this dev alert's true label."}


def error_metrics(df, results):
    recs = [results.get(a) for a in df["alert_id"]]
    return {"status_counts": count_by([r["status"] if r else "not_run" for r in recs]), "error_code_counts": count_by([r["error_code"] for r in recs if r and r.get("error_code")]),
            "graph_status_counts": count_by([r.get("graph_status") for r in recs if r]), "graph_error_alerts": sum(1 for r in recs if r and r.get("graph_errors")),
            "routing_errors": sum(1 for r in recs if r and r.get("routing_error")), "first_try_malformed_replies": sum(1 for r in recs if r and r.get("malformed_first_try"))}


def action_metrics(df, results):
    n = sum(len((results.get(a) or {}).get("proposed_actions") or []) for a in df["alert_id"])
    by_type = {}
    for a in df["alert_id"]:
        for act in (results.get(a) or {}).get("proposed_actions") or []:
            by_type[act["action_type"]] = by_type.get(act["action_type"], 0) + 1
    return {"proposed_actions": n, "by_type": dict(sorted(by_type.items())), "executed": 0,
            "approval_note": "Every proposed action starts as 'pending'. Approving or rejecting is a human decision made through the approval API; these runs contain none, so no approval rate exists and none is invented. Nothing is ever executed."}


def read_states(run_dir):
    path = os.path.join(run_dir, "states.jsonl")
    latest = {}
    if os.path.isfile(path):
        for rec in store.read_jsonl(path):
            latest[rec["alert_id"]] = rec
    return latest


def score_arm(run_dir, alerts, labels, threshold, allow_partial):
    """-> {df, meta, metrics} for one run folder. Raises EvaluationInputError for any input problem (Week 2 checks, unchanged)."""
    latest, n_lines, _, _ = ev.load_run(run_dir)
    ev.check_inputs(alerts, labels, latest, threshold, allow_partial)
    df = ev.build_table(alerts, labels, latest, allow_partial)
    df["routing"] = routing_column(latest, list(df["alert_id"]))
    meta = store.read_json(os.path.join(run_dir, "run_meta.json"))
    states = read_states(run_dir)
    metrics = {"population": em.population_counts(df), "verdict": em.verdict_metrics(df), "attack_type": em.attack_type_metrics(df), "mitre": em.mitre_metrics(df),
               "reliability": em.reliability(df), "per_class": em.per_class(df, ev.CLASSES), "routing": routing_metrics(df), "actions": action_metrics(df, latest),
               "errors": error_metrics(df, latest)}
    if (meta.get("agent") or {}).get("memory", {}).get("mode") == "on":
        metrics["memory"] = memory_metrics(df, states)
    tokens = {"model_calls": int(pd.to_numeric(df["model_calls"], errors="coerce").fillna(0).sum()), "total_tokens": int(pd.to_numeric(df["total_tokens"], errors="coerce").fillna(0).sum())}
    metrics["usage"] = tokens
    return {"df": df, "meta": meta, "metrics": metrics, "result_lines": n_lines}


# ------------------------------------------------------------------------------------------------ paired view
def correct_technique(row):
    return bool(row["has_verdict"] and row["is_attack"] and em._in_accepted(row))


def correct_type(row):
    return bool(row["has_verdict"] and row["is_attack"] and row["pred_attack_type"] == row["label"])


def paired(off_df, on_df):
    """Counts of alerts by outcome in the two arms. Defined on alerts present in both. No test statistic."""
    a, b = off_df.set_index("alert_id"), on_df.set_index("alert_id")
    ids = [i for i in a.index if i in b.index]
    out = {"alerts_in_both": len(ids)}
    for name, fn, mask in (("technique_correct_on_true_attacks", correct_technique, "is_attack"), ("attack_type_correct_on_true_attacks", correct_type, "is_attack")):
        sel = [i for i in ids if a.loc[i, mask]]
        cells = {"both_correct": 0, "only_memory_off_correct": 0, "only_memory_on_correct": 0, "neither_correct": 0}
        for i in sel:
            x, y = fn(a.loc[i]), fn(b.loc[i])
            cells["both_correct" if x and y else "only_memory_off_correct" if x else "only_memory_on_correct" if y else "neither_correct"] += 1
        out[name] = dict(cells, true_attacks_compared=len(sel), definition="a no-verdict alert counts as not correct in its arm")
    moved = {"same_decision": 0, "changed_decision": 0}
    changes = {}
    for i in ids:
        x, y = a.loc[i, "routing"], b.loc[i, "routing"]
        if x == y:
            moved["same_decision"] += 1
        else:
            moved["changed_decision"] += 1
            key = x + "->" + y
            changes[key] = changes.get(key, 0) + 1
    out["routing"] = dict(moved, changes=dict(sorted(changes.items())))
    return out


# ------------------------------------------------------------------------------------------------ provenance
def provenance(off_meta, on_meta):
    mem = on_meta["agent"]["memory"]
    return {
        "memory_off_run": {"run_name": off_meta["run_name"], "prompt_version": off_meta["prompt_version"], "prompt_sha256": off_meta["prompt_sha256"]},
        "memory_on_run": {"run_name": on_meta["run_name"], "prompt_version": on_meta["prompt_version"], "prompt_sha256": on_meta["prompt_sha256"]},
        "model": on_meta["model"], "settings": {k: on_meta["settings"].get(k) for k in SETTING_KEYS}, "generation_seed": on_meta["settings"].get("seed"),
        "inputs": on_meta["inputs"], "n_selected": on_meta["n_selected"], "graph_version": on_meta["agent"]["graph_version"], "policy": on_meta["agent"]["policy"],
        "locked_baseline": on_meta["agent"].get("baseline"),
        "split": {"memory_seeded_from": "train split only (train.parquet)", "train_sha256": mem["store"]["train_sha256"], "memory_manifest_sha256": mem["manifest_sha256"],
                  "memory_records": mem["store"]["n_records"], "memory_per_class_cap": mem["store"]["per_class_cap"], "memory_seed": mem["store"]["seed"], "memory_k": mem["k"],
                  "evaluated_on": "dev alerts only (dev_alerts_sha256 above)", "isolation_check": mem["isolation_check"], "frozen_set": "not opened by either run (frozen access log unchanged in both run_meta files)"},
        "git": {"memory_off": off_meta.get("git"), "memory_on": on_meta.get("git")}, "packages": on_meta.get("packages"),
    }


LIMITATIONS = [
    "One run per arm. The model is non-deterministic even at a fixed seed, so a difference between the arms mixes the effect of memory with run-to-run noise. The Week 2 Day 6 replicate spread shows how large that noise was for the baseline; no significance test is made or implied.",
    "Dev set only, one split of CIC-IDS2017. Attack flows from the same tool and the same attacker host recur across files, so training and dev flows can be near-duplicates in feature space even though no flow is shared. Memory can look helpful because of that regularity, which would not carry over to different traffic.",
    "Memory holds only training labels and a numeric flow fingerprint (decision D-W4-1): it cannot supply MITRE technique ids, so any change in technique accuracy comes through the model's attack-type reasoning, not through looked-up ids.",
    "The memory arm changes two things at once: it adds evidence (neighbour labels) and it uses a longer prompt (agent_v2_memory). They cannot be separated with these two runs.",
    "Routing thresholds are policy defaults fixed before the runs (config/risk_policy.json); none was tuned on dev or frozen data. Every dev alert is already a detector alert, so the share the policy auto-closes depends on how its detector-score ceiling sits against the detector threshold; read the auto-close and escalation rates as properties of this policy, not as a recommendation.",
    "Approvals are human decisions. The runs only propose actions; no approval rate is measured and nothing is executed.",
    "The frozen evaluation set was not used for tuning, seeding or threshold choice, and was not opened for this comparison.",
]


# ------------------------------------------------------------------------------------------------ output
def pct(r):
    if not r or r.get("value") is None:
        return "n/a (0/" + str((r or {}).get("denominator", 0)) + ")"
    ci = r.get("wilson95")
    return "%.1f%% (%d/%d)" % (100 * r["value"], r["numerator"], r["denominator"]) + ("  95%% Wilson [%.1f, %.1f]" % (100 * ci[0], 100 * ci[1]) if ci else "")


def flat(prefix, value, rows):
    if isinstance(value, dict):
        for k in sorted(value):
            flat(prefix + "." + str(k) if prefix else str(k), value[k], rows)
    elif isinstance(value, (int, float, str, bool)) or value is None:
        rows.append({"metric": prefix, "value": value})


def render_report(result):
    o, n = result["arms"]["memory_off"], result["arms"]["memory_on"]
    P = result["provenance"]
    lines = ["# Week 4 memory ablation: memory off vs memory on (dev set)", "",
             "Generated by `src/week4/evaluate_memory.py`. Dev alerts and dev labels only. Descriptive comparison of two runs; no significance is claimed.", "",
             "## Runs", "", "| | memory off | memory on |", "|---|---|---|",
             "| run | %s | %s |" % (P["memory_off_run"]["run_name"], P["memory_on_run"]["run_name"]),
             "| verdict prompt | %s | %s |" % (P["memory_off_run"]["prompt_version"], P["memory_on_run"]["prompt_version"]),
             "| alerts compared | %d | %d |" % (o["population"]["alerts"], n["population"]["alerts"]),
             "| valid verdicts | %d | %d |" % (o["population"]["ok"], n["population"]["ok"]),
             "| parse_failed / model_error / not run | %d / %d / %d | %d / %d / %d |" % (o["population"]["parse_failed"], o["population"]["model_error"], o["population"]["not_run"], n["population"]["parse_failed"], n["population"]["model_error"], n["population"]["not_run"]),
             "", "Held equal: model `%s`, settings %s, dev inputs, alert order, graph `%s`, risk policy `%s` (%s)." % (P["model"], json.dumps(P["settings"], sort_keys=True), P["graph_version"], P["policy"]["version"], P["policy"]["sha256"][:12]),
             "", "## MITRE technique accuracy (true attacks only)", "",
             "A prediction is correct if it is one of the answer key's accepted ids for the true class (exact id match). A benign verdict on an attack, or no verdict, is not correct.", "",
             "| metric | memory off | memory on |", "|---|---|---|"]
    for key, title in (("accepted_on_attacks_with_valid_verdict", "correct, among attacks with a valid verdict"), ("accepted_on_attacks_flagged_malicious", "correct, among attacks called malicious"),
                       ("accepted_all_attacks_failures_wrong", "correct, among all attacks (no verdict = wrong; lower bound)"), ("coverage", "attacks with a valid verdict")):
        lines.append("| %s | %s | %s |" % (title, pct(o["metrics"]["mitre"][key]), pct(n["metrics"]["mitre"][key])))
    lines += ["", "Attack-type exact match, among all attacks (no verdict = wrong): %s vs %s." % (pct(o["metrics"]["attack_type"]["all_attacks_failures_wrong"]), pct(n["metrics"]["attack_type"]["all_attacks_failures_wrong"])), "",
              "## Paired view (alerts in both runs)", ""]
    pr = result["paired"]
    for key in ("technique_correct_on_true_attacks", "attack_type_correct_on_true_attacks"):
        c = pr[key]
        lines.append("- %s over %d true attacks: both correct %d, only memory off %d, only memory on %d, neither %d." % (key.replace("_", " "), c["true_attacks_compared"], c["both_correct"], c["only_memory_off_correct"], c["only_memory_on_correct"], c["neither_correct"]))
    lines.append("- routing decision changed for %d of %d alerts %s." % (pr["routing"]["changed_decision"], pr["alerts_in_both"], json.dumps(pr["routing"]["changes"], sort_keys=True)))
    lines += ["", "## Routing (risk policy %s)" % P["policy"]["version"], "", "| metric | memory off | memory on |", "|---|---|---|"]
    for key, title in (("auto_close_rate", "auto-closed, of all alerts"), ("escalation_rate_escalate_only", "escalated, of all alerts"), ("review_queue_rate_escalate_or_needs_review", "in the review queue (escalate or needs_review)"),
                       ("true_attacks_auto_closed", "true attacks auto-closed (missed)"), ("true_benign_auto_closed", "true benign auto-closed"), ("true_benign_in_review_queue", "true benign sent to review"),
                       ("auto_closed_that_were_benign", "auto-closed alerts that were benign")):
        lines.append("| %s | %s | %s |" % (title, pct(o["metrics"]["routing"][key]), pct(n["metrics"]["routing"][key])))
    lines += ["", "Decision counts: off %s, on %s." % (json.dumps(o["metrics"]["routing"]["counts"], sort_keys=True), json.dumps(n["metrics"]["routing"]["counts"], sort_keys=True)), "",
              "## Proposed actions and approvals", "",
              "Proposed actions: off %d, on %d. Executed: 0 (this system never executes). %s" % (o["metrics"]["actions"]["proposed_actions"], n["metrics"]["actions"]["proposed_actions"], o["metrics"]["actions"]["approval_note"]), "",
              "## Errors", "", "| | memory off | memory on |", "|---|---|---|",
              "| status counts | %s | %s |" % (json.dumps(o["metrics"]["errors"]["status_counts"]), json.dumps(n["metrics"]["errors"]["status_counts"])),
              "| error codes | %s | %s |" % (json.dumps(o["metrics"]["errors"]["error_code_counts"]), json.dumps(n["metrics"]["errors"]["error_code_counts"])),
              "| alerts with graph errors | %d | %d |" % (o["metrics"]["errors"]["graph_error_alerts"], n["metrics"]["errors"]["graph_error_alerts"]),
              "| routing errors | %d | %d |" % (o["metrics"]["errors"]["routing_errors"], n["metrics"]["errors"]["routing_errors"]),
              "| model calls / total tokens | %d / %d | %d / %d |" % (o["metrics"]["usage"]["model_calls"], o["metrics"]["usage"]["total_tokens"], n["metrics"]["usage"]["model_calls"], n["metrics"]["usage"]["total_tokens"]), ""]
    mem = n["metrics"].get("memory")
    if mem:
        lines += ["## Memory step (memory-on run)", "", "Memory step statuses: %s." % json.dumps(mem["memory_step_status_counts"], sort_keys=True),
                  "Closest neighbour's label equals the true label: %s." % pct(mem["closest_neighbour_label_equals_true_label"]),
                  "Majority neighbour label equals the true label: %s." % pct(mem["majority_neighbour_label_equals_true_label"]), mem["note"], ""]
    sp = P["split"]
    lines += ["## Split and provenance", "", "- Memory seeded from: %s (train file sha256 `%s`, manifest `%s`, %d records, per-class cap %d, seed %d, k=%d)." % (sp["memory_seeded_from"], sp["train_sha256"], sp["memory_manifest_sha256"], sp["memory_records"], sp["memory_per_class_cap"], sp["memory_seed"], sp["memory_k"]),
              "- Evaluated on: %s. Inputs: %s." % (sp["evaluated_on"], json.dumps(P["inputs"], sort_keys=True)),
              "- Isolation check before the memory-on run: %s." % json.dumps(sp["isolation_check"], sort_keys=True),
              "- Frozen set: %s." % sp["frozen_set"], "- Generation seed: %s." % P["generation_seed"], "", "## Limitations and confounders", ""]
    lines += ["- " + t for t in LIMITATIONS]
    return "\n".join(lines) + "\n"


def compare_runs(off_dir, on_dir, alerts, labels, threshold=None, allow_partial=False):
    """The whole comparison as a plain dict (plus the two per-alert tables under result['_tables'])."""
    off_meta = store.read_json(os.path.join(off_dir, "run_meta.json"))
    on_meta = store.read_json(os.path.join(on_dir, "run_meta.json"))
    check_comparable(off_meta, on_meta, allow_partial)
    arms = {"memory_off": score_arm(off_dir, alerts, labels, threshold, allow_partial), "memory_on": score_arm(on_dir, alerts, labels, threshold, allow_partial)}
    if allow_partial:
        common = set(arms["memory_off"]["df"]["alert_id"]) & set(arms["memory_on"]["df"]["alert_id"])
        for arm in arms.values():
            arm["df"] = arm["df"][arm["df"]["alert_id"].isin(common)].reset_index(drop=True)
    return {"schema": SCHEMA, "allow_partial": allow_partial, "provenance": provenance(off_meta, on_meta), "limitations": LIMITATIONS,
            "arms": {k: {"population": v["metrics"]["population"], "metrics": v["metrics"]} for k, v in arms.items()},
            "paired": paired(arms["memory_off"]["df"], arms["memory_on"]["df"]), "_tables": {k: v["df"] for k, v in arms.items()}}


def write_outputs(result, out_dir, force=False):
    if os.path.exists(out_dir) and os.listdir(out_dir) and not force:
        raise ComparisonError(out_dir + " already has a comparison. Use --force to replace it.")
    os.makedirs(out_dir, exist_ok=True)
    tables = result.pop("_tables")
    result["generated_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(os.path.join(out_dir, "comparison.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True, default=str)
    rows = []
    flat("", {k: v for k, v in result.items() if k in ("arms", "paired")}, rows)
    with open(os.path.join(out_dir, "comparison_metrics.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["metric", "value"])
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out_dir, "COMPARISON_REPORT.md"), "w", encoding="utf-8") as f:
        f.write(render_report(result))
    cols = ["alert_id", "label", "is_attack", "status", "pred_malicious", "pred_attack_type", "pred_technique", "routing"]
    merged = tables["memory_off"][cols].merge(tables["memory_on"][cols], on=["alert_id", "label", "is_attack"], suffixes=("_memory_off", "_memory_on"))
    merged.to_csv(os.path.join(out_dir, "per_alert.csv"), index=False)
    return out_dir


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Compare a memory-off and a memory-on Week 4 dev run against the dev labels.")
    p.add_argument("--off-run", required=True)
    p.add_argument("--on-run", required=True)
    p.add_argument("--runs-dir", default=RUNS_ROOT)
    p.add_argument("--out-dir", default=None, help="default reports/week4_eval/<off>_vs_<on>")
    p.add_argument("--allow-partial", action="store_true")
    p.add_argument("--force", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    import eval_labels
    import triage_inputs
    off_dir, on_dir = os.path.join(args.runs_dir, args.off_run), os.path.join(args.runs_dir, args.on_run)
    for d in (off_dir, on_dir):
        if not os.path.isdir(d):
            print("STOPPED: no run folder " + d)
            return 1
    threshold = None
    if os.path.exists(config.THRESHOLD_PATH):
        threshold = store.read_json(config.THRESHOLD_PATH)["threshold"]
    log_before = count_lines(config.FROZEN_ACCESS_LOG)
    try:
        alerts = triage_inputs.load_dev_alerts()
        labels = eval_labels.load_dev_labels()
        result = compare_runs(off_dir, on_dir, alerts, labels, threshold, args.allow_partial)
        out = write_outputs(result, args.out_dir or os.path.join(OUT_ROOT, args.off_run + "_vs_" + args.on_run), args.force)
    except (ComparisonError, ev.EvaluationInputError, ValueError) as error:
        print("STOPPED: " + str(error))
        return 1
    log_after = count_lines(config.FROZEN_ACCESS_LOG)
    print("Report: " + os.path.join(out, "COMPARISON_REPORT.md"))
    if log_before != log_after:
        print("WARNING: the frozen access log changed during the evaluation. Check eval/frozen_access.log.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
