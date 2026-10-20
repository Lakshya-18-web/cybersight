"""Markdown report for the injection suite results."""


def _t(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    return "\n".join(out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def _pct(x):
    return "n/a" if x is None else "%.1f%%" % (100.0 * x)


def render(results):
    m, meta = results["metrics"], results["meta"]
    recs = results["records"]
    lines = ["# Prompt-injection suite report", "",
             "Run %s to %s. Python %s. Week 5 %s. Model: %s." % (meta["started_at"], meta["finished_at"], meta["python"], meta["week5_version"], meta["model"]),
             "Payload file SHA-256 `%s`; criteria file SHA-256 `%s`." % (meta["data_sha256"]["payloads.json"], meta["data_sha256"]["criteria.json"]), "",
             "**Overall: %s.** Passing means the declared controls behaved as designed against these payloads. It does not mean the system is secure." % ("PASS" if results["overall_pass"] else "FAIL"), "",
             "## Gates", "", _t([(g["gate"], "PASS" if g["pass"] else "FAIL") for g in results["gates"]], ("gate", "result")), "",
             "## Headline metrics", "",
             _t([("adversarial payloads", m["counts"]["adversarial"]), ("benign controls", m["counts"]["benign_controls"]), ("attack success rate", _pct(m["attack_success_rate"])),
                 ("attack success rate excluding declared residual risks", _pct(m["success_rate_excluding_declared_residual"])), ("intake block rate (payloads expected blocked)", _pct(m["intake_block_rate"])),
                 ("neutralisation rate (payloads not blocked at intake)", _pct(m["neutralisation_rate"])), ("false-block rate on benign controls", _pct(m["false_block_rate"])),
                 ("control fidelity", _pct(m["control_fidelity"])), ("echo count", m["echo_count"]), ("leak count", m["leak_count"]),
                 ("audit coverage (%d events checked)" % m["audit_events_checked"], _pct(m["audit_coverage"])), ("infrastructure failures", m["infra_failures"])], ("metric", "value")), "",
             "Outcome classes (adversarial): `%s`. Observed defence layers: `%s`." % (m["counts"]["by_observed_class"], m["observed_layers"]), "",
             "## By category", "", _t([(k, v["n"], v["succeeded"], _pct(v["rate"])) for k, v in m["attack_success_rate_by_category"].items()], ("category", "payloads", "succeeded", "success rate")), "",
             "## Attacks that succeeded", ""]
    won = [r for r in recs if r["observed_class"] == "succeeded"]
    if won:
        lines += [_t([(r["id"], r["title"], "yes (declared)" if r["residual_risk"] else "NO - UNDECLARED") for r in won], ("id", "payload", "declared residual risk?")), ""]
        lines += ["Declared residual risks:", ""] + ["- **%s**: %s" % (k, v) for k, v in results["residual_risks"].items()] + [""]
    else:
        lines += ["None.", ""]
    lines += ["## Expectation mismatches", ""]
    mism = [r for r in recs if r["mismatch"]]
    lines += [_t([(r["id"], r["title"], "%s / %s" % (r["expected_class"], r["expected_layer"]), "%s / %s" % (r["observed_class"], r["observed_layer"])) for r in mism], ("id", "payload", "expected", "observed")) if mism else "None.", ""]
    lines += ["## Corrections made after the first run", ""]
    lines += ["- **%s**: %s" % (c["id"], c["note"]) for c in results.get("corrections_after_first_run", [])] or ["None."]
    lines += ["", "The first run also exposed one real defect, fixed before this run: a refused Idempotency-Key (HTTP 422) wrote no audit event, and the check used the Week 4 pattern that accepts a trailing newline. Both are fixed in `api5.py` and covered by tests.", ""]
    lines += ["## Every payload", "", _t([(r["id"], r["category"], r["title"][:70], r["observed_class"], r["observed_layer"], "yes" if r["goal_achieved"] else "no", ",".join(map(str, r["http_statuses"]))) for r in recs],
                                        ("id", "category", "payload", "outcome", "layer", "goal achieved", "HTTP")), "",
              "## Limits", ""] + ["- " + x for x in results["limits"]] + [""]
    return "\n".join(lines)
