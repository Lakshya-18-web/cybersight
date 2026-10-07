"""Week 2 Day 5: cost tracking from a pricing file you supply.

No provider price is written into this code. Without a pricing file, cost is reported as "unavailable".
The pricing file has the same keys the Day 4 evaluator already uses (--pricing-file):

  currency, per_million_input_tokens, per_million_output_tokens, thinking_tokens_billed_as
  ("output", "input" or "not_billed"), source (where you read the prices), as_of (the date you read them)

Cost is computed afterwards from token counts already stored in a run's results.jsonl (prompt_tokens, output_tokens,
thinking_tokens). Retries are included because those token counts are summed over every call of an alert.
This module reads no labels, no answer key and no frozen file, calls no model and writes nothing unless you pass --out.

  python src/cost_tracking.py --run-name dev_flash_lite_v1                       (cost unavailable, tokens shown)
  python src/cost_tracking.py --run-name dev_flash_lite_v1 --pricing-file my_pricing.json
"""
import os
import sys
import json
import argparse

PRICING_REQUIRED = ["currency", "per_million_input_tokens", "per_million_output_tokens", "thinking_tokens_billed_as", "source", "as_of"]
UNAVAILABLE_REASON = ("No pricing file was given. No price is assumed. Pass --pricing-file with the exact prices, source and date.")


class PricingError(ValueError):
    pass


def validate_pricing(pricing):
    if not isinstance(pricing, dict):
        raise PricingError("the pricing file must hold one JSON object")
    missing = [k for k in PRICING_REQUIRED if pricing.get(k) in (None, "")]
    if missing:
        raise PricingError("pricing file is missing or has empty values for: " + ", ".join(missing))
    if pricing["thinking_tokens_billed_as"] not in ("output", "input", "not_billed"):
        raise PricingError("thinking_tokens_billed_as must be output, input or not_billed")
    for k in ("per_million_input_tokens", "per_million_output_tokens"):
        value = pricing[k]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise PricingError(k + " must be a number of zero or more")
    return pricing


def load_pricing(path):
    """Read and validate a pricing file. Returns None when path is None (cost then stays unavailable)."""
    if path is None:
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            pricing = json.load(f)
        except ValueError as error:
            raise PricingError("the pricing file is not valid JSON: " + str(error))
    return validate_pricing(pricing)


def token_totals(records):
    """Sum token counts over run records (the latest record per alert). Alerts without token counts are counted apart."""
    totals = {"prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None,
              "alerts_with_token_counts": 0, "alerts_without_token_counts": 0}
    for record in records:
        counted = record.get("total_tokens") is not None or record.get("prompt_tokens") is not None
        if counted:
            totals["alerts_with_token_counts"] += 1
        else:
            totals["alerts_without_token_counts"] += 1
        for key in ("prompt_tokens", "output_tokens", "thinking_tokens", "total_tokens"):
            value = record.get(key)
            if value is not None:
                totals[key] = (totals[key] or 0) + value
    return totals


def cost(tokens, pricing=None):
    """Same result shape as the Day 4 evaluator's cost block."""
    if pricing is None:
        return {"available": False, "reason": UNAVAILABLE_REASON}
    validate_pricing(pricing)
    p_in = tokens.get("prompt_tokens") or 0
    p_out = tokens.get("output_tokens") or 0
    thinking = tokens.get("thinking_tokens") or 0
    billed = pricing["thinking_tokens_billed_as"]
    in_tokens = p_in + (thinking if billed == "input" else 0)
    out_tokens = p_out + (thinking if billed == "output" else 0)
    input_cost = in_tokens / 1e6 * pricing["per_million_input_tokens"]
    output_cost = out_tokens / 1e6 * pricing["per_million_output_tokens"]
    total = input_cost + output_cost
    n = tokens.get("alerts_with_token_counts") or 0
    return {"available": True, "currency": pricing["currency"], "input_cost": input_cost, "output_cost": output_cost, "total": total,
            "per_alert_mean": total / max(1, n), "input_tokens_billed": in_tokens, "output_tokens_billed": out_tokens,
            "pricing": pricing,
            "note": "Counts only the alerts that have token counts (" + str(n) + "). Alerts whose calls all failed have none."}


def cost_for_run(records, pricing=None):
    latest = {}
    for record in records:
        latest[record["alert_id"]] = record
    tokens = token_totals(list(latest.values()))
    return {"tokens": tokens, "cost": cost(tokens, pricing)}


def read_results(run_dir):
    path = os.path.join(run_dir, "results.jsonl")
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def render(summary, run_name):
    t, c = summary["tokens"], summary["cost"]
    lines = ["Run " + run_name,
             "alerts with token counts: " + str(t["alerts_with_token_counts"]) + ", without: " + str(t["alerts_without_token_counts"]),
             "prompt tokens: " + str(t["prompt_tokens"]) + ", output tokens: " + str(t["output_tokens"]) + ", thinking tokens: "
             + str(t["thinking_tokens"]) + ", total tokens: " + str(t["total_tokens"])]
    if not c["available"]:
        lines.append("Cost: unavailable. " + c["reason"])
    else:
        p = c["pricing"]
        lines.append("Cost: " + format(c["total"], ".6f") + " " + c["currency"] + " (input " + format(c["input_cost"], ".6f") + ", output "
                     + format(c["output_cost"], ".6f") + "); per alert " + format(c["per_alert_mean"], ".8f"))
        lines.append("Prices used: input " + str(p["per_million_input_tokens"]) + " and output " + str(p["per_million_output_tokens"])
                     + " per million tokens, thinking tokens billed as " + p["thinking_tokens_billed_as"] + ". Source: " + str(p["source"])
                     + ", as of " + str(p["as_of"]) + ".")
        lines.append(c["note"])
    return "\n".join(lines)


def main(argv=None):
    import config
    default_root = os.path.join(config.PROJECT_ROOT, "runs", "week2_baseline_v1")
    parser = argparse.ArgumentParser(description="Token and cost summary of a finished run. Read-only.")
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--runs-dir", default=default_root)
    parser.add_argument("--pricing-file", default=None, help="JSON with the exact prices, source and date; without it cost is unavailable")
    parser.add_argument("--out", default=None, help="optional: also write the summary as JSON to this path (give a path outside runs/)")
    args = parser.parse_args(argv)
    run_dir = os.path.join(args.runs_dir, args.run_name)
    try:
        pricing = load_pricing(args.pricing_file)
        summary = cost_for_run(read_results(run_dir), pricing)
    except (PricingError, OSError) as error:
        print("STOPPED: " + str(error))
        return 1
    print(render(summary, args.run_name))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent="  ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
