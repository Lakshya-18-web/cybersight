# Week 2, Day 1 hand-off

Blueprint Day 1: pick the LLM provider and models (one small, one stronger), keys in `.env`, a loader that reads alerts and labels from separate files. Output: config for models, alert and label loaders.

## What was done

- Provider and two models set in `src/llm_config.py` (not yet called).
- The fixed triage-output contract, `src/triage_schema.py` (seven fields, 12 attack types, consistency rules).
- Label-free alert loader with flow context, `src/triage_inputs.py`. Dev set only.
- Separate harness-only label loader, `src/eval_labels.py`. Dev labels only.
- `.env.example`, `requirements-week2.txt`, and tests in `tests/test_week2_day1.py`.

No LLM or API call was made. Nothing from Week 1 was modified: no frozen artifact, threshold, detector, split or evaluation-set file. The frozen set was not opened and is not reachable from the new modules.

## Files in this package

| path | role |
|---|---|
| `src/triage_schema.py` | Pydantic output contract (`TriageVerdict`) |
| `src/llm_config.py` | provider, model ids, shared run settings, `.env` loading (never prints the key) |
| `src/triage_inputs.py` | agent side: dev alerts + dev flow store -> model input dict. Rejects answer-bearing columns |
| `src/eval_labels.py` | harness only: dev labels and the answer key. Never import from agent code |
| `tests/test_week2_day1.py` | 18 checks, no network |
| `.env.example` | template for the key (copy to `.env`) |
| `requirements-week2.txt` | pydantic, python-dotenv, google-genai |
| `WEEK2_DAY1_HANDOFF.md` | this file |

Existing files are not overwritten. It adds only new paths (check with `unzip -l` before extracting if you want to be sure).

## Decisions for you to confirm

1. Provider: Google Gemini (current `google-genai` SDK). Small model `gemini-2.5-flash-lite`, stronger model `gemini-2.5-pro`. Change them with `SOC_SMALL_MODEL` / `SOC_STRONG_MODEL` in `.env`, or in `llm_config.py`.
   Note: if you use Gemini's free tier, expect rate limits (the Day 3 runner will need throttling and retries), and check Google's terms on prompt use. Model ids are not verified against your account here; if a call later reports an unknown model, correct the id in `.env`.
2. Output format: you asked for `verdict / attack_type / mitre_technique / confidence / reasoning / recommended_action`. The blueprint's Day 2 says `is_malicious, attack type, MITRE technique, severity, evidence`. The evaluation harness on Day 4 will map one to the other; if you prefer the blueprint names, edit `triage_schema.py` before Day 2.
3. The model sees `detector_score` and the Day 5 display features that are in the alert file, plus a count-based context (flows from the same source IP, distinct destination ports and IPs, within +/- 5 minutes). Nothing else.

## Validation performed

- `python -m unittest tests.test_week2_day1 -v`: schema accepts valid outputs and rejects 11 bad ones; label columns are rejected; the label column never reaches the model input; an AST check shows the agent-side modules do not import or reference labels, the answer key or the frozen paths; no key-like string in the sources.
- `RealDevTests` runs only if `eval/dev_alerts.parquet` and `eval/flow_store_dev.parquet` exist. It reads those two dev files and no label file.
- Not done: any real API call, and the real-data test on your actual files (run it yourself, see below).

## Install

```
unzip week2-day1-files.zip           # from the repo root
printf '\n.env\n' >> .gitignore      # keep the key out of git
cp .env.example .env                 # then add GEMINI_API_KEY (do not paste it in chat)
pip install -r requirements-week2.txt
python -m unittest tests.test_week2_day1 -v
python src/llm_config.py             # prints models and whether a key is present, never the key
```

## Exact next step (do not start before you approve)

Week 2 Day 2: finalise the verdict format and write the parser with validation and retries (`src/triage_parser.py` plus tests): take raw model text, extract JSON, validate it with `TriageVerdict`, retry up to `MAX_RETRIES` with the validation error, and count malformed outputs for the Day 4 report. Tests will use canned strings; still no API call.
