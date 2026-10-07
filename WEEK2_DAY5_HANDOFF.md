# Week 2, Day 5 handoff: cost tracking, metadata-only tracing, prompt registry, prompts v2 and v3

Status: code and tests are written. **No Gemini call was made, no 300-alert run was made, and the Day 3 run was not touched.**
Everything below that says "later" is for the next step, after you have reviewed this.

## What was added or changed

| File | New or changed | What it is |
|---|---|---|
| `src/prompt_registry.py` | new | Registers `baseline_v1`, `baseline_v2`, `baseline_v3` with version, system prompt, user template and SHA-256 |
| `src/cost_tracking.py` | new | Token and cost summary from a pricing file you supply; no price is built in |
| `src/langsmith_tracing.py` | new | Optional, metadata-only LangSmith tracing; off by default |
| `src/run_baseline_dev.py` | changed | `--prompt-version` and `--langsmith` options; everything else as in Day 3 |
| `tests/test_week2_day5.py` | new | 76 tests |
| `pricing.template.json` | new | Empty template for the pricing file (all prices `null`) |
| `WEEK2_DAY5_HANDOFF.md` | new | This file |

Not changed: `baseline_prompt.py` (so `baseline_v1` is the same text), `gemini_client.py`, `baseline_store.py`, the verdict schema and parser,
Week 1 files, the Day 3 run, the Day 4 evaluator.

## Prompt hashes

The hash is `sha256(version + "\n" + system prompt + "\n----\n" + user template)`, the same formula Day 3 used.

| Version | SHA-256 |
|---|---|
| baseline_v1 | `0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172` (unchanged, pinned by tests) |
| baseline_v2 | `2b9a14acb3e281db0d9e23ec636e6fa1761004f1592acf3cc0ca02fb4793aa46` |
| baseline_v3 | `9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7` |

Run `python src/run_baseline_dev.py --dry-run --prompt-version baseline_v3 --limit 3` to print the exact system prompt and the first user prompt.
A dry run calls nothing and writes nothing.

**Lock rule.** After the 3-alert smoke runs, these hashes are the ones used for the 300-alert runs. If a prompt is edited after that, it is a different
prompt: it gets a new hash and the handoff and run records must say so. Only v2 and v3 exist; no other variant is added.

## v2: output contract (targets the extra-field failures)

v2 is the v1 text plus an "OUTPUT CONTRACT" block at the end. The classification wording, the attack classes, the severities and the field rules are
unchanged, so a difference between v1 and v2 is a difference in output-format wording only. The block says: one JSON object only, exactly the five keys and
no others, any other key makes the reply invalid, no MITRE tactic/name/url/version/metadata keys, no alert or context fields copied into new keys, the technique
id only in `mitre_technique`, explanations only in `evidence` (under 400 characters, inside the 600-character schema limit), no markdown fences, no text
before or after, no second object. It ends with one structural example that holds placeholders only (no class, no technique id, no digits). The user template
gets a short matching instruction.

What v2 can and cannot be expected to fix: the Day 3 audit showed final failures with `finish_reason=STOP`, with extra keys that are mostly MITRE metadata
or copies of alert fields. v2 targets exactly that. The audit did not show what the 14 invalid-JSON failures look like, so v2 is not designed around them.

## v3: v2 plus general class and MITRE guidance (targets the classification confusions)

v3 is the v1 text, then a "GUIDANCE ON THE ATTACK CLASSES" block, then the same output-contract block as v2. The guidance describes all 12 classes (including
BENIGN) in general terms from public attack characteristics, and says how to choose: a flow to a web port is not by itself a DoS; separate floods from slow
attacks first; slowloris and Slowhttptest look alike and how to tell them apart; Bot is beaconing and not a port sweep; do not choose a class because the name
is familiar.

MITRE guidance is conceptual only: it explains network DoS (T1498) versus endpoint DoS (T1499), says to choose the technique that matches the behavior in the
flow and not the class name, and says to use a sub-technique id when one clearly fits. There is **no class-to-technique table**, no evaluation mapping, and no
dev alert value anywhere in the prompt (tests check this).

One contract point: the verdict schema requires a technique id for every attack class and allows `NONE` only for BENIGN. So the guidance does not say "use NONE
when evidence is missing" for a malicious flow. It says to use NONE only with BENIGN, and that if no technique fits, the flow may be benign and should be
reconsidered.

Expected risks (to check in the evaluation, not assumed): class descriptions can move false-positive reduction in either direction, can create a new
"sink" class, and may not help classes that flow features cannot separate. Compare attack misses next to false-positive reduction.

## Runner

```
python src/run_baseline_dev.py ...                              # baseline_v1, as in Day 3
python src/run_baseline_dev.py --prompt-version baseline_v2 ... # selects v2
python src/run_baseline_dev.py --prompt-version baseline_v3 ... # selects v3
```

- Default is `baseline_v1`. With `--resume`, the run keeps the version it started with; passing a different version is refused.
- `run_meta.json` and every result record carry the prompt version and hash. `prompt_snapshot.txt` holds the selected prompt (v1 keeps the Day 3 format).
- Retry, parser, storage, rate limit and guard behavior are unchanged. A new run refuses an existing run folder name, so the Day 3 run cannot be overwritten.
- New runs go to `runs/week2_baseline_v1/<run-name>` like Day 3, so `evaluate.py --run-name <name>` finds them. Use new run names.

## Cost tracking

No price is in the code. Copy `pricing.template.json` to `pricing.json` (keep it out of git), and fill in the exact prices, where you read them and the date.
Without a file, cost is reported as unavailable.

```
python src/cost_tracking.py --run-name dev_flash_lite_v1                              # tokens, cost unavailable
python src/cost_tracking.py --run-name dev_flash_lite_v1 --pricing-file pricing.json  # cost from your prices
```

It reads `results.jsonl` only (read-only) and uses the same pricing keys and arithmetic as the Day 4 evaluator, so `evaluate.py --pricing-file pricing.json`
gives the same number. Retries are included because the stored token counts are summed over every call.

## LangSmith tracing (metadata only, optional)

Off unless you pass `--langsmith`. When off, the runner gets a no-op tracer and the langsmith package is never imported.

```
set LANGSMITH_API_KEY=...        (PowerShell: $env:LANGSMITH_API_KEY="...")   # never put it in a file
set LANGSMITH_PROJECT=soc-triage-week2                                        # optional
pip install langsmith                                                         # only when you use --langsmith
python src/run_baseline_dev.py --prompt-version baseline_v2 --limit 3 --run-name d5_smoke3_baseline_v2 --langsmith
```

Sent: run name, alert id, prompt version and hash, model, session, attempt number, latency, token counts, finish reason, parse status, error code, status,
and the dev marker. Never sent: alert or flow values, prompt text, model replies, error details, labels, the MITRE key, anything from the frozen set. Every
payload is checked against an allowlist and a payload with any other key or a content-shaped value is refused. A tracing error is counted and printed and the
run goes on; the local `raw_responses.jsonl` stays the source of truth. `run_meta.json` records whether tracing was on and how many errors there were.

**Not verified here:** the sandbox has no network and no langsmith package, so the real client call was tested only against a fake client with the same
`create_run` shape. Use the 3-alert smoke run with `--langsmith` to check it against your installed langsmith version before any 300-alert run. If it errors,
the run still completes and the error count shows it.

## Exact commands for later (do NOT run yet)

Dry runs (no calls, no files; safe once you have reviewed the prompts):
```
python src/run_baseline_dev.py --dry-run --prompt-version baseline_v2 --limit 3
python src/run_baseline_dev.py --dry-run --prompt-version baseline_v3 --limit 3
```
3-alert smoke runs (real Gemini calls, dev only):
```
python src/run_baseline_dev.py --prompt-version baseline_v2 --limit 3 --run-name d5_smoke3_baseline_v2
python src/run_baseline_dev.py --prompt-version baseline_v3 --limit 3 --run-name d5_smoke3_baseline_v3
```
One 300-alert dev run each (real calls; Day 3 used about 412 calls and 466,071 tokens for v1; v3 prompts are longer, so expect more tokens):
```
python src/run_baseline_dev.py --prompt-version baseline_v2 --run-name dev_flash_lite_v2
python src/run_baseline_dev.py --prompt-version baseline_v3 --run-name dev_flash_lite_v3
```
Evaluation of each full run (read-only on the run; no `--exclude-latency-seconds` unless a recorded latency really needs it):
```
python src/evaluate.py --run-name dev_flash_lite_v2
python src/evaluate.py --run-name dev_flash_lite_v3
```

## What must NOT be run yet

- No 300-alert v2 or v3 run, and no smoke run, until you approve.
- Nothing on the frozen set. Nothing reads labels or the answer key except the Day 4 evaluator, as before.
- Do not edit `baseline_prompt.py`, the Day 3 run folder, or Week 1 files. Do not reuse the name `dev_flash_lite_v1`.
- Do not claim v2 or v3 is better until the evaluation shows it, with the same denominators as Day 4 and attack misses reported next to false-positive reduction.

## Tests

```
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 -v
```
The Day 5 file has 76 tests: v1 hash pinned; v2/v3 resolve; hashes deterministic; the v2 contract wording, placeholder-only example and the unchanged
classification text; v3 class guidance, no dev values, no class-to-technique table; the runner defaults to v1 and selects v2 and v3, records version and hash,
resumes with its own version and refuses a changed one; tracing off, tracing on with metadata only, tracing errors contained; pricing unavailable, pricing file
calculation, the match with the Day 4 evaluator, no price in the source; no label, answer-key, frozen, key or network import in the new modules.

Note on a Day 3 test: it forbids importing `langsmith` in the Day 3 modules. The runner imports `langsmith_tracing` (a separate module), which imports the
langsmith package only inside a function, so that test still holds.

## Next step

Review the two prompts (use the dry runs), then DEV smoke tests for v2 and v3, then one full DEV run each, then evaluation and comparison with v1.
