# Week 5 Backend Phase — Report

**Report updated:** 2026-10-20

This report reflects the Week 5 package as applied to the local repository, the subsequent RR-1 mitigation, and the test results recorded during local verification. It does not claim a production deployment, a live Gemini evaluation, or a protected-data evaluation.

## 1. Status at a glance

| Day | Deliverable | State | How it was checked |
|---|---|---|---|
| 1 | Async ingestion, PostgreSQL-backed job queue, authenticated ingest, job status, idempotency, bounded retries and timeouts, health/readiness, Week 4 graph in workers | Built and tested | Week 5 and regression tests; local service health/readiness checks |
| 2 | Load testing with a fake model (JSON, CSV, Markdown; percentiles; queue wait vs processing; no invented tokens or cost) | Built and tested | Unit tests and saved sample runs; load-test figures remain simulated-model results, not production performance claims |
| 3 | Prompt-injection suite, defences and audit events | Built and tested | 61 payloads; zero succeeded; all nine security gates passed after the Week 5 evidence safeguards |
| 4 | Docker Compose stack: API, Celery worker, sweeper, Redis and PostgreSQL | Locally built and running | Local Docker services were reported healthy; `/health/ready` returned `status=ok`, with database and broker healthy |
| 5 | Final-evaluation tooling: raw detector vs single-LLM baseline vs full system, three runs each, protected-data gate | Built; synthetic rehearsal tested | Rehearsal and evaluation-tool tests passed. A real Gemini evaluation and protected-set evaluation remain unverified |
| 6 | Hardening tests, documentation, manifest with SHA-256, verification record and release verifier | Built and tested | Week 5 and full regression suites passed; final documentation is being updated |

## 2. What the package contains

The Week 5 package originally supplied 143 files. The repository also contains earlier project work and user-created files. Do not interpret this as a claim that the repository currently contains only those files or that no existing file has changed.

Week 5 files are primarily under `src/week5/`, `tests/test_week5_*.py`, `tests/week5_support.py`, `tests/week5_matrix.py`, `docs/`, and `docker/`, along with root-level files such as `Dockerfile.week5`, `docker-compose.week5.yml`, `.dockerignore`, `requirements-week5.txt`, `requirements-week5-dev.txt`, and `.env.week5.example`.

Existing Week 1–4 work and unrelated local changes must be preserved. No reset, clean, checkout, or destructive cleanup should be used as part of this report update.

## 3. Reliability and security checks

The Week 5 requirement matrix is maintained in `tests/week5_matrix.py`. `tests.test_week5_hardening` checks that the required tests remain present.

| ID | Requirement | Tests |
|---|---|---:|
| R01 | Malformed request bodies | 8 |
| R02 | Authentication and authorization boundaries | 10 |
| R03 | Duplicate ingestion | 9 |
| R04 | Queue retries and retry exhaustion | 8 |
| R05 | Worker interruption and recovery | 10 |
| R06 | Database failures | 9 |
| R07 | Invalid model output | 6 |
| R08 | Timeout behavior | 6 |
| R09 | Rate limiting and bounded admission | 8 |
| R10 | Audit logging | 10 |
| R11 | Approval enforcement | 6 |
| R12 | Secret redaction | 13 |
| R13 | Configuration errors | 12 |
| R14 | Health-check accuracy | 9 |
| R15 | Week 4 behaviour regression | 12 |

Week 4 behaviour is pinned by characterisation tests covering policy decisions, the locked policy hash, the route table, approval roles, final decisions, simulated-only execution, the audit chain and tamper detection, and the memory-label allow-list. These tests record current behaviour; they do not establish that every existing policy decision is ideal.

## 4. Test results

### Final observed test runs

| Suite | Result | Status |
|---|---|---|
| Focused Week 5 runner tests | 8 tests passed | PASS |
| Week 5 suite | 416 tests, 42 skipped | PASS |
| Full project regression suite | 1,863 tests, 110 skipped | PASS |
| Full prompt-injection suite | 61 payloads; zero succeeded; all nine gates passed | PASS |
| PI-E02 targeted rerun | Attack objective not achieved; routed to review by the evidence safeguard | PASS for the targeted mitigation check |

Skipped tests are not counted as passed tests. Their reasons depend on the individual test and environment. Review the current test output for the exact skip reasons rather than relying on an older package report.

The full regression run completed successfully after the RR-1 changes. The results establish that the tested suite passed in the local environment; they do not substitute for tests against every production dependency or a real model.

### Commands used for verification

Run from the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "src;."

python -m unittest tests.test_week5_runner -v

python -m unittest discover -s tests -t . -p "test_week5_*.py"

python -m unittest discover -s tests -t .
```

The full regression suite can take several minutes. Preserve the complete output when preparing the release record.

## 5. Security findings — prompt injection

The detailed threat model, payloads, gates, defences and residual risks are documented in `docs/WEEK5_SECURITY.md`.

The final scripted worst-case fake-model run recorded:

| Outcome | Count |
|---|---:|
| Payloads | 61 |
| Adversarial payloads | 49 |
| Benign controls | 12 |
| Blocked at intake | 29 |
| Neutralised | 19 |
| Fail-closed parse | 1 |
| Succeeded | 0 |
| Infrastructure failures | 0 |

All nine security gates passed. The observed false-block rate was 0, benign control fidelity was 1.0, echo and leak counts were 0, and audit coverage was 34/34.

### RR-1 mitigation

PI-E02 originally demonstrated a residual risk: a clean benign model reply on a low-score alert could trigger Week 4 rule R9 and auto-close the alert despite independent traffic evidence.

A Week 5-only evidence safeguard was implemented after the normal routing decision:

- If specialist beacon analysis explicitly identifies a beacon candidate, a would-be `auto_close` becomes `needs_review`.
- If successful traffic analysis reports source activity across at least 20 distinct destination ports, a would-be `auto_close` becomes `needs_review`.
- The safeguard sets the risk level to `unknown`, clears proposed actions, and records a reason for human review.
- Existing decisions other than `auto_close` are left unchanged.

The final injection rerun neutralised PI-E02. It is no longer counted as a successful attack in the final results.

This is a conservative review trigger, **not proof of malicious activity**. The 20-port threshold is an implementation choice, not a universally validated threshold. The safeguard does not eliminate every compromised-model risk: clean benign output without matching specialist evidence may still be incorrectly trusted by the existing Week 4 rule.

Other limitations remain, including specialist-tool statements reaching the model verbatim and authentication/authorization denials not being written to the tamper-evident audit chain. See `docs/WEEK5_SECURITY.md` for the full discussion.

## 6. Load-test findings

The saved load-test runs under `docs/loadtest/sample_runs/` use simulated model behaviour.

The recorded examples include:

- Closed-loop run: 300 of 300 jobs succeeded.
- Open-loop run: 40 alerts/second offered with two workers; 24 alerts/second completed, with backlog peaking at 78.
- Failure-mix run: 14 retries, 9 failed jobs and 20 duplicates recognised.

These are controlled test results, not production throughput or availability guarantees. No token or cost figures are claimed where the provider did not report them. Repeat testing on the target deployment environment before making capacity commitments.

## 7. Evaluation tooling and protected-data gate

The final-evaluation tooling compares three configurations: the raw detector, the single-LLM baseline and the full system. It supports three recorded runs per configuration and validates run consistency before reporting metrics.

The protected-data gate is designed to fail closed and requires the documented unlock setting, a valid authorisation file bound to the exact plan hash, an allowed run key, and an explicit acknowledgement flag. The ledger entry is written before protected data is read.

The evaluation rehearsal and associated tests use synthetic data and fake models. **No claim is made that the protected evaluation set was opened, scored or evaluated.** Real Gemini calls, live evaluation backends and the final protected-set evaluation remain separate tasks requiring explicit authorisation.

Run the safe synthetic rehearsal with:

```powershell
$env:PYTHONPATH = "src;."
python -m week5.evalrun rehearse --out-root runs_tmp\evalrun_rehearsal
```

Do not launch a protected-set evaluation merely to verify that the tooling works.

## 8. Deployment status

The local Docker Compose stack was built and started during verification. The API, worker, sweeper, Redis and PostgreSQL services were reported healthy. The API readiness endpoint returned an OK status and reported both the database and broker as healthy.

This confirms a local stack check, not a production deployment.

Check the current state before relying on it:

```powershell
docker compose -f docker-compose.week5.yml ps

Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

Do not paste secrets or bearer tokens into reports or chat. Keep real environment files out of source control and use `.env.week5.example` only as a template.

## 9. Not verified

The following must not be represented as completed unless supported by new recorded evidence:

- Real Gemini behaviour and real-model prompt-injection resistance.
- The final protected-set evaluation.
- Real token usage and cost figures from provider responses.
- Production deployment, production security posture, TLS termination and production-scale capacity.
- Equivalence with a real LangGraph runtime if the final test run used an instrumented or offline engine.
- Any live evaluation path that has not been exercised in the current environment.
- Verification commands that were run only against synthetic repository trees rather than the actual target files.

The local Docker readiness check does not prove all of these items.

## 10. Blocked or awaiting decisions

Before the final evaluation plan is hashed, decide:

1. Whether memory is on or off for the full-system configuration.
2. Whether identifier aliasing is on or off during evaluation.
3. Which model and generation settings will be used, and whether the live dev-set dry run is authorised.
4. Whether a pricing record is available if cost metrics are required.
5. Which queue backend is intended for the evaluation and deployment environment.

The RR-1 evidence safeguard is implemented and tested for PI-E02; the decision is no longer whether to implement that safeguard. Any subsequent policy change should be documented and retested before freezing the evaluation plan.

The React UI is not covered by the Week 5 backend verification.

## 11. Known limitations

- At-least-once job delivery means handlers must remain idempotent.
- RR-1 is mitigated for the tested scenario, but clean benign model output without matching specialist evidence can still be unsafe.
- Specialist-tool statements reach the model verbatim; this depends on their current structured/template-based construction.
- Authentication and authorization denials (401/403) are not written to the tamper-evident audit chain.
- Single-node assumptions may not hold under multi-instance production deployment.
- TLS and external ingress security must be provided by the deployment environment where required.
- Container images should be pinned and reviewed according to the intended release policy.
- Scripted-model security tests do not establish real-model attack success probabilities.
- Synthetic evaluation rehearsals do not establish model quality on the protected dataset.

## 12. Actions intentionally left unexecuted

The following actions are outside the claims made by this report unless separately authorised and recorded:

- Committing, tagging or pushing changes.
- Resetting, cleaning or checking out files in a way that could overwrite existing work.
- Making real model calls or spending provider credits.
- Opening or scoring the protected evaluation set.
- Creating or exposing production credentials.
- Running migrations against a production database.
- Deploying the stack to production.
- Claiming production readiness solely from local tests.

Preserve unrelated user changes and generated evidence artifacts.

## 13. Reproduction and evidence

Use the repository's current Week 5 test files and security documentation as the primary reproducibility record.

Relevant files:

- `docs/WEEK5_SECURITY.md`
- `docs/WEEK5_DEPLOYMENT.md`
- `docs/WEEK5_FINAL_EVALUATION.md`
- `docs/WEEK5_LOAD_TESTING.md`
- `docs/WEEK5_BACKEND.md`
- `tests/test_week5_runner.py`
- `tests/test_week5_injection.py`

Record the command, environment, date, exit code and complete test output for each release verification. Distinguish local checks, synthetic rehearsals, live-model tests and protected-data evaluations in all subsequent reports.
