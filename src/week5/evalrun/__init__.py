"""Week 5 final-evaluation tooling: raw detector vs single-LLM baseline vs full SOC-Triage system, three recorded runs each, with a fail-closed gate in front of the protected (frozen) set.

Nothing here runs by itself. The default data set is a SYNTHETIC FIXTURE and the default models are fakes: the numbers such a rehearsal produces are plumbing checks, never results.
The frozen evaluation set can be opened only through gate.py, which needs an explicit authorisation file bound to one exact plan (docs/WEEK5_FINAL_EVALUATION.md).
"""
SCHEMA_PLAN = "week5-evalrun-plan-v1"
SCHEMA_RUN_META = "week5-evalrun-run-meta-v1"
SCHEMA_RECORD = "week5-evalrun-record-v1"
SCHEMA_RESULTS = "week5-evalrun-comparison-v1"
CONFIGS = ("raw_detector", "single_llm_baseline", "full_system")
RUNS_PER_CONFIG = 3
