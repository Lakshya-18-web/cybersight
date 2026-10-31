"""The evaluation plan: one JSON file that fixes, BEFORE any run, which set, which model, which settings and which three configurations are compared.

Why a plan: the comparison is only meaningful if the raw detector, the single-LLM baseline and the full system are scored on the same records, with the same label definitions, and (for the two model-based
configurations) the same model and generation settings. Writing that down first, hashing it, and binding the protected-set authorisation to its hash means none of it can drift between runs unnoticed.
The model and generation settings are stored ONCE (plan["model"]) and shared by both model-based configurations, so they cannot differ by construction. validate.py still checks every run's recorded settings against them.
"""
import hashlib

from . import CONFIGS, RUNS_PER_CONFIG, SCHEMA_PLAN
from .data import SET_NAMES, canonical

FAKE_PREFIX = "FAKE"


def plan_sha256(plan):
    return hashlib.sha256(canonical(plan).encode("utf-8")).hexdigest()


def run_key(config, index):
    return "%s/run%d" % (config, index)


def run_keys(plan):
    return [run_key(c, i) for c in CONFIGS for i in range(1, plan["runs_per_config"] + 1)]


def project_defaults():
    """Read the existing project settings (Week 1 threshold, Week 2 model and generation settings, prompt version, Week 4 policy hash). Raises RuntimeError naming what is missing."""
    try:
        import config
        import llm_config
        import prompt_registry
        import run_baseline_dev as rb
        from week4 import policy as policy_module, VERSION as W4
    except Exception as error:
        raise RuntimeError("cannot read the project settings (%s); create the plan from a checkout that has the Week 2 files" % type(error).__name__)
    sizes = llm_config.models()
    pol = policy_module.load_policy(None)
    from week5 import evidence_policy
    _, combined_sha = evidence_policy.combined_identity(pol, evidence_policy.load())          # the identity the runner stamps on every routing decision (risk policy + evidence policy)
    return {
        "threshold": config.ACCEPTED_THRESHOLD,
        "model": {"name": str(sizes["small"]), "fake": False, "temperature": llm_config.TEMPERATURE, "max_output_tokens": llm_config.MAX_OUTPUT_TOKENS, "seed": rb.GENERATION_SEED,
                  "parse_retries": llm_config.MAX_RETRIES},
        "baseline_prompt_version": prompt_registry.DEFAULT_VERSION,
        "policy_sha256": combined_sha,
        "week4_version": W4,
    }


def rehearsal_defaults():
    from week4 import policy as policy_module
    from week5 import evidence_policy
    return {"threshold": 0.00459436746314168, "model": {"name": "FAKE:rehearsal", "fake": True, "temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2},
            "baseline_prompt_version": "baseline_v1", "policy_sha256": evidence_policy.combined_identity(policy_module.load_policy(None), evidence_policy.load())[1], "week4_version": "n/a"}


def make_plan(plan_id, set_name="fixture", defaults=None, memory="off", alias_ids=False, engine="langgraph", pricing=None, notes=()):
    if set_name not in SET_NAMES:
        raise ValueError("set must be one of " + ", ".join(SET_NAMES))
    d = defaults or (rehearsal_defaults() if set_name == "fixture" else project_defaults())
    plan = {
        "schema": SCHEMA_PLAN, "plan_id": plan_id, "set": set_name, "runs_per_config": RUNS_PER_CONFIG, "threshold": d["threshold"], "model": d["model"],
        "configs": {
            "raw_detector": {"uses_model": False, "decision": "every alert is a detector alert, so the raw detector's decision on every alert is 'malicious' (Week 2 definition)"},
            "single_llm_baseline": {"uses_model": True, "prompt_version": d["baseline_prompt_version"]},
            "full_system": {"uses_model": True, "memory": memory, "alias_ids": bool(alias_ids), "engine": engine, "policy_sha256": d.get("policy_sha256"), "week4_version": d.get("week4_version")},
        },
        "pricing": pricing,
        "notes": list(notes),
    }
    problems = validate_plan(plan)
    if problems:
        raise ValueError("invalid plan: " + "; ".join(problems))
    return plan


def validate_plan(plan):
    problems = []
    if not isinstance(plan, dict) or plan.get("schema") != SCHEMA_PLAN:
        return ["not a %s file" % SCHEMA_PLAN]
    if plan.get("set") not in SET_NAMES:
        problems.append("set must be one of " + ", ".join(SET_NAMES))
    if plan.get("runs_per_config") != RUNS_PER_CONFIG:
        problems.append("runs_per_config must be %d (three independently recorded runs per configuration)" % RUNS_PER_CONFIG)
    if set(plan.get("configs", {})) != set(CONFIGS):
        problems.append("configs must be exactly " + ", ".join(CONFIGS))
    model = plan.get("model") or {}
    for key in ("name", "fake", "temperature", "max_output_tokens", "seed", "parse_retries"):
        if key not in model:
            problems.append("model.%s is missing" % key)
    if model.get("name") is not None and bool(model.get("fake")) != str(model.get("name")).startswith(FAKE_PREFIX):
        problems.append("model.fake and the model name disagree (a fake model's name starts with FAKE)")
    if plan.get("set") in ("dev", "frozen") and model.get("fake"):
        problems.append("a %s plan cannot use a fake model" % plan.get("set"))
    if plan.get("set") == "fixture" and not model.get("fake"):
        problems.append("a fixture plan must use the fake model (the fixture is synthetic; a real model would spend money on meaningless data)")
    if not isinstance(plan.get("threshold"), (int, float)):
        problems.append("threshold must be a number")
    full = (plan.get("configs") or {}).get("full_system") or {}
    if full.get("memory") not in ("off", "on"):
        problems.append("full_system.memory must be off or on")
    if full.get("engine") not in ("langgraph", "instrumented"):
        problems.append("full_system.engine must be langgraph or instrumented")
    if plan.get("set") == "frozen" and full.get("engine") != "langgraph":
        problems.append("the frozen evaluation must use the langgraph engine (the one the project's graph is defined for)")
    return problems
