"""Orchestration: build data for a plan, collect runs, validate, score, report. The three data sources:
  fixture  synthetic, in memory, fake models. The default for everything. Needs no file and no key.
  dev      the DEV set through eval_io (free to load). A real model needs --live.
  frozen   ONLY through gate.open_frozen(); every protected load needs the authorisation file (docs/WEEK5_FINAL_EVALUATION.md). Nothing in this package launches a frozen run by itself.
"""
import os

from . import CONFIGS
from . import data as data_module, gate, plan as plan_module, rehearsal
from .collect import collect_run
from .metrics import compute_all
from .report import build_result, write_all
from .validate import validate_runs

ENV_ALLOW_LIVE = "WEEK5_ALLOW_LIVE_MODEL"


class PipelineError(Exception):
    pass


def ledger_path(out_root, plan):
    return os.path.join(out_root, plan["plan_id"], gate.LEDGER_NAME)


def load_data(plan, run_key, out_root, env=None, acknowledged=False, loader=None):
    """The ONE function that decides where evaluation data comes from."""
    if plan["set"] == "fixture":
        return data_module.fixture_data()
    if plan["set"] == "dev":
        import eval_io as io
        return data_module.EvalData("dev", io.load_alerts("dev"), io.load_labels("dev"), io.load_flow_store("dev"))
    return gate.open_frozen(plan, plan_module.plan_sha256(plan), run_key, ledger_path(out_root, plan), env=env, acknowledged=acknowledged, loader=loader)


def live_backends(plan, env=None):
    """Real model clients. Refused unless live calls were allowed explicitly; never reached by tests or by the rehearsal."""
    env = os.environ if env is None else env
    if plan["model"]["fake"]:
        raise PipelineError("the plan uses a fake model")
    if env.get(ENV_ALLOW_LIVE) != "1":
        raise PipelineError("a live-model run needs %s=1 (it spends money and quota); it was not set" % ENV_ALLOW_LIVE)
    import llm_config
    import prompt_registry
    import run_baseline_dev as rb
    from week5 import models, settings as settings_module
    spec = prompt_registry.get_prompt(plan["configs"]["single_llm_baseline"]["prompt_version"])
    client = rb.make_client_for(plan["model"]["name"], llm_config.get_api_key(), getattr(llm_config, "REQUEST_TIMEOUT_SECONDS", 60), spec)
    provider = models.GeminiModel(settings_module.Settings(model_mode="gemini", allow_live_model=True))
    return client, provider


def fake_backends(plan, data):
    ids = list(data.alerts["alert_id"])
    return rehearsal.ScriptedClient(rehearsal.baseline_script(len(ids))), rehearsal.full_system_provider(ids)


def collect_one(plan, config, index, out_root, live=False, env=None, acknowledged=False, loader=None, backends=None):
    key = plan_module.run_key(config, index)
    uses_model = plan["configs"][config]["uses_model"]
    if uses_model and backends is None and not plan["model"]["fake"]:
        if not live:       # refused BEFORE any data is loaded
            raise PipelineError("this plan names a real model; add --live to spend real calls (and set %s=1)" % ENV_ALLOW_LIVE)
        if (os.environ if env is None else env).get(ENV_ALLOW_LIVE) != "1":
            raise PipelineError("a live-model run needs %s=1 (it spends money and quota); it was not set" % ENV_ALLOW_LIVE)
    data = load_data(plan, key, out_root, env, acknowledged, loader)
    client = provider = None
    if uses_model:
        if backends is not None:
            client, provider = backends
        elif plan["model"]["fake"]:
            client, provider = fake_backends(plan, data)
        else:
            client, provider = live_backends(plan, env)
    return collect_run(plan, config, index, data, out_root, client=client, provider=provider)


def score(plan, out_root, env=None, acknowledged=False, loader=None, data=None):
    """Validate every run against the data and write the comparison. For the frozen set this opens the labels, so it needs its own authorised run key, 'score/all'."""
    data = data or load_data(plan, "score/all", out_root, env, acknowledged, loader)
    validation = validate_runs(plan, out_root, data)
    metrics = compute_all(plan, validation["runs"], data) if validation["valid"] else None
    result = build_result(plan, validation, metrics, data.hashes())
    out_dir = os.path.join(out_root, plan["plan_id"], "comparison")
    return result, write_all(result, out_dir), out_dir


def rehearse(out_root, plan_id="rehearsal", engine=None, n=24):
    """The whole pipeline on the synthetic fixture with fake models: 3 configurations x 3 runs, validation, metrics, report."""
    if engine is None:
        try:
            import langgraph  # noqa: F401
            engine = "langgraph"
        except ImportError:
            engine = "instrumented"
    plan = plan_module.make_plan(plan_id, "fixture", engine=engine, notes=["REHEARSAL on synthetic data with fake models"])
    data = data_module.fixture_data(n)
    for config in CONFIGS:
        for i in range(1, plan["runs_per_config"] + 1):
            client = provider = None
            if plan["configs"][config]["uses_model"]:
                client, provider = fake_backends(plan, data)
            collect_run(plan, config, i, data, out_root, client=client, provider=provider)
    return score(plan, out_root, data=data)
