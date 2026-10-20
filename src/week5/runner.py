"""The graph runner: one job in, one case payload out. It runs the EXISTING Week 4 graph (graph v2), then the existing risk policy, then the existing case builder. There is no second analysis pipeline.

  job (from the job store)  ->  week4 graph (LangGraph, or the instrumented loop)  ->  response guard  ->  week4.policy.route_case  ->  week4.cases.build_case_payload  ->  RunOutcome

What is added around the Week 4 code, and nothing else: the model comes from a provider (fake or Gemini) instead of a run folder; the response guard (week5.security.guard) checks the model's one free-text field
and can only make routing more cautious; timings and token usage are collected for the load tester; a transient model outage on a non-final attempt is raised (so the job is retried) instead of being
stored as a verdict-less case, while on the final attempt the case is stored as the Week 4 runner would store it (verdict status model_error -> needs_review: fail closed).

Nothing here executes an action. The proposals in the payload are stored 'pending'; only the approval API can decide them, and no code path executes them (week4.approval.SimulatedExecutor only writes a row).
"""
import os
import time
from collections import namedtuple

import week4
from agents import verdict_node as VN
from tools import FlowStore, build_registry
from week4 import cases
from week4 import policy as policy_module
from week4.graph import build as B
from week4.graph import prompt as P2
from week4.graph.memory_node import make_memory_node
from week4.graph.verdict import make_verdict_node
from agents import verdict_prompt as VP

from . import engine, errors, models
from .security import guard

RunOutcome = namedtuple("RunOutcome", "payload summary timings usage signals fake")
Executed = namedtuple("Executed", "state routed signals caller node_timings graph_seconds verdict")
def apply_beacon_candidate_veto(routed, state):
    """Prevent auto-closing cases with specialist-identified beacon candidates.

    A candidate is a reason for human review, not proof of malicious activity.
    This Week 5 safeguard does not change the Week 4 policy.
    """
    beacon = state.get("beacon_findings")
    if not isinstance(beacon, dict) or beacon.get("beacon_candidate") is not True:
        return routed

    routing = routed.get("routing")
    if not isinstance(routing, dict) or routing.get("decision") != "auto_close":
        return routed

    # Copy the containers so the original routing result isn't mutated.
    result = dict(routed)
    result["routing"] = dict(routing)
    result["routing"]["decision"] = "needs_review"
    result["routing"]["risk_level"] = "unknown"
    result["routing"]["reasons"] = list(routing.get("reasons") or []) + [
        "W5-RR1 beacon_candidate_review: specialist evidence identified a beacon candidate; human review is required before closure"
    ]
    result["actions"] = []
    return result

def apply_scan_evidence_veto(routed, state):
    """Require human review when independent traffic findings show broad port scanning."""
    traffic = state.get("traffic_findings")
    if not isinstance(traffic, dict) or traffic.get("status") != "ok":
        return routed

    findings = traffic.get("findings")
    if not isinstance(findings, list):
        return routed

    broad_scan = any(
        isinstance(item, dict)
        and item.get("kind") == "source_activity"
        and isinstance(item.get("metrics"), dict)
        and isinstance(item["metrics"].get("distinct_destination_ports"), int)
        and not isinstance(item["metrics"].get("distinct_destination_ports"), bool)
        and item["metrics"]["distinct_destination_ports"] >= 20
        for item in findings
    )
    if not broad_scan:
        return routed

    routing = routed.get("routing")
    if not isinstance(routing, dict) or routing.get("decision") != "auto_close":
        return routed

    result = dict(routed)
    result["routing"] = dict(routing)
    result["routing"]["decision"] = "needs_review"
    result["routing"]["risk_level"] = "unknown"
    result["routing"]["reasons"] = list(routing.get("reasons") or []) + [
        "W5-RR1 scan_evidence_review: traffic analysis found activity across many destination ports; human review is required before closure"
    ]
    result["actions"] = []
    return result
RUN_NAME_PREFIX = "w5job-"
MAX_PARSE_RETRIES = 2           # llm_config.MAX_RETRIES, the Week 2/3/4 value; a test checks they agree


ALIAS_ALERT_PREFIX, ALIAS_FLOW_PREFIX = "ALERT-", "FLOW-"


def alias_for(prefix, value):
    """A stable opaque stand-in for a client-supplied identifier: prefix + 12 hex characters of a SHA-256. The same identifier always gets the same alias (a retry shows the model the same prompt)."""
    import hashlib
    return prefix + hashlib.sha256(("w5alias:" + str(value)).encode("utf-8")).hexdigest()[:12]


def aliased_alert(alert):
    """-> (alert for the model, {alias: original}). Only alert_id and flow_id are replaced; every other field is a number, an address or a timestamp, all validated by intake."""
    a, f = alias_for(ALIAS_ALERT_PREFIX, alert["alert_id"]), alias_for(ALIAS_FLOW_PREFIX, alert["flow_id"])
    return dict(alert, alert_id=a, flow_id=f), {a: alert["alert_id"], f: alert["flow_id"]}


def restore_ids(value, mapping):
    """A copy of value (dicts, lists, strings) with every alias replaced by its original identifier."""
    if isinstance(value, str):
        for alias, original in mapping.items():
            if alias in value:
                value = value.replace(alias, original)
        return value
    if isinstance(value, dict):
        return {k: restore_ids(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [restore_ids(v, mapping) for v in value]
    if isinstance(value, tuple):
        return tuple(restore_ids(v, mapping) for v in value)
    return value


def run_name_for(job_id):
    return RUN_NAME_PREFIX + str(job_id)


def spec_for(memory_enabled):
    return P2.get_prompt() if memory_enabled else VP.get_prompt()


def load_memory_store(settings):
    """-> (store, evidence). Fail closed: anything but a verified, train-only, dev-disjoint store raises (the caller records memory as unavailable)."""
    from week4 import seed_memory
    from week4.memory import isolation
    from week4.memory import store as MS
    loaded = MS.MemoryStore.load(settings.memory_dir, backend="numpy", build_index=False)
    evidence = isolation.check_run_isolation(loaded, seed_memory.dev_key_texts())
    return loaded, evidence


class GraphRunner:
    def __init__(self, settings, policy, registry, provider, memory_store=None, memory_error=None, clock=time.perf_counter, guard_secrets=()):
        self.settings, self.policy, self.registry, self.provider = settings, policy, registry, provider
        self.memory_store, self.memory_error = memory_store, memory_error
        self.clock = clock
        self.guard_secrets = tuple(guard_secrets)
        self.prompts = guard.default_prompts()

    @classmethod
    def from_settings(cls, settings, env=None, provider=None):
        env = os.environ if env is None else env
        policy = policy_module.load_policy(env.get("WEEK4_RISK_POLICY") or None)
        if settings.flow_store == "dev":
            flows = FlowStore.from_dev()
        elif settings.flow_store == "fixture":
            from . import fixtures
            flows = fixtures.flow_store()
        else:
            flows = None
        registry = build_registry(flow_store=flows)
        if provider is None:
            provider = models.FakeModel() if settings.model_mode == "fake" else models.GeminiModel(settings)
        store = error = None
        if settings.memory_dir:
            try:
                store, _ = load_memory_store(settings)
            except Exception as exc:   # the type name is kept; a memory-on job then fails closed
                error = type(exc).__name__
        return cls(settings, policy, registry, provider, store, error)

    # ------------------------------------------------------------------
    def _graph_nodes(self, caller, memory_enabled):
        node = make_verdict_node(caller, memory_enabled, max_retries=MAX_PARSE_RETRIES, fatal=(models.gemini_client.PermanentModelError,), unavailable=(errors.ModelUnavailable,))
        memory_node = make_memory_node(self.memory_store, self.settings.memory_k) if (memory_enabled and self.memory_store is not None) else None
        return node, memory_node

    def execute(self, alert, memory_enabled, attempt=1, max_attempts=1):
        """The graph part of a run, shared by the worker and the evaluation tooling so that an evaluation exercises exactly the code a deployed worker runs:
        alias the ids, run the Week 3/4 graph, apply the response guard, restore the ids, route with the Week 4 policy.
        -> Executed. Raises errors.TransientFailure when the model was unreachable and attempts remain (the worker retries; an evaluation passes max_attempts=1 and records the failure instead)."""
        mapping = {}
        model_alert = alert
        if self.settings.alias_ids:
            model_alert, mapping = aliased_alert(alert)
        if memory_enabled and self.memory_store is None:
            raise errors.PermanentFailure("memory_unavailable", "memory was requested but the server has no usable memory store" + (" (" + self.memory_error + ")" if self.memory_error else ""))
        spec = spec_for(memory_enabled)
        caller = self.provider.caller(spec, alert["alert_id"])
        verdict_node, memory_node = self._graph_nodes(caller, memory_enabled)
        started = self.clock()
        node_timings = None
        if self.settings.engine == "instrumented":
            state, node_timings = engine.run_instrumented(self.registry, model_alert, verdict_node=verdict_node, memory_node=memory_node, memory_enabled=memory_enabled, clock=self.clock)
        else:
            graph = B.build_graph(self.registry, verdict_node=verdict_node, memory_node=memory_node)
            state = B.run_alert(graph, model_alert, memory_enabled=memory_enabled)
        graph_seconds = self.clock() - started
        verdict = state.get("verdict") or {}
        if verdict.get("status") == "model_error" and verdict.get("error_code") in VN.MODEL_ERROR_CODES and attempt < max_attempts:
            raise errors.TransientFailure("model_unavailable", "the model could not be reached for this alert; it will be tried again")
        guarded, signals = guard.apply_to_state(state, self.prompts, self.guard_secrets)    # the guard reads the model's text while it still holds aliases, never the client's text
        if mapping:
            guarded = restore_ids(guarded, mapping)
        routed = B.route_final(self.policy, guarded)
        routed = guard.adjust_routing(routed, signals)
        routed = apply_beacon_candidate_veto(routed, guarded)
        routed = apply_scan_evidence_veto(routed, guarded)
        return Executed(guarded, routed, signals, caller, node_timings, graph_seconds, verdict)

    def run(self, job, attempt=1, max_attempts=1):
        """-> RunOutcome. Raises errors.TransientFailure / PermanentFailure / ValueError / gemini PermanentModelError / PolicyError; the worker classifies them."""
        memory_enabled = job["memory_mode"] == "on"
        ex = self.execute(job["alert"], memory_enabled, attempt, max_attempts)
        guarded, routed, signals, caller, node_timings, graph_seconds, verdict = ex
        state = guarded
        payload = cases.build_case_payload(guarded, routed, run_name_for(job["job_id"]), alert_set=job["alert_set"], model=self.provider.name,
                                           ingested_by="worker:" + str(job.get("lease_owner") or "unknown"), proposed_by="agent:graph-v2")
        # Week 5 facts go into provenance (job id, engine, fake flag, guard codes) and the payload hash is recomputed over the final body, so the stored hash is always the hash of what is stored.
        # The attempt number is deliberately NOT included: a retry of the same job must produce the same hash, or a retry after a lost acknowledgement would look like a conflicting resubmission.
        body = {k: v for k, v in payload.items() if k not in ("payload_sha256", "ingested_by", "proposed_by")}
        body["provenance"] = dict(body["provenance"], week5={"job_id": job["job_id"], "engine": self.settings.engine, "fake_model": bool(self.provider.fake),
                                                             "guard_signals": sorted({s.code for s in signals})})
        payload = dict(body, payload_sha256=cases.sha256_of(body), ingested_by=payload["ingested_by"], proposed_by=payload["proposed_by"])
        usage = caller.usage(fake=bool(self.provider.fake))
        summary = {"graph_status": state.get("status"), "verdict_status": verdict.get("status"), "routing_decision": routed["routing"]["decision"], "risk_level": routed["routing"]["risk_level"],
                   "proposed_actions": len(routed.get("actions") or []), "memory_mode": job["memory_mode"], "fake_model": bool(self.provider.fake), "week5_version": "week5-v1",
                   "week4_version": week4.VERSION, "guard_signals": sorted({s.code for s in signals})}
        timings = {"graph_seconds": round(graph_seconds, 6), "model_seconds": usage["model_seconds"], "nodes": node_timings}
        return RunOutcome(payload, summary, timings, usage, signals, bool(self.provider.fake))
