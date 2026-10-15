"""From a finished graph-v2 state (plus its routing decision) to the case payload that repository.ingest_case() stores.

Pure functions. The payload carries: the label-free alert exactly as the model saw it, the verdict record, the routing decision, the evidence (tool calls, specialist findings, memory result,
graph errors, supervisor steps), the memory hits with their provenance, the PROPOSED actions, and run provenance (graph, prompt, policy, memory manifest, model name).
The idempotency key is derived from (run, alert set, alert id, memory mode), so re-ingesting the same run is a no-op, and payload_sha256 detects a changed resubmission.
No credentials are ever included: only the fields listed here are copied, and the database refuses credential-like keys anyway.
"""
import hashlib
import json

import week4

KEY_MAX = 200


class CaseBuildError(ValueError):
    pass


def canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise CaseBuildError("a value cannot be stored as JSON (NaN, infinity or an unsupported type): " + str(error)) from None


def jsonable(obj):
    """A JSON round-tripped copy (so the payload only holds plain data). Raises CaseBuildError for NaN, infinity or non-JSON types."""
    return json.loads(canonical(obj))


def sha256_of(obj):
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def idempotency_key(run_name, alert_set, alert_id, memory_mode):
    key = "%s:%s:%s:%s" % (run_name, alert_set, alert_id, memory_mode)
    if len(key) > KEY_MAX:
        key = key[:KEY_MAX - 17] + ":" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return key


def _verdict_payload(state, model):
    record = state.get("verdict")
    if not isinstance(record, dict):
        return None
    out = {"status": record.get("status"), "prompt_version": record.get("prompt_version"), "prompt_sha256": record.get("agent_prompt_sha256"), "model": model,
           "error_code": record.get("error_code")}
    verdict = record.get("verdict")
    if record.get("status") == "ok" and isinstance(verdict, dict):
        out.update(is_malicious=verdict["is_malicious"], attack_type=verdict["attack_type"], mitre_technique=verdict["mitre_technique"], severity=verdict["severity"],
                   evidence_text=str(verdict.get("evidence", ""))[:2000])
    return out


def _evidence_items(state):
    items = []

    def add(kind, ordinal, source, payload):
        payload = jsonable(payload)
        items.append({"kind": kind, "ordinal": ordinal, "source": source, "payload": payload, "payload_sha256": sha256_of(payload)})
    for i, entry in enumerate(state.get("evidence") or []):
        add("tool_call", i, str(entry.get("tool", "unknown")) if isinstance(entry, dict) else "unknown", entry)
    for i, (key, name) in enumerate((("traffic_findings", "traffic_analyst"), ("beacon_findings", "c2_beacon_analyst"), ("enrichment_findings", "enrichment_agent"))):
        if isinstance(state.get(key), dict):
            add("specialist_finding", i, name, state[key])
    if isinstance(state.get("memory"), dict) and state["memory"].get("status") != "disabled":
        add("memory_summary", 0, "memory_node", state["memory"])
    for i, err in enumerate(state.get("errors") or []):
        add("graph_error", i, str(err.get("node", "unknown")) if isinstance(err, dict) else "unknown", err)
    for i, step in enumerate(state.get("routing") or []):
        add("routing_step", i, "supervisor", step)
    return items


def _memory_hits(state):
    memory = state.get("memory")
    if not isinstance(memory, dict) or memory.get("status") != "ok":
        return []
    return jsonable([{k: h[k] for k in ("rank", "memory_id", "distance", "label", "source_split", "source_ref", "manifest_sha256")} for h in memory["hits"]])


def build_case_payload(state, routed, run_name, alert_set="dev", model=None, ingested_by="system:ingest", proposed_by="agent:graph-v2"):
    """routed: the dict from policy.route_case (routing, actions, inputs). Returns the payload dict for ingest_case()."""
    if alert_set not in ("dev", "synthetic"):
        raise CaseBuildError("alert_set must be 'dev' or 'synthetic'; the frozen set never enters the case store")
    if not isinstance(state, dict) or not isinstance(routed, dict) or "routing" not in routed:
        raise CaseBuildError("a finished state and its routing result are required")
    memory_mode = "on" if state.get("memory_enabled") else "off"
    alert_id = state["alert_id"]
    memory = state.get("memory") if isinstance(state.get("memory"), dict) else None
    store = memory.get("store") if memory else None
    verdict = _verdict_payload(state, model)
    provenance = {"week4_version": week4.VERSION, "graph_version": state.get("graph_version"), "graph_status": state.get("status"), "model": model,
                  "prompt_version": (verdict or {}).get("prompt_version"), "prompt_sha256": (verdict or {}).get("prompt_sha256"),
                  "policy_version": routed["routing"]["policy_version"], "policy_sha256": routed["routing"]["policy_sha256"],
                  "memory": {"enabled": bool(state.get("memory_enabled")), "status": (memory or {}).get("status"), "manifest_sha256": (store or {}).get("manifest_sha256"),
                             "backend": (store or {}).get("backend")},
                  "supervisor_visits": state.get("supervisor_visits")}
    body = {
        "idempotency_key": idempotency_key(run_name, alert_set, alert_id, memory_mode), "alert_set": alert_set, "alert_id": alert_id, "run_name": run_name,
        "graph_version": state.get("graph_version"), "memory_mode": memory_mode, "alert": jsonable(state["alert"]), "provenance": jsonable(provenance), "verdict": jsonable(verdict),
        "routing": jsonable({k: routed["routing"][k] for k in ("decision", "risk_level", "reasons", "policy_version", "policy_sha256", "memory_raised_risk")}),
        "evidence": _evidence_items(state), "memory_hits": _memory_hits(state), "actions": jsonable(routed.get("actions") or []),
    }
    payload = dict(body, payload_sha256=sha256_of(body), ingested_by=ingested_by, proposed_by=proposed_by)
    return payload
