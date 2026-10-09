"""The enrichment agent for graph v0.1: one node, deterministic, no LLM call, no external call.

It adds reference context about the alert's addresses, destination port and service, and, only when the beaconing analyst flagged a beacon_candidate (regular intervals on a consistent destination port),
a few MITRE ATT&CK reference entries. It describes things; it does not decide what the alert is, and ATT&CK entries are reference material, not a determination.

Tool calls (all local and offline):
  ip_info        alert source, then alert destination      address range and how often the flow store has seen the address
  port_info      alert destination port (tcp or udp when the alert's protocol is 6 or 17)
  service_lookup the first service name port_info returned  usual ports for that service (skipped when port_info found none)
  mitre_search   "command and control beaconing", limit 3   only if beacon_findings.beacon_candidate is true
  mitre_lookup   the first 2 technique ids that search returned
Reputation lookup is never called. Its absence is recorded explicitly in not_consulted, and so is any other enrichment that was skipped or failed.
Every finding names the tool it came from and the index of its evidence entry.
"""
from . import state as S
from . import common

AGENT_NAME = "enrichment_agent"
MITRE_QUERY = "command and control beaconing"
MITRE_SEARCH_LIMIT = 3
MITRE_LOOKUP_COUNT = 2
PROTOCOL_NAMES = {6: "tcp", 17: "udp"}
REPUTATION_NOTE = {"source": "reputation_lookup", "status": "not_consulted", "reason": "reputation lookup is disabled in graph v0.1; no external call was made"}


def wants_mitre(state):
    """True when a specialist produced something to look up: today only a beacon_candidate from the beaconing analyst."""
    beacon = state.get("beacon_findings")
    return isinstance(beacon, dict) and beacon.get("beacon_candidate") is True


def _next_index(state, evidence):
    return len(state["evidence"]) + len(evidence)


def run_calls(registry, state):
    """Make the calls. Returns (evidence, errors, skipped). Later calls depend on earlier answers, so this is a short fixed sequence, not a loop over a plan."""
    alert = state["alert"]
    evidence, errors, skipped = [], [], []

    def call(tool, arguments):
        entry, error = common.call_tool(registry, AGENT_NAME, tool, arguments, _next_index(state, evidence))
        evidence.append(entry)
        if error is not None:
            errors.append(error)
        return entry

    call("ip_info", {"ip": alert["src_ip"]})
    call("ip_info", {"ip": alert["dst_ip"]})
    port_args = {"port": int(alert["dst_port"]) if float(alert["dst_port"]).is_integer() else alert["dst_port"]}
    if alert.get("protocol") in PROTOCOL_NAMES:
        port_args["protocol"] = PROTOCOL_NAMES[alert["protocol"]]
    port = call("port_info", port_args)
    services = port["data"].get("services") if port["ok"] else None
    first_service = services[0].get("service") if isinstance(services, list) and services and isinstance(services[0], dict) else None
    if isinstance(first_service, str) and first_service:
        call("service_lookup", {"name": first_service})
    elif port["ok"]:
        skipped.append({"source": "service_lookup", "status": "not_consulted", "reason": "port_info found no curated service for port " + str(alert["dst_port"])})
    else:
        skipped.append({"source": "service_lookup", "status": "not_consulted", "reason": "port_info failed, so there was no service name to look up"})
    if wants_mitre(state):
        search = call("mitre_search", {"query": MITRE_QUERY, "limit": MITRE_SEARCH_LIMIT})
        techniques = search["data"].get("techniques") if search["ok"] else None
        ids = [t.get("technique_id") for t in techniques if isinstance(t, dict) and isinstance(t.get("technique_id"), str)] if isinstance(techniques, list) else []
        for technique_id in ids[:MITRE_LOOKUP_COUNT]:
            call("mitre_lookup", {"technique_id": technique_id})
    else:
        skipped.append({"source": "mitre_search", "status": "not_consulted", "reason": "no specialist finding asks for ATT&CK reference material"})
    return evidence, errors, skipped


def findings_from_evidence(alert, evidence):
    """Reference findings from the evidence that succeeded. Each carries its source tool and evidence index."""
    findings = []
    first_index = evidence[0]["index"] if evidence else None
    for e in evidence:
        if not e["ok"]:
            continue
        data, tool, index = e["data"], e["tool"], e["index"]
        base = {"source_tool": tool, "evidence_index": index}
        if tool == "ip_info":
            role = "source" if e["index"] == first_index else "destination"   # the first call is always the source, the second the destination
            seen = data.get("observed_in_flow_store") if isinstance(data.get("observed_in_flow_store"), dict) else None
            metrics = {"role": role, "ip": data.get("ip"), "address_type": data.get("address_type"), "scope": data.get("scope"), "is_global": data.get("is_global"),
                       "flows_as_source": seen.get("flows_as_source") if seen else None, "flows_as_destination": seen.get("flows_as_destination") if seen else None}
            findings.append(dict(base, kind="ip_context", metrics=metrics,
                                 statement="The " + role + " address " + str(data.get("ip")) + " is " + str(data.get("address_type")) + " (" + str(data.get("scope")) + ")"
                                           + ("; the flow store has it as source in " + str(metrics["flows_as_source"]) + " flow(s) and as destination in " + str(metrics["flows_as_destination"]) + "." if seen else ".")))
        elif tool == "port_info":
            names = [s.get("service") for s in data.get("services", []) if isinstance(s, dict)]
            findings.append(dict(base, kind="port_context", metrics={"port": data.get("port"), "category": data.get("category"), "in_curated_table": data.get("in_curated_table"), "services": names},
                                 statement="Destination port " + str(data.get("port")) + " is " + str(data.get("category")) + "; "
                                           + (("curated services: " + ", ".join(str(n) for n in names) + ".") if names else "it is not in the curated table, which says nothing about how it is used.")))
        elif tool == "service_lookup":
            service = data["services"][0] if isinstance(data.get("services"), list) and data["services"] and isinstance(data["services"][0], dict) else {}
            findings.append(dict(base, kind="service_context", metrics={"name": service.get("name"), "match": data.get("match"), "usual_ports": service.get("ports")},
                                 statement="Service " + str(service.get("name")) + " usually uses " + ", ".join(str(p.get("port")) + "/" + str(p.get("protocol")) for p in service.get("ports", []) if isinstance(p, dict)) + "."))
        elif tool == "mitre_search":
            for t in data.get("techniques", []) if isinstance(data.get("techniques"), list) else []:
                if isinstance(t, dict):
                    findings.append(dict(base, kind="mitre_search_hit", metrics={"technique_id": t.get("technique_id"), "name": t.get("name"), "tactics": t.get("tactics"), "score": t.get("score")},
                                         statement="Reference search hit " + str(t.get("technique_id")) + " " + str(t.get("name")) + ". Reference material only, not a determination."))
        elif tool == "mitre_lookup":
            findings.append(dict(base, kind="mitre_reference", metrics={"technique_id": data.get("technique_id"), "name": data.get("name"), "tactics": data.get("tactics"),
                                                                        "flow_observables": data.get("flow_observables")},
                                 statement="ATT&CK " + str(data.get("technique_id")) + " (" + str(data.get("name")) + "): " + str(data.get("flow_observables")) + " Reference material only, not a determination."))
    return findings


def make_enrichment_agent(registry):
    """Build the graph node around a tool registry. The node never raises: a failure becomes a state update."""

    def enrichment_agent_node(state):
        evidence, errors = [], []
        not_consulted = [dict(REPUTATION_NOTE)]
        try:
            evidence, errors, skipped = run_calls(registry, state)
            not_consulted += skipped
            findings = findings_from_evidence(state["alert"], evidence)
            status = common.agent_status(evidence)
        except Exception as error:  # the type is recorded, nothing else
            findings, status = [], "failed"
            errors = errors + [{"node": AGENT_NAME, "code": "node_exception", "message": "the enrichment agent failed unexpectedly (" + type(error).__name__ + ")"}]
        unavailable = [{"source": e["tool"], "arguments": e["arguments"], "status": "unavailable", "code": e["error"]["code"]} for e in evidence if not e["ok"] and e["error"]]
        output = {"agent": AGENT_NAME, "status": status, "findings": findings, "not_consulted": not_consulted, "unavailable": unavailable,
                  "tool_calls": len(evidence), "tool_errors": len(errors)}
        return {"evidence": list(state["evidence"]) + evidence, "enrichment_findings": output, "errors": list(state["errors"]) + errors,
                "trace": list(state["trace"]) + [S.NODE_ENRICHMENT_AGENT]}

    return enrichment_agent_node

