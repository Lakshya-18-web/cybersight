"""Everything the runner needs to know about a job that is not in the 21-field alert: the sensor's own record of the alert, the flow records it sent, and the threat-intelligence lookups.

It is built once per job, in the worker, from the database. It holds four kinds of thing and keeps them apart (they are stored apart, shown apart, and used differently):
  observed          the sensor's alert record and flow records, as the sensor sent them
  external          threat-intelligence lookups, with provider, status, time and cache flag
  signals           untrusted-text findings about the sensor's rule name and category (RR-2); they block auto-close and are audited
  flow store        a per-job table of the observed flows for the existing flow tools (week5.flows)
Nothing here is given to the model: the model sees the alert dict, and the specialists' structured findings, as before.
"""
from collections import namedtuple

from tools import build_registry
from tools.reputation import ReputationTool

from . import errors, eve, flows, ti, untrusted
from .security import guard

JobContext = namedtuple("JobContext", "registry sensor ti_records signals evidence_classes")


def sensor_facts(record, flow_linked, flow_count, unavailable, source):
    sig, cat = untrusted.Untrusted(record.get("signature"), "sensor_signature"), untrusted.Untrusted(record.get("category"), "sensor_category")
    return {"sensor": record["sensor"], "event_id": record.get("event_id"), "event_time": record.get("timestamp"), "received_at": record.get("received_at"), "flow_ref": record["flow_ref"],
            "severity": record.get("severity"), "signature_id": record.get("signature_id"), "gid": record.get("gid"), "rev": record.get("rev"), "action": record.get("action"),
            "app_proto": record.get("app_proto"), "category": record.get("category"),
            "flow_linked": bool(flow_linked), "flows_in_window": int(flow_count), "flow_source": source, "unavailable_fields": list(unavailable),
            "display": {"signature": sig.display(), "category": cat.display()}, "adapter_version": eve.ADAPTER_VERSION}


def build(repo, job, threat_intel=None, base_registry=None):
    """-> JobContext. repo: a Repo5. For a job that did not come from a sensor the context is only the (optional) threat-intelligence lookups, which are off for dev and synthetic alerts."""
    alert, alert_set = job["alert"], job["alert_set"]
    records = threat_intel.lookup_alert(alert, alert_set) if threat_intel is not None else []
    if alert_set != "sensor":
        return JobContext(base_registry, None, records, [], {})
    record = repo.sensor_alert(job["alert_id"])
    if record is None:
        raise errors.PermanentFailure("sensor_event_missing", "no stored sensor alert event matches this job's alert id")
    store, n = flows.flow_store_for(repo, alert)
    flow = repo.sensor_flow_for(record["sensor"], record["flow_ref"])
    _, unavailable, source = eve.build_alert(record, flow, record["sensor"])
    registry = build_registry(flow_store=store, reputation=ReputationTool())          # reputation stays off inside the graph: it is read by the evidence policy, not by the agents
    sensor = sensor_facts(record, flow is not None, n, unavailable, source)
    signals = untrusted.scan("sensor_signature", record.get("signature")) + untrusted.scan("sensor_category", record.get("category"))
    classes = {"observed": ["alert_record", "flow_records"], "external_enrichment": ["threat_intel"] if records else [], "model_hypothesis": ["verdict"], "policy_decision": ["routing", "evidence_policy"]}
    return JobContext(registry, sensor, records, signals, classes)


def merge_signals(signals, extra):
    """The response guard's signals plus the untrusted-text ones (kept in order, no duplicates)."""
    out = list(signals)
    for s in extra:
        if s not in out:
            out.append(s)
    return out


def provenance(ctx, evidence_result):
    """What goes into provenance.week5 beside the Week 5 facts: typed evidence classes for the API and the dashboard."""
    return {"evidence_classes": {"observed": {"sensor": ctx.sensor}, "external_enrichment": {"threat_intel": ctx.ti_records},
                                 "model_hypothesis": {"stored_in": "verdict"}, "policy_decision": {"stored_in": "routing", "evidence_policy": evidence_result}}}
