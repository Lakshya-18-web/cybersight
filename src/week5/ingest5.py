"""Sensor ingestion service: Suricata EVE events in, stored evidence and analysis jobs out.

    events --normalise (week5.eve)--> records --one transaction (repo.ingest_sensor_batch)--> soc.sensor_events
                                            \\--> for every ALERT record: alert dict (+ its flow's counts) --> job (alert_set 'sensor') --> queue --> worker --> case

Authentication, roles and rate limiting happen before this module is reached (Api5). What this module guarantees:
  * all or nothing for the events of one request (the database function is one transaction); an event seen before is reported as a duplicate and writes nothing
  * one job per alert event, ever: the job's idempotency key is "sensor:<alert id>:<memory>", and the alert id is a hash of the event's identity. Replaying a batch (a client retry, a sensor that re-sends a file)
    finds the existing job and creates nothing. The job's payload hash covers only that identity, so a flow event that arrives later can never turn a replay into a conflict. The alert dict the model sees is built
    when the job is first created: send an alert's flow event before it (flows in the same batch are always handled first) for the flow counts to be included. Without them the fields are marked unavailable.
  * a replay also RECOVERS: if an earlier request stored the events and then failed before queueing the job (queue full, process killed), sending the batch again queues the missing jobs.
  * never invents a value: what EVE did not send is None in the alert dict, listed in `unavailable_fields`, and the Week 1 detector score is always None (the detector scores CIC feature vectors, not EVE records).
The model never sees the sensor's rule name or category (week5.untrusted); the job carries numbers, addresses and a timestamp only.
"""
from . import eve, intake


def _job_key(alert_id, memory):
    return "sensor:%s:%s" % (alert_id, memory)


def _job_hash(alert_id, memory):
    import hashlib
    return hashlib.sha256(("w5sensorjob:%s:%s" % (alert_id, memory)).encode("utf-8")).hexdigest()


def ingest(repo, jobs, dispatcher, settings, actor, sensor, events, memory="off", analyze=True):
    """-> a result dict (see the keys below). Raises eve.EveError for a bad sensor name or batch shape (nothing stored), ValueError for a bad actor, and DbError when the database fails.
    {"outcome": "ok"|"unauthorized", "sensor", "received", "usable", "stored", "duplicates", "ignored": {reason: n}, "rejected": [{index, code, message}], "alerts": [{...}]}"""
    records, ignored, rejected = eve.normalise_batch(events, sensor)
    result = {"outcome": "ok", "sensor": sensor, "received": len(events), "usable": len(records), "stored": 0, "duplicates": 0, "ignored": ignored, "rejected": rejected, "alerts": [],
              "flows_stored": 0}
    if not records:
        return result
    stored = repo.ingest_sensor_batch(actor, sensor, [r for _, r in records])
    if stored["outcome"] == "unauthorized":
        result["outcome"] = "unauthorized"
        return result
    result["stored"], result["duplicates"] = stored["stored"], stored["duplicates"]
    outcomes = {r["index"]: r["outcome"] for r in stored["results"]}
    result["flows_stored"] = sum(1 for i, (_, rec) in enumerate(records) if rec["event_type"] == "flow" and outcomes.get(i) == "stored")
    batch_flows = {rec["record"]["flow_ref"]: rec["record"] for _, rec in records if rec["event_type"] == "flow"}
    for i, (_orig_index, rec) in enumerate(records):
        if rec["event_type"] != "alert":
            continue
        record = rec["record"]
        flow = batch_flows.get(record["flow_ref"]) or repo.sensor_flow_for(sensor, record["flow_ref"])
        alert, unavailable, source = eve.build_alert(record, flow, sensor)
        entry = {"alert_id": record["alert_id"], "event": outcomes.get(i), "flow_linked": flow is not None, "unavailable_fields": unavailable, "job_id": None, "job_outcome": None}
        result["alerts"].append(entry)
        if not analyze:
            entry["job_outcome"] = "not_requested"
            continue
        try:
            clean = eve.validate_alert_record(alert)
        except intake.IntakeError as error:             # the adapter built something the strict rules refuse: stored as evidence, no job, reported
            entry["job_outcome"] = "invalid_alert"
            entry["detail"] = error.code
            continue
        res = jobs.submit(clean, "sensor", memory, actor, _job_key(record["alert_id"], memory), _job_hash(record["alert_id"], memory), settings.max_attempts,
                          max_queue_depth=settings.max_queue_depth, dispatched=dispatcher.queue.implicit_dispatch)
        entry["job_outcome"], entry["job_id"] = res["outcome"], res["job_id"]
        if res["outcome"] == "created":
            entry["dispatch"] = dispatcher.dispatch(res["job_id"])
    result["jobs"] = {k: sum(1 for a in result["alerts"] if a["job_outcome"] == k) for k in sorted({a["job_outcome"] for a in result["alerts"]})}
    return result
