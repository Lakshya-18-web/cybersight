# Sensor ingestion (Suricata EVE), threat intelligence and case management

**Status of verification (read first).** Implemented in code and exercised by unit and end-to-end tests with the in-memory stores and with a real PostgreSQL 16 (sandbox). **Not verified against a real Suricata sensor, a real Gemini model or the real AbuseIPDB service**: the sample events are hand-written to match the EVE format (`samples/eve/generate_samples.py`), the model in every test is a scripted fake, and the threat-intelligence tests inject a fake fetch function. The FastAPI web layer and Docker were not run here (tests drive `Api5.dispatch` and a stdlib HTTP test double).

## The path
```
Suricata eve.json --(python -m week5.eve_send | any HTTP client)--> POST /sensors/{sensor}/eve  (token, analyst/approver/admin role, rate limit)
  -> strict per-event validation + normalisation (week5/eve.py)      -> soc.sensor_events   (append-only, de-duplicated, one transaction per batch)
  -> alert event + its flow event linked by flow_id                  -> analysis job (alert_set 'sensor', idempotent) -> queue -> worker
  -> flows for the two addresses around the alert read from the DB   -> the existing Week 3 agents (traffic, beacon, enrichment) -> verdict (model)
  -> optional threat-intel lookup (public IPs only)                  -> risk policy -> evidence policy (veto) -> case (+ audit)
  -> GET /search/cases, /cases/{id}/analysis, /overview ...          -> notes, feedback, resolve (each audited)
```

## What is stored from an EVE event
Only `event_type` `alert` and `flow` are used; everything else (dns, http, tls, stats ...) is counted as *ignored* with a reason. Unknown fields inside an alert or flow are dropped. A fixed list is kept: timestamp, flow_id, addresses, ports, protocol, app_proto, flow packet/byte counts, start/end/age/state/reason/alerted, alert signature_id/gid/rev/severity/action, and the signature and category text as **display-only** strings. Events with no ports (ICMP) are ignored (`no_ports`), never stored with an invented port. A bad event is rejected individually with a code and index (never its content); the rest of the batch continues.
- **Authentication**: same bearer tokens as the rest of the API. Viewers and unknown or inactive accounts are refused (401/403) and nothing is stored. A refused batch is audited (`sensor_batch_refused`).
- **De-duplication**: each event has a SHA-256 over its identity. The same event again is a *duplicate* and writes nothing. One job per alert, ever (idempotency key `sensor:<alert id>:off`). A replay also *recovers*: if an earlier request stored events but failed before queueing, sending the batch again queues the missing jobs.
- **Alert-to-flow link**: by `flow_id` (per sensor). Send flow events first or in the same batch (flows in a batch are processed first). Without a linked flow the alert's flow-derived fields are `null` and listed in `unavailable_fields`, and rule E6 sends the case to review.
- **Missing is "unavailable", never invented**: the detector score is always `null` for EVE (the Week 1 detector scores CIC feature vectors). The CIC features EVE cannot supply (`Flow IAT Mean`, `SYN Flag Count`, `ACK Flag Count`) are `null`. Suricata counts wire bytes (headers included); CIC counts payload bytes: values are copied as reported, so thresholds learned on CIC data transfer only approximately.
- **The model never sees sensor text.** See docs/WEEK5_SECURITY.md (RR-2).
- **The CIC-style intake keeps working**: `POST /alerts` is unchanged.

## Try it (no Suricata needed)
```powershell
$env:WEEK5_SENSOR_TOKEN = "<an analyst token>"          # never on the command line
python -m week5.eve_send --base-url http://127.0.0.1:8000 --sensor sensor-lab-1 --file samples\eve\eve_mixed.ndjson
```
The sample has 23 events: 16 flows, 4 alerts (SSH brute force, a benign TLS rule, a hostile signature text, a C2 beacon), 3 ignored (dns, stats, ICMP). Running it twice reports `duplicates=20` the second time and creates nothing. `eve_invalid.ndjson` has five invalid events and shows the rejection codes. With a real sensor, point `--file` at `eve.json` (or tail it in batches); the same command applies.

## Threat intelligence (AbuseIPDB), optional
| Setting (worker only) | Meaning |
|---|---|
| `SOC_REPUTATION_API_KEY` | the AbuseIPDB key. Empty = disabled: records say `disabled`, nothing is called. Never stored, logged, returned or shown; `status()` only says whether one exists. |
| `SOC_REPUTATION_TIMEOUT` | seconds per call (default 5) |
| `WEEK5_TI_ALERT_SETS` | alert sets that may be looked up (default `sensor`). Labelled dev/synthetic data is **never** sent to a third party. |
| `WEEK5_TI_DAILY_BUDGET` | rolling 24 h call budget (default 500); over budget = `unavailable (budget)` |
Per address the case stores a record: `provider`, `status` (`ok` / `disabled` / `not_applicable` (private or documentation address) / `unavailable` (timeout, error, budget) / `skipped`), `reason`, `cache_hit`, `checked_at` (UTC), and the answer reduced to known shapes (score, report count, country code, usage type, last report time). Results are cached (the existing client's TTL cache). A failed or missing lookup never changes a decision and never fails a job. A high score can only *raise* caution (rule E5). The result is shown in the case view and is **not** given to the model. The key reaches the worker container only (docker-compose.egress.yml), and the worker reaches AbuseIPDB only through the allow-list proxy.

## Case management API (all audited, idempotent with an optional `Idempotency-Key` header)
| Route | Role | Purpose |
|---|---|---|
| `GET /search/cases` | read | text search, status, severity, risk, routing decision, alert set, verdict status, malicious flag, pending-approval flag, date range, sort, paging |
| `GET /cases/{id}/analysis` | read | one case with evidence kept in four classes, notes, feedback and the audit timeline |
| `POST /cases/{id}/notes` | analyst+ | add a note (<= 4000 chars; never read by any prompt) |
| `POST /cases/{id}/feedback` | analyst+ | `assessment` correct/incorrect/unsure, optional `disposition`, optional comment; stored for evaluation, never changes the verdict or routing |
| `POST /cases/{id}/resolve` | analyst+ | close an escalated/needs_review case that has no pending proposals; records the decision, approves/rejects/executes nothing |
| `GET /overview`, `/providers`, `/diagnostics`, `/sensors`, `/evaluation/reports[/{name}]` | read | dashboard data; every number comes from stored records |
Approval of proposed actions stays with the approver role (`POST /actions/{id}/decision`), and "execution" stays a recorded **simulation**. Duplicate submissions (same key, same body) return the original result; the same key with a different body is a 409 conflict.

## Limits
- Hand-written sample events, not captured traffic; no Suricata run here.
- Sensor alerts are never auto-closed (no calibrated detector score). The system prioritises; it does not reduce volume.
- Flow context is limited to flows the sensor sent for the two addresses in a +/-120 minute window (5000 flows maximum).
- Batches are limited to 500 events and `WEEK5_MAX_EVE_BODY_BYTES`.
- The sensor name is a label chosen by the sender; the token identifies who sent it, not which sensor.
