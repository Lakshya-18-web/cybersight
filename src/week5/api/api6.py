"""Handlers for the Week 5 phase 2 routes (see routes6). A mixin for Api5: it uses self.repo, self.jobs, self.dispatcher, self.settings, self.limiter and the helpers of the Week 4 Api.

Rules kept here, each tested:
  * every write names its actor from the authenticated principal; the body has no field for it, and an unknown body field is refused
  * business outcomes map to statuses: created 201, replayed 200, conflict 409, not found 404, invalid 422, store unavailable 503; nothing echoes submitted text in an error
  * analyst text (notes, comments, reasons) is stored verbatim and returned as JSON strings; it is never put into a prompt, a log line or an audit payload (the audit row records lengths)
  * nothing here creates, approves or executes a containment action
  * a number that cannot be computed is returned as null with a reason, never as zero
"""
import json
import os
import re

from week4.api import handlers as h
from week4.db.drivers import DbError
from week5 import eve, ingest5, intake, jobs as jobs_module, repo5

NDJSON_TYPES = ("application/x-ndjson", "application/ndjson")
NOTE_KEYS, FEEDBACK_KEYS, RESOLVE_KEYS, EVE_KEYS = {"body"}, {"assessment", "disposition", "comment"}, {"reason", "disposition"}, {"events", "analyze", "memory"}
REPORT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,99}\.(json|md)", re.ASCII)
REPORT_MAX_BYTES = 4 * 1024 * 1024
FLOW_TOOLS = ("query_flows", "summarize_flows", "beacon_stats")
EVENT_TEXT = {
    "case_ingested": "case created by the analysis pipeline", "action_proposed": "a containment action was proposed (pending a human decision)", "action_approved": "an action was approved by a person",
    "action_rejected": "an action was rejected by a person", "approval_denied": "an approval attempt was refused", "decision_conflict": "a conflicting decision attempt was refused",
    "action_simulated": "an approved action was recorded as a SIMULATED execution (nothing real happened)", "case_note_added": "an analyst note was added", "case_feedback_added": "an analyst recorded feedback on the verdict",
    "case_resolved": "the case was resolved by an analyst", "case_resolve_refused": "an attempt to resolve the case was refused", "case_note_refused": "a note was refused", "case_feedback_refused": "feedback was refused",
}
SAFE_PAYLOAD_KEYS = ("action_type", "target", "from_status", "disposition", "assessment", "length", "reason", "why", "attempted", "note_id", "feedback_id")


class Api6Mixin:
    # optional collaborators, set by the process that builds the Api (serve5) or by tests
    threat_intel = None
    eval_report_dir = None
    risk_policy = None
    evidence = None
    model_name = None

    @property
    def r5(self):
        got = self.__dict__.get("_r5")
        if got is None:
            got = self.__dict__["_r5"] = repo5.wrap(self.repo)
        return got

    def body_limit(self, name):
        return self.settings.max_eve_body_bytes if name == "ingest_eve" else self.settings.max_body_bytes

    # ------------------------------------------------------------------ helpers
    def _json_body(self, headers, raw_body, body, allowed, required=()):
        ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return None, h.error(415, "unsupported_media_type", "send the body as application/json")
        if raw_body is None:
            raw_body = intake.canonical(body).encode("utf-8") if isinstance(body, dict) else b""
        try:
            parsed = intake.parse_body(raw_body, self.settings.max_body_bytes)
        except intake.IntakeError as rejection:
            status = 413 if rejection.code == intake.TOO_LARGE else 400
            return None, h.error(status, rejection.code, str(rejection))
        extra = [k for k in parsed if k not in allowed]
        if extra:
            return None, h.error(422, "invalid_input", "the request has %d field(s) that are not allowed; only %s are accepted" % (len(extra), ", ".join(sorted(allowed))))
        missing = [k for k in required if k not in parsed]
        if missing:
            return None, h.error(422, "invalid_input", "missing: " + ", ".join(missing))
        return parsed, None

    @staticmethod
    def _key(headers):
        key = headers.get("idempotency-key")
        if key is None or key == "":
            return None
        return repo5.check_key(key)

    def _case_or_404(self, path_params):
        case_id = self._uuid(path_params, "case_id")
        return case_id

    # ------------------------------------------------------------------ ingestion
    def _ingest_eve(self, principal, headers, query, path_params, body, raw_body):
        ok_, retry_after = self.limiter.allow(principal.analyst_id)
        if not ok_:
            return h.error(429, "rate_limited", "too many submissions; slow down", {"Retry-After": str(retry_after)})
        sensor = path_params.get("sensor")
        try:
            eve.check_sensor(sensor)
        except eve.EveError as error:
            return h.error(422, "invalid_input", str(error))
        ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
        raw = raw_body if raw_body is not None else (intake.canonical(body).encode("utf-8") if isinstance(body, dict) else b"")
        analyze, memory = True, self.settings.default_memory if self.settings.memory_dir else "off"
        try:
            if ctype in NDJSON_TYPES:
                events = eve.parse_ndjson(raw, self.settings.max_eve_body_bytes)
                flag = (query.get("analyze") or "").strip().lower()
                if flag:
                    if flag not in ("true", "false"):
                        raise eve.EveError("bad_body", "analyze must be true or false")
                    analyze = flag == "true"
            elif ctype == "application/json":
                parsed = intake.parse_body(raw, self.settings.max_eve_body_bytes)
                extra = [k for k in parsed if k not in EVE_KEYS]
                if extra or "events" not in parsed:
                    raise eve.EveError("bad_body", "the body must be an object with an events list (and optionally analyze)" if not extra else "the body has fields that are not allowed")
                events, analyze = parsed["events"], parsed.get("analyze", True)
                if not isinstance(analyze, bool):
                    raise eve.EveError("bad_body", "analyze must be true or false")
                if parsed.get("memory") not in (None, "off"):
                    raise eve.EveError("bad_body", "sensor alerts are analysed without memory")
            else:
                return h.error(415, "unsupported_media_type", "send application/json or application/x-ndjson")
            if not isinstance(events, list):
                raise eve.EveError("bad_body", "events must be a list")
        except (eve.EveError, intake.IntakeError) as error:
            code = getattr(error, "code", "bad_body")
            self._audit_rejection(principal, code, None, raw)
            status = 413 if code in ("too_large", "batch_too_large") else 422
            return h.error(status, code, str(error))
        try:
            result = ingest5.ingest(self.r5, self.jobs, self.dispatcher, self.settings, principal.analyst_id, sensor, events, memory=memory, analyze=analyze)
        except eve.EveError as error:
            self._audit_rejection(principal, error.code, None, raw)
            return h.error(422 if error.code != "batch_too_large" else 413, error.code, str(error))
        if result["outcome"] == "unauthorized":
            return h.error(403, "forbidden", "your role does not allow this")
        if result["usable"] == 0:
            if result["rejected"]:
                return h.Response(422, {"error": {"code": "no_valid_events", "message": "none of the events could be used"}, "rejected": result["rejected"][:50], "ignored": result["ignored"]}, {})
            return h.ok(dict(result, note="nothing usable: only event types other than alert and flow, or events without ports"))
        created = (result.get("jobs") or {}).get("created", 0)
        return h.Response(202 if created else 200, result, {})

    def _list_sensors(self, principal, headers, query, path_params, body, raw_body):
        return h.ok(dict(self.r5.sensor_stats(), note="counts of stored sensor events"))

    # ------------------------------------------------------------------ search and numbers
    def _search_cases(self, principal, headers, query, path_params, body, raw_body):
        page = self._page(query)
        filters = {k: query.get(k) for k in ("q", "status", "severity", "risk_level", "routing_decision", "alert_set", "verdict_status", "is_malicious", "has_pending", "created_from", "created_to", "sort")}
        return h.ok(self._with_next(self.r5.search_cases(filters, **page)))

    def _list_actions(self, principal, headers, query, path_params, body, raw_body):
        page = self._page(query)
        try:
            result = self.r5.list_actions(query.get("state"), query.get("executed"), **page)
        except ValueError as error:
            return h.error(422, "invalid_input", str(error))
        return h.ok(self._with_next(result))

    def _get_overview(self, principal, headers, query, path_params, body, raw_body):
        data = self.r5.overview()
        jobs = self.jobs.stats()
        data["jobs"] = {k: v["n"] for k, v in jobs.items()}
        queued = [v["oldest_age_seconds"] for k, v in jobs.items() if k in ("queued", "running") and v.get("oldest_age_seconds") is not None]
        data["oldest_unfinished_job_age_seconds"] = max(queued) if queued else None
        data.pop("jobs_by_status", None)
        data.pop("oldest_queued_age_seconds", None)
        data["sensor_events"] = self.r5.sensor_stats()
        return h.ok(data)

    # ------------------------------------------------------------------ case analysis
    @staticmethod
    def _event_view(e):
        payload = e.get("payload") or {}
        safe = {k: payload[k] for k in SAFE_PAYLOAD_KEYS if k in payload and isinstance(payload[k], (str, int, float, bool, type(None)))}
        return {"at": e.get("occurred_at"), "actor": e.get("actor"), "kind": e.get("event_type"), "summary": EVENT_TEXT.get(e.get("event_type"), str(e.get("event_type"))), "detail": safe}

    def _case_analysis(self, principal, headers, query, path_params, body, raw_body):
        case_id = self._uuid(path_params, "case_id")
        case = self.repo.get_case(case_id)
        if case is None:
            return h.error(404, "not_found", "no such case")
        evidence = self.repo.case_evidence(case_id)
        prov = case.get("provenance") or {}
        w5 = prov.get("week5") or {}
        classes = w5.get("evidence_classes") or {}
        specialists = {e["source"]: e["payload"] for e in evidence if e["kind"] == "specialist_finding"}
        tool_calls = [e["payload"] for e in evidence if e["kind"] == "tool_call"]
        flow_calls = [{"tool": t.get("tool"), "ok": t.get("ok"), "arguments": t.get("arguments"), "n_flows": (t.get("data") or {}).get("n_flows") if isinstance(t.get("data"), dict) else None,
                       "error_code": (t.get("error") or {}).get("code") if isinstance(t.get("error"), dict) else None} for t in tool_calls if t.get("tool") in FLOW_TOOLS]
        lookups = [t["data"] for t in tool_calls if t.get("tool") == "reputation_lookup" and isinstance(t.get("data"), dict)]
        policy_step = next((e["payload"] for e in evidence if e["kind"] == "routing_step" and e["source"] == "evidence_policy"), None)
        enrich = specialists.get("enrichment_agent") or {}
        alert = case["alert"]
        mitre_ref = [f for f in (enrich.get("findings") or []) if f.get("kind") in ("mitre_reference", "mitre_search_hit")]
        verdict = case.get("verdict")
        mitre = {"model_technique": (verdict or {}).get("mitre_technique"), "from": "model_hypothesis", "reference": mitre_ref,
                 "note": "ATT&CK entries are reference material found by a keyword search, not a determination"}
        if lookups:
            ti_view = {"status": "recorded", "records": lookups}
        elif case["alert_set"] != "sensor":
            ti_view = {"status": "not_enabled", "records": [], "reason": "threat-intelligence lookups are only made for sensor alerts"}
        else:
            ti_view = {"status": "not_recorded", "records": [], "reason": "no lookup was recorded for this case"}
        notes, feedback = self.r5.case_notes(case_id), self.r5.case_feedback(case_id)
        timeline = [self._event_view(e) for e in self.repo.case_history(case_id)]
        job = None
        if w5.get("job_id"):
            try:
                found = self.jobs.get(w5["job_id"])
                job = jobs_module.public_job(found) if found else None
            except (DbError, ValueError):
                job = None
        return h.ok({
            "case": {k: case[k] for k in ("case_id", "alert_set", "alert_id", "run_name", "graph_version", "memory_mode", "status", "created_at", "updated_at")},
            "evidence_classes": {
                "observed": {"alert": alert, "unavailable_fields": sorted(k for k, v in alert.items() if v is None), "sensor": (classes.get("observed") or {}).get("sensor"),
                             "specialist_findings": {"traffic_analyst": specialists.get("traffic_analyst"), "c2_beacon_analyst": specialists.get("c2_beacon_analyst")}, "flow_tool_calls": flow_calls,
                             "description": "what the sensor reported and what the flow records show; produced by deterministic code from stored records"},
                "external_enrichment": {"reference_context": enrich or None, "threat_intel": ti_view,
                                        "description": "reference tables (offline) and third-party threat intelligence; context to weigh, never a verdict, never shown to the model"},
                "model_hypothesis": {"verdict": verdict, "model": prov.get("model"), "fake_model": w5.get("fake_model"), "prompt_version": prov.get("prompt_version"),
                                     "description": "a language model's reading of the alert; a hypothesis, not evidence, and never able to act on its own"},
                "policy_decision": {"routing": case.get("routing"), "evidence_policy": policy_step or w5.get("evidence_policy"), "guard_signals": w5.get("guard_signals", []), "actions": case.get("actions", []),
                                    "description": "deterministic rules applied after the model; they can only raise caution; actions are proposals that need a person"},
            },
            "mitre": mitre, "notes": notes, "feedback": feedback, "timeline": timeline, "job": job,
            "provenance": {"week4_version": prov.get("week4_version"), "graph_version": prov.get("graph_version"), "risk_policy": w5.get("risk_policy"),
                           "evidence_policy": {k: (w5.get("evidence_policy") or {}).get(k) for k in ("version", "sha256")}, "memory": prov.get("memory")},
        })

    # ------------------------------------------------------------------ notes, feedback, resolution
    def _outcome_response(self, result, created="created", success_status=201):
        outcome = result["outcome"]
        if outcome == created:
            return h.Response(success_status, dict(result, replayed=False), {})
        if outcome == "replayed":
            return h.Response(200, dict(result, replayed=True), {})
        if outcome == "conflict":
            return h.error(409, "conflict", "that Idempotency-Key was already used for a different request, or the case is not in a state that allows this")
        if outcome == "pending_actions":
            return h.error(409, "pending_actions", "this case still has proposed actions waiting for a human decision; decide them first")
        if outcome == "not_found":
            return h.error(404, "not_found", "no such case")
        if outcome == "unauthorized":
            return h.error(403, "forbidden", "your role does not allow this")
        return h.error(422, "invalid_input", "the request was refused")

    def _add_note(self, principal, headers, query, path_params, body, raw_body):
        case_id = self._uuid(path_params, "case_id")
        parsed, err = self._json_body(headers, raw_body, body, NOTE_KEYS, ("body",))
        if err:
            return err
        result = self.r5.add_note(case_id, principal.analyst_id, parsed["body"], self._key(headers))
        return self._outcome_response(result)

    def _add_feedback(self, principal, headers, query, path_params, body, raw_body):
        case_id = self._uuid(path_params, "case_id")
        parsed, err = self._json_body(headers, raw_body, body, FEEDBACK_KEYS, ("assessment",))
        if err:
            return err
        result = self.r5.add_feedback(case_id, principal.analyst_id, parsed["assessment"], parsed.get("disposition"), parsed.get("comment"), self._key(headers))
        return self._outcome_response(result)

    def _resolve_case(self, principal, headers, query, path_params, body, raw_body):
        case_id = self._uuid(path_params, "case_id")
        parsed, err = self._json_body(headers, raw_body, body, RESOLVE_KEYS, ("reason",))
        if err:
            return err
        result = self.r5.resolve_case(case_id, principal.analyst_id, parsed.get("disposition"), parsed["reason"], self._key(headers))
        return self._outcome_response(result, created="resolved", success_status=200)

    # ------------------------------------------------------------------ providers and diagnostics
    def _get_providers(self, principal, headers, query, path_params, body, raw_body):
        s = self.settings
        try:
            overview = self.r5.overview()
            outcomes = self.r5.provider_outcomes(24)
            db_ok = bool(self.repo.ping()) and bool(self.jobs.ping())
        except DbError:
            return self._unavailable()
        broker_ok, detail = self.dispatcher.queue.ready()
        by_verdict = overview.get("by_verdict_status") or {}
        ti = self.threat_intel
        jobs = self.jobs.stats()
        return h.ok({
            "model": {"mode": s.model_mode, "live_calls_allowed": bool(s.allow_live_model), "configured_model": self.model_name,
                      "status": "not_checked", "status_note": "the API never calls the model to test it (that would cost money); outcomes below come from stored cases",
                      "verdicts_by_status": by_verdict, "model_errors_total": by_verdict.get("model_error", 0)},
            "threat_intel": {"status": ti.status() if ti is not None else {"configured": None, "note": "this API process was not given the threat-intelligence settings; the worker holds them"},
                             "lookups_last_24h": outcomes, "enabled_for": list(ti.alert_sets) if ti is not None else None},
            "queue": {"backend": self.dispatcher.queue.name, "broker_ready": bool(broker_ok), "detail": detail if not broker_ok else None},
            "database": {"reachable": db_ok},
            "jobs": {k: {"count": v["n"], "oldest_age_seconds": v.get("oldest_age_seconds")} for k, v in jobs.items()},
            "workers": {"status": "unavailable", "reason": "worker heartbeats are files inside each worker container; the API cannot read them. Check them with: docker compose ps (the worker health check reads the heartbeat)"},
        })

    def _migrations(self):
        db = getattr(self.repo, "db", None) or getattr(getattr(self.repo, "_inner", None), "db", None)
        if db is None:
            return None
        try:
            return {"week4": [r[:2] for r in db.query("SELECT version, name FROM soc.schema_migrations ORDER BY version")],
                    "week5": [r[:2] for r in db.query("SELECT version, name FROM soc.schema_migrations_week5 ORDER BY version")]}
        except DbError:
            return None

    def _get_diagnostics(self, principal, headers, query, path_params, body, raw_body):
        import week4
        from week4 import policy as w4_policy
        from week5 import evidence_policy
        from week5.api import app5
        try:
            risk = self.risk_policy or w4_policy.load_policy(None)
            ev = self.evidence or evidence_policy.load()
            policies = {"risk_policy": {"version": risk.version, "sha256": risk.sha256}, "evidence_policy": {"version": ev.version, "sha256": ev.sha256}}
        except w4_policy.PolicyError:
            policies = {"error": "a policy file could not be loaded"}
        try:
            chain = self.repo.verify_audit_chain()
        except DbError:
            chain = {"checked": False, "reason": "the store could not be reached"}
        migrations = self._migrations()
        return h.ok({"versions": {"api": app5.VERSION, "week4": week4.VERSION, "eve_adapter": eve.ADAPTER_VERSION}, "policies": policies, "audit_chain": chain,
                     "migrations": migrations if migrations is not None else {"status": "unavailable", "reason": "this repository does not expose its migration table"},
                     "settings": {k: v for k, v in self.settings.public().items() if k not in ("eval_report_dir", "memory_dir")}, "auth_mode": self.auth.mode})

    # ------------------------------------------------------------------ evaluation reports
    def _report_dir(self):
        d = self.eval_report_dir or self.settings.eval_report_dir
        return d if d and os.path.isdir(d) else None

    def _list_evaluation_reports(self, principal, headers, query, path_params, body, raw_body):
        d = self._report_dir()
        if d is None:
            return h.ok({"available": False, "items": [], "reason": "no evaluation report folder is configured or it does not exist (WEEK5_EVAL_REPORT_DIR)"})
        items = []
        for name in sorted(os.listdir(d)):
            if REPORT_NAME_RE.fullmatch(name) and os.path.isfile(os.path.join(d, name)):
                st = os.stat(os.path.join(d, name))
                items.append({"name": name, "bytes": st.st_size, "modified": int(st.st_mtime)})
        return h.ok({"available": True, "items": items})

    def _get_evaluation_report(self, principal, headers, query, path_params, body, raw_body):
        d = self._report_dir()
        name = path_params.get("name")
        if d is None or not isinstance(name, str) or not REPORT_NAME_RE.fullmatch(name):
            return h.error(404, "not_found", "no such report")
        path = os.path.join(d, name)
        if not os.path.isfile(path) or os.path.islink(path) or os.path.getsize(path) > REPORT_MAX_BYTES:
            return h.error(404, "not_found", "no such report")
        with open(path, "rb") as fh:
            raw = fh.read()
        if name.endswith(".json"):
            try:
                return h.ok({"name": name, "format": "json", "content": json.loads(raw.decode("utf-8"))})
            except (ValueError, UnicodeDecodeError):
                return h.error(422, "invalid_report", "the report file is not valid JSON")
        return h.ok({"name": name, "format": "markdown", "content": raw.decode("utf-8", "replace")})
