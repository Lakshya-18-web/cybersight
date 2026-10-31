"""Threat-intelligence enrichment: the existing AbuseIPDB client (tools.reputation) wired into a case, optional and never required.

What is added around tools.reputation.ReputationTool (which is not edited):
  * a rolling daily call budget (the tool's own budget never resets, which would silence a long-running worker)
  * a lock, so two job threads share one cache and one count
  * a record per address with provenance: provider, status, reason, cache_hit, checked_at (UTC), the answer reduced to fields of a known shape (week5.untrusted.clean_provider_field)
  * a failure of any kind becomes a record with status "unavailable"; it never raises into the job
  * only the alert sets named in WEEK5_TI_ALERT_SETS are looked up (default: sensor). Labelled dev and synthetic data is never sent to a third party, so an evaluation makes no external call.

What the result may be used for: it is shown to the analyst (API and dashboard) and read by the evidence policy (rule E5) to RAISE caution. It is never given to the model, and a score of 0, a disabled provider,
a private address and a failed lookup all leave the decision exactly as it was. The API key comes from SOC_REPUTATION_API_KEY (the Week 3 name), is only ever put in the request header by the tool, and is
never stored, logged or returned: ThreatIntel has no attribute that holds it, and status() reports only whether one is configured.
Status values: ok | disabled (no key) | not_applicable (not a public address) | unavailable (timeout, error, budget) | skipped (alert set not enabled).
"""
import datetime
import threading
import time

from tools import reputation as rep

from . import untrusted

DEFAULT_ALERT_SETS = ("sensor",)
DEFAULT_DAILY_BUDGET = 500
STATUSES = ("ok", "disabled", "not_applicable", "unavailable", "skipped")
WINDOW_SECONDS = 24 * 3600


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThreatIntel:
    def __init__(self, tool=None, alert_sets=DEFAULT_ALERT_SETS, daily_budget=DEFAULT_DAILY_BUDGET, clock=time.monotonic, now=_utc_now):
        self._tool = tool if tool is not None else rep.ReputationTool(max_calls=10 ** 9)
        self._tool.max_calls = 10 ** 9              # the rolling budget below replaces the per-object lifetime budget
        self.alert_sets = tuple(alert_sets)
        self.daily_budget = int(daily_budget)
        self.clock, self.now = clock, now
        self._stamps = []
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, env=None):
        import os
        env = os.environ if env is None else env
        sets = tuple(s.strip() for s in (env.get("WEEK5_TI_ALERT_SETS") or ",".join(DEFAULT_ALERT_SETS)).split(",") if s.strip())
        bad = [s for s in sets if s not in ("dev", "synthetic", "sensor")]
        if bad:
            raise ValueError("WEEK5_TI_ALERT_SETS may name dev, synthetic or sensor")
        try:
            budget = int(env.get("WEEK5_TI_DAILY_BUDGET", DEFAULT_DAILY_BUDGET))
        except ValueError:
            budget = DEFAULT_DAILY_BUDGET
        return cls(rep.ReputationTool.from_env(env), sets, max(0, min(budget, 100000)))

    def __repr__(self):
        return "ThreatIntel(configured=%s, alert_sets=%s)" % (self.configured, list(self.alert_sets))

    @property
    def configured(self):
        return self._tool.enabled

    def applies_to(self, alert_set):
        return alert_set in self.alert_sets

    def _used(self):
        cutoff = self.clock() - WINDOW_SECONDS
        self._stamps = [t for t in self._stamps if t > cutoff]
        return len(self._stamps)

    def status(self):
        """Safe to return from the API: no key, no address."""
        with self._lock:
            return {"provider": rep.PROVIDER, "configured": self.configured, "alert_sets": list(self.alert_sets), "daily_budget": self.daily_budget, "used_last_24h": self._used(),
                    "timeout_seconds": self._tool.timeout, "cache_ttl_seconds": self._tool.cache.ttl, "cache_entries": len(self._tool.cache)}

    def _record(self, ip, role, answer=None, status=None, reason=None):
        a = answer or {}
        r = a.get("reputation") if isinstance(a.get("reputation"), dict) else None
        clean = None
        if r is not None:
            clean = {"abuse_confidence_score": untrusted.clean_provider_field("score", r.get("abuse_confidence_score")), "total_reports": untrusted.clean_provider_field("count", r.get("total_reports")),
                     "last_reported_at": untrusted.clean_provider_field("time", r.get("last_reported_at")), "country_code": untrusted.clean_provider_field("country", r.get("country_code")),
                     "usage_type": untrusted.clean_provider_field("usage_type", r.get("usage_type")), "is_whitelisted": untrusted.clean_provider_field("flag", r.get("is_whitelisted"))}
            if clean["abuse_confidence_score"] is None:          # an answer without a usable score is not an answer
                clean, status, reason = None, "unavailable", "the provider's answer had no usable score"
        st = status or a.get("status") or "unavailable"
        return {"ip": ip, "role": role, "provider": rep.PROVIDER, "status": st if st in STATUSES else "unavailable", "reason": reason if reason is not None else a.get("reason"),
                "cache_hit": bool(a.get("cache_hit")), "checked_at": self.now(), "reputation": clean if st == "ok" else None, "source": rep.SOURCE_NOTE}

    def lookup_one(self, ip, role):
        try:
            with self._lock:
                cached = self._tool.cache.get(ip) if self.configured else None
                if self.configured and cached is None and self._used() >= self.daily_budget and rep.classify_ip(ip)[1] == "external":
                    return self._record(ip, role, status="unavailable", reason="the daily call budget is used up")
                before = self._tool.calls_made
                answer = self._tool.lookup({"ip": ip})
                if self._tool.calls_made > before:
                    self._stamps.append(self.clock())
            return self._record(ip, role, answer)
        except Exception as error:                  # never into the job
            return self._record(ip, role, status="unavailable", reason="the lookup failed (%s)" % type(error).__name__)

    def lookup_alert(self, alert, alert_set):
        """-> list of records (source then destination, one each when they differ). [] is returned only when the alert set is not enabled: then one 'skipped' record explains why."""
        if not self.applies_to(alert_set):
            return [self._record(alert["src_ip"], "src", status="skipped", reason="threat-intelligence lookups are not enabled for %s alerts" % alert_set)]
        out, seen = [], set()
        for role, ip in (("src", alert["src_ip"]), ("dst", alert["dst_ip"])):
            if ip in seen:
                continue
            seen.add(ip)
            out.append(self.lookup_one(ip, role))
        return out


def evidence_items(records, first_ordinal):
    """The stored form: one 'tool_call' evidence item per record, source 'reputation_lookup'. payload.data.status is what the provider-health query reads."""
    import hashlib
    import json
    items = []
    for i, r in enumerate(records):
        payload = {"index": first_ordinal + i, "tool": "reputation_lookup", "arguments": {"ip": r["ip"]}, "ok": True, "error": None, "data": r, "evidence_class": "external_enrichment"}
        items.append({"kind": "tool_call", "ordinal": first_ordinal + i, "source": "reputation_lookup", "payload": payload,
                      "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()})
    return items
