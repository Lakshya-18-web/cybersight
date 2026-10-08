"""Optional IP reputation tool.

Off unless a key is configured (environment variable SOC_REPUTATION_API_KEY) or a fetch function is passed in. Normal tests never use the network:
they pass a fake fetch function. When it is off, or the service is down, slow or answers badly, the tool still returns a normal result whose
status says so (disabled, unavailable), so an agent can carry on without it.

Controls on external calls:
  - one fixed provider host (api.abuseipdb.com, HTTPS); the address being checked is the only value sent, in the query string
  - only public addresses are ever sent: private, loopback, multicast and other special addresses return status not_applicable
  - a timeout on every request (default 5 s, at most 15 s) and a cap on the size of the answer read
  - an in-memory cache with a time limit, and a short cache of failures so a dead service is not hammered
  - a budget of calls per tool object (default 100); after that the tool answers unavailable
  - the key is only sent as a request header and is never stored in a result, an error message or the repr
"""
import os
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import P, ToolSpec
from .enrichment import classify_ip

ENV_KEY = "SOC_REPUTATION_API_KEY"
ENV_TIMEOUT = "SOC_REPUTATION_TIMEOUT"
PROVIDER = "abuseipdb"
API_HOST = "api.abuseipdb.com"
API_PATH = "/api/v2/check"
MAX_AGE_DAYS = 90
DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 15.0
DEFAULT_TTL = 24 * 3600
FAILURE_TTL = 60
DEFAULT_BUDGET = 100
MAX_RESPONSE_BYTES = 65536
SOURCE_NOTE = "third-party reputation score; a score is evidence to weigh, not a verdict"


class ReputationFetchError(Exception):
    """A fetch function raises this for any failure. The message must not contain the key."""


class TTLCache:
    def __init__(self, ttl_seconds=DEFAULT_TTL, max_entries=1000, clock=time.monotonic):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self.clock = clock
        self.items = {}

    def get(self, key):
        entry = self.items.get(key)
        if entry is None:
            return None
        expires, value = entry
        if self.clock() >= expires:
            del self.items[key]
            return None
        return value

    def put(self, key, value, ttl=None):
        if len(self.items) >= self.max_entries and key not in self.items:
            oldest = min(self.items, key=lambda k: self.items[k][0])
            del self.items[oldest]
        self.items[key] = (self.clock() + (self.ttl if ttl is None else ttl), value)

    def __len__(self):
        return len(self.items)


def make_abuseipdb_fetch(api_key):
    """The default fetch function. Only called when a key is configured. Returns a normalised dict or raises ReputationFetchError."""
    def fetch(ip, timeout):
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS})
        url = "https://" + API_HOST + API_PATH + "?" + query
        request = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise ReputationFetchError("the reputation service answered HTTP " + str(error.code))
        except urllib.error.URLError as error:
            raise ReputationFetchError("the reputation service could not be reached (" + type(error.reason).__name__ + ")")
        except (TimeoutError, OSError) as error:
            raise ReputationFetchError("the reputation request failed (" + type(error).__name__ + ")")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ReputationFetchError("the reputation answer was too large")
        try:
            data = json.loads(raw.decode("utf-8"))["data"]
            return {"abuse_confidence_score": int(data["abuseConfidenceScore"]), "total_reports": int(data.get("totalReports", 0)),
                    "last_reported_at": data.get("lastReportedAt"), "country_code": data.get("countryCode"), "usage_type": data.get("usageType"),
                    "is_whitelisted": data.get("isWhitelisted")}
        except (ValueError, KeyError, TypeError):
            raise ReputationFetchError("the reputation answer could not be read")
    return fetch


class ReputationTool:
    def __init__(self, api_key=None, fetch=None, timeout=DEFAULT_TIMEOUT, ttl_seconds=DEFAULT_TTL, max_calls=DEFAULT_BUDGET, clock=time.monotonic):
        self._api_key = api_key or None
        self.timeout = min(max(float(timeout), 0.5), MAX_TIMEOUT)
        self.fetch = fetch if fetch is not None else (make_abuseipdb_fetch(self._api_key) if self._api_key else None)
        self.cache = TTLCache(ttl_seconds, clock=clock)
        self.max_calls = max_calls
        self.calls_made = 0

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        try:
            timeout = float(env.get(ENV_TIMEOUT, DEFAULT_TIMEOUT))
        except ValueError:
            timeout = DEFAULT_TIMEOUT
        return cls(api_key=(env.get(ENV_KEY) or "").strip() or None, timeout=timeout)

    def __repr__(self):
        return "ReputationTool(enabled=" + str(self.enabled) + ", calls_made=" + str(self.calls_made) + ")"

    @property
    def enabled(self):
        return self.fetch is not None

    def _answer(self, ip, status, reason=None, reputation=None, cache_hit=False):
        return {"ip": ip, "status": status, "reason": reason, "provider": PROVIDER, "cache_hit": cache_hit, "reputation": reputation, "source": SOURCE_NOTE}

    def lookup(self, c):
        ip = c["ip"]
        if classify_ip(ip)[1] != "external":
            return self._answer(ip, "not_applicable", "only public addresses are sent to the external service")
        if not self.enabled:
            return self._answer(ip, "disabled", "no reputation key is configured (" + ENV_KEY + ")")
        cached = self.cache.get(ip)
        if cached is not None:
            return self._answer(ip, cached["status"], cached["reason"], cached["reputation"], cache_hit=True)
        if self.calls_made >= self.max_calls:
            return self._answer(ip, "unavailable", "the call budget for this run is used up")
        self.calls_made += 1
        try:
            reputation = self.fetch(ip, self.timeout)
        except ReputationFetchError as error:
            self.cache.put(ip, {"status": "unavailable", "reason": str(error), "reputation": None}, ttl=FAILURE_TTL)
            return self._answer(ip, "unavailable", str(error))
        except Exception as error:  # a broken fetch function must not break the agent
            self.cache.put(ip, {"status": "unavailable", "reason": "the reputation lookup failed (" + type(error).__name__ + ")", "reputation": None}, ttl=FAILURE_TTL)
            return self._answer(ip, "unavailable", "the reputation lookup failed (" + type(error).__name__ + ")")
        self.cache.put(ip, {"status": "ok", "reason": None, "reputation": reputation})
        return self._answer(ip, "ok", None, reputation)

    def specs(self):
        return [ToolSpec("reputation_lookup", "Optional third-party reputation score for a public IP address. Returns status 'disabled' when no key is configured, "
                         "'not_applicable' for private or special addresses, and 'unavailable' on a timeout or error. Never required; never a verdict.",
                         {"ip": P("ip", "Public IPv4 or IPv6 address.", required=True)}, self.lookup)]
