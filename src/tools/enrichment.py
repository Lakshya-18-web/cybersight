"""Enrichment tools: what an address, a port or a service name is. Deterministic, offline, no external call.

  ip_info         address type from the address itself (private, public, loopback, ...), plus how often the flow store has seen it
  port_info       port range and the curated services known for a port
  service_lookup  ports and description for a service name

The IP tool classifies by address range only (RFC 1918 and the other special ranges). It carries no list of known attacker or victim
addresses, because the evaluation sets must not be solvable by recognising addresses. The reference tables are in reference_data.py.
"""
import ipaddress

from . import reference_data as ref
from .base import P, ToolSpec, ToolFailure, CODE_NOT_FOUND

_V4_RANGES = [
    ("0.0.0.0/8", "this_network", "special"),
    ("10.0.0.0/8", "private_rfc1918", "internal"),
    ("172.16.0.0/12", "private_rfc1918", "internal"),
    ("192.168.0.0/16", "private_rfc1918", "internal"),
    ("100.64.0.0/10", "shared_address_space", "special"),
    ("127.0.0.0/8", "loopback", "special"),
    ("169.254.0.0/16", "link_local", "special"),
    ("192.0.0.0/24", "ietf_protocol_assignments", "special"),
    ("192.0.2.0/24", "documentation", "special"),
    ("198.51.100.0/24", "documentation", "special"),
    ("203.0.113.0/24", "documentation", "special"),
    ("198.18.0.0/15", "benchmarking", "special"),
    ("224.0.0.0/4", "multicast", "special"),
    ("240.0.0.0/4", "reserved", "special"),
]
_V6_RANGES = [
    ("::/128", "unspecified", "special"),
    ("::1/128", "loopback", "special"),
    ("fc00::/7", "private_unique_local", "internal"),
    ("fe80::/10", "link_local", "special"),
    ("ff00::/8", "multicast", "special"),
    ("2001:db8::/32", "documentation", "special"),
]
_PARSED_V4 = [(ipaddress.ip_network(n), t, s) for n, t, s in _V4_RANGES]
_PARSED_V6 = [(ipaddress.ip_network(n), t, s) for n, t, s in _V6_RANGES]


def classify_ip(text):
    """(address_type, scope) for a valid address string. scope: internal, external or special."""
    address = ipaddress.ip_address(text)
    if address.version == 4 and int(address) == 0xFFFFFFFF:
        return "broadcast", "special"
    for network, kind, scope in (_PARSED_V4 if address.version == 4 else _PARSED_V6):
        if address in network:
            return kind, scope
    if address.is_global:
        return "public", "external"
    return "reserved", "special"


def port_category(port):
    if port == 0:
        return "reserved"
    if port <= ref.WELL_KNOWN_MAX:
        return "well_known"
    if port <= ref.REGISTERED_MAX:
        return "registered"
    return "dynamic_private"


class EnrichmentTools:
    def __init__(self, store=None):
        """store: optional FlowStore. If given, ip_info also reports how often the address appears in it."""
        self.store = store

    def ip(self, c):
        address = ipaddress.ip_address(c["ip"])
        kind, scope = classify_ip(c["ip"])
        out = {"ip": str(address), "version": address.version, "address_type": kind, "scope": scope, "is_global": bool(address.is_global),
               "observed_in_flow_store": None}
        if self.store is not None:
            out["observed_in_flow_store"] = self.store.host_summary(str(address))
        return out

    def port(self, c):
        port, protocol = c["port"], c["protocol"]
        protocols = [protocol] if protocol else ["tcp", "udp"]
        services = []
        for proto in protocols:
            for name in ref.PORTS.get((port, proto), []):
                services.append({"service": name, "protocol": proto, "description": ref.SERVICES[name]["description"]})
        return {"port": port, "protocol_filter": protocol, "category": port_category(port), "in_curated_table": len(services) > 0, "services": services,
                "source": ref.SOURCE_NOTE,
                "note": None if services else "not in the curated table; that says nothing about what the port is used for"}

    def service(self, c):
        key = c["name"].strip().lower()
        if key in ref.SERVICES:
            return {"query": c["name"], "match": "exact", "services": [ref.SERVICES[key]], "source": ref.SOURCE_NOTE}
        if key in ref.ALIASES:
            return {"query": c["name"], "match": "alias", "services": [ref.SERVICES[ref.ALIASES[key]]], "source": ref.SOURCE_NOTE}
        found = sorted({n for n in ref.SERVICES if key in n} | {ref.ALIASES[a] for a in ref.ALIASES if key in a})
        if not found:
            raise ToolFailure(CODE_NOT_FOUND, "no service named '" + c["name"] + "' in the curated table")
        return {"query": c["name"], "match": "partial", "services": [ref.SERVICES[n] for n in found[:5]], "source": ref.SOURCE_NOTE}

    def specs(self):
        return [
            ToolSpec("ip_info", "Classify an IP address by range (private, public, loopback, multicast, ...) and, if a flow store is attached, "
                     "report how many flows in the store have it as source or destination. Works from the address alone.",
                     {"ip": P("ip", "IPv4 or IPv6 address.", required=True)}, self.ip),
            ToolSpec("port_info", "Say which IANA port range a port is in and which well-known services use it (curated table).",
                     {"port": P("integer", "Port number.", required=True, minimum=0, maximum=65535),
                      "protocol": P("enum", "Restrict to one transport protocol.", enum=["tcp", "udp"])}, self.port),
            ToolSpec("service_lookup", "Look up a service by name (for example 'ssh' or 'rdp') and return its usual ports and a short description (curated table).",
                     {"name": P("string", "Service name or alias.", required=True, max_length=50)}, self.service),
        ]
