"""Week 3 tool layer: infrastructure for the agent system. No LLM calls, no graph logic, no verdicts.

Tools: query_flows, summarize_flows, beacon_stats, ip_info, port_info, service_lookup, reputation_lookup (optional), mitre_lookup, mitre_search.
Entry point: tools.registry.build_registry(...). See tools/registry.py.
"""
from .base import ToolSpec, ToolFailure
from .flow_query import FlowStore, FlowTools
from .enrichment import EnrichmentTools, classify_ip
from .reputation import ReputationTool
from .mitre_lookup import MitreTools
from .registry import ToolRegistry, build_registry

__all__ = ["ToolSpec", "ToolFailure", "FlowStore", "FlowTools", "EnrichmentTools", "classify_ip", "ReputationTool", "MitreTools", "ToolRegistry", "build_registry"]
