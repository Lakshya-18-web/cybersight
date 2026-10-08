"""The tool registry: one place that lists the Week 3 tools, describes them to a model, and runs a call by name.

    registry = build_registry(flow_store=FlowStore.from_dev())        # reputation stays off
    registry = build_registry(flow_store=store, reputation=ReputationTool.from_env())   # opt in to the optional reputation tool
    registry.declarations()                                           # JSON-Schema tool descriptions for a model
    registry.call("port_info", {"port": 22})                          # result envelope, never raises

Day 3's graph imports this module. The tools hold no LLM call, no graph state and make no verdict.
"""
from .base import ToolSpec, error_result, CODE_UNKNOWN_TOOL
from .flow_query import FlowTools
from .enrichment import EnrichmentTools
from .reputation import ReputationTool
from .mitre_lookup import MitreTools


class ToolRegistry:
    def __init__(self, specs):
        self._specs = {}
        for spec in specs:
            if not isinstance(spec, ToolSpec):
                raise TypeError("a registry holds ToolSpec objects")
            if spec.name in self._specs:
                raise ValueError("duplicate tool name: " + spec.name)
            self._specs[spec.name] = spec

    def names(self):
        return sorted(self._specs)

    def get(self, name):
        return self._specs.get(name)

    def declarations(self):
        """Tool descriptions (name, description, JSON-Schema parameters), sorted by name."""
        return [self._specs[name].declaration() for name in self.names()]

    def call(self, name, arguments=None):
        spec = self._specs.get(name) if isinstance(name, str) else None
        if spec is None:
            return error_result(str(name)[:60], CODE_UNKNOWN_TOOL, "no tool named '" + str(name)[:60] + "'. Available: " + ", ".join(self.names()))
        return spec.run(arguments)


def build_registry(flow_store=None, reputation=None):
    """flow_store: a FlowStore (the flow tools answer 'unavailable' without one). reputation: a ReputationTool; default is a switched-off one."""
    reputation = reputation if reputation is not None else ReputationTool()
    specs = []
    specs += FlowTools(flow_store).specs()
    specs += EnrichmentTools(flow_store).specs()
    specs += reputation.specs()
    specs += MitreTools().specs()
    return ToolRegistry(specs)
