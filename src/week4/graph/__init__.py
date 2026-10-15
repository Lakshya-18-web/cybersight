"""Graph v2: the frozen Week 3 agent graph plus ONE optional step, incident memory, between the specialists and the verdict step.

New modules only. Nothing under src/agents or src/tools is edited; v1 nodes, the v1 supervisor rules and the v1 verdict node are imported and reused.
With memory off, routing, evidence, findings, prompt (agent_v1, same bytes) and verdict handling are the same as graph v0.1; only two extra state fields exist (memory_enabled, memory).
"""
