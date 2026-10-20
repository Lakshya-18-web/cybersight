"""Fake models for the rehearsal and the tests. They exist so the whole evaluation pipeline can be exercised end to end without a network, a key, money or protected data.
Their replies are SCRIPTED from the synthetic fixture's own pattern (see data.fixture_data); a rehearsal's metrics describe the script, never any real system."""
import json

import gemini_client

from week5 import models

ATTACK = {0: ("Bot", "T1071"), 1: ("PortScan", "T1046")}
WRONG_EVERY = 6                 # every 6th alert gets a deliberately wrong verdict, so the metrics are not all-perfect
MALFORMED_AT = (4, 13)          # these alerts first get an unusable reply, then a good one (exercises the retry path)


def _verdict(index):
    wrong = index % WRONG_EVERY == WRONG_EVERY - 1
    attack = (index % 4) in ATTACK
    if wrong:
        attack = not attack
    if attack:
        label, mitre = ATTACK.get(index % 4, ("PortScan", "T1046"))
        return {"is_malicious": True, "attack_type": label, "mitre_technique": mitre, "severity": "high", "evidence": "FAKE scripted reply"}
    return {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "FAKE scripted reply"}


def baseline_script(n):
    """Reply texts in the order the baseline will ask for them (one per alert, two for the MALFORMED_AT alerts)."""
    out = []
    for i in range(n):
        if i in MALFORMED_AT:
            out.append("this is not json")
        out.append(json.dumps(_verdict(i)))
    return out


class ScriptedClient:
    """Stands in for gemini_client.GeminiClient: generate(prompt) -> CallRecord. Reports NO token counts (fields None): none are invented."""

    model = "FAKE:rehearsal"
    config = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42}

    def __init__(self, replies):
        self.replies, self.i = list(replies), 0

    def generate(self, prompt):
        text = self.replies[self.i % len(self.replies)]
        self.i += 1
        return gemini_client.CallRecord(text=text, finish_reason="STOP", block_reason=None, prompt_tokens=None, output_tokens=None, thinking_tokens=None, total_tokens=None)


def full_system_provider(alert_ids):
    """A week5 FakeModel with a scenario per alert id: the canned attack reply for scripted attacks, benign otherwise, one malformed and one outage."""
    table = {}
    for i, alert_id in enumerate(alert_ids):
        v = _verdict(i)
        table[alert_id] = "ok_attack" if v["is_malicious"] else "ok_benign"
    if len(alert_ids) > 5:
        table[alert_ids[5]] = "malformed"
    if len(alert_ids) > 11:
        table[alert_ids[11]] = "unavailable"
    return RehearsalProvider(scenario_for=table)


class RehearsalProvider(models.FakeModel):
    name = "FAKE:rehearsal"
    observed_settings = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42}
