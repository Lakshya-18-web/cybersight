"""Day 2 verdict format: the five blueprint fields, nothing else.

  is_malicious    true or false (a real JSON boolean, not the text "true")
  attack_type     BENIGN or one of the 11 Week 1 attack classes
  mitre_technique ATT&CK technique id such as T1046 or T1071.001, or NONE for benign
  severity        none, low, medium, high or critical
  evidence        short text citing the flow facts behind the verdict (required)

The alert id is not part of the model's answer. The runner (Day 3) keeps it next to the verdict.
This module does not import or read labels, the MITRE answer key or any evaluation file. Technique ids are
checked for format only; whether a technique is the right one for an attack class is scored by the harness (Day 4).
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

AttackType = Literal[
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "FTP-Patator",
    "PortScan",
    "SSH-Patator",
    "Web Attack - Brute Force",
    "Web Attack - XSS/SQLi",
]
Severity = Literal["none", "low", "medium", "high", "critical"]

ATTACK_TYPES = list(AttackType.__args__)
SEVERITIES = list(Severity.__args__)
FIELDS = ["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"]
MITRE_TECHNIQUE_PATTERN = r"^(NONE|T\d{4}(\.\d{3})?)$"
EVIDENCE_MAX_CHARS = 600


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    is_malicious: StrictBool
    attack_type: AttackType
    mitre_technique: str = Field(pattern=MITRE_TECHNIQUE_PATTERN)
    severity: Severity
    evidence: str = Field(min_length=1, max_length=EVIDENCE_MAX_CHARS)

    @model_validator(mode="after")
    def fields_agree(self):
        benign = self.attack_type == "BENIGN"
        if self.is_malicious and benign:
            raise ValueError("is_malicious is true but attack_type is BENIGN")
        if not self.is_malicious and not benign:
            raise ValueError("is_malicious is false but attack_type is an attack class")
        if benign and self.mitre_technique != "NONE":
            raise ValueError("BENIGN requires mitre_technique NONE")
        if not benign and self.mitre_technique == "NONE":
            raise ValueError("an attack class requires a technique id, not NONE")
        if benign and self.severity != "none":
            raise ValueError("BENIGN requires severity none")
        if not benign and self.severity == "none":
            raise ValueError("an attack class requires severity low, medium, high or critical")
        return self
