"""Fixed triage-output contract for Week 2 (and later weeks).

One TriageVerdict is what the model returns for one alert. The model's input is one alert row plus its
label-free flow-store context. Labels, the MITRE answer key (config.MITRE_MAP, eval/mitre_map.csv) and the
dev/frozen label files are never part of that input, and this module does not import or read any of them.

Rules enforced here:
  - the output has exactly these seven fields and nothing else
  - verdict "false_positive" goes with attack_type BENIGN, and "true_positive" with one of the 11 attack classes
  - mitre_technique is an ATT&CK technique id such as T1071 or T1071.001, or NONE for BENIGN
  - confidence is a number from 0 to 1
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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

# T1071 or T1071.001, or NONE when the alert is benign.
MITRE_TECHNIQUE_PATTERN = r"^(NONE|T\d{4}(\.\d{3})?)$"


class TriageVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str = Field(min_length=1, max_length=64, description="Copied unchanged from the input alert.")
    verdict: Literal["true_positive", "false_positive"]
    attack_type: AttackType
    mitre_technique: str = Field(pattern=MITRE_TECHNIQUE_PATTERN, description="ATT&CK technique id, or NONE for BENIGN.")
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1, max_length=600, description="Short: which flow evidence supports the verdict.")
    recommended_action: str = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def verdict_matches_attack_type(self):
        benign = self.attack_type == "BENIGN"
        if self.verdict == "false_positive" and not benign:
            raise ValueError("verdict false_positive requires attack_type BENIGN")
        if self.verdict == "true_positive" and benign:
            raise ValueError("verdict true_positive requires an attack class, not BENIGN")
        if benign and self.mitre_technique != "NONE":
            raise ValueError("BENIGN requires mitre_technique NONE")
        if not benign and self.mitre_technique == "NONE":
            raise ValueError("an attack class requires a technique id, not NONE")
        return self


ATTACK_TYPES = list(AttackType.__args__)
