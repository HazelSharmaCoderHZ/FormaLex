from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    detected: bool
    attack_type: Optional[str]
    rule: Optional[str]
    explanation: Optional[str]