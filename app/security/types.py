# app/security/types.py
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

class ThreatType(Enum):
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    SYSTEM_LEAK = "system_leak"
    TOXICITY = "toxicity"

class SecurityAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    FLAG = "flag"  # Allow but log a warning

@dataclass
class AnalysisResult:
    action: SecurityAction
    threat_type: ThreatType = ThreatType.NONE
    message: str = "Safe"
    sanitized_content: Optional[str] = None
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)