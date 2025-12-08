# app/security/policy.py
from dataclasses import dataclass

@dataclass
class SecurityConfig:
    # Thresholds (0.0 to 1.0)
    injection_threshold: float
    toxicity_threshold: float
    pii_enabled: bool
    
    # Feature Toggles
    block_on_injection: bool = True
    block_on_jailbreak: bool = True

class SecurityPolicy:
    def __init__(self, level: str = "balanced"):
        self.level = level
        self.config = self._load_config(level)

    def _load_config(self, level: str) -> SecurityConfig:
        if level == "strict":
            return SecurityConfig(
                injection_threshold=0.5, # Low tolerance
                toxicity_threshold=0.5,
                pii_enabled=True
            )
        elif level == "permissive":
            return SecurityConfig(
                injection_threshold=0.9, # High tolerance
                toxicity_threshold=0.9,
                pii_enabled=False,
                block_on_injection=False # Just flag it
            )
        else: # "balanced" (Default)
            return SecurityConfig(
                injection_threshold=0.75,
                toxicity_threshold=0.7,
                pii_enabled=True
            )