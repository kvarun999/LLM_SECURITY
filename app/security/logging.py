# app/security/logging.py
from datetime import datetime
from typing import Optional, Dict, Any
import hashlib

from .types import ThreatType, ActionType


class SecurityLogger:
    def __init__(self):
        # later: accept log file path, external logger, etc.
        pass

    def _hash_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def log_event(
        self,
        threat_type: ThreatType,
        action: ActionType,
        original_text: str,
        sanitized_text: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "threat_type": threat_type.value,
            "action": action.value,
            "original_prompt_hash": self._hash_text(original_text),
            "sanitized_output": sanitized_text,
            "extra": extra or {},
        }
        # For now, just print; later, integrate with structured logging
        print(event)
        return event
