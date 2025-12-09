# app/security/middleware.py
from typing import Dict, Any
from .policy import SecurityPolicy
from .input_validator import InputValidator
from .output_validator import OutputValidator
from .types import SecurityAction
from .detectors.regex_detector import RegexDetector
from .detectors.pii_detector import PIIDetector
from .detectors.embedding_detector import EmbeddingDetector

class LLMSecurityMiddleware:
    def __init__(self, policy_level: str = "balanced"):
        self.policy = SecurityPolicy(level=policy_level)
        self.input_validator = InputValidator(self.policy)
        self.output_validator = OutputValidator(self.policy)
        
        self._setup_detectors()

    def _setup_detectors(self):
        # 1. INPUT: Regex (Fastest)
        regex_detector = RegexDetector()
        self.input_validator.register_detector(regex_detector.scan)

        # 2. INPUT: Semantic (Slower but smarter)
        # CHANGE: Set threshold to 0.5 to catch "System Override" (which scored 0.54)
        embedding_detector = EmbeddingDetector(threshold=0.5) 
        self.input_validator.register_detector(embedding_detector.scan)

        # 3. OUTPUT: PII
        pii_detector = PIIDetector()
        self.output_validator.register_scrubber(pii_detector.scan)

    def process_input(self, prompt: str) -> Dict[str, Any]:
        """Validates the user prompt before sending to LLM."""
        result = self.input_validator.evaluate(prompt)

        if result.action == SecurityAction.BLOCK:
            return {
                "allow": False,
                "message": f"Blocked: {result.message}",
                "metadata": result.metadata
            }
        
        return {
            "allow": True,
            "prompt": result.sanitized_content or prompt,
            "metadata": result.metadata
        }

    def process_output(self, response_text: str) -> Dict[str, Any]:
        """Validates the LLM response before sending to User."""
        result = self.output_validator.evaluate(response_text)

        if result.action == SecurityAction.BLOCK:
            return {
                "allow": False,
                "message": "Response blocked due to security policy.",
                "metadata": result.metadata
            }

        return {
            "allow": True,
            "response": result.sanitized_content or response_text,
            "metadata": result.metadata
        }