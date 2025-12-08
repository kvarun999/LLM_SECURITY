# app/security/output_validator.py
from typing import List, Callable
from .types import AnalysisResult, SecurityAction
from .policy import SecurityPolicy

class OutputValidator:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.scrubbers: List[Callable[[str], AnalysisResult]] = []

    def register_scrubber(self, scrubber_func: Callable[[str], AnalysisResult]):
        self.scrubbers.append(scrubber_func)

    def evaluate(self, response_text: str) -> AnalysisResult:
        """
        Runs the response through scrubbers.
        Unlike InputValidator, this typically prioritizes Sanitization over Blocking.
        """
        current_text = response_text
        metadata_agg = {}

        for scrubber in self.scrubbers:
            result = scrubber(current_text)

            if result.action == SecurityAction.BLOCK:
                return result
            
            if result.action == SecurityAction.SANITIZE and result.sanitized_content:
                current_text = result.sanitized_content
                # Collect metadata (e.g., "Redacted 2 emails")
                metadata_agg.update(result.metadata)

        return AnalysisResult(
            action=SecurityAction.ALLOW, 
            sanitized_content=current_text,
            metadata=metadata_agg
        )