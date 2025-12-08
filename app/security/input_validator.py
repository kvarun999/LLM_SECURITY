# app/security/input_validator.py
from typing import List, Callable
from .types import AnalysisResult, SecurityAction
from .policy import SecurityPolicy

class InputValidator:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.detectors: List[Callable[[str], AnalysisResult]] = []

    def register_detector(self, detector_func: Callable[[str], AnalysisResult]):
        """Add a detector function to the pipeline."""
        self.detectors.append(detector_func)

    def evaluate(self, prompt: str) -> AnalysisResult:
        """
        Runs the prompt through all detectors in order.
        Stops immediately if a BLOCK action is returned (Fail-Fast).
        """
        current_prompt = prompt

        for detector in self.detectors:
            result = detector(current_prompt)

            # 1. IMMEDIATE BLOCK
            if result.action == SecurityAction.BLOCK:
                return result
            
            # 2. SANITIZATION (Update the prompt for the next detector)
            if result.action == SecurityAction.SANITIZE and result.sanitized_content:
                current_prompt = result.sanitized_content
        
        # If we survive all detectors
        return AnalysisResult(action=SecurityAction.ALLOW, sanitized_content=current_prompt)