# app/security/detectors/regex_detector.py
import re
from typing import List, Tuple
from ..types import AnalysisResult, ThreatType, SecurityAction

class RegexDetector:
    def __init__(self):
        # We compile these patterns once when the server starts for performance.
        # Format: (Regex Pattern, Threat Type, Failure Message)
        self.patterns: List[Tuple[re.Pattern, ThreatType, str]] = [
            
            # --- Category 1: Direct Prompt Injection ---
            (re.compile(r"ignore (previous|all|the) instructions", re.IGNORECASE), 
             ThreatType.PROMPT_INJECTION, 
             "Detected attempt to override system instructions."),
            
            (re.compile(r"forget (all|the) instructions", re.IGNORECASE), 
             ThreatType.PROMPT_INJECTION, 
             "Detected attempt to clear system memory."),

            # --- Category 2: Jailbreaks (DAN / Roleplay) ---
            # \b matches "word boundaries" so we don't match parts of other words
            (re.compile(r"\b(act|operate) as (an? )?unfiltered", re.IGNORECASE), 
             ThreatType.JAILBREAK, 
             "Detected 'Unfiltered Persona' jailbreak attempt."),
            
            (re.compile(r"\byou are (now )?do anything now\b", re.IGNORECASE), 
             ThreatType.JAILBREAK, 
             "Detected 'DAN' (Do Anything Now) jailbreak signature."),
            
            (re.compile(r"\bignore (safety|security|ethical) (guidelines|protocols)\b", re.IGNORECASE),
             ThreatType.JAILBREAK,
             "Detected attempt to bypass safety protocols."),

            # --- Category 3: System Prompt Leakage ---
            (re.compile(r"(repeat|print|reveal|show) (the|your) (system|initial) (prompt|instructions)", re.IGNORECASE), 
             ThreatType.SYSTEM_LEAK, 
             "Detected attempt to extract system prompt."),
        ]

    def _normalize(self, text: str) -> str:
        """
        Cleans the input to make it harder to hide attacks.
        1. Converts to lowercase.
        2. Replaces newlines/tabs with spaces.
        3. Collapses multiple spaces into one.
        """
        text = text.lower()
        # Replace any whitespace character (\s) with a single space
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def scan(self, prompt: str) -> AnalysisResult:
        """
        Checks the prompt against known attack signatures.
        """
        # 1. Normalize first to catch "I g n o r e"
        clean_prompt = self._normalize(prompt)

        # 2. Check all patterns
        for pattern, threat_type, message in self.patterns:
            if pattern.search(clean_prompt):
                return AnalysisResult(
                    action=SecurityAction.BLOCK,
                    threat_type=threat_type,
                    message=message,
                    metadata={"matched_pattern": pattern.pattern}
                )

        # 3. If no patterns match, pass.
        return AnalysisResult(action=SecurityAction.ALLOW)