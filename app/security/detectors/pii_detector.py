# app/security/detectors/pii_detector.py
import re
from typing import List, Tuple
from ..types import AnalysisResult, ThreatType, SecurityAction

class PIIDetector:
    def __init__(self):
        # Format: (Regex Pattern, Redaction Placeholder, Threat Type)
        self.patterns: List[Tuple[re.Pattern, str, ThreatType]] = [
            
            # 1. Email Addresses
            # Looks for: name@domain.com
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), 
             "<EMAIL_REDACTED>", 
             ThreatType.PII),

            # 2. US/Intl Phone Numbers
            # Looks for: (123) 456-7890, 123-456-7890, +1 555...
            (re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), 
             "<PHONE_REDACTED>", 
             ThreatType.PII),

            # 3. AWS Access Key ID (High Confidence)
            # Starts with AKIA, usually 20 chars
            (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 
             "<AWS_KEY_REDACTED>", 
             ThreatType.PII),

            # 4. Generic API Key / Private Token indicators
            # Looks for sk- (OpenAI), ghp_ (GitHub), etc. followed by long alphanumeric
            (re.compile(r'\b(sk-|ghp_|hk_)[a-zA-Z0-9]{20,}\b'), 
             "<API_KEY_REDACTED>", 
             ThreatType.PII),
        ]

    def scan(self, text: str) -> AnalysisResult:
        """
        Scans text for PII and returns a SANITIZED version.
        """
        current_text = text
        redaction_count = 0
        found_threats = []

        for pattern, placeholder, threat_type in self.patterns:
            # Check if pattern exists
            if pattern.search(current_text):
                # Count matches for metadata
                matches = pattern.findall(current_text)
                redaction_count += len(matches)
                found_threats.append(threat_type.value)
                
                # Perform the replacement (Redaction)
                current_text = pattern.sub(placeholder, current_text)

        if redaction_count > 0:
            return AnalysisResult(
                action=SecurityAction.SANITIZE,
                threat_type=ThreatType.PII,
                message=f"Redacted {redaction_count} PII items.",
                sanitized_content=current_text,
                metadata={
                    "redaction_count": redaction_count,
                    "threats_found": list(set(found_threats))
                }
            )
        
        # If nothing found, return ALLOW
        return AnalysisResult(action=SecurityAction.ALLOW)