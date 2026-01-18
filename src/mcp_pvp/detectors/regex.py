"""Regex-based PII detector (fallback)."""

import re

from mcp_pvp.detectors.base import PIIDetector
from mcp_pvp.models import PIIDetection, PIIType

# Regex patterns for PII detection
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b|\b\d{3}[-.\s]?\d{4}\b"
)

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Credit card pattern (basic Luhn check not included for simplicity)
CC_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
)

# API key pattern (generic, high false positives)
API_KEY_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9]{32,})\b"  # Simple pattern for demonstration
)


class RegexDetector(PIIDetector):
    """Regex-based PII detector (fallback implementation)."""

    def __init__(self) -> None:
        """Initialize regex detector."""
        self.patterns = {
            PIIType.EMAIL: EMAIL_PATTERN,
            PIIType.PHONE: PHONE_PATTERN,
            PIIType.IPV4: IPV4_PATTERN,
            PIIType.CC: CC_PATTERN,
            # API_KEY disabled by default due to false positives
        }

    def detect(
        self,
        content: str,
        types: list[PIIType] | None = None,
    ) -> list[PIIDetection]:
        """
        Detect PII using regex patterns.

        Args:
            content: Text content to analyze
            types: List of PII types to detect (None = detect all)

        Returns:
            List of PIIDetection instances
        """
        if types is None:
            types = list(self.patterns.keys())

        detections: list[PIIDetection] = []

        for pii_type in types:
            pattern = self.patterns.get(pii_type)
            if pattern is None:
                continue

            for match in pattern.finditer(content):
                detection = PIIDetection(
                    pii_type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    confidence=0.8,  # Regex has lower confidence than ML models
                )
                detections.append(detection)

        # Sort by start position
        detections.sort(key=lambda d: d.start)

        return detections

    def supports_type(self, pii_type: PIIType) -> bool:
        """
        Check if detector supports a PII type.

        Args:
            pii_type: PII type

        Returns:
            True if supported, False otherwise
        """
        return pii_type in self.patterns
