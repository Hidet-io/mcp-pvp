"""Base detector interface."""

from abc import ABC, abstractmethod

from mcp_pvp.models import PIIDetection, PIIType


class PIIDetector(ABC):
    """Abstract PII detector interface."""

    @abstractmethod
    def detect(
        self,
        content: str,
        types: list[PIIType] | None = None,
    ) -> list[PIIDetection]:
        """
        Detect PII in content.

        Args:
            content: Text content to analyze
            types: List of PII types to detect (None = detect all)

        Returns:
            List of PIIDetection instances
        """
        pass

    @abstractmethod
    def supports_type(self, pii_type: PIIType) -> bool:
        """
        Check if detector supports a PII type.

        Args:
            pii_type: PII type

        Returns:
            True if supported, False otherwise
        """
        pass
