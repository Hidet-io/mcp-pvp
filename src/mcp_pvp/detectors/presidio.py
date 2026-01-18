"""Presidio-based PII detector (optional)."""

from mcp_pvp.detectors.base import PIIDetector
from mcp_pvp.errors import DetectionError
from mcp_pvp.models import PIIDetection, PIIType

# Mapping from Presidio entity types to PIIType
PRESIDIO_ENTITY_MAP = {
    "EMAIL_ADDRESS": PIIType.EMAIL,
    "PHONE_NUMBER": PIIType.PHONE,
    "IP_ADDRESS": PIIType.IPV4,
    "CREDIT_CARD": PIIType.CC,
    "API_KEY": PIIType.API_KEY,
}

# Reverse mapping
PIITYPE_TO_PRESIDIO = {v: k for k, v in PRESIDIO_ENTITY_MAP.items()}


class PresidioDetector(PIIDetector):
    """Presidio-based PII detector."""

    def __init__(self) -> None:
        """
        Initialize Presidio detector.

        Raises:
            ImportError: If presidio is not installed
        """
        try:
            from presidio_analyzer import AnalyzerEngine

            self.analyzer: AnalyzerEngine = AnalyzerEngine()
        except ImportError as e:
            raise ImportError(
                "Presidio is not installed. Install with: pip install mcp-pvp[presidio]"
            ) from e

    def detect(
        self,
        content: str,
        types: list[PIIType] | None = None,
    ) -> list[PIIDetection]:
        """
        Detect PII using Presidio.

        Args:
            content: Text content to analyze
            types: List of PII types to detect (None = detect all)

        Returns:
            List of PIIDetection instances

        Raises:
            DetectionError: If detection fails
        """
        try:
            # Map PIIType to Presidio entity types
            entities = None
            if types is not None:
                entities = [PIITYPE_TO_PRESIDIO[t] for t in types if t in PIITYPE_TO_PRESIDIO]

            # Run analysis
            results = self.analyzer.analyze(
                text=content,
                language="en",
                entities=entities,
            )

            # Convert to PIIDetection
            detections: list[PIIDetection] = []
            for result in results:
                pii_type = PRESIDIO_ENTITY_MAP.get(result.entity_type)
                if pii_type is None:
                    continue

                detection = PIIDetection(
                    pii_type=pii_type,
                    start=result.start,
                    end=result.end,
                    text=content[result.start : result.end],
                    confidence=result.score,
                )
                detections.append(detection)

            # Sort by start position
            detections.sort(key=lambda d: d.start)

            return detections

        except Exception as e:
            raise DetectionError(
                f"Presidio detection failed: {e}",
                details={"error": str(e)},
            ) from e

    def supports_type(self, pii_type: PIIType) -> bool:
        """
        Check if detector supports a PII type.

        Args:
            pii_type: PII type

        Returns:
            True if supported, False otherwise
        """
        return pii_type in PIITYPE_TO_PRESIDIO
