from datetime import UTC, datetime


def utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(UTC)  # UTC timezone can be added if needed
