from datetime import datetime, UTC
def utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(UTC)  # UTC timezone can be added if needed