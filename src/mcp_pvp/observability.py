"""Optional observability integrations for mcp-pvp.

This module provides optional integrations with observability platforms like Sentry.
All integrations are opt-in and require explicit configuration.
"""

import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def configure_sentry(
    dsn: str | None = None,
    environment: str | None = None,
    release: str | None = None,
    traces_sample_rate: float = 0.1,
    profiles_sample_rate: float = 0.1,
    **kwargs: Any,
) -> None:
    """Configure Sentry error tracking and performance monitoring.

    This is an optional integration. Requires: pip install 'mcp-pvp[sentry]'

    Args:
        dsn: Sentry DSN (or set SENTRY_DSN environment variable)
        environment: Environment name (dev/staging/prod)
        release: Release version (defaults to mcp_pvp.__version__)
        traces_sample_rate: Fraction of transactions to trace (0.0-1.0)
        profiles_sample_rate: Fraction of transactions to profile (0.0-1.0)
        **kwargs: Additional Sentry SDK options

    Example:
        >>> from mcp_pvp.observability import configure_sentry
        >>> configure_sentry(
        ...     dsn="https://...@sentry.io/...",
        ...     environment="production",
        ...     traces_sample_rate=0.2,
        ... )

    Security Notes:
        - Sentry integration automatically redacts PII using before_send hook
        - Audit IDs and token references are safe to include
        - Never log raw PII values to Sentry
    """
    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError as e:
        raise ImportError(
            "Sentry not installed. Install with: pip install 'mcp-pvp[sentry]'"
        ) from e

    # Get DSN from argument or environment
    dsn = dsn or os.getenv("SENTRY_DSN")
    if not dsn:
        logger.warning(
            "sentry_configuration_skipped",
            reason="No DSN provided (set dsn= or SENTRY_DSN env var)",
        )
        return

    # Get version if not specified
    if release is None:
        try:
            from mcp_pvp import __version__

            release = f"mcp-pvp@{__version__}"
        except ImportError:
            release = "mcp-pvp@unknown"

    # Configure logging integration
    sentry_logging = LoggingIntegration(
        level=None,  # Capture all log levels
        event_level=None,  # Don't create Sentry events from logs (we handle errors explicitly)
    )

    # Before send hook to ensure no PII leaks
    def before_send(event, hint):  # type: ignore[no-untyped-def]
        """Scrub any potential PII before sending to Sentry."""
        # Remove request data that might contain PII
        if "request" in event:
            if "data" in event["request"]:
                event["request"]["data"] = "[REDACTED - may contain PII]"
            if "json" in event["request"]:
                event["request"]["json"] = "[REDACTED - may contain PII]"

        # Scrub breadcrumbs
        if "breadcrumbs" in event:
            for crumb in event["breadcrumbs"]:
                if "data" in crumb:
                    # Keep safe metadata but remove potential PII
                    safe_data = {
                        k: v
                        for k, v in crumb["data"].items()
                        if k
                        in {
                            "audit_id",
                            "event_type",
                            "vault_session",
                            "tool_name",
                            "sink_kind",
                            "status_code",
                            "method",
                        }
                    }
                    crumb["data"] = safe_data

        return event

    # Initialize Sentry
    sentry_sdk.init(
        dsn=dsn,
        environment=environment or os.getenv("SENTRY_ENVIRONMENT", "development"),
        release=release,
        traces_sample_rate=traces_sample_rate,
        profiles_sample_rate=profiles_sample_rate,
        integrations=[sentry_logging],
        before_send=before_send,
        send_default_pii=False,  # CRITICAL: Never send PII
        **kwargs,
    )

    logger.info(
        "sentry_initialized",
        environment=environment,
        release=release,
        traces_sample_rate=traces_sample_rate,
    )


def capture_exception(error: Exception, **extra: Any) -> None:
    """Capture an exception to Sentry (if configured).

    Args:
        error: Exception to capture
        **extra: Additional context (safe values only, no PII)

    Example:
        >>> try:
        ...     vault.tokenize(request)
        ... except PolicyDeniedError as e:
        ...     capture_exception(e, vault_session=session_id, audit_id=audit_id)
    """
    try:
        import sentry_sdk

        # Only include safe context
        safe_extra = {
            k: v
            for k, v in extra.items()
            if k
            in {
                "audit_id",
                "vault_session",
                "event_type",
                "tool_name",
                "sink_kind",
                "error_code",
            }
        }

        with sentry_sdk.push_scope() as scope:
            for key, value in safe_extra.items():
                scope.set_extra(key, value)
            sentry_sdk.capture_exception(error)

    except ImportError:
        # Sentry not installed, skip silently
        pass


def start_transaction(name: str, op: str, **kwargs: Any) -> Any:
    """Start a Sentry performance transaction (if configured).

    Args:
        name: Transaction name (e.g., "vault.tokenize")
        op: Operation type (e.g., "tokenize", "resolve", "deliver")
        **kwargs: Additional transaction data

    Returns:
        Transaction context manager or no-op

    Example:
        >>> with start_transaction("vault.tokenize", "tokenize"):
        ...     response = vault.tokenize(request)
    """
    try:
        import sentry_sdk

        return sentry_sdk.start_transaction(name=name, op=op, **kwargs)
    except ImportError:
        # Return no-op context manager
        from contextlib import nullcontext

        return nullcontext()
