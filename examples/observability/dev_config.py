"""
Development observability configuration example for mcp-pvp.

This example demonstrates a minimal local development setup with:
- Pretty console logging (structlog)
- In-memory audit trail
- Optional debug output

Usage:
    python dev_config.py
"""

import logging

import structlog

from mcp_pvp import DeliverRequest, Policy, TokenizeRequest, Vault

# ============================================================================
# DEVELOPMENT LOGGING CONFIGURATION
# ============================================================================


def configure_dev_logging(debug: bool = False):
    """Configure pretty console logging for local development."""

    log_level = logging.DEBUG if debug else logging.INFO

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
    )

    # Configure structlog for pretty output
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="%H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(),  # Pretty colors!
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    logger = structlog.get_logger(__name__)
    logger.info("logging_configured", mode="development", debug=debug)


# ============================================================================
# EXAMPLE USAGE
# ============================================================================


def main():
    """Example showing development logging in action."""

    # Configure pretty console logging
    configure_dev_logging(debug=True)

    logger = structlog.get_logger(__name__)
    logger.info("app_starting", version="0.2.0")

    # Create vault (uses in-memory audit logger by default)
    vault = Vault(policy=Policy())
    logger.info("vault_initialized", detector="presidio")

    # Example 1: Tokenize content
    logger.info("example_1_tokenize", description="Tokenizing email content")

    request = TokenizeRequest(
        content="Please email john.doe@example.com with updates.",
        token_format="JSON",
    )

    response = vault.tokenize(request)

    logger.info(
        "tokenize_complete",
        vault_session=response.vault_session,
        tokens_created=len(response.tokens),
        redacted_preview=response.redacted[:50],
    )

    # Example 2: Deliver to tool
    logger.info("example_2_deliver", description="Delivering PII to send_email tool")

    # Use the token reference from the response
    first_token = response.tokens[0]
    if isinstance(first_token, dict):
        token_ref = first_token.get("pii_ref") or first_token.get("ref")
    else:
        token_ref = getattr(first_token, "pii_ref", None) or getattr(first_token, "ref", None)

    from mcp_pvp.models import ToolCall

    deliver_request = DeliverRequest(
        vault_session=response.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={"to": token_ref, "subject": "Hello"},
        ),
    )

    try:
        deliver_response = vault.deliver(deliver_request)
        logger.info(
            "deliver_complete",
            delivered=deliver_response.delivered,
            audit_id=deliver_response.audit_id,
        )
    except Exception as e:
        logger.error("deliver_failed", error=str(e), error_type=type(e).__name__)

    # Example 3: Query audit trail
    logger.info("example_3_audit", description="Querying audit events")

    audit_events = vault.audit_logger.get_events(
        vault_session=response.vault_session,
    )

    for event in audit_events:
        logger.info(
            "audit_event",
            audit_id=event.audit_id,
            event_type=event.event_type.value,
            details=event.details,
        )

    logger.info("examples_complete", total_audit_events=len(audit_events))


if __name__ == "__main__":
    main()
