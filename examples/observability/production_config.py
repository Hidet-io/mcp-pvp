"""
Production observability configuration example for mcp-pvp.

This example demonstrates a complete production setup with:
- Structured JSON logging
- Sentry error tracking
- Prometheus metrics
- PostgreSQL audit trail
- Health check endpoints

Usage:
    export DATABASE_URL="postgresql://..."
    export SENTRY_DSN="https://...@sentry.io/..."
    python production_config.py
"""

import logging
import os
import sys
from datetime import datetime

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import Counter, Gauge, Histogram, generate_latest, start_http_server

# Optional: Sentry integration
try:
    from mcp_pvp.observability import capture_exception, configure_sentry, start_transaction

    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False
    print("Sentry not available. Install with: pip install 'mcp-pvp[sentry]'", file=sys.stderr)

from mcp_pvp import DeliverRequest, Policy, TokenizeRequest, Vault, __version__
from mcp_pvp.audit import AuditEvent, AuditEventType, AuditLogger
from mcp_pvp.models import ToolCall

# ============================================================================
# 1. STRUCTURED LOGGING CONFIGURATION
# ============================================================================


def configure_logging(log_level: str = "INFO", environment: str = "production"):
    """Configure structured logging for production."""

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # Configure structlog
    if environment == "development":
        # Pretty console output for local development
        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(),
        ]
    else:
        # JSON output for production
        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, log_level.upper())),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    logger = structlog.get_logger(__name__)
    logger.info(
        "logging_configured",
        environment=environment,
        log_level=log_level,
        format="json" if environment != "development" else "console",
    )


# ============================================================================
# 2. PROMETHEUS METRICS
# ============================================================================

# Define metrics
tokenize_requests_total = Counter(
    "pvp_tokenize_requests_total",
    "Total number of tokenize requests",
    ["status"],  # success, error
)

tokenize_duration_seconds = Histogram(
    "pvp_tokenize_duration_seconds",
    "Tokenize operation duration in seconds",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

deliver_requests_total = Counter(
    "pvp_deliver_requests_total",
    "Total number of deliver requests",
    ["status", "tool_name"],
)

deliver_duration_seconds = Histogram(
    "pvp_deliver_duration_seconds",
    "Deliver operation duration in seconds",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

active_vault_sessions = Gauge(
    "pvp_active_vault_sessions",
    "Number of active vault sessions",
)

pii_disclosures_total = Counter(
    "pvp_pii_disclosures_total",
    "Total number of PII values disclosed",
    ["pii_type"],
)

audit_events_total = Counter(
    "pvp_audit_events_total",
    "Total number of audit events logged",
    ["event_type"],
)


# ============================================================================
# 3. CUSTOM AUDIT LOGGER (PostgreSQL Example)
# ============================================================================


class PostgreSQLAuditLogger(AuditLogger):
    """Audit logger that persists events to PostgreSQL.

    In production, replace this with a real database connection.
    This example uses an in-memory fallback.
    """

    def __init__(self, database_url: str | None = None):
        self.database_url = database_url
        self._events: list[AuditEvent] = []  # Fallback storage

        logger = structlog.get_logger(__name__)
        if database_url:
            logger.info("audit_logger_initialized", backend="postgresql", url=database_url)
        else:
            logger.warning(
                "audit_logger_initialized", backend="in_memory", message="No DATABASE_URL provided"
            )

    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event to PostgreSQL."""
        logger = structlog.get_logger(__name__)

        # Increment audit event counter
        audit_events_total.labels(event_type=event.event_type.value).inc()

        # Count PII disclosures
        if event.event_type == AuditEventType.DELIVER:
            disclosed = event.details.get("disclosed", {})
            for pii_type, count in disclosed.items():
                pii_disclosures_total.labels(pii_type=pii_type).inc(count)

        # In production: INSERT INTO audit_events ...
        # For this example, store in memory
        self._events.append(event)

        logger.info(
            "audit_event_logged",
            audit_id=event.audit_id,
            event_type=event.event_type.value,
            vault_session=event.vault_session,
        )

    def get_events(
        self,
        *,
        vault_session: str | None = None,
        event_type: AuditEventType | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events from PostgreSQL."""
        # In production: SELECT * FROM audit_events WHERE ...
        # For this example, filter in-memory events
        events = self._events

        if vault_session:
            events = [e for e in events if e.vault_session == vault_session]
        if event_type:
            events = [e for e in events if e.event_type == event_type]

        return events[:limit]


# ============================================================================
# 4. FASTAPI APPLICATION WITH HEALTH CHECKS
# ============================================================================

app = FastAPI(title="mcp-pvp Production Server", version=__version__)

# Global vault instance (initialized on startup)
vault: Vault | None = None


@app.on_event("startup")
async def startup_event():
    """Initialize vault and observability on startup."""
    global vault

    logger = structlog.get_logger(__name__)

    # Configure logging
    environment = os.getenv("ENV", "production")
    log_level = os.getenv("LOG_LEVEL", "INFO")
    configure_logging(log_level=log_level, environment=environment)

    # Configure Sentry (if available and DSN provided)
    sentry_dsn = os.getenv("SENTRY_DSN")
    if SENTRY_AVAILABLE and sentry_dsn:
        configure_sentry(
            dsn=sentry_dsn,
            environment=environment,
            release=f"mcp-pvp@{os.getenv('VERSION', __version__)}",
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.2")),
            profiles_sample_rate=float(os.getenv("SENTRY_PROFILES_SAMPLE_RATE", "0.1")),
        )
        logger.info("sentry_configured", environment=environment)

    # Start Prometheus metrics server
    metrics_port = int(os.getenv("METRICS_PORT", "9090"))
    start_http_server(metrics_port)
    logger.info("prometheus_metrics_started", port=metrics_port)

    # Initialize vault with PostgreSQL audit logger
    database_url = os.getenv("DATABASE_URL")
    audit_logger = PostgreSQLAuditLogger(database_url)

    vault = Vault(
        policy=Policy(),
        audit_logger=audit_logger,
    )

    logger.info(
        "vault_initialized",
        audit_backend="postgresql" if database_url else "in_memory",
    )


@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers."""
    return {
        "status": "healthy",
        "version": __version__,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint for orchestration platforms."""
    logger = structlog.get_logger(__name__)

    if vault is None:
        logger.error("readiness_check_failed", reason="vault_not_initialized")
        return {"status": "not_ready", "reason": "vault not initialized"}, 503

    # Check if detector is functional
    try:
        vault.detector.detect("test@example.com")
        active_vault_sessions.set(len(vault.session_store._sessions))
        return {
            "status": "ready",
            "active_sessions": len(vault.session_store._sessions),
        }
    except Exception as e:
        logger.error("readiness_check_failed", error=str(e))
        if SENTRY_AVAILABLE:
            capture_exception(e)
        return {"status": "not_ready", "error": str(e)}, 503


@app.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics endpoint (if not using separate port)."""
    return Response(content=generate_latest(), media_type="text/plain")


@app.post("/tokenize")
async def tokenize_endpoint(request: Request):
    """Tokenize PII in content."""
    logger = structlog.get_logger(__name__)

    if vault is None:
        return {"error": "vault not initialized"}, 503

    # Parse request
    body = await request.json()
    tokenize_request = TokenizeRequest(
        content=body["content"],
        token_format=body.get("token_format", "JSON"),
    )

    # Track metrics
    start_time = datetime.utcnow()

    try:
        # Start Sentry transaction (if available)
        if SENTRY_AVAILABLE:
            with start_transaction("vault.tokenize", "tokenize"):
                response = vault.tokenize(tokenize_request)
        else:
            response = vault.tokenize(tokenize_request)

        # Record success metrics
        duration = (datetime.utcnow() - start_time).total_seconds()
        tokenize_requests_total.labels(status="success").inc()
        tokenize_duration_seconds.observe(duration)
        active_vault_sessions.set(len(vault.session_store._sessions))

        logger.info(
            "tokenize_success",
            vault_session=response.vault_session,
            tokens_created=len(response.tokens),
            duration_seconds=duration,
        )

        return {
            "vault_session": response.vault_session,
            "redacted": response.redacted,
            "tokens": [t.model_dump() for t in response.tokens],
        }

    except Exception as e:
        # Record error metrics
        duration = (datetime.utcnow() - start_time).total_seconds()
        tokenize_requests_total.labels(status="error").inc()
        tokenize_duration_seconds.observe(duration)

        logger.error(
            "tokenize_error",
            error=str(e),
            error_type=type(e).__name__,
            duration_seconds=duration,
        )

        if SENTRY_AVAILABLE:
            capture_exception(e)

        return {"error": str(e)}, 500


@app.post("/deliver")
async def deliver_endpoint(request: Request):
    """Deliver PII to a tool."""
    logger = structlog.get_logger(__name__)

    if vault is None:
        return {"error": "vault not initialized"}, 503

    # Parse request
    body = await request.json()
    deliver_request = DeliverRequest(
        vault_session=body["vault_session"],
        tool_call=ToolCall(
            name=body["tool_name"],
            args=body["tool_args"],
        ),
    )

    # Track metrics
    start_time = datetime.utcnow()

    try:
        # Start Sentry transaction (if available)
        if SENTRY_AVAILABLE:
            with start_transaction("vault.deliver", "deliver"):
                response = vault.deliver(deliver_request)
        else:
            response = vault.deliver(deliver_request)

        # Record success metrics
        duration = (datetime.utcnow() - start_time).total_seconds()
        deliver_requests_total.labels(
            status="success",
            tool_name=deliver_request.tool_call.name,
        ).inc()
        deliver_duration_seconds.observe(duration)

        logger.info(
            "deliver_success",
            vault_session=deliver_request.vault_session,
            tool_name=deliver_request.tool_call.name,
            delivered=response.delivered,
            duration_seconds=duration,
        )

        return {
            "delivered": response.delivered,
            "tool_result": response.tool_result,
            "audit_id": response.audit_id,
        }

    except Exception as e:
        # Record error metrics
        duration = (datetime.utcnow() - start_time).total_seconds()
        deliver_requests_total.labels(
            status="error",
            tool_name=deliver_request.tool_call.name,
        ).inc()
        deliver_duration_seconds.observe(duration)

        logger.error(
            "deliver_error",
            vault_session=deliver_request.vault_session,
            tool_name=deliver_request.tool_call.name,
            error=str(e),
            error_type=type(e).__name__,
            duration_seconds=duration,
        )

        if SENTRY_AVAILABLE:
            capture_exception(
                e,
                vault_session=deliver_request.vault_session,
                tool_name=deliver_request.tool_call.name,
            )

        return {"error": str(e)}, 500


# ============================================================================
# 5. MAIN ENTRYPOINT
# ============================================================================

if __name__ == "__main__":
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    workers = int(os.getenv("WORKERS", "4"))

    # Run server
    uvicorn.run(
        "production_config:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
        access_log=True,
    )
