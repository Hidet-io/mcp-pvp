# Observability Guide

This guide covers logging, monitoring, and observability best practices for mcp-pvp deployments.

---

## Table of Contents

1. [Logging Pipeline](#logging-pipeline)
2. [Audit Trail](#audit-trail)
3. [Error Tracking (Sentry)](#error-tracking-sentry)
4. [Monitoring & Metrics](#monitoring--metrics)
5. [Security Best Practices](#security-best-practices)

---

## Logging Pipeline

mcp-pvp uses [structlog](https://www.structlog.org/) for structured logging, making logs machine-readable and easy to integrate with log aggregation systems.

### Default Configuration

```python
import structlog

# mcp-pvp uses structlog throughout the codebase
logger = structlog.get_logger(__name__)

# Example log output:
logger.info(
    "vault_tokenize_complete",
    vault_session="vs_abc123",
    tokens_created=2,
    detections=2,
)
# Output: {"event": "vault_tokenize_complete", "vault_session": "vs_abc123", ...}
```

### Production Configuration

For production deployments, configure JSON logging with timestamps:

```python
import structlog
import logging

# Configure standard library logging
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
)

# Configure structlog
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=False,
)
```

### Development Configuration

For local development, use console-friendly output:

```python
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
        structlog.dev.ConsoleRenderer(),  # Pretty console output
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=False,
)
```

### Log Levels

| Level | Usage |
|-------|-------|
| `DEBUG` | Detailed diagnostic information (disabled in production) |
| `INFO` | General informational messages (default) |
| `WARNING` | Warning messages for unexpected but handled conditions |
| `ERROR` | Error messages for failures that don't crash the system |
| `CRITICAL` | Critical errors requiring immediate attention |

### Key Events Logged

| Event | Description | Fields |
|-------|-------------|--------|
| `vault_initialized` | Vault instance created | `detector` |
| `vault_tokenize_start` | Tokenization started | `content_length`, `token_format` |
| `vault_tokenize_complete` | Tokenization finished | `vault_session`, `tokens_created`, `detections` |
| `vault_resolve_start` | Resolution started | `vault_session`, `token_count` |
| `vault_resolve_complete` | Resolution finished | `vault_session`, `resolved_count` |
| `vault_deliver_start` | Delivery started | `vault_session`, `tool_name` |
| `vault_deliver_complete` | Delivery finished | `vault_session`, `disclosed_count` |
| `audit_event` | Audit event logged | `audit_id`, `event_type`, `vault_session` |

**CRITICAL:** Logs NEVER contain raw PII values, only metadata (IDs, counts, types).

### Integration with Log Aggregation

#### CloudWatch Logs

```python
import watchtower

handler = watchtower.CloudWatchLogHandler(
    log_group="/mcp-pvp/production",
    stream_name="vault-{machine}",
)
logging.getLogger().addHandler(handler)
```

#### Datadog

```python
from datadog import initialize, statsd

initialize(
    api_key=os.getenv("DD_API_KEY"),
    app_key=os.getenv("DD_APP_KEY"),
)

# Log to Datadog via syslog or agent
```

#### Elasticsearch/Logstash

Configure structlog with JSON output and ship logs via Filebeat or Logstash.

---

## Audit Trail

mcp-pvp maintains a comprehensive audit trail of all PII operations.

### Audit Events

All PII disclosures are logged:

```python
from mcp_pvp import Vault, Policy

vault = Vault(policy=Policy())

# Tokenize creates TOKENIZE audit event
response = vault.tokenize(...)

# Deliver creates DELIVER audit event
result = vault.deliver(...)

# Query audit events
events = vault.audit_logger.get_events(
    vault_session=response.vault_session,
    event_type=AuditEventType.DELIVER,
    limit=100,
)
```

### Event Structure

```python
from mcp_pvp.audit import AuditEvent, AuditEventType

event = AuditEvent(
    audit_id="aud_abc123",           # Unique event ID
    timestamp="2026-01-18T10:30:00Z", # ISO 8601 timestamp
    event_type=AuditEventType.DELIVER,
    vault_session="vs_xyz789",
    run=RunContext(                   # Optional workflow context
        workflow_run_id="wf_123",
        step_id="step_456",
    ),
    details={                         # Event-specific metadata
        "tool_name": "send_email",
        "disclosed": {"EMAIL": 2},    # PII types and counts
        # NO raw PII values here!
    },
)
```

### Custom Audit Logger

Implement persistent audit storage:

```python
from mcp_pvp.audit import AuditLogger, AuditEvent

class DatabaseAuditLogger(AuditLogger):
    \"\"\"Audit logger backed by PostgreSQL.\"\"\"
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def log_event(self, event: AuditEvent) -> None:
        self.db.execute(
            \"\"\"
            INSERT INTO audit_events 
            (audit_id, timestamp, event_type, vault_session, details)
            VALUES (%s, %s, %s, %s, %s)
            \"\"\",
            (
                event.audit_id,
                event.timestamp,
                event.event_type.value,
                event.vault_session,
                json.dumps(event.details),
            ),
        )
    
    def get_events(self, **filters) -> list[AuditEvent]:
        # Query database with filters
        pass

# Use custom logger
vault = Vault(policy=policy, audit_logger=DatabaseAuditLogger(db))
```

### Compliance Reporting

Generate compliance reports from audit trail:

```python
# Query all DELIVER events (PII disclosures)
deliver_events = vault.audit_logger.get_events(
    event_type=AuditEventType.DELIVER,
    limit=10000,
)

# Generate summary
summary = {
    "total_disclosures": len(deliver_events),
    "by_tool": {},
    "by_pii_type": {},
}

for event in deliver_events:
    tool = event.details.get("tool_name", "unknown")
    summary["by_tool"][tool] = summary["by_tool"].get(tool, 0) + 1
    
    for pii_type, count in event.details.get("disclosed", {}).items():
        summary["by_pii_type"][pii_type] = summary["by_pii_type"].get(pii_type, 0) + count

print(json.dumps(summary, indent=2))
```

---

## Error Tracking (Sentry)

Optional integration with [Sentry](https://sentry.io/) for error tracking and performance monitoring.

### Installation

```bash
pip install 'mcp-pvp[sentry]'
```

### Configuration

```python
from mcp_pvp.observability import configure_sentry

configure_sentry(
    dsn="https://...@sentry.io/...",
    environment="production",
    release="mcp-pvp@0.2.0",
    traces_sample_rate=0.2,  # Sample 20% of transactions
    profiles_sample_rate=0.1,  # Profile 10% of transactions
)
```

**Environment Variables:**

```bash
export SENTRY_DSN="https://...@sentry.io/..."
export SENTRY_ENVIRONMENT="production"
```

### Automatic Error Capture

Errors are automatically captured with safe context:

```python
from mcp_pvp import Vault, PolicyDeniedError
from mcp_pvp.observability import capture_exception

try:
    vault.deliver(request)
except PolicyDeniedError as e:
    # Automatically captured to Sentry (if configured)
    # Only safe metadata included, no PII
    capture_exception(
        e,
        vault_session=session_id,
        audit_id=audit_id,
        tool_name=tool_name,
    )
    raise
```

### Performance Monitoring

Track operation performance:

```python
from mcp_pvp.observability import start_transaction

with start_transaction("vault.tokenize", "tokenize"):
    response = vault.tokenize(request)

with start_transaction("vault.deliver", "deliver"):
    result = vault.deliver(deliver_request)
```

### PII Protection

Sentry integration includes automatic PII redaction:

- Request/response bodies are redacted
- Only safe metadata (audit IDs, session IDs, event types) included
- `send_default_pii=False` enforced
- Custom `before_send` hook scrubs breadcrumbs

---

## Monitoring & Metrics

### Health Checks

Implement health check endpoints for orchestration platforms:

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "0.2.0",
        "vault": vault.session_store.active_sessions_count(),
    }

@app.get("/ready")
def readiness_check():
    # Check dependencies (database, detector, etc.)
    try:
        vault.detector.detect("test@example.com")
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}, 503
```

### Prometheus Metrics

Export metrics for Prometheus:

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
tokenize_total = Counter("pvp_tokenize_total", "Total tokenize operations")
tokenize_errors = Counter("pvp_tokenize_errors", "Tokenize errors")
tokenize_duration = Histogram("pvp_tokenize_duration_seconds", "Tokenize duration")

deliver_total = Counter("pvp_deliver_total", "Total deliver operations")
deliver_errors = Counter("pvp_deliver_errors", "Deliver errors")
deliver_duration = Histogram("pvp_deliver_duration_seconds", "Deliver duration")

active_sessions = Gauge("pvp_active_sessions", "Active vault sessions")
disclosed_pii_total = Counter("pvp_disclosed_pii_total", "Total PII disclosures", ["pii_type"])

# Start metrics server
start_http_server(9090)

# Instrument code
@tokenize_duration.time()
def tokenize(request):
    tokenize_total.inc()
    try:
        response = vault.tokenize(request)
        active_sessions.set(len(vault.session_store._sessions))
        return response
    except Exception:
        tokenize_errors.inc()
        raise
```

### Kubernetes Monitoring

Deploy with Prometheus annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mcp-pvp
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
spec:
  containers:
  - name: mcp-pvp
    image: mcp-pvp:0.2.0
    ports:
    - containerPort: 8000  # HTTP API
    - containerPort: 9090  # Metrics
    livenessProbe:
      httpGet:
        path: /health
        port: 8000
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /ready
        port: 8000
      initialDelaySeconds: 5
      periodSeconds: 5
```

### CloudWatch Metrics

Publish custom metrics to CloudWatch:

```python
import boto3

cloudwatch = boto3.client('cloudwatch')

def publish_metric(metric_name, value, unit='Count'):
    cloudwatch.put_metric_data(
        Namespace='MCP-PVP',
        MetricData=[
            {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.utcnow(),
            },
        ],
    )

# Usage
publish_metric('TokenizeRequests', 1)
publish_metric('PIIDisclosures', count, 'Count')
```

---

## Security Best Practices

### Never Log Raw PII

```python
# ✗ WRONG
logger.info("email_sent", to=email_address)  # Leaks PII!

# ✓ CORRECT
logger.info("email_sent", token_ref=token.pii_ref, audit_id=audit_id)
```

### Use Audit IDs for Correlation

```python
# Link operations via audit_id, not PII
tokenize_resp = vault.tokenize(...)
deliver_resp = vault.deliver(...)

logger.info(
    "operation_complete",
    tokenize_audit_id=tokenize_resp.audit_id,
    deliver_audit_id=deliver_resp.audit_id,
)
```

### Redact Errors

```python
try:
    vault.tokenize(request)
except Exception as e:
    # Don't leak PII in error messages
    logger.error("tokenize_failed", error_type=type(e).__name__)
    raise
```

### Secure Metrics

Ensure metrics endpoints don't expose PII:

```python
# ✓ CORRECT: Count of operations
tokenize_total.inc()

# ✗ WRONG: Operation details
# tokenize_by_email.labels(email=email).inc()  # Don't do this!
```

### Log Rotation

Configure log rotation to prevent unbounded growth:

```bash
# Logrotate configuration
/var/log/mcp-pvp/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 mcp-pvp mcp-pvp
    sharedscripts
    postrotate
        systemctl reload mcp-pvp
    endscript
}
```

---

## Example: Complete Observability Setup

```python
import os
import logging
import structlog
from prometheus_client import start_http_server
from mcp_pvp import Vault, Policy
from mcp_pvp.observability import configure_sentry
from mcp_pvp.audit import DatabaseAuditLogger

# 1. Configure structured logging
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)

# 2. Configure Sentry (optional)
if os.getenv("SENTRY_DSN"):
    configure_sentry(
        environment=os.getenv("ENV", "development"),
        traces_sample_rate=0.2,
    )

# 3. Start Prometheus metrics server
start_http_server(9090)

# 4. Create vault with custom audit logger
db = DatabaseConnection(os.getenv("DATABASE_URL"))
vault = Vault(
    policy=Policy(),
    audit_logger=DatabaseAuditLogger(db),
)

# 5. Add health checks
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/metrics")
def metrics():
    return {"active_sessions": len(vault.session_store._sessions)}

# Now your deployment has:
# - Structured JSON logs
# - Error tracking via Sentry
# - Prometheus metrics on :9090
# - Persistent audit trail in database
# - Health check endpoints
```

---

## Further Reading

- [Structlog Documentation](https://www.structlog.org/)
- [Sentry Python SDK](https://docs.sentry.io/platforms/python/)
- [Prometheus Python Client](https://github.com/prometheus/client_python)
- [mcp-pvp Audit Trail](../README.md#audit-trail)
- [Security Best Practices](../README.md#threat-model-what-this-helps-with)
