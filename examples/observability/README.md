# Observability Examples

This directory contains example configurations for observability in production and development environments.

## Examples

### [production_config.py](production_config.py)

Complete production-ready configuration demonstrating:

- **Structured JSON Logging**: Using structlog with ISO timestamps
- **Sentry Error Tracking**: Optional integration with PII protection
- **Prometheus Metrics**: Request rates, durations, active sessions, PII disclosures
- **PostgreSQL Audit Trail**: Persistent audit logger example
- **FastAPI Health Checks**: `/health` and `/ready` endpoints for Kubernetes
- **Full Instrumentation**: Metrics on every tokenize/deliver operation

**Usage:**

```bash
# Install dependencies
pip install 'mcp-pvp[sentry,http]' fastapi uvicorn prometheus-client

# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost/audit"
export SENTRY_DSN="https://...@sentry.io/..."
export ENV="production"
export LOG_LEVEL="INFO"
export METRICS_PORT="9090"
export PORT="8000"

# Run server
python production_config.py
```

**Endpoints:**

- `POST /tokenize` - Tokenize PII in content
- `POST /deliver` - Deliver PII to tools
- `GET /health` - Health check (liveness probe)
- `GET /ready` - Readiness check (checks vault status)
- `GET /metrics` - Prometheus metrics

**Metrics Available:**

```
pvp_tokenize_requests_total{status="success|error"}
pvp_tokenize_duration_seconds
pvp_deliver_requests_total{status="success|error", tool_name="..."}
pvp_deliver_duration_seconds
pvp_active_vault_sessions
pvp_pii_disclosures_total{pii_type="EMAIL|PHONE|..."}
pvp_audit_events_total{event_type="TOKENIZE|DELIVER|..."}
```

**Logs Example:**

```json
{
  "event": "tokenize_success",
  "vault_session": "vs_abc123",
  "tokens_created": 2,
  "duration_seconds": 0.042,
  "timestamp": "2026-01-18T10:30:00.123456Z",
  "level": "info"
}
```

---

### [dev_config.py](dev_config.py)

Minimal local development configuration demonstrating:

- **Pretty Console Logging**: Using structlog with colors and timestamps
- **In-Memory Audit Trail**: Default InMemoryAuditLogger
- **Debug Mode**: Optional verbose output
- **Example Workflow**: Tokenize → Deliver → Query Audit Trail

**Usage:**

```bash
# Install dependencies
pip install mcp-pvp

# Run example
python dev_config.py
```

**Example Output:**

```
10:30:00 [info     ] logging_configured         mode=development debug=True
10:30:00 [info     ] app_starting              version=0.2.0
10:30:00 [info     ] vault_initialized         detector=presidio
10:30:00 [info     ] example_1_tokenize        description=Tokenizing email content
10:30:00 [info     ] vault_tokenize_start      content_length=47 token_format=JSON
10:30:00 [info     ] vault_tokenize_complete   detections=1 tokens_created=1 vault_session=vs_abc123
10:30:00 [info     ] tokenize_complete         content_preview=Please email {"type":"EMAIL","pii_ref":"pii_001"} tokens_created=1 vault_session=vs_abc123
10:30:00 [info     ] example_2_deliver         description=Delivering PII to send_email tool
10:30:00 [info     ] vault_deliver_start       tool_name=send_email vault_session=vs_abc123
10:30:00 [info     ] vault_deliver_complete    disclosed_count=1 vault_session=vs_abc123
10:30:00 [info     ] deliver_complete          disclosed_count=1 disclosed_types=['EMAIL']
10:30:00 [info     ] example_3_audit           description=Querying audit events
10:30:00 [info     ] audit_event               audit_id=aud_001 details={'detections': 1, 'tokens_created': 1} event_type=TOKENIZE
10:30:00 [info     ] audit_event               audit_id=aud_002 details={'disclosed': {'EMAIL': 1}, 'tool_name': 'send_email'} event_type=DELIVER
10:30:00 [info     ] examples_complete         total_audit_events=2
```

---

## Configuration Options

### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `ENV` | Environment name | `production` | `development`, `staging` |
| `LOG_LEVEL` | Logging level | `INFO` | `DEBUG`, `WARNING`, `ERROR` |
| `DATABASE_URL` | PostgreSQL connection URL | `None` | `postgresql://...` |
| `SENTRY_DSN` | Sentry project DSN | `None` | `https://...@sentry.io/...` |
| `SENTRY_TRACES_SAMPLE_RATE` | Sentry transaction sampling rate | `0.2` | `0.1` (10%) |
| `SENTRY_PROFILES_SAMPLE_RATE` | Sentry profile sampling rate | `0.1` | `0.05` (5%) |
| `METRICS_PORT` | Prometheus metrics port | `9090` | `9091` |
| `PORT` | HTTP server port | `8000` | `8080` |
| `HOST` | HTTP server host | `0.0.0.0` | `127.0.0.1` |
| `WORKERS` | Uvicorn worker processes | `4` | `8` |

---

## Kubernetes Deployment

Deploy with observability:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-pvp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-pvp
  template:
    metadata:
      labels:
        app: mcp-pvp
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: mcp-pvp
        image: mcp-pvp:0.2.0
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: ENV
          value: "production"
        - name: LOG_LEVEL
          value: "INFO"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: mcp-pvp-secrets
              key: database-url
        - name: SENTRY_DSN
          valueFrom:
            secretKeyRef:
              name: mcp-pvp-secrets
              key: sentry-dsn
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-pvp
spec:
  selector:
    app: mcp-pvp
  ports:
  - name: http
    port: 80
    targetPort: 8000
  - name: metrics
    port: 9090
    targetPort: 9090
```

---

## Docker Compose

Run locally with all observability features:

```yaml
version: '3.8'

services:
  mcp-pvp:
    build: .
    ports:
      - "8000:8000"
      - "9090:9090"
    environment:
      - ENV=production
      - LOG_LEVEL=INFO
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/audit
      - SENTRY_DSN=${SENTRY_DSN}
    depends_on:
      - postgres

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=audit
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  grafana_data:
```

**prometheus.yml:**

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mcp-pvp'
    static_configs:
      - targets: ['mcp-pvp:9090']
```

---

## See Also

- [OBSERVABILITY.md](../../docs/OBSERVABILITY.md) - Complete observability guide
- [README.md](../../README.md) - Main project documentation
- [safe_email_sender example](../safe_email_sender/) - Golden example with PVP integration
