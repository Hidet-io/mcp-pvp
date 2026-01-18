"""Pydantic models for PVP protocol."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_pvp.utils import utc_now


class PIIType(str, Enum):
    """Types of PII that can be detected and tokenized."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IPV4 = "IPV4"
    CC = "CC"  # Credit card (masked by default)
    API_KEY = "API_KEY"  # API keys (masked by default)
    CUSTOM = "CUSTOM"  # Custom pattern


class TokenFormat(str, Enum):
    """Format for token representation."""

    TEXT = "TEXT"  # [[PII:TYPE:REF]]
    JSON = "JSON"  # {"$pii_ref": "tkn_x", "type": "EMAIL", "cap": "cap_x"}


class SinkKind(str, Enum):
    """Kind of sink for disclosure."""

    TOOL = "tool"  # MCP tool
    LLM = "llm"  # LLM/model (default deny)
    ENGINE = "engine"  # Agent engine (default deny)
    LOCAL = "local"  # Local execution
    CUSTOM = "custom"  # Custom sink


# ============================================================================
# Domain models
# ============================================================================


class RunContext(BaseModel):
    """Run context for correlation and audit."""

    workflow_run_id: str | None = None
    step_id: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)


class Sink(BaseModel):
    """Sink specification for disclosure."""

    kind: SinkKind
    name: str  # e.g., "send_email" for tool, "gpt-4" for llm
    arg_path: str | None = None  # e.g., "to", "email", "args.recipient"


class PIIDetection(BaseModel):
    """Detected PII span."""

    pii_type: PIIType
    start: int
    end: int
    text: str
    confidence: float = 1.0


class TextToken(BaseModel):
    """Text token representation: [[PII:TYPE:REF]]."""

    ref: str
    pii_type: PIIType

    def to_text(self) -> str:
        """Convert to text format."""
        return f"[[PII:{self.pii_type.value}:{self.ref}]]"


class JSONToken(BaseModel):
    """JSON token object."""

    pii_ref: str = Field(alias="$pii_ref")
    type: PIIType
    cap: str | None = None

    model_config = {"populate_by_name": True}


class StoredPII(BaseModel):
    """PII value stored in vault."""

    ref: str
    pii_type: PIIType
    value: str
    created_at: datetime = Field(default_factory=utc_now)


class VaultSession(BaseModel):
    """Vault session containing tokenized PII."""

    session_id: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    tokens: dict[str, StoredPII] = Field(default_factory=dict)  # ref -> StoredPII
    disclosed_count: int = 0
    disclosed_bytes: int = 0


class Capability(BaseModel):
    """Capability authorizing disclosure."""

    vault_session: str
    pii_ref: str
    pii_type: PIIType
    sink: Sink
    run: RunContext | None = None
    exp: datetime  # Expiration timestamp


class PolicyAllow(BaseModel):
    """Allow rule for a sink."""

    type: PIIType
    arg_paths: list[str] | None = None  # If None, allow any arg_path


class SinkPolicy(BaseModel):
    """Policy for a specific sink."""

    allow: list[PolicyAllow] = Field(default_factory=list)


class PolicyLimits(BaseModel):
    """Limits for disclosure."""

    max_disclosures_per_step: int = 50
    max_total_disclosed_bytes_per_step: int = 8192


class Policy(BaseModel):
    """PVP policy specification."""

    sinks: dict[str, SinkPolicy] = Field(default_factory=dict)  # sink_id -> SinkPolicy
    defaults: SinkPolicy = Field(default_factory=lambda: SinkPolicy(allow=[]))
    limits: PolicyLimits = Field(default_factory=PolicyLimits)
    type_rules: dict[PIIType, dict[str, Any]] = Field(default_factory=dict)


# ============================================================================
# Request/Response models
# ============================================================================


class TokenizeRequest(BaseModel):
    """Request to tokenize content."""

    content: str
    run: RunContext | None = None
    token_format: TokenFormat = TokenFormat.JSON
    include_caps: bool = True
    types: list[PIIType] | None = None  # If None, detect all types
    session_ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class TokenStats(BaseModel):
    """Statistics about tokenization."""

    detections: int
    tokens_created: int
    types: dict[PIIType, int]


class TokenizeResponse(BaseModel):
    """Response from tokenize operation."""

    vault_session: str
    redacted: str
    tokens: list[TextToken | JSONToken]
    stats: TokenStats
    expires_at: datetime


class ResolveTokenRequest(BaseModel):
    """Single token to resolve."""

    ref: str
    cap: str | None = None  # Optional - vault issues if not provided


class ResolveRequest(BaseModel):
    """Request to resolve tokens."""

    vault_session: str
    tokens: list[ResolveTokenRequest]
    sink: Sink
    run: RunContext | None = None


class ResolveResponse(BaseModel):
    """Response from resolve operation."""

    values: dict[str, str]  # ref -> raw value
    audit_id: str
    disclosed: dict[PIIType, int]


class ToolCall(BaseModel):
    """Tool call with arguments that may contain tokens."""

    name: str
    args: dict[str, Any]


class DeliverRequest(BaseModel):
    """Request to deliver (inject and execute)."""

    vault_session: str
    tool_call: ToolCall
    run: RunContext | None = None


class DeliverResponse(BaseModel):
    """Response from deliver operation."""

    delivered: bool
    tool_result: Any = None  # Result from tool execution (stub)
    audit_id: str


# ============================================================================
# Envelope responses
# ============================================================================


class SuccessEnvelope(BaseModel):
    """Success response envelope."""

    ok: Literal[True] = True
    result: Any


class ErrorDetail(BaseModel):
    """Error detail."""

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorEnvelope(BaseModel):
    """Error response envelope."""

    ok: Literal[False] = False
    error: ErrorDetail
