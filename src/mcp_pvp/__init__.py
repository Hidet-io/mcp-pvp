"""
mcp-pvp: Privacy Vault Protocol for MCP.

Tokenize sensitive data before the LLM sees it.
"""

__version__ = "0.3.0"

from mcp_pvp.errors import (
    CapabilityInvalidError,
    DetectionError,
    PolicyDeniedError,
    PVPError,
    SessionNotFoundError,
    TokenNotFoundError,
)
from mcp_pvp.executor import DummyExecutor, MCP_ToolExecutor, ToolExecutor
from mcp_pvp.models import (
    Capability,
    DeliverRequest,
    DeliverResponse,
    JSONToken,
    PIIDetection,
    PIIType,
    Policy,
    PolicyAllow,
    PolicyLimits,
    ResolveRequest,
    ResolveResponse,
    ResolveTokenRequest,
    RunContext,
    Sink,
    SinkKind,
    SinkPolicy,
    StoredPII,
    TextToken,
    TokenFormat,
    TokenizeRequest,
    TokenizeResponse,
    TokenStats,
    ToolCall,
    VaultSession,
)
from mcp_pvp.vault import Vault

__all__ = [
    "Capability",
    "CapabilityInvalidError",
    "DeliverRequest",
    "DeliverResponse",
    "DetectionError",
    "DummyExecutor",
    "JSONToken",
    "MCP_ToolExecutor",
    "PIIDetection",
    # Models
    "PIIType",
    # Errors
    "PVPError",
    "Policy",
    "PolicyAllow",
    "PolicyDeniedError",
    "PolicyLimits",
    "ResolveRequest",
    "ResolveResponse",
    "ResolveTokenRequest",
    "RunContext",
    "SessionNotFoundError",
    "Sink",
    "SinkKind",
    "SinkPolicy",
    "StoredPII",
    "TextToken",
    "TokenFormat",
    "TokenNotFoundError",
    "TokenStats",
    "TokenizeRequest",
    "TokenizeResponse",
    "ToolCall",
    # Executors
    "ToolExecutor",
    # Core
    "Vault",
    "VaultSession",
    "__version__",
]
