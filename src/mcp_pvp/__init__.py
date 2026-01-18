"""
mcp-pvp: Privacy Vault Protocol for MCP.

Tokenize sensitive data before the LLM sees it.
"""

__version__ = "0.2.0"

from mcp_pvp.errors import (
    PVPError,
    PolicyDeniedError,
    CapabilityInvalidError,
    SessionNotFoundError,
    TokenNotFoundError,
    DetectionError,
)
from mcp_pvp.executor import DummyExecutor, MCP_ToolExecutor, ToolExecutor
from mcp_pvp.models import (
    PIIType,
    TokenFormat,
    SinkKind,
    TextToken,
    JSONToken,
    TokenizeRequest,
    TokenizeResponse,
    ResolveRequest,
    ResolveResponse,
    DeliverRequest,
    DeliverResponse,
    Sink,
    RunContext,
    PIIDetection,
    StoredPII,
    VaultSession,
    Capability,
    PolicyAllow,
    SinkPolicy,
    PolicyLimits,
    Policy,
    TokenStats,
    ResolveTokenRequest,
    ToolCall,
)
from mcp_pvp.vault import Vault

__all__ = [
    "__version__",
    # Errors
    "PVPError",
    "PolicyDeniedError",
    "CapabilityInvalidError",
    "SessionNotFoundError",
    "TokenNotFoundError",
    "DetectionError",
    # Executors
    "ToolExecutor",
    "DummyExecutor",
    "MCP_ToolExecutor",
    # Models
    "PIIType",
    "TokenFormat",
    "SinkKind",
    "TextToken",
    "JSONToken",
    "TokenizeRequest",
    "TokenizeResponse",
    "ResolveRequest",
    "ResolveResponse",
    "DeliverRequest",
    "DeliverResponse",
    "Sink",
    "RunContext",
    "PIIDetection",
    "StoredPII",
    "VaultSession",
    "Capability",
    "PolicyAllow",
    "SinkPolicy",
    "PolicyLimits",
    "Policy",
    "TokenStats",
    "ResolveTokenRequest",
    "ToolCall",
    # Core
    "Vault",
]
