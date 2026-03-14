"""
mcp-pvp: Privacy Vault Protocol for MCP.

Tokenize sensitive data before the LLM sees it.
"""

__version__ = "0.6.15"

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
from mcp_pvp.session import (
    MCPHttpSessionManager,
    MCPSessionManager,
    create_mcp_executor,
    create_mcp_executor_http,
    create_mcp_executor_sync,
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
    "MCPHttpSessionManager",
    "MCPSessionManager",
    "MCP_ToolExecutor",
    "PIIDetection",
    "PIIType",
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
    "ToolExecutor",
    "Vault",
    "VaultSession",
    "__version__",
    "create_mcp_executor",
    "create_mcp_executor_http",
    "create_mcp_executor_sync",
]
