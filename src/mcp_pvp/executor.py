"""Tool execution interface for PVP.

This module defines the ToolExecutor interface that allows callers to provide
their own tool execution logic while the vault handles PII injection.

CRITICAL SECURITY NOTE:
=======================
When vault.deliver() calls executor.execute():
1. Raw PII values exist in memory in the `injected_args` dict
2. This is the ONLY place in PVP where raw PII is exposed outside the vault
3. Executors MUST treat injected_args as sensitive and avoid logging/persistence
4. After execution completes, injected_args should be promptly garbage-collected

Memory exposure timeline:
- vault.deliver() builds injected_args with raw PII (line ~416 in vault.py)
- executor.execute() receives injected_args
- Tool execution happens (PII in memory)
- execute() returns result
- injected_args goes out of scope and is GC'd

To minimize exposure:
- Keep tool execution fast
- Don't log injected_args
- Don't persist injected_args to disk
- Return results without PII when possible
"""

from abc import ABC, abstractmethod
from typing import Any


class ToolExecutor(ABC):
    """Abstract interface for executing tool calls with injected PII.

    Implementers provide the actual tool execution logic while the vault
    handles PII injection, policy checks, and audit logging.

    Security considerations:
    - The `injected_args` parameter contains raw PII values
    - Implementers MUST NOT log or persist injected_args
    - Keep execution time minimal to reduce PII memory exposure
    - Return results that don't contain PII when possible
    """

    @abstractmethod
    def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
        """Execute a tool call with PII-injected arguments.

        Args:
            tool_name: Name of the tool to execute
            injected_args: Tool arguments with PII tokens replaced by raw values
                          ⚠️ CONTAINS RAW PII - Handle with care

        Returns:
            Tool execution result (any JSON-serializable value)

        Raises:
            Exception: Any exception from tool execution

        Security:
            - This is the ONLY method in PVP where raw PII values are exposed
            - Do NOT log injected_args
            - Do NOT persist injected_args
            - Minimize execution time to reduce memory exposure
        """
        pass


class DummyExecutor(ToolExecutor):
    """Reference implementation that returns stub results.

    This executor doesn't actually execute tools - it returns a stub response
    indicating which tool would have been called with which arguments.

    Use this for:
    - Testing and development
    - Demonstrating PVP integration
    - As a template for real executors

    Do NOT use this in production - implement your own ToolExecutor.
    """

    def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
        """Return stub result showing what would have been executed.

        Args:
            tool_name: Name of the tool to execute
            injected_args: Tool arguments with PII tokens replaced by raw values

        Returns:
            Dict with stub execution details
        """
        return {
            "status": "stub",
            "message": "DummyExecutor does not execute real tools",
            "tool": tool_name,
            "args_received": True,
            "arg_count": len(injected_args),
        }


class MCP_ToolExecutor(ToolExecutor):
    """Executor that calls MCP tools via the MCP SDK.

    This executor integrates with Model Context Protocol servers to execute
    actual tool calls with injected PII.

    Example:
        ```python
        from mcp import ClientSession

        # Create MCP session
        mcp_session = await ClientSession.connect(...)

        # Create executor
        executor = MCP_ToolExecutor(mcp_session)

        # Use with vault
        vault = Vault(executor=executor)
        result = vault.deliver(request)
        ```
    """

    def __init__(self, mcp_session: Any):
        """Initialize with MCP client session.

        Args:
            mcp_session: MCP ClientSession instance for tool execution
        """
        self.mcp_session = mcp_session

    def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
        """Execute tool via MCP with injected PII.

        Args:
            tool_name: Name of the MCP tool to call
            injected_args: Tool arguments with PII tokens replaced by raw values

        Returns:
            Tool execution result from MCP server

        Raises:
            Exception: Any exception from MCP tool execution
        """
        # Import here to avoid requiring mcp SDK for basic usage
        try:
            from mcp.types import CallToolRequest
        except ImportError as e:
            raise ImportError(
                "MCP SDK not installed. Install with: pip install 'mcp-pvp[mcp]'"
            ) from e

        # Call the MCP tool with injected args
        # Note: This is synchronous - for async, use AsyncMCP_ToolExecutor
        result = self.mcp_session.call_tool(
            CallToolRequest(name=tool_name, arguments=injected_args)  # type: ignore[call-arg]
        )

        return result
