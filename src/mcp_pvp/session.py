"""MCP session management with context manager support.

This module provides a context manager for managing MCP ClientSession lifecycle,
making it easy to connect to MCP servers, execute tools, and ensure proper cleanup.

Example:
    async with create_mcp_executor(server_path="path/to/server.py") as executor:
        # executor is ready to use
        result = await executor.execute("tool_name", {"arg": "value"})
        # Automatic cleanup on exit
"""

import asyncio
import logging
import types
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .executor import MCP_ToolExecutor

logger = logging.getLogger(__name__)


class MCPSessionManager:
    """Manages MCP ClientSession lifecycle.

    Connects to an MCP server via stdio and maintains the session.
    Designed to be used as an async context manager.
    """

    def __init__(
        self,
        server_command: str = "python",
        server_path: str | None = None,
        server_args: list[str] | None = None,
    ):
        """Initialize MCP session manager.

        Args:
            server_command: Command to run MCP server (e.g., 'python', 'node')
            server_path: Path to MCP server script
            server_args: Additional arguments for the MCP server
        """
        self.server_command = server_command
        self.server_path = server_path
        self.server_args = server_args or []
        self.exit_stack: AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def __aenter__(self) -> ClientSession:
        """Connect to MCP server and return ClientSession.

        Returns:
            Initialized MCP ClientSession

        Raises:
            RuntimeError: If connection fails or server path not configured
        """
        if self.server_path is None:
            raise RuntimeError(
                "MCP server path not configured. "
                "Provide server_path parameter or set VAULT_MCP_SERVER_PATH environment variable."
            )

        try:
            self.exit_stack = AsyncExitStack()

            # Build server command
            shell_command = f"{self.server_command} {self.server_path}"
            if self.server_args:
                shell_command += " " + " ".join(self.server_args)

            logger.info(f"Starting MCP server: {shell_command}")

            # Connect to MCP server via stdio
            # Note: stderr is NOT suppressed so startup errors are visible
            read, write = await self.exit_stack.enter_async_context(
                stdio_client(
                    server=StdioServerParameters(
                        command="sh",
                        args=["-c", shell_command],
                        env=None,
                    )
                )
            )

            # Create and initialize client session with a timeout
            # If the MCP server crashes on startup (e.g. missing deps),
            # initialize() would hang forever waiting for a response.
            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
            try:
                await asyncio.wait_for(self.session.initialize(), timeout=30.0)
            except TimeoutError as e:
                logger.error(f"Timeout while waiting for MCP server to initialize: {e}")
                raise RuntimeError(
                    f"Timed out waiting for MCP server to respond (30s). "
                    f"The server process may have crashed on startup. "
                    f"Check that '{self.server_command}' can run '{self.server_path}' "
                    f"and that all dependencies (e.g. 'mcp' package) are installed."
                ) from e
            except (asyncio.CancelledError, BaseExceptionGroup) as e:
                logger.error(f"MCP server process failed during initialization: {e}")
                raise RuntimeError(
                    f"MCP server process terminated unexpectedly. "
                    f"Check that '{self.server_command} {self.server_path}' is a valid command."
                ) from e

            logger.info(f"Connected to MCP server: {self.server_path}")
            return self.session

        except RuntimeError:
            # Re-raise RuntimeError as-is (don't double-wrap)
            if self.exit_stack:
                await self.exit_stack.aclose()
            raise
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            if self.exit_stack:
                await self.exit_stack.aclose()
            raise RuntimeError(f"Failed to connect to MCP server: {e}") from e

    async def __aexit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        """Disconnect from MCP server and clean up resources."""
        if self.exit_stack:
            await self.exit_stack.aclose()
            self.exit_stack = None
            self.session = None
            logger.info("Disconnected from MCP server")
        return False


@asynccontextmanager
async def create_mcp_executor(
    server_command: str = "python",
    server_path: str | None = None,
    server_args: list[str] | None = None,
    session: ClientSession | None = None,
) -> AsyncIterator[MCP_ToolExecutor]:
    """Create MCP_ToolExecutor as a context manager.

    This is the recommended way to use MCP_ToolExecutor. It automatically
    handles session connection, initialization, and cleanup.

    Args:
        server_command: Command to run MCP server (default: 'python')
        server_path: Path to MCP server script (required unless session provided)
        server_args: Additional arguments for MCP server
        session: Pre-configured ClientSession (for testing/advanced use)

    Yields:
        MCP_ToolExecutor instance ready to execute tools

    Example:
        async with create_mcp_executor(server_path="server.py") as executor:
            result = await executor.execute("tool_name", {"arg": "value"})

    Example (with custom session for testing):
        async with create_mcp_executor(session=mock_session) as executor:
            result = await executor.execute("tool_name", {"arg": "value"})
    """
    if session is not None:
        # Use provided session (testing mode)
        logger.info("Using provided MCP session")
        executor = MCP_ToolExecutor(session)
        try:
            yield executor
        finally:
            pass  # Caller manages session lifecycle
    else:
        # Create new session (production mode)
        async with MCPSessionManager(server_command, server_path, server_args) as mcp_session:
            executor = MCP_ToolExecutor(mcp_session)
            logger.info("MCP executor initialized")
            try:
                yield executor
            finally:
                logger.info("MCP executor cleanup complete")


def create_mcp_executor_sync(session: ClientSession) -> MCP_ToolExecutor:
    """Create MCP_ToolExecutor synchronously with a pre-configured session.

    This is a simple factory function for cases where you already have a session
    and don't need async context management. Useful for testing.

    Args:
        session: Pre-configured ClientSession

    Returns:
        MCP_ToolExecutor instance

    Example:
        executor = create_mcp_executor_sync(mock_session)
        # Use executor in sync context
    """
    return MCP_ToolExecutor(session)


class MCPHttpSessionManager:
    """Manages MCP ClientSession lifecycle for HTTP-based MCP servers.

    Connects to an MCP server via HTTP and maintains the session.
    Designed to be used as an async context manager.
    """

    def __init__(self, server_url: str):
        """Initialize HTTP MCP session manager.

        Args:
            server_url: URL of the MCP server (e.g., 'http://localhost:8002/mcp')
        """
        self.server_url = server_url
        self.exit_stack: AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def __aenter__(self) -> ClientSession:
        """Connect to HTTP MCP server and return ClientSession.

        Returns:
            Initialized MCP ClientSession

        Raises:
            RuntimeError: If connection fails
        """
        try:
            self.exit_stack = AsyncExitStack()

            # Connect to MCP server via HTTP
            read_stream, write_stream, _ = await self.exit_stack.enter_async_context(
                streamable_http_client(self.server_url)
            )

            # Create and initialize client session
            self.session = await self.exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self.session.initialize()

            logger.info(f"Connected to HTTP MCP server: {self.server_url}")
            return self.session

        except Exception as e:
            logger.error(f"Failed to connect to HTTP MCP server: {e}")
            if self.exit_stack:
                await self.exit_stack.aclose()
            raise RuntimeError(f"Failed to connect to HTTP MCP server: {e}") from e

    async def __aexit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        """Disconnect from HTTP MCP server and clean up resources."""
        if self.exit_stack:
            await self.exit_stack.aclose()
            self.exit_stack = None
            self.session = None
            logger.info("Disconnected from HTTP MCP server")
        return False


@asynccontextmanager
async def create_mcp_executor_http(
    server_url: str,
    session: ClientSession | None = None,
) -> AsyncIterator[MCP_ToolExecutor]:
    """Create MCP_ToolExecutor for HTTP-based MCP servers as a context manager.

    This is the recommended way to use MCP_ToolExecutor with HTTP servers.
    It automatically handles session connection, initialization, and cleanup.

    Args:
        server_url: URL of the MCP server (e.g., 'http://localhost:8002/mcp')
        session: Pre-configured ClientSession (for testing/advanced use)

    Yields:
        MCP_ToolExecutor instance ready to execute tools

    Example:
        async with create_mcp_executor_http("http://localhost:8002/mcp") as executor:
            result = await executor.execute("tool_name", {"arg": "value"})

    Example (with custom session for testing):
        async with create_mcp_executor_http("http://...", session=mock_session) as executor:
            result = await executor.execute("tool_name", {"arg": "value"})
    """
    if session is not None:
        # Use provided session (testing mode)
        logger.info("Using provided HTTP MCP session")
        executor = MCP_ToolExecutor(session)
        try:
            yield executor
        finally:
            pass  # Caller manages session lifecycle
    else:
        # Create new HTTP session (production mode)
        async with MCPHttpSessionManager(server_url) as mcp_session:
            executor = MCP_ToolExecutor(mcp_session)
            logger.info("HTTP MCP executor initialized")
            try:
                yield executor
            finally:
                logger.info("HTTP MCP executor cleanup complete")
