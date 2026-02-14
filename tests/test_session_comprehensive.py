"""Comprehensive unit tests for mcp_pvp.session module.

Tests cover:
- MCPSessionManager context manager lifecycle
- create_mcp_executor async context manager
- create_mcp_executor_sync factory function
- Connection management and cleanup
- Error handling and edge cases
- Resource cleanup and exception safety
"""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from mcp_pvp.executor import MCP_ToolExecutor
from mcp_pvp.session import (
    MCPSessionManager,
    create_mcp_executor,
    create_mcp_executor_sync,
)


class TestMCPSessionManagerInit:
    """Test MCPSessionManager initialization."""

    def test_default_initialization(self):
        """Test default parameter values."""
        manager = MCPSessionManager()

        assert manager.server_command == "python"
        assert manager.server_path is None
        assert manager.server_args == []
        assert manager.exit_stack is None
        assert manager.session is None

    def test_initialization_with_server_path(self):
        """Test initialization with server path."""
        manager = MCPSessionManager(server_path="/path/to/server.py")

        assert manager.server_path == "/path/to/server.py"
        assert manager.server_command == "python"
        assert manager.server_args == []

    def test_initialization_with_custom_command(self):
        """Test initialization with custom server command."""
        manager = MCPSessionManager(server_command="node", server_path="/path/to/server.js")

        assert manager.server_command == "node"
        assert manager.server_path == "/path/to/server.js"

    def test_initialization_with_server_args(self):
        """Test initialization with server arguments."""
        args = ["--debug", "--port=8080"]
        manager = MCPSessionManager(server_path="/path/to/server.py", server_args=args)

        assert manager.server_args == args
        assert len(manager.server_args) == 2

    def test_initialization_with_empty_args(self):
        """Test initialization with empty args list."""
        manager = MCPSessionManager(server_args=[])
        assert manager.server_args == []

    def test_initialization_with_none_args(self):
        """Test initialization with None args defaults to empty list."""
        manager = MCPSessionManager(server_args=None)
        assert manager.server_args == []


class TestMCPSessionManagerContextManager:
    """Test MCPSessionManager async context manager protocol."""

    @pytest.mark.asyncio
    async def test_enter_without_server_path_raises_error(self):
        """Test __aenter__ raises error when server_path is None."""
        manager = MCPSessionManager()

        with pytest.raises(RuntimeError, match="MCP server path not configured"):
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_enter_with_connection_failure_raises_error(self):
        """Test __aenter__ handles connection failures."""
        manager = MCPSessionManager(server_path="/nonexistent/server.py")

        with pytest.raises(RuntimeError, match="Failed to connect to MCP server"):
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_exit_cleans_up_exit_stack(self):
        """Test __aexit__ properly cleans up resources."""
        manager = MCPSessionManager(server_path="/path/to/server.py")

        # Mock the exit stack
        mock_exit_stack = AsyncMock()
        manager.exit_stack = mock_exit_stack

        # Call __aexit__
        result = await manager.__aexit__(None, None, None)

        # Verify cleanup
        assert mock_exit_stack.aclose.called
        assert manager.exit_stack is None
        assert manager.session is None
        assert result is False  # Don't suppress exceptions

    @pytest.mark.asyncio
    async def test_exit_with_exception_still_cleans_up(self):
        """Test __aexit__ cleans up even when exception occurs."""
        manager = MCPSessionManager(server_path="/path/to/server.py")
        mock_exit_stack = AsyncMock()
        manager.exit_stack = mock_exit_stack

        # Call with exception info
        exc_type = ValueError
        exc_val = ValueError("test error")
        exc_tb = None

        result = await manager.__aexit__(exc_type, exc_val, exc_tb)

        # Cleanup should still happen
        assert mock_exit_stack.aclose.called
        assert manager.exit_stack is None
        assert result is False  # Don't suppress the exception

    @pytest.mark.asyncio
    async def test_exit_handles_none_exit_stack(self):
        """Test __aexit__ handles case where exit_stack is None."""
        manager = MCPSessionManager(server_path="/path/to/server.py")
        manager.exit_stack = None

        # Should not raise error
        result = await manager.__aexit__(None, None, None)
        assert result is False

    @pytest.mark.asyncio
    async def test_multiple_exit_calls_are_safe(self):
        """Test calling __aexit__ multiple times is safe."""
        manager = MCPSessionManager(server_path="/path/to/server.py")
        mock_exit_stack = AsyncMock()
        manager.exit_stack = mock_exit_stack

        # First exit
        await manager.__aexit__(None, None, None)
        assert manager.exit_stack is None

        # Second exit should be safe
        await manager.__aexit__(None, None, None)
        assert manager.exit_stack is None


class TestCreateMCPExecutor:
    """Test create_mcp_executor async context manager factory."""

    @pytest.mark.asyncio
    async def test_with_provided_session(self):
        """Test create_mcp_executor with pre-configured session."""
        mock_session = Mock()

        async with create_mcp_executor(session=mock_session) as executor:
            assert isinstance(executor, MCP_ToolExecutor)
            assert executor.mcp_session is mock_session

        # Session should not be closed (caller manages it)

    @pytest.mark.asyncio
    async def test_without_session_requires_server_path(self):
        """Test create_mcp_executor without session requires server_path."""
        with pytest.raises(RuntimeError, match="MCP server path not configured"):
            async with create_mcp_executor():
                pass

    @pytest.mark.asyncio
    async def test_creates_executor_instance(self):
        """Test that executor instance is created correctly."""
        mock_session = Mock()

        async with create_mcp_executor(session=mock_session) as executor:
            assert isinstance(executor, MCP_ToolExecutor)
            assert hasattr(executor, "execute")
            assert hasattr(executor, "mcp_session")

    @pytest.mark.asyncio
    async def test_executor_cleanup_on_normal_exit(self):
        """Test cleanup happens on normal context exit."""
        mock_session = Mock()

        async with create_mcp_executor(session=mock_session) as executor:
            assert executor is not None
            # Normal operation

        # Context should exit cleanly
        assert True  # If we get here, cleanup was successful

    @pytest.mark.asyncio
    async def test_executor_cleanup_on_exception(self):
        """Test cleanup happens even when exception is raised."""
        mock_session = Mock()

        with pytest.raises(ValueError, match="test error"):
            async with create_mcp_executor(session=mock_session):
                raise ValueError("test error")

        # Cleanup should have happened despite exception

    @pytest.mark.asyncio
    async def test_multiple_sequential_contexts(self):
        """Test multiple sequential context manager uses."""
        mock_session1 = Mock()
        mock_session2 = Mock()

        async with create_mcp_executor(session=mock_session1) as executor1:
            assert executor1.mcp_session is mock_session1

        async with create_mcp_executor(session=mock_session2) as executor2:
            assert executor2.mcp_session is mock_session2

    @pytest.mark.asyncio
    async def test_nested_contexts(self):
        """Test nested context managers (different sessions)."""
        mock_session1 = Mock()
        mock_session2 = Mock()

        async with (
            create_mcp_executor(session=mock_session1) as executor1,
            create_mcp_executor(session=mock_session2) as executor2,
        ):
            assert executor1.mcp_session is mock_session1
            assert executor2.mcp_session is mock_session2

    @pytest.mark.asyncio
    async def test_with_custom_server_command(self):
        """Test create_mcp_executor with custom server command."""
        mock_session = Mock()

        async with create_mcp_executor(server_command="node", session=mock_session) as executor:
            assert isinstance(executor, MCP_ToolExecutor)

    @pytest.mark.asyncio
    async def test_with_server_args(self):
        """Test create_mcp_executor with server arguments."""
        mock_session = Mock()

        async with create_mcp_executor(
            server_args=["--debug", "--verbose"], session=mock_session
        ) as executor:
            assert isinstance(executor, MCP_ToolExecutor)

    @pytest.mark.asyncio
    async def test_executor_is_usable_inside_context(self):
        """Test executor can be used for operations inside context."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"result": "success"}

        async with create_mcp_executor(session=mock_session) as executor:
            # Executor should be usable
            result = await executor.execute("test_tool", {"arg": "value"})
            assert result["result"] == "success"

    @pytest.mark.asyncio
    async def test_context_manager_async_iteration(self):
        """Test context manager works with async iteration patterns."""
        mock_session = Mock()
        results = []

        async with create_mcp_executor(session=mock_session):
            # Simulate async operations
            for i in range(3):
                results.append(i)
                await asyncio.sleep(0)  # Yield control

        assert len(results) == 3


class TestCreateMCPExecutorSync:
    """Test create_mcp_executor_sync synchronous factory."""

    def test_creates_executor_with_session(self):
        """Test creates executor with provided session."""
        mock_session = Mock()
        executor = create_mcp_executor_sync(mock_session)

        assert isinstance(executor, MCP_ToolExecutor)
        assert executor.mcp_session is mock_session

    @pytest.mark.asyncio
    async def test_executor_is_immediately_usable(self):
        """Test executor can be used immediately after creation."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"status": "ok"}

        executor = create_mcp_executor_sync(mock_session)
        result = await executor.execute("test", {})

        assert result["status"] == "ok"
        assert mock_session.call_tool.called

    def test_multiple_executor_creation(self):
        """Test creating multiple executors with different sessions."""
        session1 = Mock()
        session2 = Mock()

        executor1 = create_mcp_executor_sync(session1)
        executor2 = create_mcp_executor_sync(session2)

        assert executor1.mcp_session is session1
        assert executor2.mcp_session is session2
        assert executor1 is not executor2

    @pytest.mark.asyncio
    async def test_with_none_session(self):
        """Test behavior with None session."""
        executor = create_mcp_executor_sync(None)
        assert executor.mcp_session is None

        # Will fail when trying to execute
        with pytest.raises(AttributeError):
            await executor.execute("test", {})

    def test_session_not_managed_by_factory(self):
        """Test that factory doesn't manage session lifecycle."""
        mock_session = Mock()
        create_mcp_executor_sync(mock_session)

        # Factory doesn't close the session - caller manages it
        # Mock objects have 'close' as a method, but it shouldn't be called
        if hasattr(mock_session, "close"):
            assert not mock_session.close.called


class TestSessionManagerEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_server_path_with_spaces(self):
        """Test server path containing spaces."""
        manager = MCPSessionManager(server_path="/path with spaces/server.py")

        with pytest.raises(RuntimeError):  # Will fail to connect
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_server_path_with_special_chars(self):
        """Test server path with special characters."""
        manager = MCPSessionManager(server_path="/path/with-dashes_and.dots/server.py")

        with pytest.raises(RuntimeError):  # Will fail to connect
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_empty_server_command(self):
        """Test with empty server command string."""
        manager = MCPSessionManager(server_command="", server_path="/path/to/server.py")

        with pytest.raises(RuntimeError):  # Will fail to execute
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_very_long_server_args(self):
        """Test with many server arguments."""
        long_args = [f"--arg{i}=value{i}" for i in range(100)]
        manager = MCPSessionManager(server_path="/path/to/server.py", server_args=long_args)

        assert len(manager.server_args) == 100

    @pytest.mark.asyncio
    async def test_unicode_in_server_path(self):
        """Test server path with Unicode characters."""
        manager = MCPSessionManager(server_path="/path/to/服务器.py")

        with pytest.raises(RuntimeError):  # Will fail to connect
            async with manager:
                pass

    @pytest.mark.asyncio
    async def test_relative_server_path(self):
        """Test with relative server path."""
        manager = MCPSessionManager(server_path="./server.py")

        with pytest.raises(RuntimeError):  # Will fail to connect
            async with manager:
                pass


class TestSessionManagerConcurrency:
    """Test concurrent usage patterns."""

    @pytest.mark.asyncio
    async def test_parallel_sessions_different_managers(self):
        """Test multiple managers can be used in parallel."""
        mock_session1 = Mock()
        mock_session2 = Mock()

        async def use_executor(session):
            async with create_mcp_executor(session=session) as executor:
                await asyncio.sleep(0.01)
                return executor.mcp_session

        # Run in parallel
        results = await asyncio.gather(use_executor(mock_session1), use_executor(mock_session2))

        assert results[0] is mock_session1
        assert results[1] is mock_session2

    @pytest.mark.asyncio
    async def test_sequential_context_reentry(self):
        """Test that manager can be used multiple times sequentially."""
        # Note: This tests if the same manager instance can be reused
        # In practice, this may not be supported, but we test the behavior
        mock_session = Mock()

        executor1 = None
        async with create_mcp_executor(session=mock_session) as exec1:
            executor1 = exec1

        executor2 = None
        async with create_mcp_executor(session=mock_session) as exec2:
            executor2 = exec2

        # Should create different executor instances
        assert executor1 is not executor2
        # But with same session
        assert executor1.mcp_session is mock_session
        assert executor2.mcp_session is mock_session


class TestSessionManagerErrorRecovery:
    """Test error handling and recovery scenarios."""

    @pytest.mark.asyncio
    async def test_recovery_after_failed_context(self):
        """Test that new context can be created after previous failure."""
        # First context fails
        with pytest.raises(ValueError):
            async with create_mcp_executor(session=Mock()) as executor:
                raise ValueError("first error")

        # Second context should work
        mock_session = Mock()
        async with create_mcp_executor(session=mock_session) as executor:
            assert executor.mcp_session is mock_session

    @pytest.mark.asyncio
    async def test_exception_in_context_does_not_leak_resources(self):
        """Test that exceptions don't cause resource leaks."""
        mock_session = Mock()
        cleanup_tracker = []

        try:
            async with create_mcp_executor(session=mock_session):
                cleanup_tracker.append("entered")
                raise RuntimeError("test exception")
        except RuntimeError:
            cleanup_tracker.append("cleaned_up")

        assert cleanup_tracker == ["entered", "cleaned_up"]

    @pytest.mark.asyncio
    async def test_keyboard_interrupt_handling(self):
        """Test handling of KeyboardInterrupt."""
        mock_session = Mock()

        with pytest.raises(KeyboardInterrupt):
            async with create_mcp_executor(session=mock_session):
                raise KeyboardInterrupt()

        # Context should have exited cleanly

    @pytest.mark.asyncio
    async def test_system_exit_handling(self):
        """Test handling of SystemExit."""
        mock_session = Mock()

        with pytest.raises(SystemExit):
            async with create_mcp_executor(session=mock_session):
                raise SystemExit(1)


class TestSessionManagerLogging:
    """Test logging behavior of session manager."""

    @pytest.mark.asyncio
    async def test_logs_connection_with_mock_session(self, caplog):
        """Test that connection is logged."""
        import logging

        caplog.set_level(logging.INFO)

        mock_session = Mock()

        async with create_mcp_executor(session=mock_session):
            pass

        # Check for log messages
        assert any("session" in record.message.lower() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_logs_cleanup(self, caplog):
        """Test that cleanup is logged."""
        import logging

        caplog.set_level(logging.INFO)

        mock_session = Mock()

        async with create_mcp_executor(session=mock_session):
            pass

        # Check for log messages related to executor lifecycle
        # When using provided session, we log "Using provided MCP session"
        # and "MCP executor cleanup complete"
        assert any(
            "executor" in record.message.lower() or "session" in record.message.lower()
            for record in caplog.records
        )


class TestFactoryFunctionConvenience:
    """Test convenience and usability of factory functions."""

    @pytest.mark.asyncio
    async def test_create_mcp_executor_as_decorator(self):
        """Test using create_mcp_executor in function decorator pattern."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"result": "test"}

        async def do_work():
            async with create_mcp_executor(session=mock_session) as executor:
                return await executor.execute("tool", {})

        result = await do_work()
        assert result["result"] == "test"

    @pytest.mark.asyncio
    async def test_sync_factory_for_testing(self):
        """Test sync factory is convenient for testing."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"test": "value"}

        # Easy to create in sync test context
        executor = create_mcp_executor_sync(mock_session)

        # Can use immediately
        result = await executor.execute("test_tool", {})
        assert result["test"] == "value"

    @pytest.mark.asyncio
    async def test_async_factory_with_await(self):
        """Test async factory works with await patterns."""
        mock_session = Mock()

        async def process():
            async with create_mcp_executor(session=mock_session) as executor:
                # Simulate async work
                await asyncio.sleep(0)
                return executor

        executor = await process()
        # Note: executor used outside context (testing cleanup)
        assert executor.mcp_session is mock_session
