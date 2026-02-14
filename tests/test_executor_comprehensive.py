"""Comprehensive unit tests for mcp_pvp.executor module.

Tests cover:
- ToolExecutor abstract interface
- DummyExecutor implementation
- MCP_ToolExecutor implementation
- Error handling and edge cases
- Security considerations
"""

from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from mcp_pvp.executor import DummyExecutor, MCP_ToolExecutor, ToolExecutor


class TestToolExecutorInterface:
    """Test ToolExecutor abstract base class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that ToolExecutor cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            ToolExecutor()

    def test_must_implement_execute_method(self):
        """Test that subclasses must implement all abstract methods."""

        class IncompleteExecutor(ToolExecutor):
            pass

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompleteExecutor()

    def test_must_implement_all_abstract_methods(self):
        """Test that subclasses must implement all abstract methods."""

        # Missing list_tools, get_tool_info, get_tool
        class PartialExecutor(ToolExecutor):
            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                return {"status": "ok"}

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            PartialExecutor()

    def test_valid_subclass_implementation(self):
        """Test that valid subclass can be instantiated."""

        class ValidExecutor(ToolExecutor):
            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                return {"status": "ok"}

            async def list_tools(self) -> list[str]:
                return ["tool1", "tool2"]

            async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
                return {"description": "Test tool"}

            async def get_tool(self, tool_name: str) -> Any:
                async def stub():
                    return "result"

                return stub

        executor = ValidExecutor()
        assert isinstance(executor, ToolExecutor)

    @pytest.mark.asyncio
    async def test_all_methods_are_async(self):
        """Test that all abstract methods are async."""

        class TestExecutor(ToolExecutor):
            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                return {"status": "ok"}

            async def list_tools(self) -> list[str]:
                return ["test_tool"]

            async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
                return {"description": "Test"}

            async def get_tool(self, tool_name: str) -> Any:
                return None

        executor = TestExecutor()

        # All methods should be awaitable
        result = await executor.execute("test", {})
        assert result["status"] == "ok"

        tools = await executor.list_tools()
        assert isinstance(tools, list)

        info = await executor.get_tool_info("test")
        assert isinstance(info, dict)

        tool = await executor.get_tool("test")
        assert tool is None


class TestDummyExecutor:
    """Test DummyExecutor reference implementation."""

    def test_instantiation(self):
        """Test DummyExecutor can be instantiated."""
        executor = DummyExecutor()
        assert isinstance(executor, ToolExecutor)
        assert isinstance(executor, DummyExecutor)

    @pytest.mark.asyncio
    async def test_execute_returns_stub_response(self):
        """Test execute returns expected stub response structure."""
        executor = DummyExecutor()
        result = await executor.execute("test_tool", {"arg1": "value1"})

        assert isinstance(result, dict)
        assert result["status"] == "stub"
        assert result["message"] == "DummyExecutor does not execute real tools"
        assert result["tool"] == "test_tool"
        assert result["args_received"] is True
        assert result["arg_count"] == 1

    @pytest.mark.asyncio
    async def test_execute_with_empty_args(self):
        """Test execute with no arguments."""
        executor = DummyExecutor()
        result = await executor.execute("no_args_tool", {})

        assert result["arg_count"] == 0
        assert result["args_received"] is True

    @pytest.mark.asyncio
    async def test_execute_with_multiple_args(self):
        """Test execute with multiple arguments."""
        executor = DummyExecutor()
        args = {
            "email": "test@example.com",
            "phone": "+1-555-0100",
            "message": "Hello",
            "count": 42,
            "flag": True,
        }
        result = await executor.execute("multi_arg_tool", args)

        assert result["arg_count"] == 5
        assert result["tool"] == "multi_arg_tool"

    @pytest.mark.asyncio
    async def test_execute_with_nested_args(self):
        """Test execute with nested dict arguments."""
        executor = DummyExecutor()
        args = {
            "user": {
                "name": "Alice",
                "contact": {"email": "alice@example.com", "phone": "+1-555-0100"},
            },
            "metadata": {"timestamp": "2026-02-08"},
        }
        result = await executor.execute("nested_tool", args)

        # arg_count counts top-level keys
        assert result["arg_count"] == 2
        assert result["tool"] == "nested_tool"

    @pytest.mark.asyncio
    async def test_execute_preserves_tool_name(self):
        """Test that tool name is correctly preserved in response."""
        executor = DummyExecutor()
        tool_names = ["send_email", "process_payment", "log_event", "calculate"]

        for tool_name in tool_names:
            result = await executor.execute(tool_name, {"test": "value"})
            assert result["tool"] == tool_name

    @pytest.mark.asyncio
    async def test_execute_idempotent(self):
        """Test that multiple executions return consistent results."""
        executor = DummyExecutor()
        args = {"key": "value"}

        result1 = await executor.execute("same_tool", args)
        result2 = await executor.execute("same_tool", args)

        assert result1 == result2

    @pytest.mark.asyncio
    async def test_execute_with_pii_args(self):
        """Test DummyExecutor handles PII in args without logging."""
        executor = DummyExecutor()
        sensitive_args = {
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111",
            "email": "secret@example.com",
        }

        # Should not raise exception
        result = await executor.execute("pii_tool", sensitive_args)

        # Should not include actual args in response (security)
        assert "ssn" not in str(result)
        assert "credit_card" not in str(result)
        assert result["args_received"] is True

    @pytest.mark.asyncio
    async def test_list_tools(self):
        """Test list_tools returns expected tool list."""
        executor = DummyExecutor()
        tools = await executor.list_tools()

        assert isinstance(tools, list)
        assert len(tools) == 3
        assert "add_numbers" in tools
        assert "get_user_info" in tools
        assert "send_email" in tools

    @pytest.mark.asyncio
    async def test_get_tool_info_valid_tool(self):
        """Test get_tool_info returns metadata for valid tool."""
        executor = DummyExecutor()

        # Test add_numbers
        info = await executor.get_tool_info("add_numbers")
        assert isinstance(info, dict)
        assert info["description"] == "Add two numbers together"
        assert "args" in info
        assert info["args"]["a"] == "number"
        assert info["args"]["b"] == "number"

        # Test get_user_info
        info = await executor.get_tool_info("get_user_info")
        assert info["description"] == "Get user information by email"
        assert info["args"]["email"] == "string"

        # Test send_email
        info = await executor.get_tool_info("send_email")
        assert info["description"] == "Send an email to a recipient"
        assert "recipient_email" in info["args"]
        assert "subject" in info["args"]
        assert "body" in info["args"]

    @pytest.mark.asyncio
    async def test_get_tool_info_invalid_tool(self):
        """Test get_tool_info raises KeyError for invalid tool."""
        executor = DummyExecutor()

        with pytest.raises(KeyError, match="Tool 'nonexistent_tool' not found"):
            await executor.get_tool_info("nonexistent_tool")

    @pytest.mark.asyncio
    async def test_get_tool_valid_tool(self):
        """Test get_tool returns callable for valid tool."""
        executor = DummyExecutor()

        tool = await executor.get_tool("add_numbers")
        assert callable(tool)

        # Call the tool
        result = await tool(a=5, b=3)
        assert isinstance(result, dict)
        assert result["status"] == "stub"
        assert result["message"] == "DummyExecutor stub for tool 'add_numbers'"
        assert result["args"]["a"] == 5
        assert result["args"]["b"] == 3

    @pytest.mark.asyncio
    async def test_get_tool_invalid_tool(self):
        """Test get_tool raises KeyError for invalid tool."""
        executor = DummyExecutor()

        with pytest.raises(KeyError, match="Tool 'invalid_tool' not found"):
            await executor.get_tool("invalid_tool")

    @pytest.mark.asyncio
    async def test_get_tool_callable_execution(self):
        """Test that tool callable can be executed multiple times."""
        executor = DummyExecutor()

        send_email = await executor.get_tool("send_email")

        # Execute multiple times
        result1 = await send_email(
            recipient_email="alice@example.com", subject="Test 1", body="Hello"
        )
        result2 = await send_email(
            recipient_email="bob@example.com", subject="Test 2", body="World"
        )

        assert result1["args"]["recipient_email"] == "alice@example.com"
        assert result2["args"]["recipient_email"] == "bob@example.com"
        assert result1["message"] == result2["message"]  # Same stub message


class TestMCPToolExecutor:
    """Test MCP_ToolExecutor implementation."""

    def test_instantiation_with_session(self):
        """Test MCP_ToolExecutor can be instantiated with session."""
        mock_session = Mock()
        executor = MCP_ToolExecutor(mock_session)

        assert isinstance(executor, ToolExecutor)
        assert executor.mcp_session is mock_session

    @pytest.mark.asyncio
    async def test_execute_calls_mcp_session(self):
        """Test execute calls mcp_session.call_tool."""
        mock_session = AsyncMock()
        mock_result = {"output": "success"}
        mock_session.call_tool.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)
        result = await executor.execute("test_tool", {"arg": "value"})

        # Verify call_tool was called
        assert mock_session.call_tool.called
        assert result == mock_result

    @pytest.mark.asyncio
    async def test_execute_passes_correct_parameters(self):
        """Test execute passes correct parameters to MCP."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"status": "ok"}

        executor = MCP_ToolExecutor(mock_session)
        tool_args = {"email": "test@example.com", "subject": "Test"}
        await executor.execute("send_email", tool_args)

        # Verify call parameters
        mock_session.call_tool.assert_called_once_with(name="send_email", arguments=tool_args)

    @pytest.mark.asyncio
    async def test_execute_with_injected_pii(self):
        """Test execute handles injected PII correctly."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"sent": True}

        executor = MCP_ToolExecutor(mock_session)
        injected_args = {
            "to": "alice@example.com",  # Raw PII injected by vault
            "from": "system@example.com",
            "message": "Your account balance is $1000",
        }

        result = await executor.execute("send_email", injected_args)

        # Verify PII was passed through to tool
        call_kwargs = mock_session.call_tool.call_args.kwargs
        assert call_kwargs["arguments"]["to"] == "alice@example.com"
        assert result["sent"] is True

    @pytest.mark.asyncio
    async def test_execute_propagates_exceptions(self):
        """Test that exceptions from MCP are propagated."""
        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = RuntimeError("Tool execution failed")

        executor = MCP_ToolExecutor(mock_session)

        with pytest.raises(RuntimeError, match="Tool execution failed"):
            await executor.execute("failing_tool", {})

    @pytest.mark.asyncio
    async def test_execute_with_complex_return_value(self):
        """Test execute handles complex return values."""
        mock_session = AsyncMock()
        complex_result = {
            "status": "success",
            "data": {
                "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
                "metadata": {"total": 2, "page": 1},
            },
            "timestamp": "2026-02-08T12:00:00Z",
        }
        mock_session.call_tool.return_value = complex_result

        executor = MCP_ToolExecutor(mock_session)
        result = await executor.execute("get_users", {})

        assert result == complex_result
        assert result["data"]["users"][0]["name"] == "Alice"

    @pytest.mark.asyncio
    async def test_execute_with_empty_args(self):
        """Test execute with no arguments."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"status": "ok"}

        executor = MCP_ToolExecutor(mock_session)
        result = await executor.execute("no_args_tool", {})

        mock_session.call_tool.assert_called_once_with(name="no_args_tool", arguments={})
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_multiple_sequential_executions(self):
        """Test multiple tool executions in sequence."""
        mock_session = AsyncMock()
        results = [{"result": "first"}, {"result": "second"}, {"result": "third"}]
        mock_session.call_tool.side_effect = results

        executor = MCP_ToolExecutor(mock_session)

        result1 = await executor.execute("tool1", {})
        result2 = await executor.execute("tool2", {})
        result3 = await executor.execute("tool3", {})

        assert result1["result"] == "first"
        assert result2["result"] == "second"
        assert result3["result"] == "third"
        assert mock_session.call_tool.call_count == 3

    @pytest.mark.asyncio
    async def test_execute_with_different_tool_names(self):
        """Test execute with various tool names."""
        mock_session = AsyncMock()
        mock_session.call_tool.return_value = {"ok": True}

        executor = MCP_ToolExecutor(mock_session)

        tools = [
            "send_email",
            "process_payment",
            "log_analytics_event",
            "fetch_user_profile",
            "update_database",
        ]

        for tool_name in tools:
            await executor.execute(tool_name, {"test": "data"})
            call_kwargs = mock_session.call_tool.call_args.kwargs
            assert call_kwargs["name"] == tool_name

    @pytest.mark.asyncio
    async def test_list_tools_from_mcp_session(self):
        """Test list_tools retrieves tools from MCP session."""
        mock_session = AsyncMock()

        # Mock MCP list_tools response
        mock_tool1 = Mock()
        mock_tool1.name = "send_email"
        mock_tool2 = Mock()
        mock_tool2.name = "get_weather"
        mock_tool3 = Mock()
        mock_tool3.name = "calculate"

        mock_result = Mock()
        mock_result.tools = [mock_tool1, mock_tool2, mock_tool3]
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)
        tools = await executor.list_tools()

        assert isinstance(tools, list)
        assert len(tools) == 3
        assert "send_email" in tools
        assert "get_weather" in tools
        assert "calculate" in tools
        assert mock_session.list_tools.called

    @pytest.mark.asyncio
    async def test_get_tool_info_from_mcp_session(self):
        """Test get_tool_info retrieves metadata from MCP session."""
        mock_session = AsyncMock()

        # Mock MCP tool with metadata
        mock_tool = Mock()
        mock_tool.name = "send_email"
        mock_tool.description = "Send an email to a recipient"
        mock_tool.inputSchema = {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
        }

        mock_result = Mock()
        mock_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)
        info = await executor.get_tool_info("send_email")

        assert isinstance(info, dict)
        assert info["name"] == "send_email"
        assert info["description"] == "Send an email to a recipient"
        assert "args" in info
        assert info["args"]["type"] == "object"

    @pytest.mark.asyncio
    async def test_get_tool_info_tool_not_found(self):
        """Test get_tool_info raises KeyError for non-existent tool."""
        mock_session = AsyncMock()

        mock_tool = Mock()
        mock_tool.name = "send_email"
        mock_result = Mock()
        mock_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)

        with pytest.raises(KeyError, match="Tool 'nonexistent' not found"):
            await executor.get_tool_info("nonexistent")

    @pytest.mark.asyncio
    async def test_get_tool_from_mcp_session(self):
        """Test get_tool retrieves tool object from MCP session."""
        mock_session = AsyncMock()

        # Mock MCP tool
        mock_tool = Mock()
        mock_tool.name = "calculate"
        mock_tool.description = "Perform calculations"

        mock_result = Mock()
        mock_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)
        tool = await executor.get_tool("calculate")

        assert tool is not None
        assert tool.name == "calculate"
        assert tool.description == "Perform calculations"

    @pytest.mark.asyncio
    async def test_get_tool_not_found(self):
        """Test get_tool raises KeyError for non-existent tool."""
        mock_session = AsyncMock()

        mock_tool = Mock()
        mock_tool.name = "existing_tool"
        mock_result = Mock()
        mock_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)

        with pytest.raises(KeyError, match="Tool 'missing_tool' not found"):
            await executor.get_tool("missing_tool")

    @pytest.mark.asyncio
    async def test_get_tool_returns_none_if_not_in_list(self):
        """Test get_tool behavior when tool not in session."""
        mock_session = AsyncMock()

        # Empty tools list
        mock_result = Mock()
        mock_result.tools = []
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)

        with pytest.raises(KeyError):
            await executor.get_tool("any_tool")

    @pytest.mark.asyncio
    async def test_list_tools_empty_session(self):
        """Test list_tools when MCP session has no tools."""
        mock_session = AsyncMock()

        mock_result = Mock()
        mock_result.tools = []
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)
        tools = await executor.list_tools()

        assert isinstance(tools, list)
        assert len(tools) == 0

    @pytest.mark.asyncio
    async def test_get_tool_info_multiple_tools(self):
        """Test get_tool_info with multiple tools in session."""
        mock_session = AsyncMock()

        # Create multiple mock tools
        tools = []
        for i in range(5):
            tool = Mock()
            tool.name = f"tool_{i}"
            tool.description = f"Description for tool {i}"
            tool.inputSchema = {"type": "object"}
            tools.append(tool)

        mock_result = Mock()
        mock_result.tools = tools
        mock_session.list_tools.return_value = mock_result

        executor = MCP_ToolExecutor(mock_session)

        # Test retrieving info for tool in the middle
        info = await executor.get_tool_info("tool_2")
        assert info["name"] == "tool_2"
        assert info["description"] == "Description for tool 2"


class TestExecutorSecurityConsiderations:
    """Test security-related behavior of executors."""

    @pytest.mark.asyncio
    async def test_pii_exposure_minimization(self):
        """Test that PII exposure is minimized in executor flow."""

        class TrackingExecutor(ToolExecutor):
            def __init__(self):
                self.pii_seen = []

            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                # Record PII exposure
                if "email" in injected_args:
                    self.pii_seen.append(injected_args["email"])
                return {"status": "ok"}

            async def list_tools(self) -> list[str]:
                return []

            async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
                return {}

            async def get_tool(self, tool_name: str) -> Any:
                return None

        executor = TrackingExecutor()
        await executor.execute("send_email", {"email": "secret@example.com"})

        # PII was exposed to executor (expected)
        assert len(executor.pii_seen) == 1
        assert executor.pii_seen[0] == "secret@example.com"

    @pytest.mark.asyncio
    async def test_dummy_executor_does_not_log_sensitive_args(self):
        """Test DummyExecutor doesn't include sensitive data in response."""
        executor = DummyExecutor()
        sensitive_data = {
            "password": "super_secret_123",
            "api_key": "sk_test_1234567890",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        }

        result = await executor.execute("secure_tool", sensitive_data)

        # Result should not contain actual sensitive values
        result_str = str(result)
        assert "super_secret_123" not in result_str
        assert "sk_test_1234567890" not in result_str
        assert "eyJhbGci" not in result_str

        # But should indicate args were received
        assert result["args_received"] is True
        assert result["arg_count"] == 3

    @pytest.mark.asyncio
    async def test_custom_executor_can_implement_logging_prevention(self):
        """Test custom executor can prevent logging of sensitive data."""

        class SecureExecutor(ToolExecutor):
            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                # Executor explicitly avoids logging injected_args
                # This is the recommended pattern
                try:
                    # Do work without logging args
                    return {"success": True}
                except Exception as e:
                    # Log error without args
                    return {"success": False, "error": str(e)}

            async def list_tools(self) -> list[str]:
                return []

            async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
                return {}

            async def get_tool(self, tool_name: str) -> Any:
                return None

        executor = SecureExecutor()
        result = await executor.execute("pii_tool", {"ssn": "123-45-6789"})

        assert result["success"] is True
        # No SSN in result
        assert "123-45-6789" not in str(result)


class TestExecutorEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_executor_with_none_args(self):
        """Test executor behavior with None values in args."""
        executor = DummyExecutor()
        result = await executor.execute("test", {"key": None})

        assert result["arg_count"] == 1
        assert result["args_received"] is True

    @pytest.mark.asyncio
    async def test_executor_with_empty_string_tool_name(self):
        """Test executor with empty tool name."""
        executor = DummyExecutor()
        result = await executor.execute("", {"arg": "value"})

        assert result["tool"] == ""
        assert result["status"] == "stub"

    @pytest.mark.asyncio
    async def test_executor_with_unicode_tool_name(self):
        """Test executor with Unicode tool name."""
        executor = DummyExecutor()
        result = await executor.execute("send_📧_email", {"to": "test@example.com"})

        assert result["tool"] == "send_📧_email"

    @pytest.mark.asyncio
    async def test_executor_with_very_long_tool_name(self):
        """Test executor with very long tool name."""
        executor = DummyExecutor()
        long_name = "very_" * 100 + "long_tool_name"
        result = await executor.execute(long_name, {})

        assert result["tool"] == long_name
        assert len(result["tool"]) > 500

    @pytest.mark.asyncio
    async def test_executor_with_special_chars_in_args(self):
        """Test executor with special characters in arguments."""
        executor = DummyExecutor()
        special_args = {
            "newlines": "line1\nline2\nline3",
            "tabs": "col1\tcol2\tcol3",
            "quotes": 'She said "Hello"',
            "backslash": "C:\\Users\\test\\file.txt",
        }
        result = await executor.execute("special_tool", special_args)

        assert result["arg_count"] == 4

    @pytest.mark.asyncio
    async def test_mcp_executor_with_null_session(self):
        """Test MCP_ToolExecutor behavior with None session."""
        executor = MCP_ToolExecutor(None)

        with pytest.raises(AttributeError):
            await executor.execute("test", {})

    @pytest.mark.asyncio
    async def test_executor_memory_cleanup(self):
        """Test that executor doesn't retain references to PII."""

        class CleanupExecutor(ToolExecutor):
            def __init__(self):
                self.last_args = None

            async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
                # Intentionally DON'T store injected_args (best practice)
                result = {"tool": tool_name, "arg_count": len(injected_args)}
                # injected_args goes out of scope here
                return result

            async def list_tools(self) -> list[str]:
                return []

            async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
                return {}

            async def get_tool(self, tool_name: str) -> Any:
                return None

        executor = CleanupExecutor()
        await executor.execute("pii_tool", {"ssn": "123-45-6789", "email": "test@example.com"})

        # Executor should not have retained the PII
        assert executor.last_args is None
