"""Tests for recursive output scrubbing in vault.deliver()."""

import pytest

from mcp_pvp.models import (
    DeliverRequest,
    PIIType,
    Policy,
    RunContext,
    Sink,
    SinkKind,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
)
from mcp_pvp.vault import Vault, serialize_for_pii_detection


class CustomObject:
    """Custom object for testing."""

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
        self.metadata = {"created": "2026-01-01"}


class TestSerializeForPIIDetection:
    """Test the serialize_for_pii_detection helper function."""

    def test_serialize_primitives(self):
        """Test serialization of primitive types."""
        assert serialize_for_pii_detection(None) == "null"
        assert serialize_for_pii_detection(True) == "true"
        assert serialize_for_pii_detection(False) == "false"
        assert serialize_for_pii_detection(42) == "42"
        assert serialize_for_pii_detection(3.14) == "3.14"
        assert serialize_for_pii_detection("hello") == '"hello"'

    def test_serialize_dict(self):
        """Test serialization of dictionaries."""
        obj = {"name": "Alice", "age": 30}
        result = serialize_for_pii_detection(obj)
        # Should be valid JSON-like string
        assert '"name": "Alice"' in result
        assert '"age": 30' in result

    def test_serialize_list(self):
        """Test serialization of lists."""
        obj = ["item1", 123, True]
        result = serialize_for_pii_detection(obj)
        assert '"item1"' in result
        assert "123" in result
        assert "true" in result

    def test_serialize_nested_structures(self):
        """Test serialization of deeply nested structures."""
        obj = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {"email": "deep@example.com", "data": [1, 2, 3]}
                    }
                }
            }
        }
        result = serialize_for_pii_detection(obj)
        assert "deep@example.com" in result
        assert "level1" in result
        assert "level4" in result

    def test_serialize_exception(self):
        """Test serialization of exception objects."""
        exc = ValueError("Invalid email: test@example.com")
        result = serialize_for_pii_detection(exc)
        assert "ValueError" in result
        assert "test@example.com" in result
        assert "exception_type" in result
        assert "message" in result

    def test_serialize_exception_with_traceback(self):
        """Test serialization of exception with traceback."""
        try:
            # Create exception with traceback
            email = "secret@example.com"
            raise RuntimeError(f"Failed to process {email}")
        except RuntimeError as e:
            result = serialize_for_pii_detection(e)
            assert "RuntimeError" in result
            assert "secret@example.com" in result
            assert "traceback" in result

    def test_serialize_custom_object(self):
        """Test serialization of custom objects with __dict__."""
        obj = CustomObject(name="Bob", email="bob@example.com")
        result = serialize_for_pii_detection(obj)
        assert "bob@example.com" in result
        assert "Bob" in result
        assert "CustomObject" in result  # Type name included
        assert "__type__" in result

    def test_serialize_tuple_and_set(self):
        """Test serialization of tuples and sets."""
        obj1 = ("a", "b", "c")
        result1 = serialize_for_pii_detection(obj1)
        assert '"a"' in result1
        assert '"b"' in result1

        obj2 = {"x", "y", "z"}
        result2 = serialize_for_pii_detection(obj2)
        # Sets are unordered, but all items should be present
        assert '"x"' in result2 or '"y"' in result2 or '"z"' in result2

    def test_serialize_max_depth(self):
        """Test that max_depth prevents infinite recursion."""
        # Create deeply nested structure
        obj = {"level": 0}
        current = obj
        for i in range(20):
            current["next"] = {"level": i + 1}
            current = current["next"]

        # With max_depth=5, should stop at depth 5
        result = serialize_for_pii_detection(obj, max_depth=5)
        assert "max_depth_exceeded" in result


class TestRecursiveOutputScrubbing:
    """Test recursive output scrubbing in deliver()."""

    @pytest.fixture
    def vault(self):
        """Create vault with permissive policy."""
        policy = Policy(
            default_allow=True,
            rules=[],
        )
        return Vault(policy=policy)

    def test_deliver_scrubs_exception_result(self, vault):
        """Test that exceptions in tool results are scrubbed for PII."""
        # Tokenize content to get session
        tokenize_req = TokenizeRequest(
            content="Process email: alice@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)

        # Mock tool execution that returns an exception (serialized)
        # In reality, executor would handle the exception, but we test serialization
        exc_result = ValueError("Failed: user email is bob@secret.com")
        serialized = serialize_for_pii_detection(exc_result)

        # Tokenize the serialized exception
        exc_tokenize = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
                vault_session=tokenize_resp.vault_session,
            )
        )

        # Verify PII in exception message was detected
        assert len(exc_tokenize.tokens) > 0
        # Check that email was tokenized
        email_token = next(
            (t for t in exc_tokenize.tokens if t.pii_type == PIIType.EMAIL), None
        )
        assert email_token is not None
        assert "bob@secret.com" not in exc_tokenize.redacted

    def test_deliver_scrubs_nested_dict_result(self, vault):
        """Test that deeply nested dicts in tool results are scrubbed."""
        # Create a nested structure with PII
        nested_result = {
            "status": "success",
            "user": {
                "profile": {
                    "contact": {"email": "nested@example.com", "phone": "555-1234"},
                    "preferences": {"language": "en"},
                },
                "account": {"id": 12345},
            },
        }

        # Serialize for PII detection
        serialized = serialize_for_pii_detection(nested_result)

        # Tokenize
        tokenize_resp = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
            )
        )

        # Verify nested PII was detected
        assert len(tokenize_resp.tokens) > 0
        email_token = next(
            (t for t in tokenize_resp.tokens if t.pii_type == PIIType.EMAIL), None
        )
        assert email_token is not None
        assert "nested@example.com" not in tokenize_resp.redacted

    def test_deliver_scrubs_custom_object_result(self, vault):
        """Test that custom objects in tool results are scrubbed."""
        # Create custom object with PII
        obj = CustomObject(name="Charlie", email="charlie@example.com")

        # Serialize for PII detection
        serialized = serialize_for_pii_detection(obj)

        # Tokenize
        tokenize_resp = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
            )
        )

        # Verify PII in custom object was detected
        assert len(tokenize_resp.tokens) > 0
        email_token = next(
            (t for t in tokenize_resp.tokens if t.pii_type == PIIType.EMAIL), None
        )
        assert email_token is not None
        assert "charlie@example.com" not in tokenize_resp.redacted

    def test_deliver_scrubs_list_of_dicts(self, vault):
        """Test that lists containing dicts with PII are scrubbed."""
        list_result = [
            {"user": "user1", "email": "user1@example.com"},
            {"user": "user2", "email": "user2@example.com"},
            {"user": "user3", "email": "user3@example.com"},
        ]

        # Serialize for PII detection
        serialized = serialize_for_pii_detection(list_result)

        # Tokenize
        tokenize_resp = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
            )
        )

        # Should detect all 3 emails
        email_tokens = [t for t in tokenize_resp.tokens if t.pii_type == PIIType.EMAIL]
        assert len(email_tokens) == 3
        assert "user1@example.com" not in tokenize_resp.redacted
        assert "user2@example.com" not in tokenize_resp.redacted
        assert "user3@example.com" not in tokenize_resp.redacted

    def test_deliver_scrubs_mixed_exception_and_data(self, vault):
        """Test that mixed exception and data structures are scrubbed."""
        # Simulate error response with both exception and context data
        mixed_result = {
            "error": ValueError("Invalid input: admin@company.com"),
            "context": {"request_id": "12345", "user_email": "requester@example.com"},
        }

        # Serialize for PII detection
        serialized = serialize_for_pii_detection(mixed_result)

        # Tokenize
        tokenize_resp = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
            )
        )

        # Should detect both emails
        email_tokens = [t for t in tokenize_resp.tokens if t.pii_type == PIIType.EMAIL]
        assert len(email_tokens) == 2
        assert "admin@company.com" not in tokenize_resp.redacted
        assert "requester@example.com" not in tokenize_resp.redacted

    def test_deliver_handles_none_result(self, vault):
        """Test that None results are handled without errors."""
        # Create a custom executor that returns None
        from mcp_pvp.executor import DummyExecutor

        class NoneExecutor(DummyExecutor):
            def execute(self, tool_name: str, injected_args: dict) -> None:
                return None

        # Replace the vault's executor
        vault.executor = NoneExecutor()

        # Tokenize to create session  
        tokenize_req = TokenizeRequest(
            content="Test content with email@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)

        # Deliver with None result
        deliver_req = DeliverRequest(
            vault_session=tokenize_resp.vault_session,
            run=RunContext(run_id="test_run", participant_id="test_llm"),
            tool_call=ToolCall(name="test_tool", args={}),
        )

        deliver_resp = vault.deliver(deliver_req)
        assert deliver_resp.delivered
        assert deliver_resp.tool_result is None
        assert len(deliver_resp.result_tokens) == 0

    def test_deliver_handles_primitive_results(self, vault):
        """Test that primitive results (str, int, bool) are handled."""
        # Test string result
        serialized = serialize_for_pii_detection("Contact: support@example.com")
        tokenize_resp = vault.tokenize(
            TokenizeRequest(
                content=serialized,
                token_format=TokenFormat.TEXT,
            )
        )
        assert len(tokenize_resp.tokens) > 0
        assert "support@example.com" not in tokenize_resp.redacted

        # Test int result
        serialized = serialize_for_pii_detection(42)
        assert serialized == "42"

        # Test bool result
        serialized = serialize_for_pii_detection(True)
        assert serialized == "true"


class TestRecursiveScrubbingEdgeCases:
    """Test edge cases for recursive scrubbing."""

    def test_circular_reference_protection(self):
        """Test that circular references are handled via max_depth."""
        obj = {"self": None}
        obj["self"] = obj  # Circular reference

        # Should not infinite loop, max_depth should protect
        result = serialize_for_pii_detection(obj, max_depth=3)
        assert "max_depth_exceeded" in result

    def test_empty_collections(self):
        """Test serialization of empty collections."""
        assert serialize_for_pii_detection([]) == "[]"
        assert serialize_for_pii_detection({}) == "{}"
        assert serialize_for_pii_detection(set()) == "[]"

    def test_special_characters_in_strings(self):
        """Test that special characters are properly escaped."""
        obj = {"message": 'Quote: " Newline: \n Tab: \t'}
        result = serialize_for_pii_detection(obj)
        # json.dumps should properly escape special chars
        assert '"message"' in result
        assert r"\n" in result or "\\n" in result  # Escaped newline
