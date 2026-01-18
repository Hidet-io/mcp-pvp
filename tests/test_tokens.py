"""Tests for token utilities."""

import pytest

from mcp_pvp.errors import TokenInvalidError
from mcp_pvp.models import PIIType
from mcp_pvp.tokens import (
    extract_json_tokens,
    extract_text_tokens,
    parse_text_token,
    redact_content,
    replace_json_tokens,
    replace_text_tokens,
)


def test_parse_text_token() -> None:
    """Test parsing text token."""
    token = parse_text_token("[[PII:EMAIL:tkn_abc123]]")

    assert token.ref == "tkn_abc123"
    assert token.pii_type == PIIType.EMAIL


def test_parse_text_token_invalid_format() -> None:
    """Test parsing invalid text token format."""
    with pytest.raises(TokenInvalidError):
        parse_text_token("not a token")


def test_parse_text_token_invalid_type() -> None:
    """Test parsing text token with invalid PII type."""
    with pytest.raises(TokenInvalidError):
        parse_text_token("[[PII:INVALID_TYPE:tkn_abc]]")


def test_extract_text_tokens() -> None:
    """Test extracting text tokens from content."""
    content = "Send email to [[PII:EMAIL:tkn_1]] and call [[PII:PHONE:tkn_2]]"

    tokens = extract_text_tokens(content)

    assert len(tokens) == 2
    assert tokens[0].ref == "tkn_1"
    assert tokens[0].pii_type == PIIType.EMAIL
    assert tokens[1].ref == "tkn_2"
    assert tokens[1].pii_type == PIIType.PHONE


def test_replace_text_tokens() -> None:
    """Test replacing text tokens with values."""
    content = "Send email to [[PII:EMAIL:tkn_1]]"
    replacements = {"tkn_1": "test@example.com"}

    result = replace_text_tokens(content, replacements)

    assert result == "Send email to test@example.com"


def test_replace_text_tokens_multiple() -> None:
    """Test replacing multiple text tokens."""
    content = "Email [[PII:EMAIL:tkn_1]] at [[PII:PHONE:tkn_2]]"
    replacements = {
        "tkn_1": "test@example.com",
        "tkn_2": "555-1234",
    }

    result = replace_text_tokens(content, replacements)

    assert result == "Email test@example.com at 555-1234"


def test_extract_json_tokens() -> None:
    """Test extracting JSON tokens from data structure."""
    data = {
        "to": {"$pii_ref": "tkn_1", "type": "EMAIL", "cap": "cap_abc"},
        "subject": "Hello",
        "recipients": [
            {"$pii_ref": "tkn_2", "type": "EMAIL", "cap": "cap_def"},
        ],
    }

    token_paths = extract_json_tokens(data)

    assert len(token_paths) == 2
    assert token_paths[0][0].pii_ref == "tkn_1"
    assert token_paths[0][1] == "to"  # path
    assert token_paths[1][0].pii_ref == "tkn_2"
    assert token_paths[1][1] == "recipients[0]"  # path


def test_replace_json_tokens() -> None:
    """Test replacing JSON tokens with values."""
    data = {
        "to": {"$pii_ref": "tkn_1", "type": "EMAIL", "cap": "cap_abc"},
        "subject": "Hello",
    }
    replacements = {"tkn_1": "test@example.com"}

    result = replace_json_tokens(data, replacements)

    assert result["to"] == "test@example.com"
    assert result["subject"] == "Hello"


def test_replace_json_tokens_nested() -> None:
    """Test replacing nested JSON tokens."""
    data = {
        "recipients": [
            {"email": {"$pii_ref": "tkn_1", "type": "EMAIL"}},
            {"email": {"$pii_ref": "tkn_2", "type": "EMAIL"}},
        ]
    }
    replacements = {
        "tkn_1": "alice@example.com",
        "tkn_2": "bob@example.com",
    }

    result = replace_json_tokens(data, replacements)

    assert result["recipients"][0]["email"] == "alice@example.com"
    assert result["recipients"][1]["email"] == "bob@example.com"


def test_redact_content() -> None:
    """Test redacting content with token strings."""
    content = "Email me at user@example.com"
    detections = [
        (12, 28, "[[PII:EMAIL:tkn_abc]]"),
    ]

    result = redact_content(content, detections)

    assert result == "Email me at [[PII:EMAIL:tkn_abc]]"


def test_redact_content_multiple() -> None:
    """Test redacting multiple spans."""
    content = "Email alice@example.com or bob@example.com"
    detections = [
        (6, 23, "[[PII:EMAIL:tkn_1]]"),
        (27, 42, "[[PII:EMAIL:tkn_2]]"),
    ]

    result = redact_content(content, detections)

    assert result == "Email [[PII:EMAIL:tkn_1]] or [[PII:EMAIL:tkn_2]]"
