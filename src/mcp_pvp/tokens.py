"""Token parsing, extraction, and substitution utilities."""

import re
from enum import Enum
from typing import Any

from mcp_pvp.errors import TokenInvalidError
from mcp_pvp.models import JSONToken, PIIType, TextToken

# Text token pattern: [[PII:TYPE:REF]]
TEXT_TOKEN_PATTERN = re.compile(r"\[\[PII:([A-Z_]+):([a-zA-Z0-9_-]+)\]\]")


class ScanState(Enum):
    """States for token scanner state machine."""

    TEXT = "TEXT"  # Normal text
    BRACKET1 = "BRACKET1"  # After first [
    BRACKET2 = "BRACKET2"  # After second [
    PII = "PII"  # Reading 'PII'
    COLON1 = "COLON1"  # After first :
    TYPE = "TYPE"  # Reading TYPE
    COLON2 = "COLON2"  # After second :
    REF = "REF"  # Reading REF
    CLOSE1 = "CLOSE1"  # After first ]


class TokenScanner:
    """Linear-time scanner for TEXT tokens using state machine."""

    def __init__(self, content: str):
        """Initialize scanner with content."""
        self.content = content
        self.pos = 0
        self.length = len(content)

    def scan_tokens(self) -> list[TextToken]:
        """
        Scan content for TEXT tokens using state machine.

        Returns:
            List of TextToken instances found in content

        This uses a single-pass character-by-character scan with O(n) time complexity,
        avoiding backtracking and catastrophic regex issues with malformed tokens.
        """
        tokens: list[TextToken] = []
        state = ScanState.TEXT
        type_start = 0
        type_end = 0
        ref_start = 0

        i = 0
        while i < self.length:
            ch = self.content[i]

            if state == ScanState.TEXT:
                if ch == "[":
                    state = ScanState.BRACKET1
                i += 1

            elif state == ScanState.BRACKET1:
                if ch == "[":
                    state = ScanState.BRACKET2
                    i += 1
                else:
                    # Not a second '[', go back to TEXT and reprocess this character
                    state = ScanState.TEXT
                    # Check if this character is '[' to start a new potential token
                    if ch == "[":
                        state = ScanState.BRACKET1
                    i += 1

            elif state == ScanState.BRACKET2:
                # Expect 'PII:'
                if i + 3 < self.length and self.content[i : i + 4] == "PII:":
                    state = ScanState.COLON1
                    i += 4  # Skip 'PII:'
                else:
                    # Not PII:, reset to TEXT and reprocess character
                    state = ScanState.TEXT
                    # Check if this character starts a new potential token
                    if ch == "[":
                        state = ScanState.BRACKET1
                    i += 1

            elif state == ScanState.COLON1:
                # Start reading TYPE
                type_start = i
                state = ScanState.TYPE
                # Don't increment, let TYPE handler process first char

            elif state == ScanState.TYPE:
                # Read TYPE until ':'
                if ch == ":":
                    type_end = i
                    state = ScanState.COLON2
                    i += 1
                elif ch.isupper() or ch == "_" or ch.isdigit():
                    # Valid TYPE character (uppercase, underscore, or digit)
                    i += 1
                else:
                    # Invalid TYPE character, abort token and reprocess character
                    state = ScanState.TEXT
                    # Check if this character starts a new potential token
                    if ch == "[":
                        state = ScanState.BRACKET1
                    i += 1

            elif state == ScanState.COLON2:
                # Start reading REF
                ref_start = i
                state = ScanState.REF
                # Don't increment, let REF handler process first char

            elif state == ScanState.REF:
                # Read REF until ']'
                if ch == "]":
                    ref_end = i
                    state = ScanState.CLOSE1
                    i += 1
                elif ch.isalnum() or ch in "-_":
                    # Valid REF character
                    i += 1
                else:
                    # Invalid REF character, abort token and reprocess character
                    state = ScanState.TEXT
                    # Check if this character starts a new potential token
                    if ch == "[":
                        state = ScanState.BRACKET1
                    i += 1

            elif state == ScanState.CLOSE1:
                # Expect second ']'
                if ch == "]":
                    # Token complete!
                    type_str = self.content[type_start:type_end]
                    ref_str = self.content[ref_start:ref_end]

                    # Validate TYPE
                    try:
                        pii_type = PIIType(type_str)
                        tokens.append(TextToken(ref=ref_str, pii_type=pii_type))
                    except ValueError:
                        # Invalid PII type, skip token
                        pass

                    state = ScanState.TEXT
                    i += 1
                else:
                    # Missing second ']', abort token and reprocess character
                    state = ScanState.TEXT
                    # Check if this character starts a new potential token
                    if ch == "[":
                        state = ScanState.BRACKET1
                    i += 1

        return tokens


def parse_text_token(token_str: str) -> TextToken:
    """
    Parse a text token string into a TextToken.

    Args:
        token_str: Token string in format [[PII:TYPE:REF]]

    Returns:
        TextToken instance

    Raises:
        TokenInvalidError: If token format is invalid
    """
    match = TEXT_TOKEN_PATTERN.match(token_str)
    if not match:
        raise TokenInvalidError(
            f"Invalid text token format: {token_str}",
            details={"token": token_str},
        )

    type_str, ref = match.groups()
    try:
        pii_type = PIIType(type_str)
    except ValueError as e:
        raise TokenInvalidError(
            f"Unknown PII type: {type_str}",
            details={"type": type_str, "token": token_str},
        ) from e

    return TextToken(ref=ref, pii_type=pii_type)


def extract_text_tokens(content: str) -> list[TextToken]:
    """
    Extract all text tokens from content using scanner.

    Args:
        content: String potentially containing text tokens

    Returns:
        List of TextToken instances

    This uses TokenScanner for O(n) linear-time parsing with proper state machine,
    avoiding regex backtracking and handling malformed tokens gracefully.
    """
    scanner = TokenScanner(content)
    return scanner.scan_tokens()


def replace_text_tokens(content: str, replacements: dict[str, str]) -> str:
    """
    Replace text tokens in content with raw values.

    Args:
        content: String containing text tokens
        replacements: Mapping from ref to raw value

    Returns:
        String with tokens replaced
    """

    def replacer(match: re.Match[str]) -> str:
        _, ref = match.groups()
        return replacements.get(ref, match.group(0))

    return TEXT_TOKEN_PATTERN.sub(replacer, content)


def parse_json_token(token_obj: dict[str, Any]) -> JSONToken:
    """
    Parse a JSON token object into a JSONToken.

    Args:
        token_obj: Dictionary with $pii_ref, type, and optional cap

    Returns:
        JSONToken instance

    Raises:
        TokenInvalidError: If token format is invalid
    """
    try:
        return JSONToken.model_validate(token_obj)
    except Exception as e:
        raise TokenInvalidError(
            "Invalid JSON token format",
            details={"token": token_obj, "error": str(e)},
        ) from e


def extract_json_tokens(data: Any, path_prefix: str = "") -> list[tuple[JSONToken, str]]:
    """
    Recursively extract JSON tokens from a data structure with their paths.

    Args:
        data: Dictionary, list, or primitive value
        path_prefix: Current path prefix for tracking location

    Returns:
        List of tuples (JSONToken, path) where path is the JSON path to the token
    """
    tokens: list[tuple[JSONToken, str]] = []

    def recurse(obj: Any, current_path: str) -> None:
        if isinstance(obj, dict):
            if "$pii_ref" in obj:
                try:
                    token = parse_json_token(obj)
                    tokens.append((token, current_path))
                except TokenInvalidError:
                    pass
            for key, value in obj.items():
                new_path = f"{current_path}.{key}" if current_path else key
                recurse(value, new_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                new_path = f"{current_path}[{idx}]"
                recurse(item, new_path)

    recurse(data, path_prefix)
    return tokens


def replace_json_tokens(data: Any, replacements: dict[str, str]) -> Any:
    """
    Recursively replace JSON tokens in a data structure with raw values.

    Args:
        data: Dictionary, list, or primitive value
        replacements: Mapping from ref to raw value

    Returns:
        Data structure with tokens replaced by raw values
    """

    def recurse(obj: Any) -> Any:
        if isinstance(obj, dict):
            if "$pii_ref" in obj:
                ref = obj.get("$pii_ref")
                if ref in replacements:
                    return replacements[ref]
            return {k: recurse(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [recurse(item) for item in obj]
        else:
            return obj

    return recurse(data)


def redact_content(content: str, detections: list[tuple[int, int, str]]) -> str:
    """
    Redact content by replacing detected spans with token strings.

    Args:
        content: Original content
        detections: List of (start, end, token_string) tuples, sorted by start position

    Returns:
        Redacted content with token strings
    """
    if not detections:
        return content

    # Sort by start position in reverse to avoid index shifting
    sorted_detections = sorted(detections, key=lambda x: x[0], reverse=True)

    result = content
    for start, end, token_str in sorted_detections:
        result = result[:start] + token_str + result[end:]

    return result
