"""Tests for scanner-based TEXT token parser (Task 3: Vault Hardening)."""

from mcp_pvp.models import PIIType
from mcp_pvp.tokens import TokenScanner, extract_text_tokens


class TestTokenScanner:
    """Test suite for TokenScanner state machine."""

    def test_scanner_extracts_simple_token(self):
        """Test basic token extraction."""
        content = "[[PII:EMAIL:tkn_abc123]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_abc123"
        assert tokens[0].pii_type == PIIType.EMAIL

    def test_scanner_extracts_multiple_tokens(self):
        """Test extraction of multiple tokens."""
        content = "Email: [[PII:EMAIL:tkn_1]] Phone: [[PII:PHONE:tkn_2]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 2
        assert tokens[0].ref == "tkn_1"
        assert tokens[0].pii_type == PIIType.EMAIL
        assert tokens[1].ref == "tkn_2"
        assert tokens[1].pii_type == PIIType.PHONE

    def test_scanner_handles_token_in_middle_of_text(self):
        """Test token surrounded by text."""
        content = "Contact [[PII:EMAIL:tkn_xyz]] for details"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_xyz"

    def test_scanner_handles_malformed_single_bracket(self):
        """Test scanner recovers from single opening bracket."""
        content = "[PII:EMAIL:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # Malformed, should be skipped

    def test_scanner_handles_malformed_missing_pii_prefix(self):
        """Test scanner handles missing 'PII:' prefix."""
        content = "[[EMAIL:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0

    def test_scanner_handles_malformed_missing_closing_bracket(self):
        """Test scanner handles missing closing bracket."""
        content = "[[PII:EMAIL:tkn_1]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0

    def test_scanner_handles_invalid_pii_type(self):
        """Test scanner skips tokens with invalid PII type."""
        content = "[[PII:INVALID_TYPE:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # Invalid type should be skipped

    def test_scanner_handles_lowercase_type(self):
        """Test scanner rejects lowercase type."""
        content = "[[PII:email:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # Type must be uppercase

    def test_scanner_handles_ref_with_special_chars(self):
        """Test scanner accepts refs with alphanumeric, dash, underscore."""
        content = "[[PII:EMAIL:tkn_abc-123_xyz]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_abc-123_xyz"

    def test_scanner_rejects_ref_with_invalid_chars(self):
        """Test scanner rejects refs with invalid characters."""
        content = "[[PII:EMAIL:tkn@invalid]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # @ is not allowed in ref

    def test_scanner_handles_adjacent_tokens(self):
        """Test scanner handles tokens with no space between."""
        content = "[[PII:EMAIL:tkn_1]][[PII:PHONE:tkn_2]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 2
        assert tokens[0].ref == "tkn_1"
        assert tokens[1].ref == "tkn_2"

    def test_scanner_handles_nested_brackets(self):
        """Test scanner with nested/escaped brackets."""
        content = "Text with [[ inside [[PII:EMAIL:tkn_1]] more ]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_1"

    def test_scanner_handles_empty_string(self):
        """Test scanner with empty input."""
        scanner = TokenScanner("")
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0

    def test_scanner_handles_long_content(self):
        """Test scanner with large content."""
        # Create content with 1000 tokens
        parts = []
        for i in range(1000):
            parts.append(f"Token {i}: [[PII:EMAIL:tkn_{i}]] ")

        content = "".join(parts)
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1000

    def test_scanner_linear_time_complexity(self):
        """Test that scanner has O(n) time complexity."""
        import time

        # Create content with many potential false starts
        # Regex would backtrack heavily, scanner should be linear
        false_starts = "[" * 1000 + "[[PII:EMAIL:tkn_1]]"

        start = time.perf_counter()
        scanner = TokenScanner(false_starts)
        tokens = scanner.scan_tokens()
        elapsed = time.perf_counter() - start

        assert len(tokens) == 1
        assert elapsed < 0.01  # Should be very fast (< 10ms)

    def test_scanner_all_pii_types(self):
        """Test scanner works with all PIIType values."""
        types = [PIIType.EMAIL, PIIType.PHONE, PIIType.IPV4, PIIType.CC, PIIType.API_KEY]

        for pii_type in types:
            content = f"[[PII:{pii_type.value}:tkn_test]]"
            scanner = TokenScanner(content)
            tokens = scanner.scan_tokens()

            assert len(tokens) == 1
            assert tokens[0].pii_type == pii_type

    def test_scanner_underscore_in_type(self):
        """Test scanner accepts underscores in TYPE."""
        content = "[[PII:API_KEY:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].pii_type == PIIType.API_KEY


class TestExtractTextTokens:
    """Test extract_text_tokens function with scanner backend."""

    def test_extract_text_tokens_uses_scanner(self):
        """Test that extract_text_tokens uses scanner."""
        content = "Email: [[PII:EMAIL:tkn_abc]]"
        tokens = extract_text_tokens(content)

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_abc"
        assert tokens[0].pii_type == PIIType.EMAIL

    def test_extract_text_tokens_backward_compatible(self):
        """Test that new implementation is backward compatible."""
        test_cases = [
            ("[[PII:EMAIL:tkn_1]]", 1),
            ("No tokens here", 0),
            ("[[PII:EMAIL:tkn_1]] and [[PII:PHONE:tkn_2]]", 2),
            ("Malformed [[PII:EMAIL:tkn_1]", 0),
            ("", 0),
        ]

        for content, expected_count in test_cases:
            tokens = extract_text_tokens(content)
            assert len(tokens) == expected_count


class TestScannerEdgeCases:
    """Test edge cases and malformed inputs."""

    def test_scanner_partial_token_at_end(self):
        """Test scanner handles partial token at end of content."""
        content = "Valid [[PII:EMAIL:tkn_1]] then partial [[PII:EMAIL:tkn"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1  # Only the valid token

    def test_scanner_token_with_spaces(self):
        """Test scanner rejects tokens with spaces in ref."""
        content = "[[PII:EMAIL:tkn 123]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # Space not allowed

    def test_scanner_token_with_newlines(self):
        """Test scanner with newlines."""
        content = "Line 1 [[PII:EMAIL:tkn_1]]\nLine 2 [[PII:PHONE:tkn_2]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 2

    def test_scanner_unicode_content(self):
        """Test scanner with unicode characters in surrounding text."""
        content = "Unicode 你好 [[PII:EMAIL:tkn_1]] مرحبا"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == "tkn_1"

    def test_scanner_mixed_valid_invalid(self):
        """Test scanner with mix of valid and invalid tokens."""
        content = (
            "[[PII:EMAIL:tkn_1]] "  # Valid
            "[[PII:INVALID:tkn_2]] "  # Invalid type
            "[[EMAIL:tkn_3]] "  # Missing PII:
            "[[PII:PHONE:tkn_4]] "  # Valid
        )
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 2
        assert tokens[0].ref == "tkn_1"
        assert tokens[1].ref == "tkn_4"

    def test_scanner_type_with_numbers(self):
        """Test scanner rejects type with numbers."""
        content = "[[PII:EMAIL123:tkn_1]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # Numbers not allowed in type

    def test_scanner_empty_ref(self):
        """Test scanner with empty ref."""
        content = "[[PII:EMAIL:]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        # Scanner will parse this as having empty ref
        # Depending on implementation, might accept or reject
        # Let's verify it doesn't crash
        assert isinstance(tokens, list)

    def test_scanner_very_long_ref(self):
        """Test scanner with very long ref."""
        long_ref = "tkn_" + "a" * 1000
        content = f"[[PII:EMAIL:{long_ref}]]"
        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 1
        assert tokens[0].ref == long_ref

    def test_scanner_performance_with_many_false_starts(self):
        """Test scanner performance with pathological input."""
        # Create input designed to cause regex backtracking
        content = "[" * 10000 + "a"  # No valid tokens, just brackets

        scanner = TokenScanner(content)
        tokens = scanner.scan_tokens()

        assert len(tokens) == 0  # No valid tokens found
