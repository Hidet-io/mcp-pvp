"""Error types and error codes for PVP."""

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """PVP error codes."""

    ERR_POLICY_DENIED = "ERR_POLICY_DENIED"
    ERR_CAP_INVALID = "ERR_CAP_INVALID"
    ERR_CAP_EXPIRED = "ERR_CAP_EXPIRED"
    ERR_CAP_TAMPERED = "ERR_CAP_TAMPERED"
    ERR_SESSION_NOT_FOUND = "ERR_SESSION_NOT_FOUND"
    ERR_SESSION_EXPIRED = "ERR_SESSION_EXPIRED"
    ERR_TOKEN_NOT_FOUND = "ERR_TOKEN_NOT_FOUND"
    ERR_TOKEN_INVALID = "ERR_TOKEN_INVALID"
    ERR_DETECTION_FAILED = "ERR_DETECTION_FAILED"
    ERR_DISCLOSURE_LIMIT_EXCEEDED = "ERR_DISCLOSURE_LIMIT_EXCEEDED"
    ERR_INVALID_REQUEST = "ERR_INVALID_REQUEST"
    ERR_INTERNAL = "ERR_INTERNAL"


class PVPError(Exception):
    """Base exception for all PVP errors."""

    def __init__(self, message: str, code: ErrorCode, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary for API responses."""
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


class PolicyDeniedError(PVPError):
    """Raised when policy denies disclosure."""

    def __init__(
        self,
        message: str = "Policy denied disclosure",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_POLICY_DENIED, details)


class CapabilityInvalidError(PVPError):
    """Raised when capability is invalid, expired, or tampered."""

    def __init__(
        self,
        message: str = "Capability is invalid",
        code: ErrorCode = ErrorCode.ERR_CAP_INVALID,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, code, details)


class CapabilityExpiredError(CapabilityInvalidError):
    """Raised when capability has expired."""

    def __init__(
        self,
        message: str = "Capability has expired",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_CAP_EXPIRED, details)


class CapabilityTamperedError(CapabilityInvalidError):
    """Raised when capability signature verification fails."""

    def __init__(
        self,
        message: str = "Capability signature invalid (tampered)",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_CAP_TAMPERED, details)


class SessionNotFoundError(PVPError):
    """Raised when vault session is not found or expired."""

    def __init__(
        self,
        message: str = "Vault session not found or expired",
        code: ErrorCode = ErrorCode.ERR_SESSION_NOT_FOUND,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, code, details)


class SessionExpiredError(SessionNotFoundError):
    """Raised when vault session has expired."""

    def __init__(
        self,
        message: str = "Vault session expired",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_SESSION_EXPIRED, details)


class TokenNotFoundError(PVPError):
    """Raised when token reference is not found."""

    def __init__(
        self,
        message: str = "Token not found",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_TOKEN_NOT_FOUND, details)


class TokenInvalidError(PVPError):
    """Raised when token format is invalid."""

    def __init__(
        self,
        message: str = "Token format is invalid",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_TOKEN_INVALID, details)


class DetectionError(PVPError):
    """Raised when PII detection fails."""

    def __init__(
        self,
        message: str = "PII detection failed",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_DETECTION_FAILED, details)


class DisclosureLimitExceededError(PVPError):
    """Raised when disclosure limits are exceeded."""

    def __init__(
        self,
        message: str = "Disclosure limit exceeded",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_DISCLOSURE_LIMIT_EXCEEDED, details)


class InvalidRequestError(PVPError):
    """Raised when request is malformed or invalid."""

    def __init__(
        self,
        message: str = "Invalid request",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_INVALID_REQUEST, details)


class InternalError(PVPError):
    """Raised for internal errors."""

    def __init__(
        self,
        message: str = "Internal error",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message, ErrorCode.ERR_INTERNAL, details)
