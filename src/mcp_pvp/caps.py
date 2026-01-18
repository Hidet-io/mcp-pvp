"""Capability creation and verification."""

import base64
import hmac
import json
from datetime import timedelta

from mcp_pvp.errors import CapabilityExpiredError, CapabilityInvalidError, CapabilityTamperedError
from mcp_pvp.models import Capability, PIIType, RunContext, Sink
from mcp_pvp.utils import utc_now


class CapabilityManager:
    """Manages capability creation and verification."""

    def __init__(self, secret_key: bytes):
        """
        Initialize capability manager.

        Args:
            secret_key: Secret key for HMAC signing (should be >= 32 bytes)
        """
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 bytes")
        self.secret_key = secret_key

    def create(
        self,
        vault_session: str,
        pii_ref: str,
        pii_type: PIIType,
        sink: Sink,
        run: RunContext | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        """
        Create a capability string.

        Args:
            vault_session: Vault session ID
            pii_ref: PII token reference
            pii_type: PII type
            sink: Sink specification
            run: Run context (optional)
            ttl_seconds: Time-to-live in seconds

        Returns:
            Capability string (base64url(json).base64url(sig))
        """
        exp = utc_now() + timedelta(seconds=ttl_seconds)

        cap = Capability(
            vault_session=vault_session,
            pii_ref=pii_ref,
            pii_type=pii_type,
            sink=sink,
            run=run,
            exp=exp,
        )

        payload = cap.model_dump_json(exclude_none=True)
        payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

        signature = hmac.new(self.secret_key, payload_b64.encode(), "sha256").digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{payload_b64}.{signature_b64}"

    def verify(
        self,
        cap_string: str,
        vault_session: str,
        pii_ref: str,
        sink: Sink,
        run: RunContext | None = None,
    ) -> Capability:
        """
        Verify a capability string.

        Args:
            cap_string: Capability string
            vault_session: Expected vault session ID
            pii_ref: Expected PII token reference
            sink: Expected sink
            run: Expected run context (optional)

        Returns:
            Verified Capability instance

        Raises:
            CapabilityInvalidError: If capability is malformed
            CapabilityTamperedError: If signature verification fails
            CapabilityExpiredError: If capability has expired
        """
        parts = cap_string.split(".")
        if len(parts) != 2:
            raise CapabilityInvalidError(
                "Capability must have format: payload.signature",
                details={"cap": cap_string},
            )

        payload_b64, signature_b64 = parts

        # Verify signature
        expected_signature = hmac.new(self.secret_key, payload_b64.encode(), "sha256").digest()
        expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).decode().rstrip("=")

        # Constant-time comparison
        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            raise CapabilityTamperedError(details={"cap": cap_string})

        # Decode payload
        try:
            # Add padding if needed
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_dict = json.loads(payload_bytes)
            cap = Capability.model_validate(payload_dict)
        except Exception as e:
            raise CapabilityInvalidError(
                "Failed to decode capability payload",
                details={"cap": cap_string, "error": str(e)},
            ) from e

        # Check expiration
        if cap.exp < utc_now():
            raise CapabilityExpiredError(
                details={
                    "expired_at": cap.exp.isoformat(),
                    "now": utc_now().isoformat(),
                }
            )

        # Verify constraints
        if cap.vault_session != vault_session:
            raise CapabilityInvalidError(
                "Capability vault_session mismatch",
                details={
                    "expected": vault_session,
                    "got": cap.vault_session,
                },
            )

        if cap.pii_ref != pii_ref:
            raise CapabilityInvalidError(
                "Capability pii_ref mismatch",
                details={
                    "expected": pii_ref,
                    "got": cap.pii_ref,
                },
            )

        # Verify sink matches - ALL capabilities must be sink-bound
        # No wildcard capabilities allowed (security tightening)
        if cap.sink.kind != sink.kind or cap.sink.name != sink.name:
            raise CapabilityInvalidError(
                "Capability sink mismatch",
                details={
                    "expected": sink.model_dump(),
                    "got": cap.sink.model_dump(),
                },
            )
        else:
            # For arg_path, capability may have None (generic) while request has specific path
            # Only fail if both are non-None and different
            if (
                cap.sink.arg_path is not None
                and sink.arg_path is not None
                and cap.sink.arg_path != sink.arg_path
            ):
                raise CapabilityInvalidError(
                    "Capability arg_path mismatch",
                    details={
                        "expected": sink.arg_path,
                        "got": cap.sink.arg_path,
                    },
                )

        # Verify run context if specified in capability
        if (
            cap.run is not None
            and run is not None
            and (cap.run.workflow_run_id != run.workflow_run_id or cap.run.step_id != run.step_id)
        ):
            raise CapabilityInvalidError(
                "Capability run context mismatch",
                details={
                    "expected": run.model_dump(),
                    "got": cap.run.model_dump(),
                },
            )

        return cap

    def issue(
        self,
        vault_session: str,
        pii_ref: str,
        pii_type: PIIType,
        sink: Sink,
        run: RunContext | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        """
        Issue a sink-specific capability (used by vault after policy check).

        This is the recommended way to create capabilities - vault validates policy first,
        then issues a capability bound to the specific sink, tool name, and arg_path.

        This prevents capability reuse attacks where a compromised agent tries to route
        a token to a different, more dangerous sink.

        Args:
            vault_session: Vault session ID
            pii_ref: PII token reference
            pii_type: PII type
            sink: Sink specification (kind, name, arg_path)
            run: Run context (optional)
            ttl_seconds: Time-to-live in seconds (default: 300s = 5 min)

        Returns:
            Capability string bound to specific sink + tool + arg_path

        Example:
            >>> cap = mgr.issue(
            ...     vault_session="vs_123",
            ...     pii_ref="tkn_abc",
            ...     pii_type=PIIType.EMAIL,
            ...     sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to"),
            ...     ttl_seconds=300,
            ... )
        """
        # Use create() but with explicit sink binding
        return self.create(
            vault_session=vault_session,
            pii_ref=pii_ref,
            pii_type=pii_type,
            sink=sink,
            run=run,
            ttl_seconds=ttl_seconds,
        )
