"""Tests for capability creation and verification."""

from datetime import datetime, timedelta

import pytest
from freezegun import freeze_time

from mcp_pvp.caps import CapabilityManager
from mcp_pvp.errors import (
    CapabilityExpiredError,
    CapabilityInvalidError,
    CapabilityTamperedError,
)
from mcp_pvp.models import PIIType, RunContext, Sink, SinkKind


def test_create_capability(cap_manager: CapabilityManager, sample_sink: Sink) -> None:
    """Test capability creation."""
    cap_str = cap_manager.create(
        vault_session="vs_test123",
        pii_ref="tkn_abc",
        pii_type=PIIType.EMAIL,
        sink=sample_sink,
        ttl_seconds=300,
    )

    assert isinstance(cap_str, str)
    assert "." in cap_str
    parts = cap_str.split(".")
    assert len(parts) == 2


def test_verify_capability_success(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test successful capability verification."""
    vault_session = "vs_test123"
    pii_ref = "tkn_abc"
    pii_type = PIIType.EMAIL

    cap_str = cap_manager.create(
        vault_session=vault_session,
        pii_ref=pii_ref,
        pii_type=pii_type,
        sink=sample_sink,
        ttl_seconds=300,
    )

    # Verify should succeed
    cap = cap_manager.verify(
        cap_string=cap_str,
        vault_session=vault_session,
        pii_ref=pii_ref,
        sink=sample_sink,
    )

    assert cap.vault_session == vault_session
    assert cap.pii_ref == pii_ref
    assert cap.pii_type == pii_type


def test_verify_capability_tampered(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test capability verification with tampered signature."""
    cap_str = cap_manager.create(
        vault_session="vs_test123",
        pii_ref="tkn_abc",
        pii_type=PIIType.EMAIL,
        sink=sample_sink,
        ttl_seconds=300,
    )

    # Tamper with signature
    parts = cap_str.split(".")
    tampered = f"{parts[0]}.TAMPERED"

    with pytest.raises(CapabilityTamperedError):
        cap_manager.verify(
            cap_string=tampered,
            vault_session="vs_test123",
            pii_ref="tkn_abc",
            sink=sample_sink,
        )


def test_verify_capability_expired(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test capability verification with expired capability."""
    with freeze_time("2024-01-01 12:00:00"):
        cap_str = cap_manager.create(
            vault_session="vs_test123",
            pii_ref="tkn_abc",
            pii_type=PIIType.EMAIL,
            sink=sample_sink,
            ttl_seconds=300,
        )

    # Move time forward past expiration
    with freeze_time("2024-01-01 12:10:00"):  # 10 minutes later
        with pytest.raises(CapabilityExpiredError):
            cap_manager.verify(
                cap_string=cap_str,
                vault_session="vs_test123",
                pii_ref="tkn_abc",
                sink=sample_sink,
            )


def test_verify_capability_mismatch_session(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test capability verification with mismatched session."""
    cap_str = cap_manager.create(
        vault_session="vs_test123",
        pii_ref="tkn_abc",
        pii_type=PIIType.EMAIL,
        sink=sample_sink,
        ttl_seconds=300,
    )

    with pytest.raises(CapabilityInvalidError, match="vault_session mismatch"):
        cap_manager.verify(
            cap_string=cap_str,
            vault_session="vs_different",  # Different session
            pii_ref="tkn_abc",
            sink=sample_sink,
        )


def test_verify_capability_mismatch_ref(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test capability verification with mismatched ref."""
    cap_str = cap_manager.create(
        vault_session="vs_test123",
        pii_ref="tkn_abc",
        pii_type=PIIType.EMAIL,
        sink=sample_sink,
        ttl_seconds=300,
    )

    with pytest.raises(CapabilityInvalidError, match="pii_ref mismatch"):
        cap_manager.verify(
            cap_string=cap_str,
            vault_session="vs_test123",
            pii_ref="tkn_different",  # Different ref
            sink=sample_sink,
        )


def test_verify_capability_mismatch_sink(
    cap_manager: CapabilityManager, sample_sink: Sink
) -> None:
    """Test capability verification with mismatched sink."""
    cap_str = cap_manager.create(
        vault_session="vs_test123",
        pii_ref="tkn_abc",
        pii_type=PIIType.EMAIL,
        sink=sample_sink,
        ttl_seconds=300,
    )

    different_sink = Sink(
        kind=SinkKind.TOOL,
        name="different_tool",  # Different name
        arg_path="email",
    )

    with pytest.raises(CapabilityInvalidError, match="sink mismatch"):
        cap_manager.verify(
            cap_string=cap_str,
            vault_session="vs_test123",
            pii_ref="tkn_abc",
            sink=different_sink,
        )
