"""Test configuration and fixtures."""

import pytest

from mcp_pvp.caps import CapabilityManager
from mcp_pvp.models import (
    PIIType,
    Policy,
    PolicyAllow,
    RunContext,
    Sink,
    SinkKind,
    SinkPolicy,
)
from mcp_pvp.policy import PolicyEvaluator
from mcp_pvp.store import SessionStore
from mcp_pvp.vault import Vault


@pytest.fixture
def secret_key() -> bytes:
    """Secret key for testing."""
    # Exactly 32 bytes
    return b"test_secret_key_32_bytes_long!!!!"


@pytest.fixture
def cap_manager(secret_key: bytes) -> CapabilityManager:
    """Capability manager fixture."""
    return CapabilityManager(secret_key)


@pytest.fixture
def session_store() -> SessionStore:
    """Session store fixture."""
    return SessionStore()


@pytest.fixture
def permissive_policy() -> Policy:
    """Permissive policy for testing."""
    return Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[
                    PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc"]),
                ]
            ),
            "tool:test_tool": SinkPolicy(
                allow=[
                    PolicyAllow(type=PIIType.EMAIL, arg_paths=None),
                    PolicyAllow(type=PIIType.PHONE, arg_paths=None),
                ]
            ),
        }
    )


@pytest.fixture
def policy_evaluator(permissive_policy: Policy) -> PolicyEvaluator:
    """Policy evaluator fixture."""
    return PolicyEvaluator(permissive_policy)


@pytest.fixture
def vault(permissive_policy: Policy) -> Vault:
    """Vault fixture."""
    return Vault(policy=permissive_policy)


@pytest.fixture
def sample_run_context() -> RunContext:
    """Sample run context fixture."""
    return RunContext(
        workflow_run_id="test_run_123",
        step_id="step_1",
    )


@pytest.fixture
def sample_sink() -> Sink:
    """Sample sink fixture."""
    return Sink(
        kind=SinkKind.TOOL,
        name="test_tool",
        arg_path="email",
    )
