"""Tests for policy evaluation."""

import pytest

from mcp_pvp.errors import DisclosureLimitExceededError, PolicyDeniedError
from mcp_pvp.models import PIIType, Policy, PolicyAllow, Sink, SinkKind, SinkPolicy
from mcp_pvp.policy import PolicyEvaluator
from mcp_pvp.store import SessionStore


def test_policy_allow_disclosure(policy_evaluator: PolicyEvaluator, session_store: SessionStore) -> None:
    """Test policy allows disclosure for matching rule."""
    session = session_store.create_session()

    sink = Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to")

    # Should allow EMAIL to send_email:to
    policy_evaluator.check_disclosure(
        session=session,
        pii_type=PIIType.EMAIL,
        sink=sink,
        value_size=20,
    )


def test_policy_deny_llm_sink() -> None:
    """Test policy denies LLM sinks by default."""
    policy = Policy()
    evaluator = PolicyEvaluator(policy)
    store = SessionStore()
    session = store.create_session()

    sink = Sink(kind=SinkKind.LLM, name="gpt-4", arg_path=None)

    with pytest.raises(PolicyDeniedError, match="llm sinks is denied"):
        evaluator.check_disclosure(
            session=session,
            pii_type=PIIType.EMAIL,
            sink=sink,
            value_size=20,
        )


def test_policy_deny_engine_sink() -> None:
    """Test policy denies ENGINE sinks by default."""
    policy = Policy()
    evaluator = PolicyEvaluator(policy)
    store = SessionStore()
    session = store.create_session()

    sink = Sink(kind=SinkKind.ENGINE, name="agent_engine", arg_path=None)

    with pytest.raises(PolicyDeniedError, match="engine sinks is denied"):
        evaluator.check_disclosure(
            session=session,
            pii_type=PIIType.EMAIL,
            sink=sink,
            value_size=20,
        )


def test_policy_deny_wrong_arg_path(policy_evaluator: PolicyEvaluator, session_store: SessionStore) -> None:
    """Test policy denies disclosure for wrong arg_path."""
    session = session_store.create_session()

    # send_email only allows to/cc, not 'subject'
    sink = Sink(kind=SinkKind.TOOL, name="send_email", arg_path="subject")

    with pytest.raises(PolicyDeniedError, match="No policy rule allows"):
        policy_evaluator.check_disclosure(
            session=session,
            pii_type=PIIType.EMAIL,
            sink=sink,
            value_size=20,
        )


def test_policy_deny_wrong_type(policy_evaluator: PolicyEvaluator, session_store: SessionStore) -> None:
    """Test policy denies disclosure for wrong PII type."""
    session = session_store.create_session()

    # send_email only allows EMAIL, not PHONE
    sink = Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to")

    with pytest.raises(PolicyDeniedError, match="No policy rule allows"):
        policy_evaluator.check_disclosure(
            session=session,
            pii_type=PIIType.PHONE,
            sink=sink,
            value_size=20,
        )


def test_policy_limit_max_disclosures(policy_evaluator: PolicyEvaluator, session_store: SessionStore) -> None:
    """Test policy enforces max disclosures limit."""
    session = session_store.create_session()
    sink = Sink(kind=SinkKind.TOOL, name="test_tool", arg_path=None)

    # Set limit to 2
    policy_evaluator.policy.limits.max_disclosures_per_step = 2

    # First two should succeed
    policy_evaluator.check_disclosure(session, PIIType.EMAIL, sink, value_size=10)
    policy_evaluator.record_disclosure(session, 10)

    policy_evaluator.check_disclosure(session, PIIType.EMAIL, sink, value_size=10)
    policy_evaluator.record_disclosure(session, 10)

    # Third should fail
    with pytest.raises(DisclosureLimitExceededError, match="Max disclosures per step exceeded"):
        policy_evaluator.check_disclosure(session, PIIType.EMAIL, sink, value_size=10)


def test_policy_limit_max_bytes(policy_evaluator: PolicyEvaluator, session_store: SessionStore) -> None:
    """Test policy enforces max bytes limit."""
    session = session_store.create_session()
    sink = Sink(kind=SinkKind.TOOL, name="test_tool", arg_path=None)

    # Set limit to 50 bytes
    policy_evaluator.policy.limits.max_total_disclosed_bytes_per_step = 50

    # Disclose 40 bytes
    policy_evaluator.check_disclosure(session, PIIType.EMAIL, sink, value_size=40)
    policy_evaluator.record_disclosure(session, 40)

    # Try to disclose 20 more (would exceed 50)
    with pytest.raises(DisclosureLimitExceededError, match="Max disclosed bytes per step exceeded"):
        policy_evaluator.check_disclosure(session, PIIType.EMAIL, sink, value_size=20)
