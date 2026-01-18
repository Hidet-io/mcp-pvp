"""Policy evaluation for disclosure authorization."""

from mcp_pvp.errors import DisclosureLimitExceededError, PolicyDeniedError
from mcp_pvp.models import PIIType, Policy, RunContext, Sink, SinkKind, VaultSession


class PolicyEvaluator:
    """Evaluates policies for PII disclosure."""

    def __init__(self, policy: Policy):
        """
        Initialize policy evaluator.

        Args:
            policy: Policy specification
        """
        self.policy = policy

    def check_disclosure(
        self,
        session: VaultSession,
        pii_type: PIIType,
        sink: Sink,
        run: RunContext | None = None,
        value_size: int = 0,
    ) -> None:
        """
        Check if disclosure is allowed by policy.

        Args:
            session: Vault session
            pii_type: Type of PII being disclosed
            sink: Sink requesting disclosure
            run: Run context (optional)
            value_size: Size of value being disclosed in bytes

        Raises:
            PolicyDeniedError: If disclosure is denied by policy
            DisclosureLimitExceededError: If limits are exceeded
        """
        # Check limits first
        self._check_limits(session, value_size)

        # Default deny for LLM and ENGINE sinks
        if sink.kind in (SinkKind.LLM, SinkKind.ENGINE):
            raise PolicyDeniedError(
                f"Disclosure to {sink.kind.value} sinks is denied by default",
                details={
                    "sink_kind": sink.kind.value,
                    "sink_name": sink.name,
                    "pii_type": pii_type.value,
                },
            )

        # Check type-specific rules
        type_rule = self.policy.type_rules.get(pii_type)
        if type_rule and type_rule.get("mode") == "MASK":
            raise PolicyDeniedError(
                f"PII type {pii_type.value} is configured for MASK mode only",
                details={
                    "pii_type": pii_type.value,
                    "sink": sink.model_dump(),
                },
            )

        # Build sink ID
        sink_id = f"{sink.kind.value}:{sink.name}"

        # Get sink policy (or default)
        sink_policy = self.policy.sinks.get(sink_id, self.policy.defaults)

        # Check allow rules
        allowed = False
        for allow_rule in sink_policy.allow:
            if allow_rule.type != pii_type:
                continue

            # Check arg_path constraint
            if allow_rule.arg_paths is not None:
                if sink.arg_path is None or sink.arg_path not in allow_rule.arg_paths:
                    continue

            allowed = True
            break

        if not allowed:
            raise PolicyDeniedError(
                "No policy rule allows this disclosure",
                details={
                    "pii_type": pii_type.value,
                    "sink": sink.model_dump(),
                    "sink_id": sink_id,
                },
            )

    def _check_limits(self, session: VaultSession, value_size: int) -> None:
        """
        Check disclosure limits.

        Args:
            session: Vault session
            value_size: Size of value being disclosed

        Raises:
            DisclosureLimitExceededError: If limits are exceeded
        """
        limits = self.policy.limits

        # Check count limit
        if session.disclosed_count >= limits.max_disclosures_per_step:
            raise DisclosureLimitExceededError(
                f"Max disclosures per step exceeded ({limits.max_disclosures_per_step})",
                details={
                    "current": session.disclosed_count,
                    "max": limits.max_disclosures_per_step,
                },
            )

        # Check bytes limit
        new_total = session.disclosed_bytes + value_size
        if new_total > limits.max_total_disclosed_bytes_per_step:
            raise DisclosureLimitExceededError(
                f"Max disclosed bytes per step exceeded ({limits.max_total_disclosed_bytes_per_step})",
                details={
                    "current": session.disclosed_bytes,
                    "adding": value_size,
                    "max": limits.max_total_disclosed_bytes_per_step,
                },
            )

    def record_disclosure(self, session: VaultSession, value_size: int) -> None:
        """
        Record a disclosure in the session.

        Args:
            session: Vault session
            value_size: Size of value disclosed
        """
        session.disclosed_count += 1
        session.disclosed_bytes += value_size
