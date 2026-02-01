"""Main Vault service implementing tokenize/resolve/deliver operations."""

import json
import secrets
import traceback
from typing import Any

import structlog

from mcp_pvp.audit import (
    AuditLogger,
    InMemoryAuditLogger,
    create_deliver_event,
    create_policy_denied_event,
    create_resolve_event,
    create_tokenize_event,
)
from mcp_pvp.caps import CapabilityManager
from mcp_pvp.detectors.base import PIIDetector
from mcp_pvp.detectors.regex import RegexDetector
from mcp_pvp.errors import PolicyDeniedError
from mcp_pvp.executor import DummyExecutor, ToolExecutor
from mcp_pvp.models import (
    DeliverRequest,
    DeliverResponse,
    JSONToken,
    PIIType,
    Policy,
    ResolveRequest,
    ResolveResponse,
    RunContext,
    Sink,
    SinkKind,
    TextToken,
    TokenFormat,
    TokenizeRequest,
    TokenizeResponse,
    TokenStats,
)
from mcp_pvp.policy import PolicyEvaluator
from mcp_pvp.store import SessionStore
from mcp_pvp.tokens import (
    extract_json_tokens,
    extract_text_tokens,
    redact_content,
    replace_json_tokens,
    replace_text_tokens,
)

logger = structlog.get_logger(__name__)


def serialize_for_pii_detection(obj: Any, max_depth: int = 10, _depth: int = 0) -> str:
    """
    Recursively serialize an object to a string for PII detection.

    Handles:
    - Exceptions: extracts message and traceback
    - Nested structures: recursively traverses dicts, lists, tuples, sets
    - Custom types: converts via __dict__ or repr
    - Primitive types: str, int, float, bool, None

    Args:
        obj: Object to serialize
        max_depth: Maximum recursion depth to prevent infinite loops
        _depth: Current recursion depth (internal)

    Returns:
        String representation suitable for PII detection
    """
    if _depth >= max_depth:
        return '"<max_depth_exceeded>"'

    # Handle None
    if obj is None:
        return "null"

    # Handle primitive types
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int | float):
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)  # Properly escape strings

    # Handle exceptions
    if isinstance(obj, Exception):
        parts = [
            f'"exception_type": {json.dumps(type(obj).__name__)}',
            f'"message": {json.dumps(str(obj))}',
        ]
        # Extract traceback if available
        if hasattr(obj, "__traceback__") and obj.__traceback__ is not None:
            tb_lines = traceback.format_exception(type(obj), obj, obj.__traceback__)
            tb_str = "".join(tb_lines)
            parts.append(f'"traceback": {json.dumps(tb_str)}')
        return "{" + ", ".join(parts) + "}"

    # Handle dict
    if isinstance(obj, dict):
        items = []
        for key, value in obj.items():
            key_str = json.dumps(str(key))
            value_str = serialize_for_pii_detection(value, max_depth, _depth + 1)
            items.append(f"{key_str}: {value_str}")
        return "{" + ", ".join(items) + "}"

    # Handle list, tuple, set
    if isinstance(obj, (list | tuple | set)):
        items = [serialize_for_pii_detection(item, max_depth, _depth + 1) for item in obj]
        return "[" + ", ".join(items) + "]"

    # Handle custom objects with __dict__
    if hasattr(obj, "__dict__"):
        obj_dict = {}
        obj_dict["__type__"] = type(obj).__name__
        obj_dict.update(obj.__dict__)
        return serialize_for_pii_detection(obj_dict, max_depth, _depth + 1)

    # Fallback: use repr
    return json.dumps(repr(obj))


class Vault:
    """Main PVP Vault service."""

    def __init__(
        self,
        policy: Policy | None = None,
        detector: PIIDetector | None = None,
        secret_key: bytes | None = None,
        audit_logger: AuditLogger | None = None,
        executor: ToolExecutor | None = None,
    ):
        """
        Initialize Vault.

        Args:
            policy: Policy specification (default: deny all)
            detector: PII detector (default: try Presidio, fallback to regex)
            secret_key: Secret key for capabilities (default: generate random)
            audit_logger: Audit logger (default: in-memory)
            executor: ToolExecutor for deliver mode (default: DummyExecutor)
                     Provide your own executor to enable real tool execution
        """
        self.policy = policy or Policy()
        self.policy_evaluator = PolicyEvaluator(self.policy)
        self.store = SessionStore()
        self.audit_logger = audit_logger or InMemoryAuditLogger()
        self.executor = executor or DummyExecutor()

        # Initialize detector
        if detector is None:
            try:
                from mcp_pvp.detectors.presidio import PresidioDetector

                self.detector: PIIDetector = PresidioDetector()
                logger.info("vault_initialized", detector="presidio")
            except ImportError:
                self.detector = RegexDetector()
                logger.info("vault_initialized", detector="regex_fallback")
        else:
            self.detector = detector

        # Initialize capability manager
        if secret_key is None:
            secret_key = secrets.token_bytes(32)
        self.cap_manager = CapabilityManager(secret_key)

    def issue_capability(
        self,
        vault_session: str,
        pii_ref: str,
        pii_type: PIIType,
        sink: Sink,
        run: RunContext | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        """
        Issue a sink-specific capability after policy validation.

        SECURITY: This method should only be called AFTER policy.check_disclosure()
        succeeds. It creates a capability bound to the specific sink, tool name,
        and arg_path, preventing capability reuse attacks.

        Args:
            vault_session: Vault session ID
            pii_ref: PII token reference
            pii_type: PII type
            sink: Sink specification (kind, name, arg_path)
            run: Run context (optional)
            ttl_seconds: Capability TTL in seconds (default: 300 = 5 min)

        Returns:
            Capability string bound to the specific sink

        Example:
            >>> # After policy check passes:
            >>> cap = vault.issue_capability(
            ...     vault_session=\"vs_123\",
            ...     pii_ref=\"tkn_abc\",
            ...     pii_type=PIIType.EMAIL,
            ...     sink=Sink(kind=SinkKind.TOOL, name=\"send_email\", arg_path=\"to\"),
            ... )
        """
        return self.cap_manager.issue(
            vault_session=vault_session,
            pii_ref=pii_ref,
            pii_type=pii_type,
            sink=sink,
            run=run,
            ttl_seconds=ttl_seconds,
        )

    def tokenize(self, request: TokenizeRequest) -> TokenizeResponse:
        """
        Tokenize content containing PII.

        Args:
            request: TokenizeRequest

        Returns:
            TokenizeResponse with vault_session, redacted content, and tokens
        """
        logger.info(
            "vault_tokenize_start",
            content_length=len(request.content),
            token_format=request.token_format.value,
            workflow_run_id=request.run.workflow_run_id if request.run else None,
            step_id=request.run.step_id if request.run else None,
            vault_session=request.vault_session,
        )

        # Create or reuse vault session
        if request.vault_session:
            # Reuse existing session (e.g., for result tokenization)
            session = self.store.get_session(request.vault_session)
            logger.info(
                "vault_tokenize_reusing_session",
                vault_session=request.vault_session,
            )
        else:
            # Create new session
            session = self.store.create_session(ttl_seconds=request.session_ttl_seconds)

        # Detect PII
        detections = self.detector.detect(request.content, types=request.types)

        # Tokenize detections
        tokens: list[TextToken | JSONToken] = []
        token_replacements: list[tuple[int, int, str]] = []
        type_counts: dict[PIIType, int] = {}

        for detection in detections:
            # Store PII in vault
            stored = self.store.store_pii(
                session_id=session.session_id,
                pii_type=detection.pii_type.value,
                value=detection.text,
            )

            # Track type counts
            type_counts[detection.pii_type] = type_counts.get(detection.pii_type, 0) + 1

            # Create token
            token: TextToken | JSONToken
            if request.token_format == TokenFormat.TEXT:
                token = TextToken(ref=stored.ref, pii_type=detection.pii_type)
                token_str = token.to_text()
                tokens.append(token)
            else:  # JSON
                # SECURITY: Capabilities are NO LONGER issued during tokenization
                # They must be requested explicitly via vault.issue_capability()
                # after policy check in resolve/deliver operations.
                # This prevents capability reuse attacks.
                token = JSONToken(
                    pii_ref=stored.ref,
                    type=detection.pii_type,
                    cap=None,  # No capability at tokenization time
                )
                token_str = f"{{{token.model_dump_json()}}}"  # Simplified JSON representation
                tokens.append(token)

            # Record replacement
            token_replacements.append((detection.start, detection.end, token_str))

        # Redact content
        redacted = redact_content(request.content, token_replacements)

        # Create response
        stats = TokenStats(
            detections=len(detections),
            tokens_created=len(tokens),
            types=type_counts,
        )

        # Audit
        event = create_tokenize_event(
            vault_session=session.session_id,
            run=request.run,
            detections=stats.detections,
            tokens_created=stats.tokens_created,
            types=stats.types,
            parent_audit_id=request.parent_audit_id,
        )
        self.audit_logger.log_event(event)

        logger.info(
            "vault_tokenize_complete",
            vault_session=session.session_id,
            detections=stats.detections,
            tokens_created=stats.tokens_created,
        )

        return TokenizeResponse(
            vault_session=session.session_id,
            redacted=redacted,
            tokens=tokens,
            stats=stats,
            expires_at=session.expires_at,
        )

    def resolve(self, request: ResolveRequest) -> ResolveResponse:
        """
        Resolve tokens to raw values (with policy enforcement).

        Args:
            request: ResolveRequest

        Returns:
            ResolveResponse with raw values

        Raises:
            PolicyDeniedError: If policy denies disclosure
            CapabilityInvalidError: If capability is invalid
        """
        logger.info(
            "vault_resolve_start",
            vault_session=request.vault_session,
            sink_kind=request.sink.kind.value,
            sink_name=request.sink.name,
            token_count=len(request.tokens),
        )

        # Get session
        session = self.store.get_session(request.vault_session)

        values: dict[str, str] = {}
        disclosed_types: dict[PIIType, int] = {}

        for token_req in request.tokens:
            # Get stored PII
            stored = self.store.get_pii(request.vault_session, token_req.ref)

            # Check policy FIRST (before issuing capability)
            try:
                self.policy_evaluator.check_disclosure(
                    session=session,
                    pii_type=stored.pii_type,
                    sink=request.sink,
                    run=request.run,
                    value_size=len(stored.value),
                )
            except PolicyDeniedError as e:
                # Log policy denial
                self.audit_logger.log_event(
                    create_policy_denied_event(
                        vault_session=request.vault_session,
                        pii_type=stored.pii_type,
                        sink_kind=request.sink.kind.value,
                        sink_name=request.sink.name,
                        run=request.run,
                        reason=str(e),
                    )
                )
                raise

            # Issue capability if not provided (security: on-demand issuance)
            cap_string = token_req.cap
            if cap_string is None:
                cap_string = self.issue_capability(
                    vault_session=request.vault_session,
                    pii_ref=token_req.ref,
                    pii_type=stored.pii_type,
                    sink=request.sink,
                    run=request.run,
                    ttl_seconds=300,  # 5 minutes
                )

            # Verify capability (even if we just issued it - validates structure)
            self.cap_manager.verify(
                cap_string=cap_string,
                vault_session=request.vault_session,
                pii_ref=token_req.ref,
                sink=request.sink,
                run=request.run,
            )

            # Record disclosure
            self.policy_evaluator.record_disclosure(session, len(stored.value))

            # Add to result
            values[token_req.ref] = stored.value
            disclosed_types[stored.pii_type] = disclosed_types.get(stored.pii_type, 0) + 1

        # Audit
        event = create_resolve_event(
            vault_session=request.vault_session,
            run=request.run,
            sink_kind=request.sink.kind.value,
            sink_name=request.sink.name,
            disclosed=disclosed_types,
        )
        self.audit_logger.log_event(event)

        logger.info(
            "vault_resolve_complete",
            vault_session=request.vault_session,
            disclosed_count=len(values),
        )

        return ResolveResponse(
            values=values,
            audit_id=event.audit_id,
            disclosed=disclosed_types,
        )

    def deliver(self, request: DeliverRequest) -> DeliverResponse:
        """
        Deliver: inject PII into tool call and execute (stub).

        Args:
            request: DeliverRequest

        Returns:
            DeliverResponse

        Raises:
            PolicyDeniedError: If policy denies disclosure
            CapabilityInvalidError: If capability is invalid
        """
        logger.info(
            "vault_deliver_start",
            vault_session=request.vault_session,
            tool_name=request.tool_call.name,
        )

        # Get session
        session = self.store.get_session(request.vault_session)

        # Extract JSON tokens from args with their paths
        json_token_paths = extract_json_tokens(request.tool_call.args)

        # Build replacements and verify
        replacements: dict[str, str] = {}
        disclosed_types: dict[PIIType, int] = {}

        # Process JSON format tokens
        for token, path in json_token_paths:
            # Extract just the top-level key from path (e.g., "to" from "to.nested")
            arg_path = path.split(".")[0] if path else None

            sink = Sink(
                kind=SinkKind.TOOL,
                name=request.tool_call.name,
                arg_path=arg_path,
            )

            # Get stored PII
            stored = self.store.get_pii(request.vault_session, token.pii_ref)

            # Verify capability if provided
            if token.cap:
                self.cap_manager.verify(
                    cap_string=token.cap,
                    vault_session=request.vault_session,
                    pii_ref=token.pii_ref,
                    sink=sink,
                    run=request.run,
                )

            # Check policy
            try:
                self.policy_evaluator.check_disclosure(
                    session=session,
                    pii_type=stored.pii_type,
                    sink=sink,
                    run=request.run,
                    value_size=len(stored.value),
                )
            except PolicyDeniedError as e:
                # Audit denial
                event = create_policy_denied_event(
                    vault_session=request.vault_session,
                    run=request.run,
                    pii_type=stored.pii_type,
                    sink_kind=sink.kind.value,
                    sink_name=sink.name,
                    reason=e.message,
                )
                self.audit_logger.log_event(event)
                raise

            # Record disclosure
            self.policy_evaluator.record_disclosure(session, len(stored.value))

            # Add to replacements
            replacements[token.pii_ref] = stored.value
            disclosed_types[stored.pii_type] = disclosed_types.get(stored.pii_type, 0) + 1

        # Process TEXT format tokens embedded in string arguments
        def extract_text_tokens_recursive(
            obj: Any, current_path: str = ""
        ) -> list[tuple[TextToken, str]]:
            """Recursively extract TEXT tokens from strings in data structure."""
            tokens_with_paths: list[tuple[TextToken, str]] = []

            if isinstance(obj, str):
                text_tokens = extract_text_tokens(obj)
                for text_token in text_tokens:
                    tokens_with_paths.append((text_token, current_path))
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{current_path}.{key}" if current_path else key
                    tokens_with_paths.extend(extract_text_tokens_recursive(value, new_path))
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    new_path = f"{current_path}[{idx}]"
                    tokens_with_paths.extend(extract_text_tokens_recursive(item, new_path))

            return tokens_with_paths

        text_token_paths = extract_text_tokens_recursive(request.tool_call.args)

        for text_token, path in text_token_paths:
            # Extract just the top-level key from path (strip array indices and nested paths)
            # e.g., "messages[0]" -> "messages", "config.nested.deep" -> "config"
            arg_path = path.split(".")[0].split("[")[0] if path else None

            sink = Sink(
                kind=SinkKind.TOOL,
                name=request.tool_call.name,
                arg_path=arg_path,
            )

            # Get stored PII
            stored = self.store.get_pii(request.vault_session, text_token.ref)

            # Check policy
            try:
                self.policy_evaluator.check_disclosure(
                    session=session,
                    pii_type=stored.pii_type,
                    sink=sink,
                    run=request.run,
                    value_size=len(stored.value),
                )
            except PolicyDeniedError as e:
                # Audit denial
                event = create_policy_denied_event(
                    vault_session=request.vault_session,
                    run=request.run,
                    pii_type=stored.pii_type,
                    sink_kind=sink.kind.value,
                    sink_name=sink.name,
                    reason=e.message,
                )
                self.audit_logger.log_event(event)
                raise

            # Add to replacements and record disclosure (only for unique refs)
            if text_token.ref not in replacements:
                replacements[text_token.ref] = stored.value
                disclosed_types[stored.pii_type] = disclosed_types.get(stored.pii_type, 0) + 1
                # Record disclosure only once per unique token reference
                self.policy_evaluator.record_disclosure(session, len(stored.value))

        # Inject values into args (handle both JSON and TEXT tokens)
        injected_args = replace_json_tokens(request.tool_call.args, replacements)

        # Also replace TEXT format tokens in strings recursively
        def replace_text_tokens_recursive(obj: Any) -> Any:
            """Recursively replace TEXT tokens in strings."""
            if isinstance(obj, str):
                return replace_text_tokens(obj, replacements)
            elif isinstance(obj, dict):
                return {k: replace_text_tokens_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_text_tokens_recursive(item) for item in obj]
            return obj

        injected_args = replace_text_tokens_recursive(injected_args)

        # SECURITY: Raw PII exists in injected_args - handle with care
        # Execute tool call via executor
        try:
            tool_result = self.executor.execute(
                tool_name=request.tool_call.name,
                injected_args=injected_args,
            )
        except Exception as e:
            # SECURITY: Scrub PII from exception message before logging
            error_msg = str(e)

            # Tokenize the error message to remove PII
            tokenize_resp = self.tokenize(
                TokenizeRequest(
                    content=error_msg,
                    vault_session=request.vault_session,
                    run=request.run,
                    token_format=TokenFormat.TEXT,
                )
            )
            scrubbed_error = tokenize_resp.redacted

            # Audit the failed deliver attempt for complete audit trail
            deliver_event = create_deliver_event(
                vault_session=request.vault_session,
                run=request.run,
                tool_name=request.tool_call.name,
                disclosed=disclosed_types,
            )
            self.audit_logger.log_event(deliver_event)

            # Log execution failure with scrubbed error message
            logger.error(
                "tool_execution_failed",
                tool_name=request.tool_call.name,
                error=scrubbed_error,
                audit_id=deliver_event.audit_id,
            )

            # SECURITY: Return scrubbed error instead of raising
            # This prevents raw PII from appearing in stack traces
            return DeliverResponse(
                delivered=False,
                tool_result=None,
                result_tokens=[],
                audit_id=deliver_event.audit_id,
                error=scrubbed_error,
            )

        # SECURITY: Tokenize tool result to prevent PII leakage
        # We need to detect PII in the result and replace with tokens
        result_tokens: list[JSONToken | TextToken] = []
        if tool_result is not None:
            # Recursively serialize result to string for PII detection
            # This handles exceptions, nested objects, and custom types
            result_str = serialize_for_pii_detection(tool_result)

            # Audit the deliver event BEFORE result tokenization so we can link them
            deliver_event = create_deliver_event(
                vault_session=request.vault_session,
                run=request.run,
                tool_name=request.tool_call.name,
                disclosed=disclosed_types,
            )
            self.audit_logger.log_event(deliver_event)

            # Tokenize to detect PII using TEXT format for simple replacement
            # Pass deliver event's audit_id as parent to create audit trail
            result_tokenization = self.tokenize(
                TokenizeRequest(
                    content=result_str,
                    vault_session=request.vault_session,
                    token_format=TokenFormat.TEXT,  # Use TEXT for [[PII:TYPE:REF]] format
                    parent_audit_id=deliver_event.audit_id,  # Link to parent deliver event
                )
            )

            result_tokens = result_tokenization.tokens
            # Use the redacted string representation with PII tokens
            tokenized_result: Any = result_tokenization.redacted
        else:
            # None result - audit but no tokenization needed
            deliver_event = create_deliver_event(
                vault_session=request.vault_session,
                run=request.run,
                tool_name=request.tool_call.name,
                disclosed=disclosed_types,
            )
            self.audit_logger.log_event(deliver_event)
            tokenized_result = tool_result

        logger.info(
            "vault_deliver_complete",
            vault_session=request.vault_session,
            tool_name=request.tool_call.name,
            disclosed_count=len(replacements),
            result_tokens_found=len(result_tokens),
        )

        return DeliverResponse(
            delivered=True,
            tool_result=tokenized_result,
            result_tokens=result_tokens,
            audit_id=deliver_event.audit_id,
        )
