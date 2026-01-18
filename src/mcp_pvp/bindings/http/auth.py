"""Authentication and anti-replay middleware for HTTP binding."""

import hashlib
import hmac
import time

from fastapi import Header, HTTPException, Request, status

from mcp_pvp.bindings.http.config import HTTPConfig


class AuthMiddleware:
    """Authentication middleware."""

    def __init__(self, config: HTTPConfig):
        """
        Initialize auth middleware.

        Args:
            config: HTTP configuration
        """
        self.config = config

    async def verify_shared_secret(self, authorization: str | None = Header(None)) -> None:
        """
        Verify shared secret.

        Args:
            authorization: Authorization header

        Raises:
            HTTPException: If authentication fails
        """
        if self.config.shared_secret is None:
            return  # Auth not required

        if authorization is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
            )

        # Expect: Bearer <secret>
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization format (expected: Bearer <secret>)",
            )

        provided_secret = parts[1]
        if not hmac.compare_digest(provided_secret, self.config.shared_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid secret",
            )

    async def verify_anti_replay(
        self,
        request: Request,
        x_pvp_timestamp: str | None = Header(None),
        x_pvp_signature: str | None = Header(None),
    ) -> None:
        """
        Verify anti-replay headers.

        Args:
            request: FastAPI request
            x_pvp_timestamp: Timestamp header
            x_pvp_signature: Signature header

        Raises:
            HTTPException: If verification fails
        """
        if not self.config.enable_anti_replay:
            return  # Anti-replay not enabled

        if x_pvp_timestamp is None or x_pvp_signature is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anti-replay headers required (X-PVP-Timestamp, X-PVP-Signature)",
            )

        # Verify timestamp is recent
        try:
            timestamp = int(x_pvp_timestamp)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid timestamp format",
            ) from e

        now = int(time.time())
        age = abs(now - timestamp)
        if age > self.config.anti_replay_window_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Request too old (age: {age}s, max: {self.config.anti_replay_window_seconds}s)"
                ),
            )

        # Verify signature
        if self.config.shared_secret is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Anti-replay requires shared_secret",
            )

        body = await request.body()
        message = f"{x_pvp_timestamp}.{body.decode('utf-8')}"
        expected_sig = hmac.new(
            self.config.shared_secret.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(x_pvp_signature, expected_sig):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid signature",
            )
