"""FastAPI HTTP binding for PVP."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from mcp_pvp.bindings.http.auth import AuthMiddleware
from mcp_pvp.bindings.http.config import HTTPConfig
from mcp_pvp.errors import PVPError
from mcp_pvp.models import (
    DeliverRequest,
    ErrorDetail,
    ErrorEnvelope,
    Policy,
    ResolveRequest,
    SuccessEnvelope,
    TokenizeRequest,
)
from mcp_pvp.vault import Vault

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
)

logger = structlog.get_logger(__name__)

# Global vault instance
vault: Vault | None = None
config: HTTPConfig | None = None
auth_middleware: AuthMiddleware | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager."""
    global vault, config, auth_middleware

    config = HTTPConfig()
    auth_middleware = AuthMiddleware(config)

    # TODO: Load policy from config file or environment
    policy = Policy()

    vault = Vault(policy=policy)
    logger.info("vault_started", host=config.host, port=config.port)

    yield

    logger.info("vault_shutdown")


app = FastAPI(
    title="mcp-pvp HTTP API",
    description="Privacy Vault Protocol for MCP - HTTP binding",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(PVPError)
async def pvp_error_handler(request: Request, exc: PVPError) -> JSONResponse:
    """Handle PVP errors."""
    envelope = ErrorEnvelope(
        error=ErrorDetail(
            code=exc.code.value,
            message=exc.message,
            details=exc.details,
        )
    )
    # Map error codes to HTTP status codes
    status_code = 400
    if "NOT_FOUND" in exc.code.value or "EXPIRED" in exc.code.value:
        status_code = 404
    elif "DENIED" in exc.code.value:
        status_code = 403
    elif "INVALID" in exc.code.value:
        status_code = 400
    elif "INTERNAL" in exc.code.value:
        status_code = 500

    return JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(),
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/pvp/v1/tokenize", response_model=SuccessEnvelope)
async def tokenize(
    request: TokenizeRequest,
    _auth: None = Depends(
        lambda: auth_middleware.verify_shared_secret if auth_middleware else None
    ),  # type: ignore
) -> SuccessEnvelope:
    """
    Tokenize content containing PII.

    Returns envelope: {ok: true, result: TokenizeResponse}
    """
    if vault is None:
        raise RuntimeError("Vault not initialized")

    response = vault.tokenize(request)
    return SuccessEnvelope(result=response)


@app.post("/pvp/v1/resolve", response_model=SuccessEnvelope)
async def resolve(
    request: ResolveRequest,
    _auth: None = Depends(
        lambda: auth_middleware.verify_shared_secret if auth_middleware else None
    ),  # type: ignore
) -> SuccessEnvelope:
    """
    Resolve tokens to raw values (with policy enforcement).

    Returns envelope: {ok: true, result: ResolveResponse}
    """
    if vault is None:
        raise RuntimeError("Vault not initialized")

    response = vault.resolve(request)
    return SuccessEnvelope(result=response)


@app.post("/pvp/v1/deliver", response_model=SuccessEnvelope)
async def deliver(
    request: DeliverRequest,
    _auth: None = Depends(
        lambda: auth_middleware.verify_shared_secret if auth_middleware else None
    ),  # type: ignore
) -> SuccessEnvelope:
    """
    Deliver: inject PII into tool call and execute.

    Returns envelope: {ok: true, result: DeliverResponse}
    """
    if vault is None:
        raise RuntimeError("Vault not initialized")

    response = vault.deliver(request)
    return SuccessEnvelope(result=response)


def main() -> None:
    """Run the HTTP server."""
    cfg = HTTPConfig()

    # Configure logging level
    log_level = cfg.log_level.lower()

    uvicorn.run(
        app,
        host=cfg.host,
        port=cfg.port,
        log_level=log_level,
        access_log=True,
    )


if __name__ == "__main__":
    main()
