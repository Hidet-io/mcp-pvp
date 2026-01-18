"""Configuration for HTTP binding."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class HTTPConfig(BaseSettings):
    """HTTP binding configuration."""

    model_config = SettingsConfigDict(env_prefix="PVP_HTTP_")

    host: str = "127.0.0.1"  # Localhost only by default
    port: int = 8765
    shared_secret: str | None = None  # Optional shared secret for auth
    enable_anti_replay: bool = False  # Optional anti-replay protection
    anti_replay_window_seconds: int = 300  # 5 minutes
    log_level: str = "INFO"
