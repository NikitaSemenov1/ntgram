from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class GatewaySettings:
    host: str = os.getenv("NTGRAM_GATEWAY_HOST", "0.0.0.0")
    port: int = int(os.getenv("NTGRAM_GATEWAY_PORT", "8080"))
    rsa_private_key_path: str = os.getenv("NTGRAM_RSA_PRIVATE_KEY_PATH", "./keys/private.pem")
    rsa_public_key_path: str = os.getenv("NTGRAM_RSA_PUBLIC_KEY_PATH", "./keys/public.pem")
    log_path: str = os.getenv("NTGRAM_GATEWAY_LOG_PATH", "./.data/gateway.log")
    # Empty: use default next to install root (see GatewayRouter._help_get_config_file_default).
    help_get_config_path: str = os.getenv("NTGRAM_HELP_GET_CONFIG_PATH", "")


_DEFAULT_PG_HOST = os.getenv("NTGRAM_POSTGRES_HOST", "localhost")
_DEFAULT_PG_PORT = os.getenv("NTGRAM_POSTGRES_PORT", "5432")
_DEFAULT_PG_USER = os.getenv("NTGRAM_POSTGRES_USER", "ntgram")
_DEFAULT_PG_PASS = os.getenv("NTGRAM_POSTGRES_PASSWORD", "ntgram")


def _per_service_dsn(env_var: str, default_db: str) -> str:
    explicit = os.getenv(env_var)
    if explicit:
        return explicit
    return (
        f"postgresql://{_DEFAULT_PG_USER}:{_DEFAULT_PG_PASS}"
        f"@{_DEFAULT_PG_HOST}:{_DEFAULT_PG_PORT}/{default_db}"
    )


@dataclass(slots=True, frozen=True)
class DatabaseSettings:
    """Per-service Postgres DSNs."""

    account_dsn: str = _per_service_dsn("NTGRAM_ACCOUNT_DSN", "account_db")
    chat_dsn: str = _per_service_dsn("NTGRAM_CHAT_DSN", "chat_db")
    updates_dsn: str = _per_service_dsn("NTGRAM_UPDATES_DSN", "updates_db")


@dataclass(slots=True, frozen=True)
class RedisSettings:
    dsn: str = os.getenv("NTGRAM_REDIS_DSN", "redis://localhost:6379/0")


@dataclass(slots=True, frozen=True)
class ServiceSettings:
    """Inter-service gRPC addresses."""

    account_addr: str = os.getenv("NTGRAM_ACCOUNT_ADDR", "127.0.0.1:50051")
    chat_addr: str = os.getenv("NTGRAM_CHAT_ADDR", "127.0.0.1:50052")
    updates_addr: str = os.getenv("NTGRAM_UPDATES_ADDR", "127.0.0.1:50056")
    services_log_dir: str = os.getenv("NTGRAM_SERVICES_LOG_DIR", "./.data")
