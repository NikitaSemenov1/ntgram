from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class GatewaySettings:
    host: str = os.getenv("NTGRAM_GATEWAY_HOST", "0.0.0.0")
    port: int = int(os.getenv("NTGRAM_GATEWAY_PORT", "8080"))
    rsa_private_key_path: str = os.getenv("NTGRAM_RSA_PRIVATE_KEY_PATH", "./keys/private.pem")
    rsa_public_key_path: str = os.getenv("NTGRAM_RSA_PUBLIC_KEY_PATH", "./keys/public.pem")
    log_path: str = os.getenv("NTGRAM_GATEWAY_LOG_PATH", "./.cursor/gateway.log")
    # Empty: use default next to install root (see GatewayRouter._help_get_config_file_default).
    help_get_config_path: str = os.getenv("NTGRAM_HELP_GET_CONFIG_PATH", "")


@dataclass(slots=True, frozen=True)
class DatabaseSettings:
    dsn: str = os.getenv("NTGRAM_POSTGRES_DSN", "postgresql://ntgram:ntgram@localhost:5432/ntgram")


@dataclass(slots=True, frozen=True)
class RedisSettings:
    dsn: str = os.getenv("NTGRAM_REDIS_DSN", "redis://localhost:6379/0")


@dataclass(slots=True, frozen=True)
class ServiceSettings:
    account_addr: str = os.getenv("NTGRAM_ACCOUNT_ADDR", "127.0.0.1:50051")
    chat_addr: str = os.getenv("NTGRAM_CHAT_ADDR", "127.0.0.1:50052")
    message_addr: str = os.getenv("NTGRAM_MESSAGE_ADDR", "127.0.0.1:50053")
    profile_addr: str = os.getenv("NTGRAM_PROFILE_ADDR", "127.0.0.1:50054")
    status_addr: str = os.getenv("NTGRAM_STATUS_ADDR", "127.0.0.1:50055")
    updates_addr: str = os.getenv("NTGRAM_UPDATES_ADDR", "127.0.0.1:50056")
