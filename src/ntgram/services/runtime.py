from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import asyncpg
import grpc

from ntgram.gen import (
    account_pb2_grpc,
    chat_pb2_grpc,
    updates_pb2_grpc,
)
from ntgram.services.account.service import AccountService
from ntgram.services.chat.service import ChatService
from ntgram.services.grpc_logging import LoggingInterceptor
from ntgram.services.updates.service import UpdatesService

logger = logging.getLogger(__name__)


def _make_server(
    name: str, log_dir: Path | None,
) -> grpc.aio.Server:
    interceptors: list[grpc.aio.ServerInterceptor] = []
    if log_dir is not None:
        interceptors.append(LoggingInterceptor(name, log_dir / f"{name}.log"))
    return grpc.aio.server(interceptors=interceptors)


async def serve_account(
    address: str,
    pool: asyncpg.Pool,
    *,
    log_dir: Path | None = None,
) -> None:
    server = _make_server("account", log_dir)
    account_pb2_grpc.add_AccountServiceServicer_to_server(
        AccountService(pool), server,
    )
    server.add_insecure_port(address)
    await server.start()
    logger.info("account-service listening on %s", address)
    await server.wait_for_termination()


async def serve_chat(
    address: str,
    pool: asyncpg.Pool,
    *,
    account_addr: str,
    updates_addr: str,
    log_dir: Path | None = None,
) -> None:
    """Start ChatService."""
    if not account_addr:
        raise ValueError("ChatService requires --account-addr")
    if not updates_addr:
        raise ValueError("ChatService requires --updates-addr")
    account_channel = grpc.aio.insecure_channel(account_addr)
    updates_channel = grpc.aio.insecure_channel(updates_addr)
    server = _make_server("chat", log_dir)
    chat_pb2_grpc.add_ChatServiceServicer_to_server(
        ChatService(pool, account_channel, updates_channel), server,
    )
    server.add_insecure_port(address)
    await server.start()
    logger.info("chat-service listening on %s", address)
    await server.wait_for_termination()


async def serve_updates(
    address: str,
    pool: asyncpg.Pool,
    *,
    log_dir: Path | None = None,
) -> None:
    server = _make_server("updates", log_dir)
    updates_pb2_grpc.add_UpdatesServiceServicer_to_server(
        UpdatesService(pool), server,
    )
    server.add_insecure_port(address)
    await server.start()
    logger.info("updates-service listening on %s", address)
    await server.wait_for_termination()


async def serve_all(
    *,
    bind_addresses: dict[str, str],
    pools: dict[str, asyncpg.Pool],
    dependency_addresses: dict[str, str],
    log_dir: Path | None = None,
) -> None:
    """Start all three services in one process."""
    tasks = [
        serve_account(
            bind_addresses["account"], pools["account"],
            log_dir=log_dir,
        ),
        serve_updates(
            bind_addresses["updates"], pools["updates"],
            log_dir=log_dir,
        ),
        serve_chat(
            bind_addresses["chat"], pools["chat"],
            account_addr=dependency_addresses["account"],
            updates_addr=dependency_addresses["updates"],
            log_dir=log_dir,
        ),
    ]
    await asyncio.gather(*tasks)
