from __future__ import annotations

import asyncio
import logging

import asyncpg
import grpc

from ntgram.gen import (
    account_pb2_grpc,
    chat_pb2_grpc,
    message_pb2_grpc,
    profile_pb2_grpc,
    status_pb2_grpc,
    updates_pb2_grpc,
)
from ntgram.services.account.service import AccountService
from ntgram.services.chat.service import ChatService
from ntgram.services.message.service import MessageService
from ntgram.services.profile.service import ProfileService
from ntgram.services.status.service import StatusService
from ntgram.services.updates.service import UpdatesService

logger = logging.getLogger(__name__)


async def serve_service(
    name: str,
    address: str,
    pool: asyncpg.Pool,
    *,
    account_addr: str = "",
    chat_addr: str = "",
) -> None:
    """Start a single gRPC service.

    cross-service addresses are needed only for services that call other services:
      - chat, profile -> account_addr
      - message -> chat_addr
    """
    server = grpc.aio.server()
    if name == "account":
        account_pb2_grpc.add_AccountServiceServicer_to_server(AccountService(pool), server)
    elif name == "chat":
        channel = grpc.aio.insecure_channel(account_addr)
        chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatService(pool, channel), server)
    elif name == "message":
        channel = grpc.aio.insecure_channel(chat_addr)
        message_pb2_grpc.add_MessageServiceServicer_to_server(MessageService(pool, channel), server)
    elif name == "profile":
        channel = grpc.aio.insecure_channel(account_addr)
        profile_pb2_grpc.add_ProfileServiceServicer_to_server(ProfileService(pool, channel), server)
    elif name == "status":
        status_pb2_grpc.add_StatusServiceServicer_to_server(StatusService(pool), server)
    elif name == "updates":
        updates_pb2_grpc.add_UpdatesServiceServicer_to_server(UpdatesService(pool), server)
    else:
        raise ValueError(f"unknown service: {name}")

    server.add_insecure_port(address)
    await server.start()
    logger.info("%s-service listening on %s", name, address)
    await server.wait_for_termination()


async def serve_all(addresses: dict[str, str], pool: asyncpg.Pool) -> None:
    account_addr = addresses["account"]
    chat_addr = addresses["chat"]
    tasks = []
    for name, addr in addresses.items():
        tasks.append(
            serve_service(
                name, addr, pool,
                account_addr=account_addr,
                chat_addr=chat_addr,
            )
        )
    await asyncio.gather(*tasks)
