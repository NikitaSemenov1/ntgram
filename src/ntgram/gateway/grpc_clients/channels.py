from __future__ import annotations

from dataclasses import dataclass

import grpc

from ntgram.gen import (
    account_pb2_grpc,
    chat_pb2_grpc,
    updates_pb2_grpc,
)


@dataclass(slots=True, frozen=True)
class ServiceAddresses:
    """Per-service gRPC endpoints; passed to :meth:`GrpcChannels.from_addresses`."""

    account: str
    chat: str
    updates: str


class GrpcChannels:
    """Owns the three insecure grpc.aio channels for one gateway process."""

    __slots__ = (
        "_account_channel",
        "_chat_channel",
        "_updates_channel",
        "account",
        "chat",
        "updates",
    )

    def __init__(self, addrs: ServiceAddresses) -> None:
        self._account_channel = grpc.aio.insecure_channel(addrs.account)
        self._chat_channel = grpc.aio.insecure_channel(addrs.chat)
        self._updates_channel = grpc.aio.insecure_channel(addrs.updates)
        self.account = account_pb2_grpc.AccountServiceStub(self._account_channel)
        self.chat = chat_pb2_grpc.ChatServiceStub(self._chat_channel)
        self.updates = updates_pb2_grpc.UpdatesServiceStub(self._updates_channel)

    async def close(self) -> None:
        await self._account_channel.close()
        await self._chat_channel.close()
        await self._updates_channel.close()
