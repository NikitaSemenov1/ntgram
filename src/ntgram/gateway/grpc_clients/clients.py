from __future__ import annotations

from ntgram.gateway.grpc_clients.account_client import AccountClient
from ntgram.gateway.grpc_clients.channels import GrpcChannels, ServiceAddresses
from ntgram.gateway.grpc_clients.chat_client import ChatClient
from ntgram.gateway.grpc_clients.updates_client import UpdatesClient


class GrpcClients:
    """Bundle of typed per-service clients."""

    __slots__ = (
        "_channels",
        "_owns_channels",
        "account",
        "chat",
        "updates",
    )

    def __init__(
        self,
        channels: GrpcChannels,
        *,
        owns_channels: bool = True,
    ) -> None:
        self._channels = channels
        self._owns_channels = owns_channels
        self.account = AccountClient(channels.account)
        self.chat = ChatClient(channels.chat)
        self.updates = UpdatesClient(channels.updates)

    @classmethod
    def from_addresses(
        cls,
        *,
        account_addr: str,
        chat_addr: str,
        updates_addr: str,
    ) -> GrpcClients:
        """Convenience factory that creates and owns the channels."""
        channels = GrpcChannels(
            ServiceAddresses(
                account=account_addr,
                chat=chat_addr,
                updates=updates_addr,
            ),
        )
        return cls(channels, owns_channels=True)

    async def close(self) -> None:
        """Close owned channels; no-op if channels were injected."""
        if self._owns_channels:
            await self._channels.close()
