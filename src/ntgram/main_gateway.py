from __future__ import annotations

import asyncio
import logging

import uvloop

from ntgram.gateway.server import GatewayServer
from ntgram.settings import GatewaySettings, ServiceSettings


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    uvloop.install()

    async def _run() -> None:
        server = GatewayServer(GatewaySettings(), ServiceSettings())
        await server.serve()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
