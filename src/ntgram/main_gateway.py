from __future__ import annotations

import asyncio
import logging

import uvloop

from ntgram.gateway.server import GatewayServer
from ntgram.settings import GatewaySettings, ServiceSettings


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    uvloop.install()
    server = GatewayServer(GatewaySettings(), ServiceSettings())
    asyncio.run(server.serve())


if __name__ == "__main__":
    main()
