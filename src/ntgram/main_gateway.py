from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import uvloop

from ntgram.gateway.server import GatewayServer
from ntgram.settings import GatewaySettings, RedisSettings, ServiceSettings


def main() -> None:
    gateway_settings = GatewaySettings()
    log_path = Path(gateway_settings.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_format = "%(asctime)s %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            # mode="w" truncates file on every process start.
            logging.FileHandler(log_path, mode="w", encoding="utf-8"),
        ],
    )
    uvloop.install()

    async def _run() -> None:
        server = GatewayServer(gateway_settings, ServiceSettings(), RedisSettings())
        await server.serve()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
