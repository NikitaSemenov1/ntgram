from __future__ import annotations

import argparse
import asyncio
import logging

import uvloop

from ntgram.db import create_pool
from ntgram.services.runtime import serve_all, serve_service
from ntgram.settings import DatabaseSettings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ntgram domain service(s).")
    parser.add_argument(
        "--service",
        choices=["all", "account", "chat", "message", "profile", "status"],
        default="all",
    )
    parser.add_argument("--address", default="127.0.0.1:50051")
    parser.add_argument("--account-addr", default="127.0.0.1:50051")
    parser.add_argument("--chat-addr", default="127.0.0.1:50052")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    uvloop.install()

    db_settings = DatabaseSettings()

    if args.service == "all":
        addresses = {
            "account": "127.0.0.1:50051",
            "chat": "127.0.0.1:50052",
            "message": "127.0.0.1:50053",
            "profile": "127.0.0.1:50054",
            "status": "127.0.0.1:50055",
        }

        async def _run_all() -> None:
            pool = await create_pool(db_settings.dsn)
            try:
                await serve_all(addresses, pool)
            finally:
                await pool.close()

        asyncio.run(_run_all())
        return

    async def _run_single() -> None:
        pool = await create_pool(db_settings.dsn)
        try:
            await serve_service(
                args.service, args.address, pool,
                account_addr=args.account_addr,
                chat_addr=args.chat_addr,
            )
        finally:
            await pool.close()

    asyncio.run(_run_single())


if __name__ == "__main__":
    main()
