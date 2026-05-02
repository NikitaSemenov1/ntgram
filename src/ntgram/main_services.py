from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

import uvloop

from ntgram.db import create_pool
from ntgram.services.runtime import (
    serve_account,
    serve_all,
    serve_chat,
    serve_updates,
)
from ntgram.settings import DatabaseSettings, ServiceSettings


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ntgram domain service(s).")
    parser.add_argument(
        "--service",
        choices=["all", "account", "chat", "updates"],
        default="all",
    )
    parser.add_argument("--address", default="0.0.0.0:50051")
    parser.add_argument("--account-addr", default="127.0.0.1:50051")
    parser.add_argument("--updates-addr", default="127.0.0.1:50056")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    db_settings = DatabaseSettings()
    service_settings = ServiceSettings()

    log_dir = Path(service_settings.services_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
        handlers=[logging.StreamHandler()],
    )

    uvloop.install()

    if args.service == "all":
        bind_addresses = {
            "account": os.getenv("NTGRAM_ACCOUNT_BIND_ADDR", "0.0.0.0:50051"),
            "chat": os.getenv("NTGRAM_CHAT_BIND_ADDR", "0.0.0.0:50052"),
            "updates": os.getenv("NTGRAM_UPDATES_BIND_ADDR", "0.0.0.0:50056"),
        }
        dependency_addresses = {
            "account": service_settings.account_addr,
            "updates": service_settings.updates_addr,
        }

        async def _run_all() -> None:
            account_pool, chat_pool, updates_pool = await asyncio.gather(
                create_pool(db_settings.account_dsn),
                create_pool(db_settings.chat_dsn),
                create_pool(db_settings.updates_dsn),
            )
            try:
                await serve_all(
                    bind_addresses=bind_addresses,
                    pools={
                        "account": account_pool,
                        "chat": chat_pool,
                        "updates": updates_pool,
                    },
                    dependency_addresses=dependency_addresses,
                    log_dir=log_dir,
                )
            finally:
                await asyncio.gather(
                    account_pool.close(),
                    chat_pool.close(),
                    updates_pool.close(),
                )

        asyncio.run(_run_all())
        return

    # Single-service mode: only open the DSN that this service needs.
    async def _run_single() -> None:
        if args.service == "account":
            pool = await create_pool(db_settings.account_dsn)
            try:
                await serve_account(args.address, pool, log_dir=log_dir)
            finally:
                await pool.close()
            return

        if args.service == "chat":
            pool = await create_pool(db_settings.chat_dsn)
            try:
                await serve_chat(
                    args.address, pool,
                    account_addr=args.account_addr,
                    updates_addr=args.updates_addr,
                    log_dir=log_dir,
                )
            finally:
                await pool.close()
            return

        if args.service == "updates":
            pool = await create_pool(db_settings.updates_dsn)
            try:
                await serve_updates(args.address, pool, log_dir=log_dir)
            finally:
                await pool.close()
            return

        raise ValueError(f"unknown service: {args.service}")

    asyncio.run(_run_single())


if __name__ == "__main__":
    main()
