from __future__ import annotations

import logging
import time
from pathlib import Path

import grpc
import grpc.aio

_LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


class LoggingInterceptor(grpc.aio.ServerInterceptor):
    """Per-service gRPC interceptor that logs every unary RPC call."""

    def __init__(self, service_name: str, log_path: Path) -> None:
        self._logger = logging.getLogger(f"ntgram.services.{service_name}")
        handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        self._logger.addHandler(handler)
        # Don't duplicate to root logger (which already writes to stdout).
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)

    async def intercept_service(
        self,
        continuation: grpc.aio.InterceptedUnaryUnaryCall,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None or handler.unary_unary is None:
            return handler

        rpc_name = handler_call_details.method.rsplit("/", 1)[-1]
        orig = handler.unary_unary
        log = self._logger

        async def wrapped(request: object, context: grpc.aio.ServicerContext) -> object:
            log.info(">> %s\n%s", rpc_name, request)
            t0 = time.monotonic()
            try:
                response = await orig(request, context)
                elapsed = int((time.monotonic() - t0) * 1000)
                log.info("<< %s ok elapsed_ms=%d\n%s", rpc_name, elapsed, response)
                return response
            except Exception as exc:
                elapsed = int((time.monotonic() - t0) * 1000)
                log.warning("<< %s error elapsed_ms=%d: %s", rpc_name, elapsed, exc)
                raise

        return handler._replace(unary_unary=wrapped)
