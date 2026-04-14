from __future__ import annotations

from ntgram.gen import common_pb2


def ok_meta() -> common_pb2.ServiceResponseMeta:
    return common_pb2.ServiceResponseMeta(ok=True)


def err_meta(code: int, message: str) -> common_pb2.ServiceResponseMeta:
    return common_pb2.ServiceResponseMeta(
        ok=False,
        error=common_pb2.RpcError(code=code, message=message),
    )
