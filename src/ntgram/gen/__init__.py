"""Generated protobuf artifacts package.

grpc/protobuf Python generators use non-package imports by default (e.g. `import common_pb2`).
We expose aliases via `sys.modules` so generated modules are importable through `ntgram.gen`.
"""

from __future__ import annotations

import importlib
import sys

_MODULES = (
    "common_pb2",
    "account_pb2",
    "chat_pb2",
    "message_pb2",
    "profile_pb2",
    "status_pb2",
    "updates_pb2",
    "common_pb2_grpc",
    "account_pb2_grpc",
    "chat_pb2_grpc",
    "message_pb2_grpc",
    "profile_pb2_grpc",
    "status_pb2_grpc",
    "updates_pb2_grpc",
)

for name in _MODULES:
    module = importlib.import_module(f"ntgram.gen.{name}")
    sys.modules.setdefault(name, module)
