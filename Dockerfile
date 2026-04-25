FROM python:3.12-slim AS base

WORKDIR /app
ENV PYTHONPATH=/app/src

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN python - <<'PY'
import subprocess
import tomllib
from pathlib import Path

deps = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
subprocess.check_call(["pip", "install", "--no-cache-dir", *deps])
PY

COPY migrations/ migrations/
COPY scripts/ scripts/
COPY keys/ keys/
COPY config/ config/
COPY tl/ tl/
COPY src/ src/

FROM base AS gateway
CMD ["python", "-m", "ntgram.main_gateway"]

FROM base AS services
CMD ["python", "-m", "ntgram.main_services", "--service", "all"]
