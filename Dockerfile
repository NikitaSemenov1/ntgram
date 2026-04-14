FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ src/
RUN pip install --no-cache-dir -e .

COPY migrations/ migrations/
COPY scripts/ scripts/
COPY keys/ keys/

FROM base AS gateway
CMD ["python", "-m", "ntgram.main_gateway"]

FROM base AS services
CMD ["python", "-m", "ntgram.main_services", "--service", "all"]
