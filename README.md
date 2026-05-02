# ntgram

Python-реализация MTProto-совместимого серверного бэкенда для мессенджера.
Принимает TCP-подключения от Telegram-клиентов по протоколу MTProto (abridged/obfuscated transport),
выполняет DH key exchange, шифрование AES-256-IGE и маршрутизирует RPC-запросы к domain-сервисам через gRPC.

## Сервисы

| Сервис      | Порт           | Описание                                                                                 |
|-------------|----------------|------------------------------------------------------------------------------------------|
| **Gateway** | `8080` (TCP)   | MTProto edge: transport, DH handshake, AES-IGE, TL codec, routing, push relay            |
| **Account** | `50051` (gRPC) | Авторизация (sendCode / signIn / signUp / logOut), профили, GetConfig                    |
| **Chat**    | `50052` (gRPC) | Чаты и диалоги + все messages.* RPC (sendMessage, editMessage, deleteMessages, readHistory, listMessages) |
| **Updates** | `50056` (gRPC) | PTS-трекинг, getDifference, Subscribe push stream (LISTEN/NOTIFY)                        |

Каждый сервис имеет **собственный** PostgreSQL-инстанс (`account_db` / `chat_db` / `updates_db`). Cross-DB запросов нет — только gRPC.

## Стек

Python 3.12 · asyncio + uvloop · grpc.aio · asyncpg · PostgreSQL 16 · Redis 7 · cryptography

## Запуск через Docker Compose

```bash
# Сгенерировать RSA-ключи (один раз)
make gen-rsa

# Поднять всё
docker compose up --build
```

Compose поднимает три Postgres-инстанса, Redis, три domain-сервиса и Gateway.
Миграции применяются автоматически при первом старте каждого Postgres.
Gateway слушает на `localhost:8080` (MTProto TCP).

## Запуск без Docker

```bash
# Зависимости
pip install -e ".[dev]"

# RSA-ключи
make gen-rsa

# Protobuf-стабы
make proto

# Domain-сервисы (все в одном процессе, для разработки)
make run-services

# Gateway — отдельный терминал
make run-gateway
```

## Переменные окружения

| Переменная                    | По умолчанию                                             | Описание                          |
|-------------------------------|----------------------------------------------------------|-----------------------------------|
| `NTGRAM_GATEWAY_HOST`         | `0.0.0.0`                                                | Хост Gateway                      |
| `NTGRAM_GATEWAY_PORT`         | `8080`                                                   | Порт Gateway                      |
| `NTGRAM_ACCOUNT_DSN`          | `postgresql://ntgram:ntgram@localhost:5433/account_db`   | DSN account_db                    |
| `NTGRAM_CHAT_DSN`             | `postgresql://ntgram:ntgram@localhost:5434/chat_db`      | DSN chat_db                       |
| `NTGRAM_UPDATES_DSN`          | `postgresql://ntgram:ntgram@localhost:5435/updates_db`   | DSN updates_db                    |
| `NTGRAM_REDIS_DSN`            | `redis://localhost:6379/0`                               | DSN Redis (sessions, push cursor) |
| `NTGRAM_RSA_PRIVATE_KEY_PATH` | `./keys/private.pem`                                     | RSA private key                   |
| `NTGRAM_RSA_PUBLIC_KEY_PATH`  | `./keys/public.pem`                                      | RSA public key                    |
| `NTGRAM_ACCOUNT_ADDR`         | `127.0.0.1:50051`                                        | Адрес Account Service             |
| `NTGRAM_CHAT_ADDR`            | `127.0.0.1:50052`                                        | Адрес Chat Service                |
| `NTGRAM_UPDATES_ADDR`         | `127.0.0.1:50056`                                        | Адрес Updates Service             |

## Тесты

```bash
make test
```
