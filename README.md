# ntgram

Python-реализация MTProto-совместимого серверного бэкенда для мессенджера.
Принимает TCP-подключения от клиентов по протоколу MTProto (abridged transport),
выполняет DH key exchange, шифрование AES-IGE и маршрутизирует запросы к domain-сервисам через gRPC.

## Сервисы


| Сервис      | Порт           | Описание                                                                                                                          |
| ----------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Gateway** | `8080` (TCP)  | MTProto edge: abridged framing, DH handshake, RSA/AES криптография, TL-декодирование, маршрутизация RPC во внутренние gRPC-вызовы |
| **Account** | `50051` (gRPC) | Авторизация: отправка SMS-кода, вход, регистрация, выход                                                                          |
| **Chat**    | `50052` (gRPC) | Чаты: создание личных и групповых диалогов, управление участниками                                                                |
| **Message** | `50053` (gRPC) | Сообщения: отправка, удаление (revoke/personal), история, прочитано                                                               |
| **Profile** | `50054` (gRPC) | Профиль: просмотр и редактирование (имя, фамилия, bio)                                                                            |
| **Status**  | `50055` (gRPC) | Статус: online/offline, last seen, update fanout                                                                                  |
| **Updates** | `50056` (gRPC) | Обновления: PTS-трекинг, getDifference, server-push                                                                               |


## Стек

Python 3.12 · asyncio + uvloop · grpc.aio · asyncpg · PostgreSQL · Redis · cryptography

## Запуск через Docker Compose

```bash
# 1. Сгенерировать RSA-ключи (нужно один раз)
make gen-rsa

# 2. Поднять всё
docker compose up --build
```

Compose запускает PostgreSQL, Redis, domain-сервисы и Gateway.
Миграции применяются автоматически при первом старте PostgreSQL.

Gateway слушает на `localhost:8080` (MTProto TCP).

## Запуск без Docker

Необходимы работающие PostgreSQL и Redis.

```bash
# Установить зависимости
pip install -e ".[dev]"

# Сгенерировать RSA-ключи
make gen-rsa

# Сгенерировать protobuf-стабы
make proto

# Запустить domain-сервисы (все сразу)
make run-services

# В отдельном терминале — запустить Gateway
make run-gateway
```

### Переменные окружения


| Переменная                    | По умолчанию                                       | Описание               |
| ----------------------------- | -------------------------------------------------- | ---------------------- |
| `NTGRAM_GATEWAY_HOST`         | `0.0.0.0`                                          | Хост Gateway           |
| `NTGRAM_GATEWAY_PORT`         | `8080`                                            | Порт Gateway           |
| `NTGRAM_POSTGRES_DSN`         | `postgresql://ntgram:ntgram@localhost:5432/ntgram` | DSN PostgreSQL         |
| `NTGRAM_REDIS_DSN`            | `redis://localhost:6379/0`                         | DSN Redis              |
| `NTGRAM_RSA_PRIVATE_KEY_PATH` | `./keys/private.pem`                               | Путь к RSA private key |
| `NTGRAM_RSA_PUBLIC_KEY_PATH`  | `./keys/public.pem`                                | Путь к RSA public key  |
| `NTGRAM_ACCOUNT_ADDR`         | `127.0.0.1:50051`                                  | Адрес Account Service  |
| `NTGRAM_CHAT_ADDR`            | `127.0.0.1:50052`                                  | Адрес Chat Service     |
| `NTGRAM_MESSAGE_ADDR`         | `127.0.0.1:50053`                                  | Адрес Message Service  |
| `NTGRAM_PROFILE_ADDR`         | `127.0.0.1:50054`                                  | Адрес Profile Service  |
| `NTGRAM_STATUS_ADDR`          | `127.0.0.1:50055`                                  | Адрес Status Service   |
| `NTGRAM_UPDATES_ADDR`         | `127.0.0.1:50056`                                  | Адрес Updates Service  |


## Тесты

```bash
make test
```

