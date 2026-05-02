from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gateway.grpc_clients.chat_client import ChatClient


async def fetch_peers_tl(
    *,
    actor_user_id: int,
    user_ids: set[int],
    chat_ids: set[int],
    account_client: AccountClient,
    chat_client: ChatClient,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Batch-fetch TL user and chat objects for the given ids."""
    users_tl = await _fetch_users_tl(account_client, actor_user_id, user_ids)
    chats_tl = await _fetch_chats_tl(chat_client, chat_ids)
    return users_tl, chats_tl


async def _fetch_users_tl(
    account_client: AccountClient,
    actor_user_id: int,
    user_ids: set[int],
) -> list[dict[str, Any]]:
    if not user_ids:
        return []
    try:
        from ntgram.gateway.grpc_clients.dtos import MinimalProfileDto
        from ntgram.gateway.tl_builders.users import public_user_tl_from_minimal

        profiles = await account_client.get_profiles(
            actor_user_id=actor_user_id,
            user_ids=list(user_ids),
        )
        return [
            public_user_tl_from_minimal(
                MinimalProfileDto(
                    user_id=p.user_id,
                    first_name=p.first_name,
                    last_name=p.last_name,
                    username=p.username,
                ),
            )
            for p in profiles
        ]
    except Exception:
        return []


async def _fetch_chats_tl(
    chat_client: ChatClient,
    chat_ids: set[int],
) -> list[dict[str, Any]]:
    if not chat_ids:
        return []
    from ntgram.gateway.tl_messages import build_chat_minimal_tl

    chats_tl: list[dict[str, Any]] = []
    for chat_id in chat_ids:
        try:
            result = await chat_client.get_full_chat(chat_id)
            chats_tl.append(
                build_chat_minimal_tl(
                    chat_id=result.chat_id,
                    title=result.title,
                    participants_count=int(
                        result.participants_count or len(result.member_user_ids),
                    ),
                    version=int(result.version or 1),
                    date=int(result.date_unix or 0),
                ),
            )
        except Exception:
            pass
    return chats_tl
