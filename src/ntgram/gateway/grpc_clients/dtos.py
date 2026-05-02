from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ntgram.gateway.route_outcome import MessageParticipant, ReadOutboxReceipt

if TYPE_CHECKING:
    from ntgram.gen.common_pb2 import UpdateEnvelope


# Account / auth


@dataclass(slots=True, frozen=True)
class SendCodeResult:
    phone_code_hash: str


@dataclass(slots=True, frozen=True)
class SignInResult:
    user_id: int
    phone: str
    is_new_user: bool = False


@dataclass(slots=True, frozen=True)
class SignUpResult:
    user_id: int
    phone: str
    first_name: str
    last_name: str


@dataclass(slots=True, frozen=True)
class SearchUsernameHit:
    user_id: int
    first_name: str
    last_name: str
    username: str
    bio: str = ""


@dataclass(slots=True, frozen=True)
class ResolveUsernameResult:
    user_id: int
    first_name: str
    last_name: str
    username: str
    bio: str = ""


@dataclass(slots=True, frozen=True)
class SearchUsernamesResult:
    hits: tuple[SearchUsernameHit, ...]


@dataclass(slots=True, frozen=True)
class GetUserResult:
    """account.GetUser: phone + username lookup for self-user TL assembly."""

    user_id: int
    ok: bool
    phone: str
    username: str
    first_name: str
    last_name: str


@dataclass(slots=True, frozen=True)
class UpdateUsernameResult:
    user_id: int
    first_name: str
    last_name: str
    phone: str
    username: str


# Chat


@dataclass(slots=True, frozen=True)
class CreateGroupChatResult:
    chat_id: int
    dialog_id: int = 0
    date_unix: int = 0
    service_message_id: int = 0
    updates: "UpdateEnvelope | None" = None
    users: "tuple[MinimalProfileDto, ...]" = ()
    chats: "tuple[MinimalChatDto, ...]" = ()


@dataclass(slots=True, frozen=True)
class AddChatUserResult:
    updates: "UpdateEnvelope | None" = None
    users: "tuple[MinimalProfileDto, ...]" = ()
    chats: "tuple[MinimalChatDto, ...]" = ()


@dataclass(slots=True, frozen=True)
class EditChatTitleResult:
    updates: "UpdateEnvelope | None" = None
    users: "tuple[MinimalProfileDto, ...]" = ()
    chats: "tuple[MinimalChatDto, ...]" = ()


@dataclass(slots=True, frozen=True)
class CreatePrivateDialogResult:
    dialog_id: int


@dataclass(slots=True, frozen=True)
class ChatParticipantDto:
    user_id: int
    inviter_user_id: int
    date_unix: int
    # 0 = creator, 1 = regular member.
    kind: int


@dataclass(slots=True, frozen=True)
class GetFullChatResult:
    chat_id: int
    title: str
    creator_id: int
    member_user_ids: tuple[int, ...]
    participants: tuple[ChatParticipantDto, ...] = ()
    users: "tuple[MinimalProfileDto, ...]" = ()
    version: int = 1
    participants_count: int = 0
    date_unix: int = 0
    ok: bool = True


@dataclass(slots=True, frozen=True)
class DialogRow:
    """One row of chat.ListDialogs; fed into `build_dialogs_view`."""

    dialog_id: int
    peer_id: int
    is_group: bool
    read_inbox_max_id: int
    read_outbox_max_id: int
    unread_count: int
    top_message_id: int
    top_message_date: int
    top_message_text: str
    top_from_user_id: int
    top_message_out: bool


@dataclass(slots=True, frozen=True)
class MinimalProfileDto:
    user_id: int
    first_name: str
    last_name: str
    username: str


@dataclass(slots=True, frozen=True)
class MinimalChatDto:
    chat_id: int
    title: str
    participants_count: int
    version: int = 1
    date_unix: int = 0
    creator_user_id: int = 0


@dataclass(slots=True, frozen=True)
class ListDialogsResult:
    dialogs: tuple[DialogRow, ...]
    users: tuple[MinimalProfileDto, ...] = ()
    chats: tuple[MinimalChatDto, ...] = ()
    total_count: int = 0


# Messages


@dataclass(slots=True, frozen=True)
class SendMessageResult:
    actor_user_message_box_id: int
    pts: int
    date_unix: int
    participants: tuple[MessageParticipant, ...]
    updates: "UpdateEnvelope | None" = None
    users: tuple[MinimalProfileDto, ...] = ()
    chats: tuple[MinimalChatDto, ...] = ()


@dataclass(slots=True, frozen=True)
class DeleteMessagesResult:
    pts: int
    pts_count: int = 0
    deleted_ids: tuple[int, ...] = ()
    updates: "UpdateEnvelope | None" = None


@dataclass(slots=True, frozen=True)
class EditMessageResult:
    actor_user_message_box_id: int
    dialog_message_id: int
    edit_date: int
    updates: "UpdateEnvelope | None" = None
    users: tuple[MinimalProfileDto, ...] = ()
    chats: tuple[MinimalChatDto, ...] = ()


@dataclass(slots=True, frozen=True)
class MessageRow:
    message_id: int
    from_user_id: int
    date: int
    text: str
    out: bool


@dataclass(slots=True, frozen=True)
class ListMessagesResult:
    messages: tuple[MessageRow, ...]
    total_count: int
    users: tuple[MinimalProfileDto, ...] = ()
    chats: tuple[MinimalChatDto, ...] = ()


@dataclass(slots=True, frozen=True)
class ReadHistoryResult:
    pts: int
    pts_count: int
    receipts: tuple[ReadOutboxReceipt, ...]


# Profile


@dataclass(slots=True, frozen=True)
class ProfileDto:
    user_id: int
    first_name: str
    last_name: str
    bio: str
    username: str


@dataclass(slots=True, frozen=True)
class FullUserDto:
    user_id: int
    first_name: str
    last_name: str
    bio: str
    is_self: bool
    phone: str
    username: str


@dataclass(slots=True, frozen=True)
class UpdateProfileResult:
    profile: ProfileDto


# Account policy


@dataclass(slots=True, frozen=True)
class PrivacyRulesResult:
    rules: tuple[str, ...]  # TL constructor names


@dataclass(slots=True, frozen=True)
class ContentSettingsResult:
    sensitive_can_change: bool
    sensitive_enabled: bool


@dataclass(slots=True, frozen=True)
class ConfigResult:
    config_json: str


# Updates


@dataclass(slots=True, frozen=True)
class UpdatesState:
    pts: int
    qts: int
    seq: int
    date: int


@dataclass(slots=True, frozen=True)
class UpdatesDifferenceEmpty:
    date: int
    seq: int


@dataclass(slots=True, frozen=True)
class UpdatesDifferenceTooLong:
    """Service signals the client must re-sync from current state."""

    pts: int


@dataclass(slots=True, frozen=True)
class PtsUpdateRow:
    """One row from user_pts_updates, enriched for TL conversion."""

    pts: int
    update_type: str
    update_data: dict
    date: int


@dataclass(slots=True, frozen=True)
class UpdatesDifference:
    state: UpdatesState
    raw_updates: tuple[PtsUpdateRow, ...]
    is_slice: bool = False


UpdatesDifferenceResult = (
    UpdatesDifferenceEmpty | UpdatesDifference | UpdatesDifferenceTooLong
)
