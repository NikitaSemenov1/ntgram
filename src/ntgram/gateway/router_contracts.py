from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ntgram.tl.registry import default_schema_registry


class ServiceName(StrEnum):
    ACCOUNT = "account"
    CHAT = "chat"
    MESSAGE = "message"
    PROFILE = "profile"
    STATUS = "status"


@dataclass(slots=True, frozen=True)
class Route:
    constructor: str
    service: ServiceName
    method: str


ROUTES: tuple[Route, ...] = (
    # Account / auth
    Route("auth.sendCode", ServiceName.ACCOUNT, "SendCode"),
    Route("auth.signIn", ServiceName.ACCOUNT, "SignIn"),
    Route("auth.signUp", ServiceName.ACCOUNT, "SignUp"),
    Route("auth.logOut", ServiceName.ACCOUNT, "LogOut"),
    # Chat
    Route("messages.createChat", ServiceName.CHAT, "CreateGroupChat"),
    Route("messages.startPrivateChat", ServiceName.CHAT, "CreatePrivateDialog"),
    Route("messages.addChatUser", ServiceName.CHAT, "AddChatUser"),
    Route("messages.deleteChatUser", ServiceName.CHAT, "DeleteChatUser"),
    Route("messages.editChatTitle", ServiceName.CHAT, "EditChatTitle"),
    Route("messages.getFullChat", ServiceName.CHAT, "GetFullChat"),
    Route("messages.getDialogs", ServiceName.CHAT, "ListDialogs"),
    # Messages
    Route("messages.sendMessage", ServiceName.MESSAGE, "SendMessage"),
    Route("messages.deleteMessages", ServiceName.MESSAGE, "DeleteMessages"),
    Route("messages.getHistory", ServiceName.MESSAGE, "ListMessages"),
    Route("messages.readHistory", ServiceName.MESSAGE, "ReadHistory"),
    # Profile
    Route("account.getProfile", ServiceName.PROFILE, "GetProfile"),
    Route("account.updateProfile", ServiceName.PROFILE, "UpdateProfile"),
    # Status
    Route("status.setOnline", ServiceName.STATUS, "SetOnline"),
    Route("status.setOffline", ServiceName.STATUS, "SetOffline"),
    Route("status.get", ServiceName.STATUS, "GetPresence"),
)

ROUTES_BY_CONSTRUCTOR = {item.constructor: item for item in ROUTES}

_SCHEMA = default_schema_registry()
ROUTES_BY_CONSTRUCTOR_ID = {
    _SCHEMA.methods_by_name[name].id: route
    for name, route in ROUTES_BY_CONSTRUCTOR.items()
    if name in _SCHEMA.methods_by_name
}
