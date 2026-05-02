from __future__ import annotations

import asyncio
import json
import struct
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ntgram.tl.codec import (
    decode_tl_object,
    decode_tl_request,
    encode_tl_object,
    encode_tl_response,
    serialize_value,
)
from ntgram.tl.models import TlRequest, TlResponse
from ntgram.tl.registry import default_schema_registry
from ntgram.tl.serializer import serialize_object


def test_router_end_to_end_flow() -> None:
    """Full TL roundtrip: bytes -> decode -> dispatch -> encode -> bytes.

    Exercises every gateway layer above the encrypted envelope (codec, router,
    handler registry, gRPC route adapter, idempotency store, response builder)
    against a thinly-mocked ``AccountClient``. The encrypted envelope itself is
    covered by ``test_encrypted_envelope.py``.
    """
    pytest.importorskip("grpc")
    from dataclasses import replace

    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gen import account_pb2
    from ntgram.services.common import ok_meta

    stub = AsyncMock()
    stub.LogOut = AsyncMock(
        return_value=account_pb2.LogOutResponse(meta=ok_meta()),
    )
    grpc_clients = AsyncMock()
    grpc_clients.account = AccountClient(stub)

    sessions = SessionStore()
    session = sessions.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    sessions.bind_user(session.auth_key_id, 1234)

    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=sessions,
    )

    raw = encode_tl_object("auth.logOut", {})

    request = decode_tl_request(raw)
    assert request.constructor == "auth.logOut"

    # decode_tl_request sees only the TL body; in the live pipeline the
    # encrypted envelope provides auth_key_id / session_id / req_msg_id.
    request = replace(
        request,
        auth_key_id=session.auth_key_id,
        session_id=7,
        req_msg_id=12345,
    )

    response = asyncio.run(router.dispatch(request))

    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["req_msg_id"] == 12345
    assert fields["result"]["_constructor"] == "auth.loggedOut"

    stub.LogOut.assert_awaited_once()
    log_out_req = stub.LogOut.call_args[0][0]
    assert log_out_req.user_id == 1234
    assert log_out_req.auth_key_id == session.auth_key_id
    assert sessions.get_session(session.auth_key_id).user_id is None


@pytest.mark.asyncio
async def test_trace_constructors_are_supported() -> None:
    trace_path = Path(__file__).parent / "traces/client_core_trace.json"
    constructors = [
        entry["constructor"]
        for entry in json.loads(trace_path.read_text())
    ]
    assert "auth.sendCode" in constructors
    assert "updates.getDifference" in constructors


def test_binary_tl_request_response_roundtrip() -> None:
    """Round-trip: serialize a TL method, decode it, then encode a response."""
    schema = default_schema_registry()
    spec = schema.methods_by_name["ping"]

    body = serialize_object("ping", {"ping_id": 42}, schema)

    request = decode_tl_request(body)
    assert request.constructor == "ping"
    assert request.payload["ping_id"] == 42

    response = TlResponse(
        req_msg_id=77,
        result={
            "constructor": "pong",
            "msg_id": 77,
            "ping_id": 42,
        },
    )
    encoded_response = encode_tl_response(response)
    name, fields = decode_tl_object(encoded_response)
    assert name == "pong"
    assert fields["ping_id"] == 42


def test_help_get_config_returns_serializable_config() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter
    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="help.getConfig",
                req_msg_id=101,
                auth_key_id=0,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "config"
    assert inner.get("this_dc") == 1
    assert isinstance(inner.get("dc_options"), list)


def test_help_get_nearest_dc_returns_serializable_nearest_dc() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="help.getNearestDc",
                req_msg_id=102,
                auth_key_id=0,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "nearestDc"
    assert inner["this_dc"] == 1
    assert inner["nearest_dc"] == 1


def test_help_get_countries_list_returns_empty_stub() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="help.getCountriesList",
                req_msg_id=103,
                auth_key_id=0,
                session_id=1,
                payload={"lang_code": "en", "hash": 0},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "help.countriesList"
    assert inner["countries"] == []
    assert inner["hash"] == 0


def test_auth_log_out_returns_logged_out_and_unbinds_session() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gen import account_pb2
    from ntgram.services.common import ok_meta

    stub = AsyncMock()
    stub.LogOut = AsyncMock(
        return_value=account_pb2.LogOutResponse(meta=ok_meta()),
    )
    grpc_clients = AsyncMock()
    grpc_clients.account = AccountClient(stub)

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"k" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 99)
    assert store.get_session(session.auth_key_id) is not None
    assert store.get_session(session.auth_key_id).user_id == 99

    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=store,
    )

    async def _go() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="auth.logOut",
                req_msg_id=501,
                auth_key_id=session.auth_key_id,
                session_id=7,
                payload={},
            ),
        )

    resp = asyncio.run(_go())
    enc = encode_tl_response(resp)
    name, fields = decode_tl_object(enc)
    assert name == "rpc_result"
    assert fields["result"]["_constructor"] == "auth.loggedOut"
    assert store.get_session(session.auth_key_id).user_id is None
    assert store.get_sessions_for_user(99) == []

    stub.LogOut.assert_awaited_once()
    req = stub.LogOut.call_args[0][0]
    assert req.user_id == 99
    assert req.auth_key_id == session.auth_key_id


@pytest.mark.parametrize(
    ("constructor", "payload", "inner_constructor"),
    [
        ("help.getPromoData", {}, "help.promoDataEmpty"),
        ("help.getTermsOfServiceUpdate", {}, "help.termsOfServiceUpdateEmpty"),
        ("help.getInviteText", {}, "help.inviteText"),
        ("help.getPremiumPromo", {}, "help.premiumPromo"),
        ("help.getPeerColors", {"hash": 0}, "help.peerColors"),
        ("help.getPeerProfileColors", {"hash": 0}, "help.peerColorsNotModified"),
        ("help.getAppConfig", {"hash": 0}, "help.appConfig"),
        (
            "account.getNotifySettings",
            {"peer": {"constructor": "inputNotifyPeer", "peer": {"constructor": "inputPeerEmpty"}}},
            "peerNotifySettings",
        ),
        (
            "account.getReactionsNotifySettings",
            {},
            "reactionsNotifySettings",
        ),
        ("account.getContactSignUpNotification", {}, "boolFalse"),
        ("account.getAutoDownloadSettings", {}, "account.autoDownloadSettings"),
        (
            "account.getDefaultProfilePhotoEmojis",
            {"hash": 0},
            "emojiList",
        ),
        (
            "account.getGlobalPrivacySettings",
            {},
            "globalPrivacySettings",
        ),
        (
            "account.getContentSettings",
            {},
            "account.contentSettings",
        ),
        ("account.getSavedRingtones", {"hash": 0}, "account.savedRingtonesNotModified"),
        ("account.getPassword", {}, "account.password"),
        ("account.getThemes", {"format": "", "hash": 0}, "account.themesNotModified"),
        ("account.updateStatus", {"offline": True}, "boolTrue"),
        ("contacts.getContacts", {"hash": 0}, "contacts.contacts"),
        (
            "contacts.getTopPeers",
            {"offset": 0, "limit": 10, "hash": 0},
            "contacts.topPeers",
        ),
        ("contacts.getBirthdays", {}, "contacts.contactBirthdays"),
        ("contacts.getSponsoredPeers", {"q": ""}, "contacts.sponsoredPeersEmpty"),
        (
            "contacts.search",
            {"q": "x", "limit": 10},
            "contacts.found",
        ),
        (
            "channels.getAdminedPublicChannels",
            {},
            "messages.chats",
        ),
        ("messages.getAttachMenuBots", {"hash": 0}, "attachMenuBotsNotModified"),
        ("messages.getRecentReactions", {"limit": 20, "hash": 0}, "messages.reactions"),
        ("messages.getTopReactions", {"limit": 20, "hash": 0}, "messages.reactions"),
        ("messages.getAvailableEffects", {"hash": 0}, "messages.availableEffects"),
        ("messages.getAvailableReactions", {"hash": 0}, "messages.availableReactions"),
        ("messages.getDialogFilters", {}, "messages.dialogFilters"),
        (
            "messages.search",
            {
                "peer": {"constructor": "inputPeerEmpty"},
                "q": "",
                "filter": {"constructor": "inputMessagesFilterEmpty"},
                "min_date": 0,
                "max_date": 0,
                "offset_id": 0,
                "add_offset": 0,
                "limit": 20,
                "max_id": 0,
                "min_id": 0,
                "hash": 0,
            },
            "messages.messages",
        ),
            (
                "messages.searchGlobal",
                {
                    "q": "",
                    "filter": {"constructor": "inputMessagesFilterEmpty"},
                    "min_date": 0,
                    "max_date": 0,
                    "offset_rate": 0,
                    "offset_peer": {"constructor": "inputPeerEmpty"},
                    "offset_id": 0,
                    "limit": 20,
                },
                "messages.messages",
            ),
            (
                "messages.getScheduledHistory",
                {"peer": {"constructor": "inputPeerEmpty"}, "hash": 0},
                "messages.messages",
            ),
            (
                "messages.getWebPage",
            {"url": "https://example.com/", "hash": 0},
            "messages.webPage",
        ),
        (
            "messages.getPinnedDialogs",
            {"folder_id": 0},
            "messages.peerDialogs",
        ),
        ("messages.getStickers", {"emoticon": "", "hash": 0}, "messages.stickers"),
        ("messages.getEmojiStickers", {"hash": 0}, "messages.allStickersNotModified"),
        ("messages.getEmojiKeywords", {"lang_code": "en"}, "emojiKeywordsDifference"),
        (
            "messages.getEmojiKeywordsDifference",
            {"lang_code": "en", "from_version": 0},
            "emojiKeywordsDifference",
        ),
        (
            "messages.getMessagesReactions",
            {"peer": {"constructor": "inputPeerEmpty"}, "id": []},
            "updates",
        ),
        ("messages.getAllDrafts", {}, "updates"),
        (
            "messages.setTyping",
            {
                "peer": {"constructor": "inputPeerEmpty"},
                "action": {"constructor": "sendMessageTypingAction"},
            },
            "boolTrue",
        ),
        ("messages.getSavedReactionTags", {"hash": 0}, "messages.savedReactionTags"),
        ("messages.getQuickReplies", {"hash": 0}, "messages.quickReplies"),
        (
            "messages.getStickerSet",
            {"stickerset": {"constructor": "inputStickerSetEmpty"}, "hash": 0},
            "messages.stickerSet",
        ),
        ("messages.getFavedStickers", {"hash": 0}, "messages.favedStickersNotModified"),
        ("messages.getFeaturedStickers", {"hash": 0}, "messages.featuredStickersNotModified"),
        ("messages.getFeaturedEmojiStickers", {"hash": 0}, "messages.featuredStickersNotModified"),
        (
            "messages.getArchivedStickers",
            {"flags": 0, "offset_id": 0, "limit": 20},
            "messages.archivedStickers",
        ),
        (
            "messages.getPeerSettings",
            {"peer": {"constructor": "inputPeerEmpty"}},
            "messages.peerSettings",
        ),
        (
            "bots.getBotRecommendations",
            {"bot": {"constructor": "inputUserEmpty"}},
            "users.users",
        ),
        (
            "photos.getUserPhotos",
            {
                "user_id": {"constructor": "inputUserEmpty"},
                "offset": 0,
                "max_id": 0,
                "limit": 10,
            },
            "photos.photos",
        ),
        ("stories.getAllStories", {}, "stories.allStories"),
        ("stories.getAllReadPeerStories", {}, "updates"),
        ("payments.getStarGifts", {"hash": 0}, "payments.starGifts"),
        (
            "payments.getStarsStatus",
            {"flags": 0, "peer": {"constructor": "inputPeerEmpty"}},
            "payments.starsStatus",
        ),
    ],
)
def test_bootstrap_stub_methods_return_tl_objects(
    constructor: str,
    payload: dict,
    inner_constructor: str,
) -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.dtos import SearchUsernamesResult
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    grpc_clients = AsyncMock()
    grpc_clients.account.search_usernames = AsyncMock(
        return_value=SearchUsernamesResult(hits=()),
    )

    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor=constructor,
                req_msg_id=104,
                auth_key_id=1,
                session_id=1,
                payload=payload,
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["result"]["_constructor"] == inner_constructor
    if constructor == "help.getTermsOfServiceUpdate":
        exp = fields["result"].get("expires")
        assert isinstance(exp, int)
        now = int(time.time())
        assert now < exp <= now + 620


@pytest.mark.parametrize(
    ("key_ctor", "rule_ctor"),
    [
        ("inputPrivacyKeyPhoneNumber", "privacyValueDisallowAll"),
        ("inputPrivacyKeyBirthday", "privacyValueAllowContacts"),
        ("inputPrivacyKeyStatusTimestamp", "privacyValueAllowAll"),
    ],
)
def test_account_get_privacy_default_rules(
    key_ctor: str,
    rule_ctor: str,
) -> None:
    """No stored rules: phone → disallow all, birthday → contacts, else → allow all."""
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="account.getPrivacy",
                req_msg_id=104,
                auth_key_id=1,
                session_id=1,
                payload={"key": {"constructor": key_ctor}},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "account.privacyRules"
    assert inner["chats"] == []
    assert inner["users"] == []
    rules = inner["rules"]
    assert len(rules) == 1
    assert rules[0]["_constructor"] == rule_ctor


def test_account_get_privacy_invalid_key_returns_rpc_error() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="account.getPrivacy",
                req_msg_id=104,
                auth_key_id=1,
                session_id=1,
                payload={"key": {"constructor": "notAPrivacyKey"}},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    err = fields["result"]
    assert err["_constructor"] == "rpc_error"
    assert err["error_message"] == "PRIVACY_KEY_INVALID"


@pytest.mark.parametrize(
    ("constructor", "payload"),
    [
        ("messages.getSuggestedDialogFilters", {}),
        (
            "messages.getSearchCounters",
            {"peer": {"constructor": "inputPeerEmpty"}, "filters": []},
        ),
        ("contacts.getStatuses", {}),
    ],
)
def test_bootstrap_vector_stub_methods_return_empty_vectors(
    constructor: str,
    payload: dict,
) -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor=constructor,
                req_msg_id=104,
                auth_key_id=1,
                session_id=1,
                payload=payload,
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    assert struct.unpack_from("<i", encoded, 12)[0] == 0x1CB5C415
    assert struct.unpack_from("<i", encoded, 16)[0] == 0


def test_legacy_account_register_device_decodes_and_returns_true() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    body = bytearray(struct.pack("<i", 0x637EA878))
    serialize_value(body, "int", 1, default_schema_registry())
    serialize_value(body, "string", "push-token", default_schema_registry())

    request = decode_tl_request(bytes(body))
    assert request.constructor == "account.registerDevice"
    assert request.payload == {"token_type": 1, "token": "push-token"}

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    response = asyncio.run(router.dispatch(request))
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["result"]["_constructor"] == "boolTrue"


def test_legacy_account_register_device_decodes_inside_invoke_with_layer() -> None:
    schema = default_schema_registry()
    legacy_body = bytearray(struct.pack("<i", 0x637EA878))
    serialize_value(legacy_body, "int", 2, schema)
    serialize_value(legacy_body, "string", "nested-token", schema)
    body = serialize_object(
        "invokeWithLayer",
        {"layer": 214, "query": bytes(legacy_body)},
        schema,
    )

    request = decode_tl_request(body)
    assert request.constructor == "invokeWithLayer"
    inner = request.payload["query"]
    assert inner["_constructor"] == "account.registerDevice"
    assert inner["token_type"] == 2
    assert inner["token"] == "nested-token"


def test_legacy_langpack_get_languages_decodes_inside_invoke_with_layer() -> None:
    schema = default_schema_registry()
    legacy_body = struct.pack("<i", -0x7FF02A83)
    body = serialize_object(
        "invokeWithLayer",
        {"layer": 214, "query": legacy_body},
        schema,
    )

    request = decode_tl_request(body)
    assert request.constructor == "invokeWithLayer"
    assert request.payload["query"] == {"_constructor": "langpack.getLanguages"}


def test_get_future_salts_returns_direct_non_content_future_salts() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"f" * 256,
        new_nonce=9,
        server_nonce=8,
    )
    session.bind_mtproto_session(7001)
    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=store,
    )
    query_msg_id = ((int(time.time()) << 32) | 4) & ~3

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="get_future_salts",
                req_msg_id=query_msg_id,
                auth_key_id=session.auth_key_id,
                session_id=7001,
                message_id=query_msg_id,
                payload={"num": 3},
            ),
        )

    response = asyncio.run(_dispatch())
    assert response.content_related is False
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "future_salts"
    assert fields["req_msg_id"] == query_msg_id
    assert fields["now"] > 0
    assert isinstance(fields["salts"], list)
    assert len(fields["salts"]) == 3
    for item in fields["salts"]:
        assert item["_constructor"] == "future_salt"
        assert item["valid_since"] <= item["valid_until"]
    # Current salt is returned as the first item; only additional scheduled salts
    # need storing in accepted_future_salts.
    assert len(store.get_session(session.auth_key_id).accepted_future_salts) == 2


def test_bind_temp_auth_key_returns_bool_true() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.encrypted_layer import (
        encode_bind_temp_auth_key_inner_message,
    )
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    perm_session = store.complete_handshake(
        session_id=1,
        auth_key=b"p" * 256,
        new_nonce=10,
        server_nonce=20,
    )
    temp_session = store.complete_handshake(
        session_id=2,
        auth_key=b"t" * 256,
        new_nonce=11,
        server_nonce=21,
    )
    temp_session_id = 123456789
    nonce = 42
    expires_at = int(time.time()) + 3600
    inner = encode_tl_object(
        "bind_auth_key_inner",
        {
            "nonce": nonce,
            "temp_auth_key_id": temp_session.auth_key_id,
            "perm_auth_key_id": perm_session.auth_key_id,
            "temp_session_id": temp_session_id,
            "expires_at": expires_at,
        },
    )
    msg_id = ((int(time.time()) << 32) | 4) & ~3
    encrypted_message = encode_bind_temp_auth_key_inner_message(
        perm_session,
        msg_id=msg_id,
        message_data=inner,
    )
    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=store,
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="auth.bindTempAuthKey",
                req_msg_id=msg_id,
                auth_key_id=temp_session.auth_key_id,
                session_id=temp_session_id,
                payload={
                    "perm_auth_key_id": perm_session.auth_key_id,
                    "nonce": nonce,
                    "expires_at": expires_at,
                    "encrypted_message": encrypted_message,
                },
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["result"]["_constructor"] == "boolTrue"
    assert store.get_session(perm_session.auth_key_id).temp_auth_key_binding is not None
    assert store.get_session(temp_session.auth_key_id).temp_auth_key_binding is not None


def test_destroy_session_returns_ok_or_none() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"d" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    session.bind_mtproto_session(777)
    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=store,
    )

    async def _dispatch_destroy(target: int) -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="destroy_session",
                req_msg_id=500,
                auth_key_id=session.auth_key_id,
                session_id=777,
                payload={"session_id": target},
            ),
        )

    r_ok = asyncio.run(_dispatch_destroy(777))
    enc_ok = encode_tl_response(r_ok)
    name_ok, fields_ok = decode_tl_object(enc_ok)
    assert name_ok == "rpc_result"
    assert fields_ok["result"]["_constructor"] == "destroy_session_ok"

    r_none = asyncio.run(_dispatch_destroy(777))
    enc_none = encode_tl_response(r_none)
    _, fields_none = decode_tl_object(enc_none)
    assert fields_none["result"]["_constructor"] == "destroy_session_none"


def test_langpack_get_languages_returns_empty_vector() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    router = GatewayRouter(
        grpc_clients=AsyncMock(),
        sessions=SessionStore(),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="langpack.getLanguages",
                req_msg_id=600,
                auth_key_id=1,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "vector"
    # rpc_result(Object) contains boxed vector bytes; verify it's empty.
    assert struct.unpack_from("<i", encoded, 12)[0] == 0x1CB5C415
    assert struct.unpack_from("<i", encoded, 16)[0] == 0


# --- Per-user fanout flow tests (MessageBox model) ---


def _make_router_with_two_slots(
    actor_uid: int = 1, peer_uid: int = 2,
):
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry, PushSlot
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    actor_session = store.complete_handshake(
        session_id=11, auth_key=b"a" * 256,
        new_nonce=11, server_nonce=21,
    )
    peer_session = store.complete_handshake(
        session_id=12, auth_key=b"b" * 256,
        new_nonce=12, server_nonce=22,
    )
    store.bind_user(actor_session.auth_key_id, actor_uid)
    store.bind_user(peer_session.auth_key_id, peer_uid)

    registry = PushRegistry()
    actor_slot = PushSlot(
        user_id=actor_uid,
        auth_key_id=actor_session.auth_key_id,
        session_id=11,
    )
    peer_slot = PushSlot(
        user_id=peer_uid,
        auth_key_id=peer_session.auth_key_id,
        session_id=12,
    )
    registry.register(actor_slot)
    registry.register(peer_slot)

    grpc_clients = AsyncMock()
    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=store,
    )
    return router, grpc_clients, actor_session, peer_session, actor_slot, peer_slot


def test_send_message_no_direct_fanout_after_t16() -> None:
    """Gateway no longer fans out updates directly (t16).

    Push notifications now flow via ``UpdatesService.Subscribe`` stream →
    ``gateway/push/subscriber.py``.  Both sender and peer queues remain
    empty after a ``messages.sendMessage`` dispatch.
    """
    from ntgram.gateway.grpc_clients.dtos import SendMessageResult
    from ntgram.gateway.route_outcome import MessageParticipant

    (router, grpc_clients, actor_session, peer_session,
     actor_slot, peer_slot) = _make_router_with_two_slots()

    grpc_clients.chat.send_message = AsyncMock(
        return_value=SendMessageResult(
            actor_user_message_box_id=42,
            pts=7,
            date_unix=1700000000,
            participants=(
                MessageParticipant(
                    user_id=1, user_message_box_id=42, pts=7,
                    dialog_id=2001, peer_id=2, is_group=False,
                ),
                MessageParticipant(
                    user_id=2, user_message_box_id=11, pts=3,
                    dialog_id=2001, peer_id=1, is_group=False,
                ),
            ),
        ),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.sendMessage",
                req_msg_id=900,
                auth_key_id=actor_session.auth_key_id,
                session_id=11,
                payload={
                    "actor_user_id": 1,
                    "peer": {"constructor": "inputPeerUser", "user_id": 2},
                    "message": "hi",
                    "random_id": 12345,
                },
            ),
        )

    asyncio.run(_dispatch())

    # Neither actor nor peer should have anything in their queues.
    # Push is now driven by UpdatesService.Subscribe stream (t16).
    assert actor_slot.queue.empty()
    assert peer_slot.queue.empty()


def test_send_message_response_contains_users() -> None:
    """``messages.sendMessage`` TL response must embed users vector.

    The MessageService now embeds ``users`` and ``chats`` directly inside
    ``SendMessageResponse``.  The
    gateway is a pure proto→TL relay — it must not call
    ``account.get_profiles`` here.
    """
    from ntgram.gen import common_pb2
    from ntgram.gateway.grpc_clients.dtos import (
        MinimalProfileDto,
        SendMessageResult,
    )

    (router, grpc_clients, actor_session, _,
     actor_slot, _peer_slot) = _make_router_with_two_slots()

    envelope = common_pb2.UpdateEnvelope(
        updates=[
            common_pb2.UpdateItem(
                message_id=common_pb2.UpdateMessageId(message_id=1, random_id=777),
            ),
            common_pb2.UpdateItem(
                new_message=common_pb2.UpdateNewMessage(
                    message_id=1,
                    from_user_id=1,
                    text="hello",
                    date=1700000000,
                    peer_user_id=2,
                    out=True,
                    pts=5,
                    pts_count=1,
                ),
            ),
        ],
        date=1700000000,
        seq=0,
    )

    grpc_clients.chat.send_message = AsyncMock(
        return_value=SendMessageResult(
            actor_user_message_box_id=1,
            pts=5,
            date_unix=1700000000,
            participants=(),
            updates=envelope,
            users=(
                MinimalProfileDto(user_id=1, first_name="Alice", last_name="", username="alice"),
                MinimalProfileDto(user_id=2, first_name="Bob", last_name="", username="bob"),
            ),
        ),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.sendMessage",
                req_msg_id=901,
                auth_key_id=actor_session.auth_key_id,
                session_id=11,
                payload={
                    "actor_user_id": 1,
                    "peer": {"constructor": "inputPeerUser", "user_id": 2},
                    "message": "hello",
                    "random_id": 777,
                },
            ),
        )

    resp = asyncio.run(_dispatch())
    result = resp.result
    inner = result.get("result", result)
    assert inner.get("constructor") == "updates", f"expected 'updates', got {inner.get('constructor')}"
    users = inner.get("users", [])
    assert len(users) == 2, f"expected 2 users in response, got {len(users)}"
    user_ids = {u["id"] for u in users}
    assert user_ids == {1, 2}, f"expected user_ids {{1, 2}}, got {user_ids}"


def test_read_history_no_direct_fanout_after_t16() -> None:
    """Gateway no longer fans out read receipts directly (t16).

    Push notifications now flow via ``UpdatesService.Subscribe`` stream →
    ``gateway/push/subscriber.py``.  Both queues remain empty after dispatch.
    """
    from ntgram.gateway.grpc_clients.dtos import ReadHistoryResult
    from ntgram.gateway.route_outcome import ReadOutboxReceipt

    (router, grpc_clients, actor_session, peer_session,
     actor_slot, peer_slot) = _make_router_with_two_slots()

    grpc_clients.chat.read_history = AsyncMock(
        return_value=ReadHistoryResult(
            pts=8,
            pts_count=1,
            receipts=(
                ReadOutboxReceipt(
                    sender_user_id=1, sender_dialog_id=2001,
                    max_outbox_id=42, pts=9,
                ),
            ),
        ),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.readHistory",
                req_msg_id=901,
                auth_key_id=peer_session.auth_key_id,
                session_id=12,
                payload={
                    "actor_user_id": 2,
                    "peer": {"constructor": "inputPeerUser", "user_id": 1},
                    "max_id": 0,
                },
            ),
        )

    asyncio.run(_dispatch())

    # Push is now driven by UpdatesService.Subscribe stream (t16).
    assert peer_slot.queue.empty()
    assert actor_slot.queue.empty()


def test_edit_message_returns_updates_with_edit_message_inside() -> None:
    """``messages.editMessage`` returns TL ``updates`` carrying the
    ``updateEditMessage`` envelope produced by the service."""
    import json

    from ntgram.gen import common_pb2
    from ntgram.gateway.grpc_clients.dtos import EditMessageResult

    (router, grpc_clients, actor_session, _peer_session,
     actor_slot, peer_slot) = _make_router_with_two_slots()

    inner_update = {
        "constructor": "updateEditMessage",
        "message": {
            "constructor": "message",
            "id": 42,
            "from_id": {"constructor": "peerUser", "user_id": 1},
            "peer_id": {"constructor": "peerUser", "user_id": 2},
            "date": 1700000000,
            "message": "edited",
            "out": True,
            "edit_date": 1700000777,
        },
        "pts": 9,
        "pts_count": 1,
    }
    envelope = common_pb2.UpdateEnvelope(
        updates=[
            common_pb2.UpdateItem(
                raw_update_json=json.dumps(inner_update),
                update_type="updateEditMessage",
                pts=9,
            ),
        ],
        date=1700000777,
        seq=0,
    )
    grpc_clients.chat.edit_message = AsyncMock(
        return_value=EditMessageResult(
            actor_user_message_box_id=42,
            dialog_message_id=5001,
            edit_date=1700000777,
            updates=envelope,
        ),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.editMessage",
                req_msg_id=903,
                auth_key_id=actor_session.auth_key_id,
                session_id=11,
                payload={
                    "actor_user_id": 1,
                    "peer": {"constructor": "inputPeerUser", "user_id": 2},
                    "id": 42,
                    "message": "edited",
                },
            ),
        )

    resp = asyncio.run(_dispatch())
    inner = resp.result.get("result", resp.result)
    assert inner["constructor"] == "updates"
    assert len(inner["updates"]) == 1
    assert inner["updates"][0]["constructor"] == "updateEditMessage"
    assert inner["updates"][0]["message"]["message"] == "edited"
    # Forwarded args.
    request = grpc_clients.chat.edit_message.await_args.kwargs
    assert request["user_message_box_id"] == 42
    assert request["new_text"] == "edited"
    assert request["actor_user_id"] == 1
    # No direct router-side fanout.
    assert actor_slot.queue.empty()
    assert peer_slot.queue.empty()


def test_delete_messages_forwards_ids_and_returns_affected_messages() -> None:
    """``messages.deleteMessages`` forwards (id, revoke) and returns
    ``messages.affectedMessages { pts, pts_count }`` from the service result.

    Direct fanout no longer happens via the router: per-recipient updates
    flow through the ``UpdatesService.Subscribe`` stream after t16.
    """
    from ntgram.gateway.grpc_clients.dtos import DeleteMessagesResult

    (router, grpc_clients, actor_session, peer_session,
     actor_slot, peer_slot) = _make_router_with_two_slots()

    grpc_clients.chat.delete_messages = AsyncMock(
        return_value=DeleteMessagesResult(
            pts=5, pts_count=2, deleted_ids=(1, 2),
        ),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.deleteMessages",
                req_msg_id=902,
                auth_key_id=actor_session.auth_key_id,
                session_id=11,
                payload={
                    "actor_user_id": 1,
                    "id": [1, 2, 3],
                    "revoke": True,
                },
            ),
        )

    response = asyncio.run(_dispatch())

    # The TL response carries ``messages.affectedMessages`` with the
    # service-supplied pts / pts_count.
    payload = response.result
    inner = payload.get("result", payload)
    assert inner["constructor"] == "messages.affectedMessages"
    assert int(inner["pts"]) == 5
    assert int(inner["pts_count"]) == 2

    # Verify forwarded args.
    request = grpc_clients.chat.delete_messages.await_args.kwargs
    assert request["user_message_box_ids"] == [1, 2, 3]
    assert request["revoke"] is True
    assert request["actor_user_id"] == 1

    # No direct router-side fanout (push goes through Subscribe stream).
    assert actor_slot.queue.empty()
    assert peer_slot.queue.empty()


def test_gateway_server_rpc_drop_answer_returns_dropped_metadata() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.server import GatewayServer

    from ntgram.gateway.mtproto.outbox_service import OutboxService

    store = SessionStore()
    outbox = OutboxService(store)
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"r" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    outbox.register_outgoing_msg(
        session.auth_key_id,
        7001,
        req_msg_id=6001,
        seq_no=3,
        bytes_count=256,
    )
    server = object.__new__(GatewayServer)
    server._sessions = store
    server._outbox = outbox

    response = server._handle_rpc_drop_answer(
        TlRequest(
            constructor_id=0,
            constructor="rpc_drop_answer",
            req_msg_id=8001,
            auth_key_id=session.auth_key_id,
            session_id=1,
            payload={"req_msg_id": 6001},
        ),
    )

    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["req_msg_id"] == 8001
    assert fields["result"] == {
        "_constructor": "rpc_answer_dropped",
        "msg_id": 7001,
        "seq_no": 3,
        "bytes": 256,
    }
    assert 7001 not in session.pending_outgoing_msg_ids


def test_gateway_server_rpc_drop_answer_unknown_and_running() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.outbox_service import OutboxService
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.server import GatewayServer

    store = SessionStore()
    outbox = OutboxService(store)
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"s" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    server = object.__new__(GatewayServer)
    server._sessions = store
    server._outbox = outbox

    unknown = server._handle_rpc_drop_answer(
        TlRequest(
            constructor_id=0,
            constructor="rpc_drop_answer",
            req_msg_id=9001,
            auth_key_id=session.auth_key_id,
            session_id=1,
            payload={"req_msg_id": 123},
        ),
    )
    _, unknown_fields = decode_tl_object(encode_tl_response(unknown))
    assert unknown_fields["result"]["_constructor"] == "rpc_answer_unknown"

    outbox.register_running_rpc(session.auth_key_id, 9000)
    running = server._handle_rpc_drop_answer(
        TlRequest(
            constructor_id=0,
            constructor="rpc_drop_answer",
            req_msg_id=9002,
            auth_key_id=session.auth_key_id,
            session_id=1,
            payload={"req_msg_id": 9000},
        ),
    )
    _, running_fields = decode_tl_object(encode_tl_response(running))
    assert running_fields["result"]["_constructor"] == "rpc_answer_dropped_running"
    assert outbox.finish_running_rpc(session.auth_key_id, 9000) is True


# ---------------------------------------------------------------------------
# messages.getPeerDialogs
# ---------------------------------------------------------------------------

def _peer_dialogs_clients_with_empty_response():
    """AsyncMock GrpcClients pre-stubbed for the peerDialogs orchestration."""
    from ntgram.gateway.grpc_clients.dtos import (
        ListDialogsResult,
        ProfileDto,
        UpdatesState,
    )

    grpc_clients = AsyncMock()
    grpc_clients.chat.list_dialogs = AsyncMock(
        return_value=ListDialogsResult(dialogs=()),
    )
    grpc_clients.updates.get_state = AsyncMock(
        return_value=UpdatesState(pts=5, qts=0, seq=0, date=1234),
    )
    grpc_clients.profile.try_get_profile = AsyncMock(
        return_value=ProfileDto(
            user_id=0, first_name="", last_name="", bio="", username="",
        ),
    )
    return grpc_clients


def test_messages_get_peer_dialogs_returns_peer_dialogs() -> None:
    """getPeerDialogs orchestrates chat.list_dialogs + updates.get_state + per-user profile."""
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, user_id=42)

    grpc_clients = _peer_dialogs_clients_with_empty_response()

    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=store,
    )

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getPeerDialogs",
                req_msg_id=200,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={
                    "peers": [
                        {
                            "constructor": "inputDialogPeer",
                            "peer": {"constructor": "inputPeerUser", "user_id": 7},
                        },
                    ],
                },
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    assert fields["result"]["_constructor"] == "messages.peerDialogs"
    state = fields["result"]["state"]
    assert state["pts"] == 5
    assert state["date"] == 1234

    grpc_clients.chat.list_dialogs.assert_awaited_once()
    assert (
        grpc_clients.chat.list_dialogs.call_args.kwargs["actor_user_id"] == 42
    )


def test_messages_get_peer_dialogs_skips_folder_peers() -> None:
    """inputDialogPeerFolder entries must be silently ignored (no targets matched)."""
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"m" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, user_id=99)

    grpc_clients = _peer_dialogs_clients_with_empty_response()

    router = GatewayRouter(
        grpc_clients=grpc_clients,
        sessions=store,
    )

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getPeerDialogs",
                req_msg_id=201,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"peers": [{"constructor": "inputDialogPeerFolder", "folder_id": 0}]},
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    assert fields["result"]["_constructor"] == "messages.peerDialogs"
    assert fields["result"]["dialogs"] == []


# ---------------------------------------------------------------------------
# User status in messages.getDialogs
# ---------------------------------------------------------------------------


def test_messages_get_dialogs_user_status_is_empty_by_default() -> None:
    """``messages.getDialogs`` user TL always carries ``userStatusEmpty``.

    Presence tracking has been removed; all embedded user TL objects carry
    ``userStatusEmpty`` inline regardless of any external state.
    """
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.dtos import (
        DialogRow,
        ListDialogsResult,
        MinimalProfileDto,
    )
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"z" * 256, new_nonce=9, server_nonce=8,
    )
    store.bind_user(session.auth_key_id, user_id=1)

    peer_user_id = 7

    grpc_clients = AsyncMock()
    grpc_clients.chat.list_dialogs = AsyncMock(
        return_value=ListDialogsResult(
            dialogs=(
                DialogRow(
                    dialog_id=100,
                    peer_id=peer_user_id,
                    is_group=False,
                    read_inbox_max_id=0,
                    read_outbox_max_id=0,
                    unread_count=0,
                    top_message_id=0,
                    top_message_date=0,
                    top_message_text="",
                    top_from_user_id=0,
                    top_message_out=False,
                ),
            ),
            users=(
                MinimalProfileDto(
                    user_id=peer_user_id,
                    first_name="Bob",
                    last_name="",
                    username="",
                ),
            ),
        ),
    )

    router = GatewayRouter(grpc_clients=grpc_clients, sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getDialogs",
                req_msg_id=400,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"limit": 10, "offset_date": 0, "offset_id": 0,
                         "offset_peer": {"constructor": "inputPeerEmpty"}, "hash": 0},
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    assert fields["result"]["_constructor"] == "messages.dialogs"
    users = fields["result"]["users"]
    assert len(users) == 1
    assert users[0]["_constructor"] == "user"
    assert users[0]["id"] == peer_user_id
    assert users[0]["status"]["_constructor"] == "userStatusEmpty"


def test_messages_create_chat_returns_invited_users() -> None:
    """``messages.createChat`` → TL ``messages.invitedUsers`` with embedded updates."""
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.dtos import (
        CreateGroupChatResult,
        MinimalChatDto,
        MinimalProfileDto,
    )
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gen import common_pb2

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"c" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 1)

    actor_update_json = json.dumps({
        "constructor": "updateNewMessage",
        "message": {
            "constructor": "messageService",
            "id": 1,
            "from_id": {"constructor": "peerUser", "user_id": 1},
            "peer_id": {"constructor": "peerChat", "chat_id": 9001},
            "date": 1700000000,
            "out": True,
            "action": {
                "constructor": "messageActionChatCreate",
                "title": "Squad",
                "users": [1, 2],
            },
        },
        "pts": 1,
        "pts_count": 1,
    })
    envelope = common_pb2.UpdateEnvelope(
        updates=[
            common_pb2.UpdateItem(
                raw_update_json=actor_update_json,
                update_type="updateNewMessage",
                pts=1,
            ),
        ],
        date=1700000000, seq=0,
    )

    grpc_clients = AsyncMock()
    grpc_clients.chat.create_group_chat = AsyncMock(
        return_value=CreateGroupChatResult(
            chat_id=9001,
            dialog_id=2001,
            date_unix=1700000000,
            service_message_id=1,
            updates=envelope,
            users=(
                MinimalProfileDto(user_id=1, first_name="A", last_name="", username="a"),
                MinimalProfileDto(user_id=2, first_name="B", last_name="", username="b"),
            ),
            chats=(
                MinimalChatDto(
                    chat_id=9001, title="Squad", participants_count=2,
                    version=2, date_unix=1700000000, creator_user_id=1,
                ),
            ),
        ),
    )

    router = GatewayRouter(grpc_clients=grpc_clients, sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.createChat",
                req_msg_id=900,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"users": [{"constructor": "inputUser", "user_id": 2}],
                         "title": "Squad"},
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    result = fields["result"]
    assert result["_constructor"] == "messages.invitedUsers"
    assert result["missing_invitees"] == []
    upd = result["updates"]
    assert upd["_constructor"] == "updates"
    # The actor's updateNewMessage must round-trip through raw_update_json.
    assert any(u["_constructor"] == "updateNewMessage" for u in upd["updates"])
    chat_tl = upd["chats"]
    assert len(chat_tl) == 1
    assert chat_tl[0]["id"] == 9001
    assert chat_tl[0]["version"] == 2


def test_messages_get_chats_returns_messages_chats() -> None:
    """``messages.getChats`` → TL ``messages.chats`` (no users vector)."""
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.dtos import MinimalChatDto
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"g" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 1)

    grpc_clients = AsyncMock()
    grpc_clients.chat.get_chats_batch = AsyncMock(
        return_value=(
            MinimalChatDto(
                chat_id=10, title="Alpha", participants_count=3,
                version=1, date_unix=100, creator_user_id=1,
            ),
            MinimalChatDto(
                chat_id=20, title="Beta", participants_count=5,
                version=4, date_unix=200, creator_user_id=2,
            ),
        ),
    )

    router = GatewayRouter(grpc_clients=grpc_clients, sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getChats",
                req_msg_id=901,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"id": [10, 20]},
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    result = fields["result"]
    assert result["_constructor"] == "messages.chats"
    assert {c["id"] for c in result["chats"]} == {10, 20}
    by_id = {c["id"]: c for c in result["chats"]}
    # Actor=1 is the creator of chat 10 → ``creator`` flag set.
    assert by_id[10].get("creator") is True
    # Not creator of chat 20.
    assert not by_id[20].get("creator", False)


def test_messages_get_full_chat_returns_chat_full() -> None:
    """``messages.getFullChat`` → TL ``messages.chatFull`` with chatParticipants."""
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.dtos import (
        ChatParticipantDto,
        GetFullChatResult,
        MinimalProfileDto,
    )
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"f" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 1)

    grpc_clients = AsyncMock()
    grpc_clients.chat.get_full_chat = AsyncMock(
        return_value=GetFullChatResult(
            chat_id=11,
            title="Crew",
            creator_id=1,
            member_user_ids=(1, 2),
            participants=(
                ChatParticipantDto(user_id=1, inviter_user_id=0, date_unix=100, kind=0),
                ChatParticipantDto(user_id=2, inviter_user_id=1, date_unix=200, kind=1),
            ),
            users=(
                MinimalProfileDto(user_id=1, first_name="A", last_name="", username="a"),
                MinimalProfileDto(user_id=2, first_name="B", last_name="", username="b"),
            ),
            version=2,
            participants_count=2,
            date_unix=100,
            ok=True,
        ),
    )

    router = GatewayRouter(grpc_clients=grpc_clients, sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getFullChat",
                req_msg_id=902,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"chat_id": 11},
            ),
        ),
    )
    _, fields = decode_tl_object(encode_tl_response(response))
    result = fields["result"]
    assert result["_constructor"] == "messages.chatFull"
    full = result["full_chat"]
    assert full["_constructor"] == "chatFull"
    assert full["id"] == 11
    parts = full["participants"]
    assert parts["_constructor"] == "chatParticipants"
    assert parts["chat_id"] == 11
    by_uid = {p["user_id"]: p for p in parts["participants"]}
    assert by_uid[1]["_constructor"] == "chatParticipantCreator"
    assert by_uid[2]["_constructor"] == "chatParticipant"
    assert by_uid[2]["inviter_id"] == 1
    assert {u["id"] for u in result["users"]} == {1, 2}


def test_get_saved_dialogs_static_stub() -> None:
    """messages.getSavedDialogs → static stub: empty messages.savedDialogs."""
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 42)

    router = GatewayRouter(grpc_clients=AsyncMock(), sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getSavedDialogs",
                req_msg_id=600,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={"offset_date": 0, "offset_id": 0, "limit": 20},
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    result = fields["result"]
    assert result["_constructor"] == "messages.savedDialogs"
    assert result["dialogs"] == []
    assert result["messages"] == []


def test_get_saved_history_static_stub() -> None:
    """messages.getSavedHistory → static stub: empty messages.messages."""
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 42)

    router = GatewayRouter(grpc_clients=AsyncMock(), sessions=store)

    response = asyncio.run(
        router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="messages.getSavedHistory",
                req_msg_id=700,
                auth_key_id=session.auth_key_id,
                session_id=1,
                payload={
                    "peer": {"constructor": "inputPeerSelf"},
                    "offset_id": 0, "offset_date": 0,
                    "add_offset": 0, "limit": 20, "max_id": 0, "min_id": 0,
                    "hash": 0,
                },
            ),
        ),
    )

    _, fields = decode_tl_object(encode_tl_response(response))
    result = fields["result"]
    assert result["_constructor"] == "messages.messages"
    assert result["messages"] == []

