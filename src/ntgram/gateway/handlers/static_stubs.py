from __future__ import annotations

import time
from typing import Any

from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.handlers.registry import RpcHandler
from ntgram.gateway.mtproto.service_semantics import wrap_rpc_error, wrap_rpc_result
from ntgram.tl.models import TlRequest, TlResponse
from ntgram.tl.codec import serialize_value
from ntgram.tl.registry import default_schema_registry

_TERMS_OF_SERVICE_EMPTY_EXPIRES_SEC = 600
_SCHEMA = default_schema_registry()


def _empty_vector_result(request: TlRequest, vector_type: str) -> TlResponse:
    """Encode an empty boxed vector of the given TL type."""
    buf = bytearray()
    serialize_value(buf, vector_type, [], _SCHEMA)
    return wrap_rpc_result(request.req_msg_id, bytes(buf))



def _default_auto_download_settings() -> dict[str, Any]:
    return {
        "constructor": "autoDownloadSettings",
        "disabled": True,
        "photo_size_max": 0,
        "video_size_max": 0,
        "file_size_max": 0,
        "video_upload_maxbitrate": 0,
        "small_queue_active_operations_max": 0,
        "large_queue_active_operations_max": 0,
    }


# account.*


async def handle_account_register_device(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(request.req_msg_id, {"constructor": "boolTrue"})



async def handle_account_get_reactions_notify_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "reactionsNotifySettings",
            "messages_notify_from": {"constructor": "reactionNotificationsFromAll"},
            "stories_notify_from": {"constructor": "reactionNotificationsFromAll"},
            "sound": {"constructor": "notificationSoundDefault"},
            "show_previews": True,
        },
    )


async def handle_account_get_contact_sign_up_notification(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(request.req_msg_id, {"constructor": "boolFalse"})


async def handle_account_get_auto_download_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    settings = _default_auto_download_settings()
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "account.autoDownloadSettings",
            "low": settings,
            "medium": dict(settings),
            "high": dict(settings),
        },
    )


async def handle_account_get_default_profile_photo_emojis(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "emojiList", "hash": 0, "document_id": []},
    )


async def handle_account_get_global_privacy_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "globalPrivacySettings"},
    )


async def handle_account_get_content_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "account.contentSettings",
            "flags": 2,
            "sensitive_can_change": True,
        },
    )


async def handle_account_get_privacy(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Validates key and returns a default rule per privacy category."""
    key = request.payload.get("key")
    if not isinstance(key, dict):
        return wrap_rpc_error(request.req_msg_id, 400, "PRIVACY_KEY_INVALID")
    ctor = key.get("constructor")
    if not isinstance(ctor, str) or not ctor.startswith("inputPrivacyKey"):
        return wrap_rpc_error(request.req_msg_id, 400, "PRIVACY_KEY_INVALID")
    if ctor == "inputPrivacyKeyPhoneNumber":
        rule: dict = {"constructor": "privacyValueDisallowAll"}
    elif ctor == "inputPrivacyKeyBirthday":
        rule = {"constructor": "privacyValueAllowContacts"}
    else:
        rule = {"constructor": "privacyValueAllowAll"}
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "account.privacyRules",
            "rules": [rule],
            "chats": [],
            "users": [],
        },
    )


async def handle_account_get_saved_ringtones(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "account.savedRingtonesNotModified"},
    )


async def handle_account_get_password(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "account.password",
            "new_algo": {"constructor": "passwordKdfAlgoUnknown"},
            "new_secure_algo": {"constructor": "securePasswordKdfAlgoUnknown"},
            "secure_random": b"",
        },
    )


async def handle_account_get_themes(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "account.themesNotModified"},
    )


async def handle_account_get_account_ttl(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "accountDaysTTL", "days": 180},
    )


# contacts.*


async def handle_contacts_get_contacts(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "contacts.contacts",
            "contacts": [],
            "saved_count": 0,
            "users": [],
        },
    )


async def handle_contacts_get_top_peers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "contacts.topPeers",
            "categories": [],
            "chats": [],
            "users": [],
        },
    )


async def handle_contacts_get_statuses(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return _empty_vector_result(request, "Vector<ContactStatus>")


async def handle_users_get_requirements_to_contact(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: peer requirements to contact — not implemented; return empty list."""
    return _empty_vector_result(request, "Vector<RequirementToContact>")


async def handle_contacts_get_birthdays(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "contacts.contactBirthdays",
            "contacts": [],
            "users": [],
        },
    )


async def handle_contacts_get_sponsored_peers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "contacts.sponsoredPeersEmpty"},
    )


# channels.* / bots.* / photos.*


async def handle_channels_get_admined_public_channels(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "messages.chats", "chats": []},
    )


async def handle_channels_get_channel_recommendations(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: channel recommendations — not implemented; return empty chats list."""
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "messages.chats", "chats": []},
    )


async def handle_bots_get_bot_recommendations(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "users.users", "users": []},
    )


async def handle_photos_get_user_photos(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "photos.photos", "photos": [], "users": []},
    )


# messages.* (stubs)


async def handle_messages_get_attach_menu_bots(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "attachMenuBotsNotModified"},
    )


async def handle_messages_get_reactions(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.reactions", "hash": 0, "reactions": []},
    )


async def handle_messages_get_available_effects(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.availableEffects",
            "hash": 0,
            "effects": [],
            "documents": [],
        },
    )


async def handle_messages_get_available_reactions(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.availableReactions",
            "hash": 0,
            "reactions": [],
        },
    )


async def handle_messages_get_search_results_positions(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.searchResultsPositions",
            "count": 0,
            "positions": [],
        },
    )


async def handle_messages_search(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.messages",
            "messages": [],
            "chats": [],
            "users": [],
        },
    )



async def handle_messages_get_web_page(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.webPage",
            "webpage": {
                "constructor": "webPageEmpty",
                "flags": 0,
                "id": 0,
            },
            "chats": [],
            "users": [],
        },
    )


async def handle_messages_get_dialog_filters(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.dialogFilters", "filters": []},
    )


async def handle_messages_get_suggested_dialog_filters(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return _empty_vector_result(request, "Vector<DialogFilterSuggested>")


async def handle_messages_get_search_counters(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return _empty_vector_result(request, "Vector<messages.SearchCounter>")



async def handle_messages_get_stickers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.stickers", "hash": 0, "stickers": []},
    )


async def handle_messages_get_emoji_stickers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "messages.allStickersNotModified"},
    )


async def handle_messages_get_emoji_keywords(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    lang = request.payload.get("lang_code")
    lang_code = lang if isinstance(lang, str) else ""
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "emojiKeywordsDifference",
            "lang_code": lang_code,
            "from_version": 0,
            "version": 0,
            "keywords": [],
        },
    )


async def handle_messages_get_emoji_keywords_difference(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    lang = request.payload.get("lang_code")
    lang_code = lang if isinstance(lang, str) else ""
    raw_fv = request.payload.get("from_version", 0)
    try:
        from_version = int(raw_fv)
    except (TypeError, ValueError):
        from_version = 0
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "emojiKeywordsDifference",
            "lang_code": lang_code,
            "from_version": from_version,
            "version": from_version,
            "keywords": [],
        },
    )



async def handle_messages_get_messages_reactions(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "updates",
            "updates": [],
            "users": [],
            "chats": [],
            "date": int(time.time()),
            "seq": 0,
        },
    )



async def handle_messages_get_saved_dialogs(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.savedDialogs",
            "dialogs": [], "messages": [], "chats": [], "users": [],
        },
    )


async def handle_messages_get_saved_history(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.messages", "messages": [], "chats": [], "users": []},
    )


async def handle_messages_get_saved_reaction_tags(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.savedReactionTags", "tags": [], "hash": 0},
    )


async def handle_messages_get_quick_replies(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.quickReplies",
            "quick_replies": [],
            "messages": [],
            "chats": [],
            "users": [],
        },
    )


async def handle_messages_get_sticker_set(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.stickerSet",
            "set": {
                "constructor": "stickerSet",
                "id": 0,
                "access_hash": 0,
                "title": "",
                "short_name": "",
                "count": 0,
                "hash": 0,
            },
            "packs": [],
            "keywords": [],
            "documents": [],
        },
    )


async def handle_messages_get_featured_stickers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.featuredStickersNotModified", "count": 0},
    )


async def handle_messages_get_message_read_participants(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: read receipts per participant — not implemented; return empty list."""
    return _empty_vector_result(request, "Vector<ReadParticipantDate>")


async def handle_messages_get_outbox_read_date(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: outbox read timestamp — not stored; return date=0."""
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "outboxReadDate", "date": 0},
    )


async def handle_messages_get_saved_gifs(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: saved GIFs — not implemented; return not-modified."""
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "messages.savedGifsNotModified"},
    )


async def handle_messages_get_default_history_ttl(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: default history TTL — not implemented; return period=0 (no TTL)."""
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "defaultHistoryTTL", "period": 0},
    )


async def handle_messages_get_faved_stickers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "messages.favedStickersNotModified"},
    )


async def handle_messages_get_archived_stickers(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.archivedStickers",
            "count": 0,
            "sets": [],
        },
    )


async def handle_messages_get_peer_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.peerSettings",
            "settings": {"constructor": "peerSettings", "flags": 0},
            "chats": [],
            "users": [],
        },
    )


def _empty_updates_state() -> dict[str, Any]:
    return {
        "constructor": "updates.state",
        "pts": 0,
        "qts": 0,
        "date": int(time.time()),
        "seq": 0,
        "unread_count": 0,
    }


async def handle_account_get_notify_settings(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "peerNotifySettings"},
    )


async def handle_messages_get_pinned_dialogs(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.peerDialogs",
            "dialogs": [],
            "messages": [],
            "chats": [],
            "users": [],
            "state": _empty_updates_state(),
        },
    )


async def handle_messages_set_typing(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(request.req_msg_id, {"constructor": "boolTrue"})


async def handle_messages_get_all_drafts(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "updates",
            "updates": [],
            "users": [],
            "chats": [],
            "date": int(time.time()),
            "seq": 0,
        },
    )


async def handle_messages_get_message_edit_data(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: always report non-caption editable message.
    """
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.messageEditData"},
    )


async def handle_messages_read_reactions(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: reactions are not implemented; report no PTS change."""
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "messages.affectedHistory", "pts": 0, "pts_count": 0, "offset": 0},
    )


# help.*


async def handle_help_get_terms_of_service_update(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "help.termsOfServiceUpdateEmpty",
            "expires": int(time.time()) + _TERMS_OF_SERVICE_EMPTY_EXPIRES_SEC,
        },
    )


async def handle_help_get_invite_text(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "help.inviteText", "message": ""},
    )


async def handle_help_get_premium_promo(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "help.premiumPromo",
            "status_text": "",
            "status_entities": [],
            "video_sections": [],
            "videos": [],
            "period_options": [],
            "users": [],
        },
    )


async def handle_help_get_peer_colors(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "help.peerColors", "hash": 0, "colors": []},
    )


async def handle_help_get_peer_profile_colors(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id, {"constructor": "help.peerColorsNotModified"},
    )


async def handle_help_get_app_config(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "help.appConfig",
            "hash": 0,
            "config": {"constructor": "jsonObject", "value": []},
        },
    )


async def handle_help_get_nearest_dc(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "nearestDc",
            "country": "",
            "this_dc": 1,
            "nearest_dc": 1,
        },
    )


async def handle_help_get_countries_list(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "help.countriesList",
            "countries": [],
            "hash": 0,
        },
    )


async def handle_help_get_promo_data(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "help.promoDataEmpty",
            "expires": int(time.time()) + 3600,
        },
    )


# stories.*


async def handle_stories_get_all_stories(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "stories.allStories",
            "count": 0,
            "state": "",
            "peer_stories": [],
            "chats": [],
            "users": [],
            "stealth_mode": {"constructor": "storiesStealthMode"},
        },
    )


async def handle_stories_get_pinned_stories(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "stories.stories",
            "count": 0,
            "stories": [],
            "chats": [],
            "users": [],
        },
    )


async def handle_stories_get_albums(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "stories.albums", "hash": 0, "albums": []},
    )


async def handle_stories_get_all_read_peer_stories(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "updates",
            "updates": [],
            "users": [],
            "chats": [],
            "date": int(time.time()),
            "seq": 0,
        },
    )


async def handle_stories_can_send_story(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Stub: stories are not implemented; sending is always disallowed."""
    return wrap_rpc_result(request.req_msg_id, {"constructor": "boolFalse"})


# payments.*


async def handle_payments_get_star_gifts(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "payments.starGifts",
            "hash": 0,
            "gifts": [],
            "chats": [],
            "users": [],
        },
    )


async def handle_payments_get_saved_star_gifts(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "payments.savedStarGifts",
            "count": 0,
            "gifts": [],
            "chats": [],
            "users": [],
        },
    )


async def handle_payments_get_star_gift_collections(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": "payments.starGiftCollections", "collections": []},
    )


async def handle_payments_get_stars_status(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "payments.starsStatus",
            "flags": 0,
            "balance": {
                "constructor": "starsAmount",
                "amount": 0,
                "nanos": 0,
            },
            "chats": [],
            "users": [],
        },
    )


# langpack.*


async def handle_langpack_get_languages(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return _empty_vector_result(request, "Vector<LangPackLanguage>")


# Constructor -> handler mapping

STATIC_STUBS: dict[str, RpcHandler] = {
    # account.*
    "account.registerDevice": handle_account_register_device,
    "account.getReactionsNotifySettings": handle_account_get_reactions_notify_settings,
    "account.getContactSignUpNotification": handle_account_get_contact_sign_up_notification,
    "account.getAutoDownloadSettings": handle_account_get_auto_download_settings,
    "account.getDefaultProfilePhotoEmojis": handle_account_get_default_profile_photo_emojis,
    "account.getGlobalPrivacySettings": handle_account_get_global_privacy_settings,
    "account.getContentSettings": handle_account_get_content_settings,
    "account.getPrivacy": handle_account_get_privacy,
    "account.getSavedRingtones": handle_account_get_saved_ringtones,
    "account.getPassword": handle_account_get_password,
    "account.getThemes": handle_account_get_themes,
    "account.getAccountTTL": handle_account_get_account_ttl,
    # contacts.*
    "contacts.getContacts": handle_contacts_get_contacts,
    "contacts.getTopPeers": handle_contacts_get_top_peers,
    "contacts.getStatuses": handle_contacts_get_statuses,
    "users.getRequirementsToContact": handle_users_get_requirements_to_contact,
    "contacts.getBirthdays": handle_contacts_get_birthdays,
    "contacts.getSponsoredPeers": handle_contacts_get_sponsored_peers,
    # channels / bots / photos
    "channels.getAdminedPublicChannels": handle_channels_get_admined_public_channels,
    "channels.getChannelRecommendations": handle_channels_get_channel_recommendations,
    "bots.getBotRecommendations": handle_bots_get_bot_recommendations,
    "photos.getUserPhotos": handle_photos_get_user_photos,
    # messages.* stubs
    "messages.getAttachMenuBots": handle_messages_get_attach_menu_bots,
    "messages.getTopReactions": handle_messages_get_reactions,
    "messages.getRecentReactions": handle_messages_get_reactions,
    "messages.getDefaultTagReactions": handle_messages_get_reactions,
    "messages.getAvailableEffects": handle_messages_get_available_effects,
    "messages.getAvailableReactions": handle_messages_get_available_reactions,
    "messages.getDialogFilters": handle_messages_get_dialog_filters,
    "messages.getSuggestedDialogFilters": handle_messages_get_suggested_dialog_filters,
    "messages.getSearchCounters": handle_messages_get_search_counters,
    "messages.getSearchResultsPositions": handle_messages_get_search_results_positions,
    "messages.search": handle_messages_search,
    "messages.searchGlobal": handle_messages_search,
    "messages.getScheduledHistory": handle_messages_search,
    "messages.getWebPage": handle_messages_get_web_page,
    "messages.getStickers": handle_messages_get_stickers,
    "messages.getEmojiStickers": handle_messages_get_emoji_stickers,
    "messages.getEmojiKeywords": handle_messages_get_emoji_keywords,
    "messages.getEmojiKeywordsDifference": handle_messages_get_emoji_keywords_difference,
    "messages.getMessagesReactions": handle_messages_get_messages_reactions,
    "messages.getSavedDialogs": handle_messages_get_saved_dialogs,
    "messages.getSavedHistory": handle_messages_get_saved_history,
    "messages.getSavedReactionTags": handle_messages_get_saved_reaction_tags,
    "messages.getQuickReplies": handle_messages_get_quick_replies,
    "messages.getStickerSet": handle_messages_get_sticker_set,
    "messages.getSavedGifs": handle_messages_get_saved_gifs,
    "messages.getDefaultHistoryTTL": handle_messages_get_default_history_ttl,
    "messages.getFavedStickers": handle_messages_get_faved_stickers,
    "messages.getFeaturedStickers": handle_messages_get_featured_stickers,
    "messages.getFeaturedEmojiStickers": handle_messages_get_featured_stickers,
    "messages.getArchivedStickers": handle_messages_get_archived_stickers,
    "messages.getMessageReadParticipants": handle_messages_get_message_read_participants,
    "messages.getOutboxReadDate": handle_messages_get_outbox_read_date,
    "messages.getPeerSettings": handle_messages_get_peer_settings,
    "account.getNotifySettings": handle_account_get_notify_settings,
    "messages.getPinnedDialogs": handle_messages_get_pinned_dialogs,
    "messages.setTyping": handle_messages_set_typing,
    "messages.getAllDrafts": handle_messages_get_all_drafts,
    "messages.getMessageEditData": handle_messages_get_message_edit_data,
    "messages.readReactions": handle_messages_read_reactions,
    # help.* (static)
    "help.getTermsOfServiceUpdate": handle_help_get_terms_of_service_update,
    "help.getInviteText": handle_help_get_invite_text,
    "help.getPremiumPromo": handle_help_get_premium_promo,
    "help.getPeerColors": handle_help_get_peer_colors,
    "help.getPeerProfileColors": handle_help_get_peer_profile_colors,
    "help.getAppConfig": handle_help_get_app_config,
    "help.getNearestDc": handle_help_get_nearest_dc,
    "help.getCountriesList": handle_help_get_countries_list,
    "help.getPromoData": handle_help_get_promo_data,
    # stories.*
    "stories.getAllStories": handle_stories_get_all_stories,
    "stories.getPinnedStories": handle_stories_get_pinned_stories,
    "stories.getAlbums": handle_stories_get_albums,
    "stories.getAllReadPeerStories": handle_stories_get_all_read_peer_stories,
    "stories.canSendStory": handle_stories_can_send_story,
    # payments.*
    "payments.getStarGifts": handle_payments_get_star_gifts,
    "payments.getSavedStarGifts": handle_payments_get_saved_star_gifts,
    "payments.getStarGiftCollections": handle_payments_get_star_gift_collections,
    "payments.getStarsStatus": handle_payments_get_stars_status,
    # langpack.*
    "langpack.getLanguages": handle_langpack_get_languages,
}
