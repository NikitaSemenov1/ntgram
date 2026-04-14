from __future__ import annotations

from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.mtproto.updates_state import apply_update_counters, build_difference_response


def _make_session(store, session_id, new_nonce, server_nonce):
    import secrets
    auth_key = secrets.token_bytes(256)
    return store.complete_handshake(
        session_id=session_id,
        auth_key=auth_key,
        new_nonce=new_nonce,
        server_nonce=server_nonce,
    )


def test_apply_update_counters() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=1, new_nonce=111, server_nonce=222)
    state = apply_update_counters(session, pts_count=2, qts_count=1, seq_count=3)
    assert state.pts == 2
    assert state.qts == 1
    assert state.seq == 3


def test_build_difference_response() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=2, new_nonce=333, server_nonce=444)
    apply_update_counters(session, pts_count=1, qts_count=0, seq_count=1)
    response = build_difference_response(
        session,
        req_msg_id=7,
        updates=[{"kind": "message", "payload": {"id": 1}}, {"kind": "status", "payload": {"online": True}}],
    )
    assert response.result["constructor"] == "updates.differenceSlice"
    assert len(response.result["new_messages"]) == 1
    assert response.result["state"]["pts"] == 1
