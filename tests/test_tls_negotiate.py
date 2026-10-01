"""Reading the key-exchange group a server chose from recorded handshake messages."""

from __future__ import annotations

import json

import pytest
from probe_helpers import FIXTURES

from takestock import tls_negotiate
from takestock.tls_negotiate import HS_CLIENT_HELLO, HS_SERVER_HELLO, Negotiation

CLIENT = "test client"


def recorded(label: str) -> tuple[list[tuple[str, int, bytes]], str, str]:
    data = json.loads((FIXTURES / "tls-handshakes.json").read_text())[label]
    msgs = [(d, t, bytes.fromhex(h)) for d, t, h in data["messages"]]
    return msgs, data["version"], data["cipher"]


def with_server_group(msgs, code: int):
    """The same handshake with the ServerHello's key-share group replaced by ``code``."""
    out = []
    for d, t, m in msgs:
        if d == "read" and t == HS_SERVER_HELLO:
            i = 4 + 2 + 32                           # header, version, random
            i += 1 + m[i]                            # session id
            i += 2 + 1 + 2                           # suite, compression, extensions length
            while i < len(m):
                kind = int.from_bytes(m[i:i + 2], "big")
                size = int.from_bytes(m[i + 2:i + 4], "big")
                if kind == 0x0033:                   # key_share: group comes first
                    m = m[:i + 4] + code.to_bytes(2, "big") + m[i + 6:]
                i += 4 + size
        out.append((d, t, m))
    return out


def test_tls13_offer_and_choice_are_read():
    msgs, version, cipher = recorded("tls13")
    n = tls_negotiate.read_negotiation(msgs, version, cipher, CLIENT)
    assert n.offer_groups[0] == "X25519MLKEM768"
    assert n.pq_offered
    assert n.group == "x25519"                   # the stub server knows no hybrid group
    assert "TLSv1.3" in n.offer_versions


def test_a_hybrid_choice_is_named():
    msgs, version, cipher = recorded("tls13")
    n = tls_negotiate.read_negotiation(with_server_group(msgs, 0x11EC), version, cipher, CLIENT)
    assert n.group == "X25519MLKEM768"
    assert tls_negotiate.kex_token(n.group) == "x25519mlkem768"


def test_tls12_ecdhe_group_comes_from_the_server_key_exchange():
    msgs, version, cipher = recorded("tls12_ecdhe")
    assert tls_negotiate.read_negotiation(msgs, version, cipher, CLIENT).group == "x25519"


def test_tls12_dhe_group_is_the_prime_size():
    msgs, version, cipher = recorded("tls12_dhe")
    assert tls_negotiate.read_negotiation(msgs, version, cipher, CLIENT).group == "dh_2048"


def test_a_tls12_session_with_no_key_exchange_message_is_rsa_transport():
    msgs, _version, _cipher = recorded("tls12_ecdhe")
    no_skx = [m for m in msgs if m[1] != tls_negotiate.HS_SERVER_KEY_EXCHANGE]
    n = tls_negotiate.read_negotiation(no_skx, "TLSv1.2", "AES128-GCM-SHA256", CLIENT)
    assert n.group == "rsa"


def test_a_hello_retry_request_is_not_taken_as_the_choice():
    msgs, version, cipher = recorded("tls13")
    hrr = []
    for d, t, m in msgs:
        if d == "read" and t == HS_SERVER_HELLO:
            m = m[:6] + tls_negotiate._HRR_RANDOM + m[38:]
        hrr.append((d, t, m))
    n = tls_negotiate.read_negotiation(hrr, version, cipher, CLIENT)
    assert n.hello_retry
    assert n.group == ""
    assert n.extra()["negotiated_group"].startswith("not read")


def test_no_messages_gives_a_basis_not_a_group():
    n = tls_negotiate.read_negotiation([], "TLSv1.3", "TLS_AES_128_GCM_SHA256", CLIENT)
    assert n.group == ""
    assert "no handshake messages" in n.group_basis


def test_an_offer_without_a_pq_group_says_so():
    n = Negotiation(client=CLIENT, version="TLSv1.3", cipher="x", group="x25519", pq_offered=False)
    assert "negotiated_pq_limit" in n.extra()
    n.pq_offered = True
    assert "negotiated_pq_limit" not in n.extra()


def test_extra_values_are_all_strings():
    msgs, version, cipher = recorded("tls13")
    extra = tls_negotiate.read_negotiation(msgs, version, cipher, CLIENT).extra()
    assert all(isinstance(v, str) for v in extra.values())


def test_a_failed_handshake_records_the_error_and_no_choice():
    extra = Negotiation(client=CLIENT, error="no session with the default client: refused").extra()
    assert extra["negotiated_error"].endswith("refused")
    assert "negotiated_group" not in extra


def test_grease_values_are_dropped_from_the_offer():
    assert tls_negotiate._is_grease(0x0A0A)
    assert tls_negotiate._is_grease(0xFAFA)
    assert not tls_negotiate._is_grease(0x001D)


def test_a_truncated_message_is_refused():
    msgs, _version, _cipher = recorded("tls13")
    hello = next(m for d, t, m in msgs if t == HS_CLIENT_HELLO)
    with pytest.raises(ValueError):
        tls_negotiate.parse_client_hello(hello[:20])
    with pytest.raises(ValueError):
        tls_negotiate.parse_server_hello(hello)          # wrong message type


def test_unknown_group_codes_are_shown_in_hex():
    assert tls_negotiate.group_name(0x1234) == "0x1234"


def test_negotiate_never_raises_when_nothing_answers(monkeypatch):
    def refuse(*_a, **_k):
        raise OSError("connection refused")
    monkeypatch.setattr(tls_negotiate.socket, "create_connection", refuse)
    n = tls_negotiate.negotiate("192.0.2.10", 443, "web-01.example.test")
    assert n.error.endswith("connection refused")
    assert n.group == ""
