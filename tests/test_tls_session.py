"""Reading a pinned-version handshake: offered, refused, or could not ask."""

from __future__ import annotations

from probe_helpers import fixture

from takestock import tls_session
from takestock.tls_session import COULD_NOT_ASK, OFFERED, REFUSED, TlsSession


def test_a_completed_handshake_reports_its_version_and_cipher():
    s = tls_session.read_session(fixture("openssl-tls1_2.txt"), "TLSv1.2")
    assert s == TlsSession(OFFERED, "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", True)


def test_tls13_is_read_the_same_way():
    s = tls_session.read_session(fixture("openssl-tls1_3.txt"), "TLSv1.3")
    assert (s.state, s.cipher) == (OFFERED, "AEAD-AES256-GCM-SHA384")


def test_a_version_the_server_declines_is_refused_even_though_the_session_block_echoes_it():
    out = fixture("openssl-tls1.txt")
    assert "Protocol  : TLSv1" in out          # the echo that must not count as an offer
    s = tls_session.read_session(out, "TLSv1.0")
    assert (s.state, s.reported_version, s.cipher, s.reached_host) == (
        REFUSED, "TLSv1.0", "", True)


def test_a_refused_connection_is_could_not_ask_not_a_refusal():
    s = tls_session.read_session(fixture("openssl-refused.txt"), "TLSv1.2")
    assert s.state == COULD_NOT_ASK
    assert not s.reached_host


def test_a_probe_that_could_not_run_is_could_not_ask():
    assert tls_session.read_session("__ERROR__ no such file").state == COULD_NOT_ASK


def test_a_null_cipher_without_a_connection_is_could_not_ask():
    s = tls_session.read_session("New, (NONE), Cipher is (NONE)\n")
    assert s.state == COULD_NOT_ASK


def test_a_null_cipher_after_a_connection_is_a_refusal():
    s = tls_session.read_session("CONNECTED(00000003)\nNew, (NONE), Cipher is (NONE)\n")
    assert s.state == REFUSED


def test_a_version_line_with_no_cipher_behind_it_is_not_a_measurement():
    echo_only = "CONNECTED(00000003)\nSSL-Session:\n    Protocol  : TLSv1.2\n"
    assert tls_session.read_session(echo_only, "TLSv1.2").state == COULD_NOT_ASK
    assert tls_session.read_session("CONNECTED(00000003)\n", "TLSv1.2").state == COULD_NOT_ASK


def test_a_session_at_a_different_version_refuses_the_one_pinned():
    out = fixture("openssl-tls1_3.txt")
    s = tls_session.read_session(out, "TLSv1.2")
    assert (s.state, s.reported_version) == (REFUSED, "TLSv1.3")


def test_the_cipher_reader_never_returns_a_null_marker():
    assert tls_session.negotiated_cipher("    Cipher    : 0000\n") == ""
    assert tls_session.negotiated_cipher("    Cipher    : (NONE)\n") == ""
    assert tls_session.negotiated_cipher("    Cipher    : AES128-SHA\n") == "AES128-SHA"


def test_describe_writes_could_not_ask_as_unknown():
    probed = {"TLSv1.0": TlsSession(REFUSED), "TLSv1.2": TlsSession(OFFERED, cipher="x"),
              "TLSv1.3": TlsSession(COULD_NOT_ASK)}
    assert tls_session.describe(probed) == "TLSv1.0=refused; TLSv1.2=offered; TLSv1.3=unknown"


def test_versions_in_state_is_sorted():
    probed = {"TLSv1.3": TlsSession(OFFERED), "TLSv1.2": TlsSession(OFFERED),
              "TLSv1.0": TlsSession(REFUSED)}
    assert tls_session.versions_in_state(probed, OFFERED) == ["TLSv1.2", "TLSv1.3"]
    assert tls_session.versions_in_state(probed, COULD_NOT_ASK) == []
