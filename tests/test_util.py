"""Shared helpers: response parsing, time and key-size readings."""

from __future__ import annotations

import base64
import sys
from datetime import UTC, datetime, timedelta

import pytest

from takestock import util


def test_run_reports_failure_in_band():
    assert util.run(["/nonexistent/program-example"]).startswith(util.ERROR_PREFIX)
    assert util.run([sys.executable, "-c", "print('hi')"]).strip() == "hi"


def test_ipv6_literals_and_brackets():
    assert util.is_ipv6_literal("[2001:db8::1]")
    assert not util.is_ipv6_literal("192.0.2.1")
    assert util.scan_address("[2001:db8::1]") == "2001:db8::1"
    assert util.scan_address(" www.example.test ") == "www.example.test"


def test_the_last_header_block_describes_the_body():
    raw = ("HTTP/1.1 100 Continue\r\n\r\n"
           "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nX-Other: no\r\n\r\n"
           '{"ok": false}')
    body, meta = util._split_response(raw)
    assert body == '{"ok": false}'
    assert meta == {"status": 429, "headers": {"retry-after": "30"}}


def test_a_body_with_no_headers_passes_through():
    assert util._split_response("plain") == ("plain", {})


@pytest.mark.parametrize("text, expected", [
    ("2030-01-02T03:04:05Z", datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)),
    ("2030-01-02T03:04:05", datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)),
    ("2030-01-02T03:04:05-07:00", datetime(2030, 1, 2, 10, 4, 5, tzinfo=UTC)),
    ("not a date", None),
    ("", None),
])
def test_certificate_times_parse_to_aware_datetimes(text, expected):
    assert util.parse_cert_time(text) == expected


def test_days_remaining_and_dates():
    ref = datetime(2030, 1, 1, tzinfo=UTC)
    assert util.days_remaining(ref + timedelta(days=10, hours=1), ref) == 10
    assert util.days_remaining(ref - timedelta(days=1), ref) == -1
    assert util.now_date(ref) == "2030-01-01"


def test_file_dates(tmp_path):
    f = tmp_path / "export.csv"
    f.write_text("x\n")
    assert util.file_mtime_date(f) == util.now_date()
    assert util.file_mtime_date(tmp_path / "absent.csv") is None


@pytest.mark.parametrize("der_len, bits", [(162, 1024), (294, 2048), (422, 3072), (550, 4096)])
def test_dkim_key_size_is_estimated_from_the_key_length(der_len, bits):
    key = base64.b64encode(bytes(der_len)).decode()
    assert util.rsa_key_bits_from_dkim(f"v=DKIM1; k=rsa; p={key}") == bits


def test_a_dkim_record_without_a_key_has_no_size():
    assert util.rsa_key_bits_from_dkim("v=DKIM1; p=") is None
    assert util.rsa_key_bits_from_dkim("v=DKIM1") is None


@pytest.mark.parametrize("key_type, bits, curve, token", [
    ("RSA", 2048, None, "rsa_2048"),
    ("ec", None, "secp384r1", "ecdsa_p384"),
    ("id-ecPublicKey", 256, None, "ecdsa_p256"),
    ("ED25519", None, None, "ed25519"),
    ("ed448", None, None, "ed448"),
    ("rsa", None, None, None),
    ("dsa", 1024, None, None),
])
def test_certificate_keys_map_to_signature_tokens(key_type, bits, curve, token):
    assert util.cert_signature_token(key_type, bits, curve) == token
