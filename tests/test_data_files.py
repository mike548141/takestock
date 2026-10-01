"""The data files that ship with the package, and the placeholder CLI."""

from __future__ import annotations

import csv
import re

import pytest

from takestock import __version__, cli, config

VALID_EFFORTS = {"S", "M", "L", "XL"}
VALID_SCOPES = {"per-asset", "per-rule"}
BUNDLED_DISPOSITIONS = config.BUNDLED_DATA_DIR / "dispositions.yaml"


def test_every_disposition_rule_declares_its_effort_scope():
    doc = config.load_yaml_strict(BUNDLED_DISPOSITIONS)
    ids = [r["id"] for r in doc["rules"]]
    assert len(ids) == len(set(ids))
    for r in doc["rules"]:
        assert r.get("match"), r["id"]
        assert r["effort"] in VALID_EFFORTS, r["id"]
        assert r["effort_scope"] in VALID_SCOPES, r["id"]
        assert " ".join(r["reason"].split()), r["id"]
    assert doc["decisions"] == []
    assert [r["track"] for r in doc["ladder"]] == ["critical", "wave-1", "wave-2", "wave-3"]


def test_the_ordering_the_dispositions_rely_on():
    ids = [r["id"] for r in config.load_yaml_strict(BUNDLED_DISPOSITIONS)["rules"]]
    assert ids.index("accept-no-alternative-cleartext") < ids.index("cleartext-service")
    assert ids.index("accept-no-alternative-provider-hsts") + 1 == ids.index("no-usable-hsts-policy")
    assert ids.index("internet-facing-weak") < ids.index("accept-replacement-tolerable-control")
    assert ids.index("pqc-migrate-key-establishment") < ids.index("pqc-migrate-signature-only")


def _crypto_register() -> list[dict[str, str]]:
    with (config.BUNDLED_DATA_DIR / "crypto-software.csv").open(newline="") as f:
        return list(csv.DictReader(f))


def _first_product(register: list[dict[str, str]], name: str) -> str:
    # The reading a software-inventory collector does: first matching row wins.
    for entry in register:
        if re.match(entry["match"], name, re.IGNORECASE):
            return entry["product"]
    return ""


def test_crypto_software_rows_are_complete_and_cited():
    rows = _crypto_register()
    assert rows
    for r in rows:
        assert r["product"] and r["provides"] and r["citation"], r
        re.compile(r["match"])
        if r["branch"]:
            assert r["max_tls"] in ("TLSv1.2", "TLSv1.3"), r


@pytest.mark.parametrize("name, product", [
    ("openssl 1.1.1", "OpenSSL"),
    ("OpenSSL 3.0", "OpenSSL"),
    ("gnutls", "GnuTLS"),
    ("Network Security Services", "Mozilla NSS"),
    ("nss", "Mozilla NSS"),
    (".NET 9 SDK", ".NET platform"),
    ("OpenJDK Runtime", "Java platform"),
    ("gnupg2", "GnuPG"),
    ("openssh-server", "OpenSSH"),
    ("Google Chrome", ""),
    ("Gopher Client", ""),
    ("Javelin Editor", ""),
])
def test_inventory_names_match_the_right_product(name, product):
    assert _first_product(_crypto_register(), name) == product


def test_a_capability_row_exists_only_for_a_documented_branch():
    rows = [r for r in _crypto_register() if r["branch"]]
    assert {(r["product"], r["branch"]) for r in rows} == {("OpenSSL", "1.0"), ("OpenSSL", "3")}


def test_the_cli_prints_its_version(capsys):
    assert cli.main([]) == 0
    assert f"takestock {__version__}" in capsys.readouterr().out
    assert cli.main(["observe"]) == 2
