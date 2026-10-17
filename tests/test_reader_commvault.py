"""The Commvault backup encryption reader in takestock's readers library.

Commvault publishes no report whose columns are documented to carry each
storage policy copy's cipher and key length, so the input's columns are the
reader's own (``docs/COLLECTORS.md``), named after the console's fields. The
fixture, ``fixtures/commvault/example-backup-encryption.csv``, is a stub
written by hand with those columns only, and the cipher names and key lengths
of Commvault's *Supported Algorithms for Software Encryption* page. Every
policy, pool and key manager name in it is synthetic. It holds a copy in each
state the reader grades, each kind of key custody, a cipher the baseline does
not grade, and a row naming only a storage pool.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, plugin_kinds, roles
from takestock.model import CryptoAsset
from takestock.plugins import Context, StepResult
from takestock.policy import Policy
from takestock.readers import commvault, library

FIXTURE = (Path(__file__).resolve().parent / "fixtures" / "commvault"
           / "example-backup-encryption.csv")
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)


def _ctx(path: Path | None) -> Context:
    return Context(plugin=commvault.PLUGIN, target={}, settings={}, input=path, ref_time=NOW,
                   raw_dir=Path("."), policy=Policy(config.load_baseline()), baseline={},
                   dictionary={}, port_table={}, collected_on="2030-01-31")


def _by_name(rows: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


@pytest.fixture()
def result() -> StepResult:
    return commvault.read(_ctx(FIXTURE))


def test_one_row_per_copy(result):
    assert [a.name for a in result.records] == [
        "Commvault backup encryption Example-Daily (Primary)",
        "Commvault backup encryption Example-Daily (Secondary)",
        "Commvault backup encryption Example-Archive (Primary)",
        "Commvault backup encryption Example-Offsite (Primary)",
        "Commvault backup encryption Example-Legacy (Primary)",
        "Commvault backup encryption Example-Lab (Primary)",
        "Commvault backup encryption Example-Cloud (Primary)",
        "Commvault backup encryption Example-Pool",
        "Commvault backup encryption Example-Test"]
    assert result.gaps == []
    for a in result.records:
        assert (a.data_state, a.protocol, a.software, a.source, a.host) == (
            "at-rest", "commvault-backup", "Commvault", "commvault", "")
        assert plugin_kinds.check_asset("backup-encryption", a) == []


def test_verdicts_and_flags(result):
    p = "Commvault backup encryption "
    expect = {
        f"{p}Example-Daily (Primary)": ("strong", ["key-custody:commserve-db"], ["aes256_cbc"]),
        f"{p}Example-Daily (Secondary)": ("acceptable", ["key-custody:media-password"],
                                          ["aes_cbc"]),
        f"{p}Example-Archive (Primary)": ("weak", ["key-custody:example-kmip-server",
                                                   "weak-algorithm:Blowfish"], ["blowfish"]),
        f"{p}Example-Offsite (Primary)": ("weak", ["encryption-off"], []),
        f"{p}Example-Legacy (Primary)": ("weak", ["key-custody:commserve-db",
                                                  "weak-algorithm:3-DES"], ["3des"]),
        f"{p}Example-Lab (Primary)": ("weak", ["encryption-status:pending"], []),
        f"{p}Example-Cloud (Primary)": ("unknown", ["ungraded:symmetric:example-cipher"], []),
        f"{p}Example-Pool": ("acceptable", [], ["serpent"]),
        f"{p}Example-Test": ("weak", ["encryption-off"], []),
    }
    rows = _by_name(result.records)
    for name, (verdict, flags, symmetric) in expect.items():
        row = rows[name]
        assert (row.verdict, row.flags, row.symmetric) == (verdict, flags, symmetric), name


@pytest.mark.parametrize(("cipher", "length", "token"), [
    ("AES", "256", "aes256_cbc"), ("aes", "128", "aes_cbc"), ("Rijndael", "", "aes_cbc"),
    ("Twofish", "256", "twofish"), ("GOST", "256", "gost"), ("Triple DES", "192", "3des"),
    ("Example-Cipher", "256", "example-cipher"),
])
def test_cipher_names(cipher, length, token):
    assert commvault.cipher_token(cipher, length) == token


def test_encryption_on_with_no_cipher_is_ungraded():
    verdict, tokens, flags = commvault.grade("yes", "", "256", Policy(config.load_baseline()))
    assert (verdict, tokens, flags) == ("unknown", [], {"ungraded:symmetric:"})


def test_a_row_keeps_what_the_export_said(result):
    row = _by_name(result.records)["Commvault backup encryption Example-Pool"]
    assert row.extra == {"storage_policy": "", "storage_pool": "Example-Pool", "copy_name": "",
                         "cipher": "Serpent", "key_length": "256", "key_management": ""}
    assert row.role == roles.backup_encryption("Example-Pool")
    assert row.source_name.startswith("Commvault storage policy encryption settings, file dated ")
    assert row.notes.startswith("Backup encryption is on.")
    off = _by_name(result.records)["Commvault backup encryption Example-Offsite (Primary)"]
    assert off.notes.startswith("Backup encryption is off.")


def test_headings_may_vary_in_case_and_joining(tmp_path):
    path = tmp_path / "cv.csv"
    path.write_text("Storage Policy,Copy Name,Encryption Enabled,Cipher,Key Length\n"
                    "Example-Weekly,Primary,YES,AES,256\n")
    [row] = commvault.read(_ctx(path)).records
    assert row.name == "Commvault backup encryption Example-Weekly (Primary)"
    assert row.verdict == "strong"


@pytest.mark.parametrize(("content", "why"), [
    (None, "no input was given"),
    ("storage_policy,cipher\n", "holds no rows"),
])
def test_nothing_read_is_one_gap(tmp_path, content, why):
    path = None
    if content is not None:
        path = tmp_path / "cv.csv"
        path.write_text(content)
    out = commvault.read(_ctx(path))
    assert out.records == []
    [gap] = out.gaps
    assert why in gap
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(gap) == coverage.NO_DATA


def test_the_declaration():
    p = commvault.PLUGIN
    assert (p.name, p.kind, p.input, p.gap_prefix, p.date_rows) == (
        "commvault", "backup-encryption", "", False, True)
    assert library()["commvault"] is p
