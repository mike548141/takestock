"""The Oracle Transparent Data Encryption reader in takestock's readers library.

The fixture, ``fixtures/oracle_tde/example-tde.csv``, was written by hand. Its
columns are those the query in ``docs/COLLECTORS.md`` writes, and its values
are the ones Oracle Database Reference documents for ``V$ENCRYPTION_WALLET``
(``STATUS``, ``WALLET_TYPE``, ``WALLET_ORDER``) and
``V$ENCRYPTED_TABLESPACES`` (``ENCRYPTIONALG``). Every database name, host and
keystore location in it is synthetic. It holds a database in each state the
reader grades, a pluggable database, a mixed-algorithm database, and a row
with no values. Two values are not from the 19c reference: ``ARIA256``, there
as an algorithm the reader does not grade, and the keystore type ``HSM``,
which the reader reads as a hardware keystore.
"""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, plugin_kinds, roles
from takestock.model import CryptoAsset
from takestock.plugins import Context, StepResult
from takestock.policy import Policy
from takestock.readers import library, oracle_tde

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "oracle_tde" / "example-tde.csv"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)


def _ctx(path: Path | None) -> Context:
    return Context(plugin=oracle_tde.PLUGIN, target={}, settings={}, input=path, ref_time=NOW,
                   raw_dir=Path("."), policy=Policy(config.load_baseline()), baseline={},
                   dictionary={}, port_table={}, collected_on="2030-01-31")


def _by_name(rows: list[CryptoAsset]) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


@pytest.fixture()
def result(tmp_path) -> StepResult:
    path = tmp_path / FIXTURE.name
    shutil.copy(FIXTURE, path)
    stamp = datetime(2030, 1, 20, 12, tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    return oracle_tde.read(_ctx(path))


def test_one_row_per_database_and_none_for_a_row_with_no_values(result):
    assert [a.name for a in result.records] == [
        "Oracle TDE orders_a", "Oracle TDE ledger_a", "Oracle TDE stock_a",
        "Oracle TDE catalog_a", "Oracle TDE widgets_a (SHOP)", "Oracle TDE history_a",
        "Oracle TDE REPORTS", "Oracle TDE archive_a"]
    assert result.gaps == []
    for a in result.records:
        assert (a.data_state, a.protocol, a.software, a.source) == (
            "at-rest", "tde", "Oracle Database", "oracle_tde")
        assert plugin_kinds.check_asset("database-encryption", a) == []


def test_verdicts_and_flags(result):
    rows = _by_name(result.records)
    expect = {
        "Oracle TDE orders_a": ("acceptable", ["key-custody:hsm"], ["aes_cbc"]),
        "Oracle TDE ledger_a": ("acceptable", ["key-custody:file-local",
                                               "partial-encryption:2-of-9-tablespaces"],
                                ["aes_cbc"]),
        "Oracle TDE stock_a": ("weak", ["tde-not-enabled"], []),
        "Oracle TDE catalog_a": ("weak", ["key-custody:file-local", "wallet-closed"], []),
        "Oracle TDE widgets_a (SHOP)": ("weak", ["key-custody:file-local",
                                                 "weak-algorithm:3DES168"],
                                        ["3des", "aes_cbc"]),
        "Oracle TDE history_a": ("weak", ["key-custody:file-local", "no-encrypted-tablespaces",
                                          "tde-not-enabled"], []),
        "Oracle TDE REPORTS": ("weak", ["key-custody:file-local", "wallet-status:undefined"], []),
        "Oracle TDE archive_a": ("unknown", ["key-custody:hsm",
                                             "unrecognised-algorithm:ARIA256"], []),
    }
    for name, (verdict, flags, symmetric) in expect.items():
        row = rows[name]
        assert (row.verdict, row.flags, row.symmetric) == (verdict, flags, symmetric), name


def test_every_aes_length_is_graded_as_unsized_aes():
    policy = Policy(config.load_baseline())
    for alg in ("AES128", "AES192", "AES256"):
        verdict, tokens, flags = oracle_tde.grade("OPEN", alg, 1, 1, policy)
        assert (verdict, tokens, flags) == ("acceptable", ["aes_cbc"], set()), alg


def test_without_counts_an_algorithm_shows_encryption():
    policy = Policy(config.load_baseline())
    assert oracle_tde.grade("OPEN", "AES256", None, None, policy)[0] == "acceptable"
    assert oracle_tde.grade("OPEN", "", None, None, policy)[2] == {
        "tde-not-enabled", "no-encrypted-tablespaces"}


def test_a_row_keeps_what_the_export_said(result):
    row = _by_name(result.records)["Oracle TDE widgets_a (SHOP)"]
    assert row.host == "db5.example.test"
    assert row.collected_at == "2030-01-20"
    assert row.source_name == ("Oracle TDE export (V$ENCRYPTION_WALLET, "
                               "V$ENCRYPTED_TABLESPACES), file dated 2030-01-20")
    assert row.extra == {
        "db_name": "WIDGETS", "db_unique_name": "widgets_a", "pdb_name": "SHOP",
        "wallet_type": "FILE", "wallet_status": "OPEN", "wallet_order": "PRIMARY",
        "wrl_parameter": "/opt/example/keystore/widgets",
        "tablespace_encryption_alg": "AES256/3DES168", "encrypted_tablespace_count": 6,
        "tablespace_count": 6}
    assert row.role == roles.database_encryption("widgets_a")
    unprotected = _by_name(result.records)["Oracle TDE catalog_a"]
    assert unprotected.notes.startswith("Not protected by Transparent Data Encryption.")
    assert not row.notes.startswith("Not protected")


def test_headings_may_vary_in_case_and_joining(tmp_path):
    path = tmp_path / "tde.csv"
    path.write_text("﻿DB Name,Host-Name,STATUS,WALLET_TYPE,EncryptionAlg\n"
                    "SHOP,db9.example.test,open,file,aes256\n", encoding="utf-8")
    [row] = oracle_tde.read(_ctx(path)).records
    assert row.name == "Oracle TDE SHOP" and row.host == "db9.example.test"
    assert row.verdict == "acceptable" and "key-custody:file-local" in row.flags


@pytest.mark.parametrize(("content", "why"), [
    (None, "no input was given"),
    ("db_name,wallet_status\n", "holds no rows"),
    (b"\xff\xfe\x81\x00", "could not be read as CSV"),
])
def test_nothing_read_is_one_gap(tmp_path, content, why):
    path = None
    if content is not None:
        path = tmp_path / "tde.csv"
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    out = oracle_tde.read(_ctx(path))
    assert out.records == []
    [gap] = out.gaps
    assert why in gap
    assert coverage.kind_of(gap) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(gap) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(gap) == coverage.NO_DATA
    assert coverage.is_required(gap)


def test_the_declaration():
    p = oracle_tde.PLUGIN
    assert (p.name, p.kind, p.input, p.gap_prefix, p.date_rows) == (
        "oracle_tde", "database-encryption", "", False, True)
    assert library()["oracle_tde"] is p
