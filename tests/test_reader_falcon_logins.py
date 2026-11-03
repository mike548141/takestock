"""The CrowdStrike Falcon sign-in activity reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (or
others named in the settings), with made-up account names and small counts.
Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_logins as reader
from takestock.readers import library

OK_COLUMNS = ("account", "account_type", "logon_type", "attempts")
BAD_COLUMNS = (*OK_COLUMNS, "suspicious")


def _export(path: Path, columns: tuple[str, ...], rows: list[dict]) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _ok(account: str, kind: str, logon: str, n: int) -> dict:
    return {"account": account, "account_type": kind, "logon_type": logon, "attempts": str(n)}


def _bad(account: str, logon: str, n: int, suspicious: str = "No") -> dict:
    return {**_ok(account, "Domain", logon, n), "suspicious": suspicious}


def _run(tmp_path: Path, ok: list[dict] | None, bad: list[dict] | None,
         settings: dict | None = None):
    ok_path = _export(tmp_path / "ok.csv", OK_COLUMNS, ok) if ok is not None else None
    s = dict(settings or {})
    if bad is not None:
        s["failed"] = str(_export(tmp_path / "bad.csv", BAD_COLUMNS, bad))
    return reader.step(ctx(reader.PLUGIN, ok_path, s))


def test_the_reader_is_in_the_library():
    assert library()["falcon_logins"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_gives_one_gap_and_no_rows():
    out = reader.step(ctx(reader.PLUGIN, None))
    assert out.records == [] and len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_COLLECTED
    assert coverage.impact_kind_of(g) == coverage.CHANGES_CONCLUSION
    assert coverage.nature_of(g) == coverage.NO_DATA


def test_both_exports_give_six_rows(tmp_path):
    out = _run(tmp_path,
               [_ok("alice", "Domain", "Interactive", 60),
                _ok("bob", "Domain", "Remote interactive", 30),
                _ok("carol", "Local", "Service", 6), _ok("dave", "Local", "NetworkCleartext", 4)],
               [_bad("erin", "Batch", 2), _bad("alice", "Interactive", 5, "Yes"),
                _bad("frank", "", 1)])
    rows = by_name(out.records)
    assert out.gaps == []
    assert list(rows) == ["Cleartext network logons", "Authentication concentration",
                          "Local versus domain authentication", "Authentication paths in use",
                          "Failed authentication", "Login activity scope"]
    ct = rows["Cleartext network logons"]
    assert ct.verdict == "weak" and ct.flags == ["cleartext-credential-logon"]
    assert ct.extra == {"successful": "1", "failed": "0", "attempts": "4"}
    assert ct.hosts_count == 1 and ct.collected_at == "2030-03-17"
    conc = rows["Authentication concentration"]
    assert conc.flags == ["identity-concentration:90"]
    assert conc.extra["rank_1_share"] == "0.600" and conc.extra["rank_4_share"] == "0.040"
    assert conc.extra["identities"] == "4" and conc.extra["attempts"] == "100"
    kind = rows["Local versus domain authentication"]
    assert kind.verdict == "acceptable" and kind.flags == []
    assert kind.extra == {"local": "10", "domain": "90"}
    paths = rows["Authentication paths in use"]
    assert paths.extra == {"interactive": "60", "remote_interactive": "30", "service": "6",
                           "networkcleartext": "4"}
    assert "90 used an interactive or remote interactive logon and 6 a service" in paths.notes
    failed = rows["Failed authentication"]
    assert failed.flags == ["suspicious-failed-logins:1"]
    assert failed.extra == {"attempts": "8", "identities": "3", "suspicious_records": "1",
                            "records": "3"}
    scope = rows["Login activity scope"]
    assert scope.flags == ["scope-observed-not-enumerated"]
    assert scope.extra == {"successful_records": "4", "failed_records": "3"}
    for r in out.records:
        assert r.data_state == "identity" and r.protocol == "login"
        assert "alice" not in r.notes and "alice" not in str(r.extra)


def test_logon_type_8_is_read_by_number_or_name_and_says_what_microsoft_says(tmp_path):
    out = _run(tmp_path, [_ok("alice", "Domain", "8", 3), _ok("bob", "Domain", "NetworkCleartext", 1)],
               None)
    ct = by_name(out.records)["Cleartext network logons"]
    assert ct.extra == {"successful": "2", "failed": "0", "attempts": "4"}
    assert "unhashed" in ct.notes and "2 of them succeeded" in ct.notes


def test_a_failed_type_8_record_alone_is_still_weak(tmp_path):
    out = _run(tmp_path, [_ok("alice", "Domain", "Interactive", 3)],
               [_bad("bob", "Network cleartext", 1)])
    ct = by_name(out.records)["Cleartext network logons"]
    assert ct.verdict == "weak" and ct.extra == {"successful": "0", "failed": "1",
                                                  "attempts": "1"}
    assert "All of them failed" in ct.notes


def test_a_local_majority_is_weak(tmp_path):
    out = _run(tmp_path, [_ok("alice", "Local", "Interactive", 7),
                          _ok("bob", "Domain", "Interactive", 3)], None)
    kind = by_name(out.records)["Local versus domain authentication"]
    assert kind.verdict == "weak" and kind.flags == ["local-authentication-majority:7"]


def test_no_cleartext_row_without_type_8(tmp_path):
    out = _run(tmp_path, [_ok("alice", "Domain", "Interactive", 3)], None)
    names = by_name(out.records)
    assert "Cleartext network logons" not in names
    assert names["Local versus domain authentication"].verdict == "acceptable"
    assert names["Local versus domain authentication"].flags == []


def test_an_even_split_is_not_a_local_majority(tmp_path):
    out = _run(tmp_path, [_ok("alice", "Local", "Interactive", 5),
                          _ok("bob", "domain", "Interactive", 5)], None)
    kind = by_name(out.records)["Local versus domain authentication"]
    assert kind.verdict == "acceptable" and kind.flags == []
    assert kind.extra == {"local": "5", "domain": "5"}


def test_ranks_and_columns_are_settings(tmp_path):
    path = _export(tmp_path / "ok.csv", ("Who", "Kind", "How", "Count"), [
        {"Who": f"user{i}", "Kind": "Domain", "How": "Interactive", "Count": str(10 - i)}
        for i in range(6)])
    settings = {"ranks": 2, "columns": {"successful": {"account": "Who", "account_type": "Kind",
                                                       "logon_type": "How",
                                                       "attempts": "Count"}}}
    out = reader.step(ctx(reader.PLUGIN, path, settings))
    conc = by_name(out.records)["Authentication concentration"]
    assert sorted(k for k in conc.extra if k.startswith("rank_")) == ["rank_1_share",
                                                                       "rank_2_share"]
    assert conc.extra["identities"] == "6"


def test_a_failed_export_alone_is_read(tmp_path):
    out = _run(tmp_path, None, [_bad("erin", "Interactive", 4)])
    assert [r.name for r in out.records] == ["Failed authentication", "Login activity scope"]
    assert out.records[0].collected_at == "2030-03-17"
