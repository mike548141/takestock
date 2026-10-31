"""The Exchange Online mailbox access reader in takestock's readers library.

Each export is composed in its test, in the columns the script in
``docs/COLLECTORS.md`` writes, with ``example.test`` addresses and dates in
2030. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import exo_client_access as reader
from takestock.readers import library

MAILBOX = ("PrimarySmtpAddress", "RecipientTypeDetails", "ImapEnabled", "PopEnabled",
           "ActiveSyncEnabled", "MAPIEnabled", "OWAEnabled", "EwsEnabled", "ECPEnabled",
           "Cmdlet")
SWITCHES = MAILBOX[2:9]


def _mailbox(n: int, kind: str = "UserMailbox", off: tuple[str, ...] = (), **kw: str) -> dict:
    row = {"PrimarySmtpAddress": f"box{n}@example.test", "RecipientTypeDetails": kind,
           "Cmdlet": "Get-EXOCasMailbox"}
    row.update({s: "False" if s in off else "True" for s in SWITCHES})
    row.update(kw)
    return row


def _dated(path: Path, day: str) -> Path:
    stamp = datetime.fromisoformat(day).replace(tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    return path


def _mailboxes(path: Path, columns: tuple[str, ...] = MAILBOX, extra: list[dict] | None = None,
               day: str = "2020-06-30") -> Path:
    rows = [_mailbox(1), _mailbox(2, off=("ImapEnabled", "PopEnabled")),
            _mailbox(3, "SharedMailbox", Cmdlet="Get-CASMailbox"),
            _mailbox(4, "RoomMailbox", EwsEnabled="")] + (extra or [])
    return _dated(write(path, columns, rows), day)


def _transport(path: Path, disabled: str) -> Path:
    return write(path, ("SmtpClientAuthenticationDisabled",),
                 [{"SmtpClientAuthenticationDisabled": disabled}])


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["exo_client_access"] is reader.PLUGIN


def test_protocol_rows(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes-2030-01-31.csv")
    _transport(tmp_path / "transport-2030-01-31.csv", "True")
    out = _run(mb, {"transport": str(tmp_path / "transport-*.csv")})
    rows = by_name(out.records)
    imap = rows["Mailbox access — IMAP"]
    assert imap.verdict == "acceptable" and imap.flags == ["exo-legacy-protocol-enabled:imap"]
    assert imap.hosts_count == 3 and imap.extra["mailboxes_off"] == 1
    assert imap.extra["by_mailbox_kind"] == ("UserMailbox 1 on, 1 off; SharedMailbox 1 on; "
                                             "RoomMailbox 1 on")
    assert imap.extra["mailboxes"] == 4 and imap.extra["setting"] == "ImapEnabled"
    mapi = rows["Mailbox access — MAPI (Outlook for Windows)"]
    assert mapi.verdict == "acceptable" and mapi.flags == []
    ews = rows["Mailbox access — Exchange Web Services"]
    assert ews.extra["mailboxes_unrecorded"] == 1 and "April 2027" in ews.notes
    ecp = rows["Mailbox access — ECP (administration and settings pages)"]
    assert ecp.verdict == "unknown" and ecp.extra["basic_sign_in"] == "not graded"
    assert all(a.data_state == "identity" for a in out.records)
    assert all("@" not in repr((a.notes, a.extra)) for a in out.records)


def test_legacy_flag_only_when_on(tmp_path):
    rows = [_mailbox(1, off=("PopEnabled",))]
    out = _run(write(tmp_path / "m.csv", MAILBOX, rows))
    assert by_name(out.records)["Mailbox access — POP"].flags == []


def test_smtp_on_for_the_organisation_is_weak_before_the_default_changes(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes.csv", day="2020-06-30")
    _transport(tmp_path / "transport.csv", "False")
    out = _run(mb, {"transport": str(tmp_path / "transport.csv"),
                    "policies": str(tmp_path / "policies-*.csv")})
    smtp = by_name(out.records)["Mail submission by password — organisation setting"]
    assert smtp.verdict == "weak" and smtp.flags == ["exo-smtp-auth-enabled-tenant-wide"]
    assert smtp.extra["nzism_controls"] == "16.7.42.C.01; 15.2.46.C.01"
    assert smtp.extra["SmtpClientAuthenticationDisabled"] == "False"
    assert smtp.extra["authentication_policies"] == 0


def test_smtp_is_unknown_after_the_default_changes_or_with_a_policy(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes.csv", day="2030-01-31")
    _transport(tmp_path / "transport.csv", "False")
    out = _run(mb, {"transport": str(tmp_path / "transport.csv"),
                    "policies": str(tmp_path / "none-*.csv")})
    smtp = by_name(out.records)["Mail submission by password — organisation setting"]
    assert smtp.verdict == "unknown" and reader.SMTP_BASIC_DEFAULT_OFF in smtp.notes
    mb = _mailboxes(tmp_path / "mailboxes.csv", day="2020-06-30")
    write(tmp_path / "policies.csv", ("Name",), [{"Name": "Block legacy"}])
    out = _run(mb, {"transport": str(tmp_path / "transport.csv"),
                    "policies": str(tmp_path / "policies.csv")})
    rows = by_name(out.records)
    smtp = rows["Mail submission by password — organisation setting"]
    assert smtp.verdict == "unknown" and smtp.extra["authentication_policies"] == 1
    assert rows["Mailbox access settings — scope"].extra["policy_export"] == "policies.csv"


def test_smtp_off_for_the_organisation(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes.csv")
    _transport(tmp_path / "transport.csv", "True")
    smtp = by_name(_run(mb, {"transport": str(tmp_path / "transport.csv")}).records)[
        "Mail submission by password — organisation setting"]
    assert smtp.verdict == "acceptable" and smtp.flags == []


def test_unreadable_organisation_value(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes.csv")
    _transport(tmp_path / "transport.csv", "maybe")
    smtp = by_name(_run(mb, {"transport": str(tmp_path / "transport.csv")}).records)[
        "Mail submission by password — organisation setting"]
    assert smtp.verdict == "unknown" and "'maybe'" in smtp.notes


def test_mailbox_overrides_are_counted_when_present(tmp_path):
    columns = (*MAILBOX, "SmtpClientAuthenticationDisabled")
    mb = _mailboxes(tmp_path / "mailboxes.csv", columns,
                    extra=[_mailbox(5, SmtpClientAuthenticationDisabled="False")])
    _transport(tmp_path / "transport.csv", "True")
    out = _run(mb, {"transport": str(tmp_path / "transport.csv")})
    smtp = by_name(out.records)["Mail submission by password — organisation setting"]
    assert smtp.extra["per_mailbox_override_read"] == "yes"
    assert "0 turned off, 1 turned on, 4 following" in smtp.notes
    assert len(out.gaps) == 2  # no override gap


def test_gaps_without_the_organisation_file(tmp_path):
    out = _run(_mailboxes(tmp_path / "mailboxes.csv"))
    names = set(by_name(out.records))
    assert "Mail submission by password — organisation setting" not in names
    kinds = [coverage.kind_of(g) for g in out.gaps]
    assert kinds == [coverage.NOT_COLLECTED, coverage.NOT_MEASURED, coverage.NOT_MEASURED,
                     coverage.NOT_COLLECTED]
    scope = by_name(out.records)["Mailbox access settings — scope"]
    assert scope.extra["tenant_export"] == "not held" and scope.extra["policy_export"] == "none"


def test_files_are_paired_by_the_date_in_their_names(tmp_path):
    _mailboxes(tmp_path / "mailboxes-2030-01-01.csv")
    _mailboxes(tmp_path / "mailboxes-2030-02-01.csv")
    _transport(tmp_path / "transport-2030-01-01.csv", "False")
    settings = {"mailboxes": str(tmp_path / "mailboxes-*.csv"),
                "transport": str(tmp_path / "transport-*.csv")}
    out = _run(None, settings)
    scope = by_name(out.records)["Mailbox access settings — scope"]
    # The newest mailbox file has no organisation file of its date, so none is read.
    assert scope.extra["mailbox_export"] == "mailboxes-2030-02-01.csv"
    assert scope.extra["pull_date_in_file_name"] == "2030-02-01"
    assert scope.extra["tenant_export"] == "not held"
    _transport(tmp_path / "transport-2030-02-01.csv", "True")
    scope = by_name(_run(None, settings).records)["Mailbox access settings — scope"]
    assert scope.extra["tenant_export"] == "transport-2030-02-01.csv"


def test_no_mailbox_file_is_one_gap(tmp_path):
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert "none was named" in str(out.gaps[0])
    empty = write(tmp_path / "empty.csv", MAILBOX, [])
    assert "holds no rows" in str(_run(empty).gaps[0])


def test_outlook_on_the_web_has_its_own_basis(tmp_path):
    rows = by_name(_run(_mailboxes(tmp_path / "mailboxes.csv")).records)
    owa = rows["Mailbox access — Outlook on the web"]
    assert owa.verdict == "acceptable"
    assert owa.extra["basic_sign_in"] == "browser sign-in; modern authentication client"
    assert "not on Microsoft's list" in owa.notes and reader.BASIC_AUTH_RETIRED_URL not in owa.notes
    mapi = rows["Mailbox access — MAPI (Outlook for Windows)"]
    assert mapi.extra["basic_sign_in"] == "retired by Microsoft; token-only"


def test_the_cut_off_reads_the_date_in_the_file_name_first(tmp_path):
    _transport(tmp_path / "transport.csv", "False")
    settings = {"transport": str(tmp_path / "transport.csv"),
                "policies": str(tmp_path / "policies-*.csv")}
    late = _mailboxes(tmp_path / "mailboxes-2030-01-31.csv", day="2020-06-30")
    smtp = by_name(_run(late, settings).records)[
        "Mail submission by password — organisation setting"]
    assert smtp.verdict == "unknown" and "dated 2030-01-31" in smtp.notes
    early = _mailboxes(tmp_path / "mailboxes-2020-01-31.csv", day="2030-06-30")
    smtp = by_name(_run(early, settings).records)[
        "Mail submission by password — organisation setting"]
    assert smtp.verdict == "weak"


def test_an_unnamed_policy_file_is_said_not_read(tmp_path):
    mb = _mailboxes(tmp_path / "mailboxes.csv")
    _transport(tmp_path / "transport.csv", "False")
    rows = by_name(_run(mb, {"transport": str(tmp_path / "transport.csv")}).records)
    smtp = rows["Mail submission by password — organisation setting"]
    assert smtp.verdict == "unknown"
    assert "no authentication policy file was named" in smtp.notes
    assert "policies were not read" in rows["Mailbox access settings — scope"].notes
    rows = by_name(_run(mb, {"transport": str(tmp_path / "transport.csv"),
                             "policies": str(tmp_path / "policies-*.csv")}).records)
    smtp = rows["Mail submission by password — organisation setting"]
    assert "was found for this export" in smtp.notes and smtp.verdict == "weak"
    assert "read as no policy" in rows["Mailbox access settings — scope"].notes


def test_the_scope_row_labels_both_dates(tmp_path):
    scope = by_name(_run(_mailboxes(tmp_path / "mailboxes-2030-01-31.csv")).records)[
        "Mailbox access settings — scope"]
    assert "dated 2030-01-31 by its file name and last modified 2020-06-30" in scope.notes
    assert scope.collected_at == "2020-06-30"
    plain = by_name(_run(_mailboxes(tmp_path / "plain.csv")).records)[
        "Mailbox access settings — scope"]
    assert "by its file name" not in plain.notes and "last modified 2020-06-30" in plain.notes
