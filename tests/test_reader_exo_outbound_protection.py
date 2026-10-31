"""The Exchange Online outbound-messages-by-security-type reader in takestock's readers library.

Each export is composed in its test, in the columns the reader reads, with
dates in 2030 and small counts. Nothing here was captured from a real export.
"""

from __future__ import annotations

from pathlib import Path

from entra_helpers import ctx, write
from test_reader_exo_connector_messages import _msg, _write

from takestock import coverage
from takestock.readers import exo_outbound_protection as reader
from takestock.readers import library

COLUMNS = ("Date", "SecurityType", "CountOfSecuredMessages")


def _report(path: Path, rows: list[tuple[str, str, int]]) -> Path:
    return write(path, COLUMNS, [{"Date": d, "SecurityType": t, "CountOfSecuredMessages": str(n)}
                                 for d, t, n in rows])


def _run(path: Path | None, settings: dict | None = None):
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["exo_outbound_protection"] is reader.PLUGIN


def test_counts_by_security_type(tmp_path):
    path = _report(tmp_path / "r.csv", [("2030-01-01T09:00:00.000Z", "TLS-only", 30),
                                        ("2030-01-01T10:00:00.000Z", "MTA-STS", 4),
                                        ("2030-01-02T09:00:00.000Z", "DANE", 2),
                                        ("2030-01-02T10:00:00.000Z", "TLS-only", 10)])
    out = _run(path)
    assert out.gaps == [] and len(out.records) == 1
    row = out.records[0]
    assert row.verdict == "n/a" and row.flags == ["mail-outbound-protection-scope"]
    assert row.usage_count == 46
    assert row.extra["recipient_policy_messages"] == "6"
    assert row.extra["tls_alone_messages"] == "40"
    assert row.extra["security_type_distribution"] == "TLS-only=40; MTA-STS=4; DANE=2"
    assert row.extra["window"] == "2030-01-01T09:00:00.000Z → 2030-01-02T10:00:00.000Z"
    assert row.extra["per_message_outbound_same_dates"] == "0"
    assert "was not named" in row.notes


def test_an_unplaced_type_is_counted_apart(tmp_path):
    path = _report(tmp_path / "r.csv", [("2030-01-01T09:00:00.000Z", "TLS-only", 3),
                                        ("2030-01-01T10:00:00.000Z", "Example-new", 2)])
    row = _run(path).records[0]
    assert row.flags == ["mail-outbound-protection-scope", "ungraded:mail-security-type:Example-new"]
    assert row.extra["tls_alone_messages"] == "3" and row.extra["recipient_policy_messages"] == "0"
    assert "Example-new" in row.notes


def test_reconciled_with_the_per_message_export(tmp_path):
    report = _report(tmp_path / "r.csv", [("2030-01-02T09:00:00.000Z", "TLS-only", 8),
                                          ("2030-01-03T09:00:00.000Z", "MTA-STS", 1)])
    messages = _write(tmp_path / "m.csv", [
        _msg(1, "Outbound", "a@example.org", connector="To the mail gateway", day=2),
        _msg(2, "Outbound", "second@example.org", connector="To the mail gateway", day=3),
        _msg(3, "Outbound", "c@example.org", day=3),
        _msg(4, "Outbound", "d@example.org", day=9),           # outside the dates
        _msg(5, "Inbound", "e@example.org", day=2)])           # not outbound
    row = _run(report, {"messages": str(messages)}).records[0]
    assert row.extra["per_message_outbound_same_dates"] == "3"
    assert row.extra["per_message_via_connector_same_dates"] == "2"
    assert "if both exports count the same messages, at least 7 of it is" in row.notes


def test_tls_alone_within_the_direct_deliveries(tmp_path):
    report = _report(tmp_path / "r.csv", [("2030-01-02T09:00:00.000Z", "TLS-only", 1)])
    messages = _write(tmp_path / "m.csv", [_msg(1, "Outbound", "a@example.org", day=2),
                                           _msg(2, "Outbound", "second@example.org", day=2)])
    row = _run(report, {"messages": str(messages)}).records[0]
    assert "could be direct delivery" in row.notes


def test_missing_or_unreadable_export_is_one_gap(tmp_path):
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.impact_kind_of(out.gaps[0]) == coverage.NARROWS_CONFIDENCE
    bad = write(tmp_path / "bad.csv", ("Date", "Count"), [{"Date": "2030-01-01", "Count": "1"}])
    assert "no SecurityType column" in str(_run(bad).gaps[0])
