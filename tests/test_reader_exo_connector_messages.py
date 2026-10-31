"""The Exchange Online per-message transport reader in takestock's readers library.

Each export is composed in its test, in the columns the reader reads, with
``example.test`` and ``example.org`` addresses, made-up connector names and
dates in 2030. Nothing here was captured from a real export.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from entra_helpers import by_name, ctx

from takestock import config, coverage, plugin_kinds, sge
from takestock.readers import exo_connector_messages as reader
from takestock.readers import library

COLUMNS = ("date_utc", "message_id", "direction", "sender_address", "recipient_address",
           "connector_name", "connector_type", "tls_version", "tls_cipher")
TARGET = {"discovery": {"domains": ["example.test"], "email_domains": ["mail.example.test"]}}
GOV = {"government_suffixes": [".state.test"]}


def _msg(n: int, direction: str, other: str, version: str = "TLS1.2", connector: str = "",
         day: int = 1) -> dict:
    ours = f"user{n}@example.test"
    return {"date_utc": f"2030-01-{day:02d}", "message_id": f"<m{n}@example.test>",
            "direction": direction,
            "sender_address": ours if direction == "Outbound" else other,
            "recipient_address": other if direction == "Outbound" else ours,
            "connector_name": connector, "connector_type": "Partner" if connector else "",
            "tls_version": version, "tls_cipher": "" if version == "No Tls" else "AES256"}


def _write(path: Path, rows: list[dict], encoding: str = "utf-16-le", bom: bool = False) -> Path:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=list(COLUMNS))
    w.writeheader()
    w.writerows(rows)
    data = buf.getvalue().encode(encoding)
    if bom:
        data = b"\xff\xfe" + data
    path.write_bytes(data)
    return path


def _export(path: Path, **kw: object) -> Path:
    rows = [_msg(1, "Outbound", "a@partner.example.org", "TLS1.3", "To the mail gateway"),
            _msg(2, "Outbound", "b@partner.example.org", "TLS1.3", "To the mail gateway"),
            _msg(3, "Outbound", "c@agency.state.test", "TLS1.2", "To the mail gateway", day=2),
            _msg(4, "Outbound", "d@agency.state.test", "No Tls", day=3),
            _msg(5, "Outbound", "e@other.example.org", "TLS1.0", day=4),
            _msg(6, "Inbound", "f@agency.state.test", "TLS1.2", "From the partner relay", day=5),
            _msg(7, "Inbound", "g@mail.example.test", "TLS1.3", day=6),
            _msg(8, "Inbound", "h@sub.state.test", "SSL3", day=7)]
    return _write(path, rows, **kw)  # type: ignore[arg-type]


def _run(path: Path | None, settings: dict | None = None, target: dict | None = None):
    c = ctx(reader.PLUGIN, path, settings)
    c.target = target if target is not None else TARGET
    return reader.step(c)


def test_the_reader_is_in_the_library_as_a_mail_transport_plug_in():
    assert library()["exo_connector_messages"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "mail-transport"
    assert plugin_kinds.fixed_source("mail-transport") == reader.SOURCE


def test_one_row_per_direction_and_path_plus_scope(tmp_path):
    out = _run(_export(tmp_path / "m.csv"), GOV)
    rows = by_name(out.records)
    assert set(rows) == {"Outbound mail — To the mail gateway",
                         "Outbound mail — direct (no connector)",
                         "Inbound mail — From the partner relay",
                         "Inbound mail — direct (no connector)",
                         "Per-message mail transport scope"}
    assert out.gaps == []
    for a in out.records:
        assert a.source == "mail_transport" and a.data_state == "in-transit"
        assert a.protocol == "smtp" and "messages" in a.extra
        assert plugin_kinds.check_asset("mail-transport", a) == []


def test_grades_and_flags(tmp_path):
    rows = by_name(_run(_export(tmp_path / "m.csv"), GOV).records)
    gateway = rows["Outbound mail — To the mail gateway"]
    assert gateway.verdict == "acceptable" and gateway.flags == []
    assert gateway.extra["tls_distribution"] == "TLS1.3=2; TLS1.2=1"
    assert gateway.extra["connector_present"] == "yes"
    assert gateway.extra["connector_type"] == "Partner"
    direct = rows["Outbound mail — direct (no connector)"]
    assert direct.verdict == "weak"
    assert direct.flags == ["mail-cleartext-delivery:1", "mail-legacy-tls:TLS1.0"]
    assert direct.extra["connector_present"] == "no" and direct.extra["connector_type"] == "none"
    assert direct.extra["no_tls_events"] == "2030-01-03 → agency.state.test"
    assert "agency.state.test" in direct.notes
    inbound = rows["Inbound mail — direct (no connector)"]
    assert inbound.verdict == "unknown"
    assert inbound.flags == ["ungraded:mail-tls-version:SSL3"]
    assert inbound.usage_count == 2


def test_all_at_tls13_is_strong(tmp_path):
    path = _write(tmp_path / "m.csv", [_msg(1, "Outbound", "a@example.org", "TLS1.3")])
    row = by_name(_run(path).records)["Outbound mail — direct (no connector)"]
    assert row.verdict == "strong" and "TLS 1.3" in row.notes


def test_addresses_never_reach_a_row(tmp_path):
    for a in _run(_export(tmp_path / "m.csv"), GOV).records:
        text = repr((a.name, a.role, a.notes, a.extra))
        assert "@" not in text


def test_government_counts_exclude_own_domains(tmp_path):
    rows = by_name(_run(_export(tmp_path / "m.csv"), GOV).records)
    direct = rows["Outbound mail — direct (no connector)"]
    assert direct.extra["govt_messages"] == "1"
    assert direct.extra["govt_no_tls_messages"] == "1"
    assert direct.extra["govt_identified_by"] == (
        "counterparty domain ending .state.test, with our own domains excluded")
    inbound = rows["Inbound mail — direct (no connector)"]
    # sub.state.test counts; mail.example.test is the organisation's own.
    assert inbound.extra["govt_messages"] == "1" and inbound.extra["govt_days"] == "1"
    scope = rows["Per-message mail transport scope"]
    assert scope.extra["govt_messages_total"] == "4"
    assert scope.extra["govt_counterparty_domains_total"] == "2"
    assert scope.extra["window"] == "2030-01-01 → 2030-01-07"
    assert scope.extra["messages_outbound"] == "5" and scope.extra["messages_inbound"] == "3"
    assert scope.flags == ["mail-flow-scope"] and scope.verdict == "n/a"


def test_own_domain_under_a_government_suffix_is_not_counted():
    own = ("agency.state.test",)
    suffixes = (".state.test",)
    assert not reader.is_government("agency.state.test", own, suffixes)
    assert not reader.is_government("mail.agency.state.test", own, suffixes)
    assert reader.is_government("other.state.test", own, suffixes)
    assert not reader.is_government("", own, suffixes)


def test_default_suffixes_and_their_wording():
    assert reader.government_suffixes({}) == reader.GOVERNMENT_SUFFIXES
    assert reader.government_suffixes({"government_suffixes": "state.test"}) == (".state.test",)
    assert reader.classifier(reader.GOVERNMENT_SUFFIXES) == (
        "counterparty domain ending .govt.nz, .mil.nz or .parliament.nz, "
        "with our own domains excluded")


def test_encodings(tmp_path):
    for i, (enc, bom) in enumerate((("utf-16-le", False), ("utf-16-le", True), ("utf-8", False))):
        path = _export(tmp_path / f"m{i}.csv", encoding=enc, bom=bom)
        assert len(_run(path, GOV).records) == 5, (enc, bom)


def test_missing_or_unreadable_export_is_one_gap(tmp_path):
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n", encoding="utf-8")
    out = _run(bad)
    assert out.records == [] and "no date_utc column" in str(out.gaps[0])


def test_rows_feed_the_secure_government_email_reading(tmp_path):
    rows = _run(_export(tmp_path / "m.csv"), GOV).records
    std = config.load_yaml_strict(config.BUNDLED_DATA_DIR / "secure-government-email.yaml")
    report = sge.evaluate(rows, ["example.test"], std).rows
    sending = [r for r in report if r.requirement == "SGE-TLS-01"
               and r.subject.startswith("outbound")]
    assert sending and sending[0].status == sge.FAIL


def test_a_delivery_in_clear_alone_makes_a_path_weak(tmp_path):
    path = _write(tmp_path / "m.csv", [_msg(1, "Outbound", "a@example.org", "TLS1.3"),
                                       _msg(2, "Outbound", "second@example.org", "No Tls")])
    row = by_name(_run(path).records)["Outbound mail — direct (no connector)"]
    assert row.verdict == "weak" and row.flags == ["mail-cleartext-delivery:1"]
