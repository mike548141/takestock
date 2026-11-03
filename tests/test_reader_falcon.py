"""The CrowdStrike Falcon listener reader in takestock's readers library.

Each export is composed in its test, in the columns the queries in
``docs/COLLECTORS.md`` write (or other headings named in the settings), with
made-up machine names under ``example.test``, sensor IDs of one repeated
digit and small counts. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from entra_helpers import ctx, write

from takestock import config, coverage, plaintext
from takestock.readers import falcon as reader
from takestock.readers import library

LISTENER_COLUMNS = ("ComputerName", "aid", "port", "program", "bind_scope", "address_family",
                    "events")
ACCEPT_COLUMNS = ("ComputerName", "aid", "port", "program", "events")
HOST_COLUMNS = ("aid", "ComputerName", "Version", "ProductType")

WEB, APP, DC, LAB = ("web1.example.test", "app1.example.test", "dc1.example.test",
                     "lab1.example.test")
SID = {WEB: "1" * 32, APP: "2" * 32, DC: "3" * 32, LAB: "4" * 32}
TABLE = config.load_port_encryption()
WORDS = config.load_dictionary()
#: Ports from the start of the dynamic range RFC 6335 sets aside that the port table does not
#: list: ports the reader can grade only by the program behind them.
UNLISTED = [str(p) for p in range(49152, 65536) if plaintext.lookup(str(p), "tcp", TABLE) is None]
P1, P2, P3, P4 = UNLISTED[:4]


def _listen(host: str, port: str, program: str = "", scope: str = "all-interfaces",
            family: str = "ipv4", events: int = 3, sid: str | None = None) -> dict:
    return {"ComputerName": host, "aid": SID.get(host, "") if sid is None else sid,
            "port": port, "program": program, "bind_scope": scope,
            "address_family": family, "events": str(events)}


def _accept(host: str, port: str, program: str = "", events: int = 5) -> dict:
    return {"ComputerName": host, "aid": SID.get(host, ""), "port": port,
            "program": program, "events": str(events)}


def _host(host: str, version: str, kind: str) -> dict:
    return {"aid": SID[host], "ComputerName": host, "Version": version, "ProductType": kind}


def _file(path: Path, columns: tuple[str, ...], rows: list[dict]) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _read(tmp: Path, listeners: list[dict], accepts: list[dict] | None = None,
          hosts: list[dict] | None = None, **kw):
    lpath = _file(tmp / "listeners.csv", kw.pop("columns", LISTENER_COLUMNS), listeners)
    apath = _file(tmp / "accepts.csv", ACCEPT_COLUMNS, accepts) if accepts is not None else None
    hpath = _file(tmp / "hosts.csv", HOST_COLUMNS, hosts) if hosts is not None else None
    kw.setdefault("dictionary", WORDS)
    kw.setdefault("port_table", TABLE)
    return reader.read(lpath, accepts=apath, hosts=hpath, **kw)


def _by_name(rows: list) -> dict:
    return {a.name: a for a in rows}


def _gap_texts(gaps: list) -> list[str]:
    return [str(g) for g in gaps]


HOSTS = [_host(WEB, "Debian 12", "Server"), _host(APP, "Windows 11", "Workstation"),
         _host(DC, "Windows Server 2025", "Domain Controller")]


def test_the_library_lists_the_reader_and_it_marks_its_rows_as_host_listeners():
    assert library()["falcon"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general"
    assert plaintext.HOST_LISTENER_SOURCES[reader.NAME] == reader.NOTES_MARKER


def test_a_cleartext_listener_is_weak_and_says_what_machine_it_is_on(tmp_path):
    rows, _gaps = _read(tmp_path, [_listen(WEB, "23/tcp", "telnetd")],
                        [_accept(WEB, "23/tcp", "telnetd", 7)], HOSTS)
    row = _by_name(rows)[f"{WORDS['telnetd']['product']} on {WEB}:23/tcp"]
    assert row.verdict == "weak"
    assert "plaintext:telnet" in row.flags
    assert row.protocol == "telnet" and row.port == "23"
    assert row.notes.startswith("NO ENCRYPTION")
    assert "service=23/tcp" in row.notes and "category=remote-access" in row.notes
    assert row.usage_count == 7
    assert row.role.endswith("running on a Debian 12 server")
    assert row.source == "falcon" and row.collected_at == "2030-03-17"
    assert row.extra["host_type"] == "Server" and row.extra["os"] == "Debian 12"
    assert row.extra["confidence"] == "likely"


def test_an_encrypted_port_gets_its_protocol_and_no_cleartext_flag(tmp_path):
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd")], [], HOSTS)
    row = _by_name(rows)[f"OpenSSH server on {WEB}:22/tcp"]
    assert row.protocol == "ssh"
    assert not [f for f in row.flags if f.startswith("plaintext:")]


def test_an_out_of_band_management_port_on_the_host_is_recorded_as_unmeasured(tmp_path):
    rows, _ = _read(tmp_path, [_listen(APP, "16992/tcp")], [], HOSTS)
    row = _by_name(rows)[f"listener on {APP}:16992/tcp"]
    assert plaintext.LISTENER_ONLY in row.flags
    assert row.verdict == "weak"


def test_a_port_with_no_table_row_and_no_program_is_counted_not_listed(tmp_path):
    rows, _ = _read(tmp_path, [_listen(WEB, f"{P1}/tcp"), _listen(APP, f"{P2}/tcp"),
                               _listen(APP, f"{P3}/tcp")], [], HOSTS)
    names = _by_name(rows)
    count = names["Unclassified listener binds (3 across 2 computers)"]
    assert count.verdict == "n/a" and count.data_state == "discovery"
    assert count.extra == {"unclassified_binds": "3", "unclassified_hosts": "2"}
    assert not [n for n in names if any(f":{p}/" in n for p in (P1, P2, P3))]


def test_the_program_is_named_from_the_accept_export(tmp_path):
    rows, _ = _read(tmp_path,
                    [_listen(WEB, f"{P1}/tcp"), _listen(APP, f"{P2}/tcp"),
                     _listen(DC, f"{P3}/tcp")],
                    [_accept(WEB, f"{P1}/tcp", "nginx", 4),
                     _accept(APP, f"{P4}/tcp", "nginx"),
                     {**_accept("", f"{P2}/tcp", "nginx", 9), "aid": ""},
                     _accept(WEB, f"{P3}/tcp", "java"), _accept(APP, f"{P3}/tcp", "java")],
                    HOSTS)
    names = _by_name(rows)
    same = names[f"nginx on {WEB}:{P1}/tcp"]
    assert "program named from the accept export, same machine and port" in same.notes
    assert same.usage_count == 4
    # one program across every machine on the port: named, but no count is this machine's
    wide = names[f"nginx on {APP}:{P2}/tcp"]
    assert "one program across every machine" in wide.notes
    assert wide.usage_count is None and wide.extra["estate_connections"] == "9"
    # an ambiguous runtime is never named from the estate-wide join
    assert names["Unclassified listener binds (1 across 1 computers)"]


def test_a_program_with_many_unrecognised_ports_on_one_machine_is_one_row(tmp_path):
    many = [_listen(APP, f"{port}/tcp", "nginx", events=2) for port in UNLISTED[4:25]]
    rows, _ = _read(tmp_path, many, [], HOSTS)
    run = _by_name(rows)[f"nginx on {APP} — 21 dynamically allocated ports"]
    assert run.extra["dynamic_ports"] == "21" and run.extra["binds"] == "42"
    assert run.protocol == "" and run.port == ""
    rows, _ = _read(tmp_path, many, [], HOSTS, dynamic_port_run=30)
    assert len([a for a in rows if a.name.startswith("nginx on ")]) == 21


def test_scope_and_family_collapse_to_one_row_with_the_widest_scope(tmp_path):
    rows, gaps = _read(tmp_path, [
        _listen(WEB, "80/tcp", scope="interface", family="ipv4", events=2),
        _listen(WEB, "80/tcp", scope="all-interfaces", family="ipv6", events=3),
        _listen(APP, "80/tcp", scope="localhost", family="ipv4"),
    ], [], HOSTS)
    names = _by_name(rows)
    web = names[f"listener on {WEB}:80/tcp"]
    assert web.extra["bind_scope"] == "all-interfaces"
    assert web.extra["bind_scopes_seen"] == "all-interfaces,interface"
    assert web.extra["address_family"] == "dual-stack" and web.extra["binds"] == "5"
    local = names[f"listener on {APP}:80/tcp"]
    assert reader.LOOPBACK_FLAG in local.flags
    # a loopback row is in the export, so no row says none was seen
    assert not [n for n in names if n.startswith("Loopback-only listeners")]
    assert not [g for g in _gap_texts(gaps) if "IPv4 and none is IPv6" in g]


def test_scope_from_addresses_reads_only_the_rows_own_family(tmp_path):
    columns = ("ComputerName", "aid", "port", "address_family", "LocalAddressIP4",
               "LocalAddressIP6", "events")
    rows, gaps = _read(tmp_path, [
        {"ComputerName": WEB, "aid": SID[WEB], "port": "22/tcp", "address_family": "ipv4",
         "LocalAddressIP4": "0.0.0.0", "events": "1"},
        {"ComputerName": APP, "aid": SID[APP], "port": "22/tcp", "address_family": "ipv6",
         "LocalAddressIP6": "::1", "events": "1"},
        # an IPv6 row carrying only an IPv4 address: that address is not read for its scope
        {"ComputerName": DC, "aid": SID[DC], "port": "22/tcp", "address_family": "ipv6",
         "LocalAddressIP4": "192.0.2.10", "events": "1"},
    ], [], HOSTS, columns=columns)
    names = _by_name(rows)
    assert names[f"listener on {WEB}:22/tcp"].extra["bind_scope"] == "all-interfaces"
    assert names[f"listener on {APP}:22/tcp"].extra["bind_scope"] == "localhost"
    assert names[f"listener on {DC}:22/tcp"].extra["bind_scope"] == "unknown"
    assert [g for g in _gap_texts(gaps) if g.startswith("1 of 3 CrowdStrike")]


@pytest.mark.parametrize("addr, scope", [
    ("0.0.0.0", "all-interfaces"), ("::", "all-interfaces"), ("[::]", "all-interfaces"),
    ("127.0.0.1", "localhost"), ("::1", "localhost"),
    ("198.51.100.4", "interface"), ("2001:db8::4", "interface"), ("", "")])
def test_address_scope(addr, scope):
    assert reader.address_scope(addr) == scope


def test_split_port_reads_protocol_numbers_and_rejects_names():
    assert reader.split_port("443/TCP") == ("443", "tcp")
    assert reader.split_port("53", "17") == ("53", "udp")
    assert reader.split_port("https/tcp") == ("", "")


def test_a_machine_name_shared_by_two_sensors_is_shown_with_each_sensor(tmp_path):
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd", sid="c" * 32),
                               _listen(WEB, "22/tcp", "sshd", sid="d" * 32)], [], HOSTS)
    names = _by_name(rows)
    assert f"OpenSSH server on {WEB} [cccccccc]:22/tcp" in names
    assert f"OpenSSH server on {WEB} [dddddddd]:22/tcp" in names


def test_further_exports_override_the_machine_type_only_when_they_agree(tmp_path):
    hosts = [*HOSTS, _host(LAB, "Ubuntu 24.04", "Desktop")]
    first = _file(tmp_path / "types1.csv", ("aid", "ProductType"),
                  [{"aid": SID[LAB], "ProductType": "3"}, {"aid": SID[WEB], "ProductType": "1"}])
    second = _file(tmp_path / "types2.csv", ("aid", "ProductType"),
                   [{"aid": SID[LAB], "ProductType": "server"},
                    {"aid": SID[WEB], "ProductType": "Server"}])
    rows, _ = _read(tmp_path, [_listen(LAB, "22/tcp", "sshd"), _listen(WEB, "22/tcp", "sshd")],
                    [], hosts, type_paths=[first, second])
    names = _by_name(rows)
    assert names[f"OpenSSH server on {LAB}:22/tcp"].extra["host_type"] == "Server"
    # one export says Desktop, the other Server: no single reading, so the host export stands
    assert names[f"OpenSSH server on {WEB}:22/tcp"].extra["host_type"] == "Server"


def test_settings_name_other_headings_and_lists_of_headings(tmp_path):
    path = _file(tmp_path / "l.csv", ("Machine", "Sensor", "Svc", "Count"),
                 [{"Machine": WEB, "Sensor": SID[WEB], "Svc": "23", "Count": "2"}])
    out = reader.step(replace(ctx(reader.PLUGIN, path, {
        "columns": {"listeners": {"host": "Machine", "sensor_id": ["Missing", "Sensor"],
                                  "port": "Svc", "events": "Count"}}}), port_table=TABLE))
    names = _by_name(out.records)
    assert f"listener on {WEB}:23" in names


def test_the_loopback_row_by_default_and_when_the_profile_says_the_source_cannot_see(tmp_path):
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd")], [], HOSTS)
    row = _by_name(rows)["Loopback-only listeners: none in the CrowdStrike export"]
    assert row.verdict == "n/a" and row.extra["hosts_in_scope"] == "1"
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd", scope="localhost")], [], HOSTS,
                    loopback_binds_reported=False)
    names = _by_name(rows)
    assert "Loopback-only listeners are not observable through CrowdStrike" in names
    assert "Loopback-only listeners: none in the CrowdStrike export" not in names


def test_the_loopback_row_when_the_profile_says_the_sensors_report_loopback(tmp_path):
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd")], [], HOSTS,
                    loopback_binds_reported=True)
    row = _by_name(rows)["Loopback-only listeners: none in the CrowdStrike export"]
    assert "report listeners bound to the loopback address" in row.notes
    assert "not established" not in row.notes and "not established" not in row.role
    rows, _ = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd", scope="localhost")], [], HOSTS,
                    loopback_binds_reported=True)
    assert not [a for a in rows if a.name.startswith("Loopback-only listeners")]


def test_no_input_and_a_missing_file_each_give_one_gap(tmp_path):
    out = reader.step(ctx(reader.PLUGIN, None))
    assert not out.records and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED
    rows, gaps = reader.read(tmp_path / "absent.csv")
    assert not rows and "was named and not found" in str(gaps[0])


def test_an_export_at_the_row_limit_is_read_as_cut_short(tmp_path):
    many = [_listen(WEB, f"{1024 + n}/tcp", events=1) for n in range(200)]
    _rows, gaps = _read(tmp_path, many, [], HOSTS, row_limit=200)
    assert [g for g in gaps if coverage.kind_of(g) == coverage.EXTENT_UNKNOWN
            and "200 rows" in str(g)]
    limit = reader.ROW_LIMIT
    assert reader.looks_cut_short(limit) and reader.looks_cut_short(limit * 5 // 2)
    assert not reader.looks_cut_short(limit - 1) and not reader.looks_cut_short(limit + 1)


def test_gaps_for_ipv4_only_no_family_no_accepts_and_no_hosts(tmp_path):
    _rows, gaps = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd")])
    texts = _gap_texts(gaps)
    assert [t for t in texts if "IPv4 and none is IPv6" in t]
    assert [t for t in texts if t.startswith("no CrowdStrike Falcon accept export")]
    hosts = [g for g in gaps if str(g).startswith("no CrowdStrike Falcon host export")]
    assert hosts and not coverage.is_required(hosts[0])
    _rows, gaps = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd", family="")], [], HOSTS)
    assert [t for t in _gap_texts(gaps) if "says no row's address family" in t]


def test_an_accept_export_without_a_machine_column(tmp_path):
    apath = _file(tmp_path / "a.csv", ("port", "program", "events"),
                  [{"port": f"{P1}/tcp", "program": "nginx", "events": "3"}])
    lpath = _file(tmp_path / "l.csv", LISTENER_COLUMNS, [_listen(WEB, f"{P1}/tcp")])
    rows, gaps = reader.read(lpath, accepts=apath, dictionary=WORDS, port_table=TABLE)
    assert f"nginx on {WEB}:{P1}/tcp" in _by_name(rows)
    assert [g for g in _gap_texts(gaps) if "has no machine column" in g]


def test_machines_with_no_listener_row_are_a_gap_against_the_host_export(tmp_path):
    _rows, gaps = _read(tmp_path, [_listen(WEB, "22/tcp", "sshd")], [], HOSTS)
    blind = [g for g in gaps if str(g).startswith("2 of 3 machines")]
    assert blind and coverage.kind_of(blind[0]) == coverage.EXTENT_UNKNOWN
    assert "Windows 11 Workstation" in str(blind[0])
