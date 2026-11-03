"""The CrowdStrike Falcon HTTP request reader in takestock's readers library.

Each export is composed in its test, under the reader's default headings (or
others named in the settings), with made-up machines, ``example.test``
destinations, documentation addresses and small counts. Nothing here was
captured from a real export.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import config, coverage
from takestock.readers import falcon_http as reader
from takestock.readers import library

COLUMNS = ("aid", "ComputerName", "HttpHost", "RemotePort", "ImageFileName", "_count")
WIDGET = "C:\\Program Files\\Example\\widget.exe"
AGENT = "/opt/example/bin/agentd"
#: An address in IPv4's link-local block (RFC 3927), written as an integer.
LINK_LOCAL = str(ipaddress.IPv4Address(0xA9FE0007))


def _export(path: Path, rows: list[dict], columns: tuple[str, ...] = COLUMNS) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _run(path: Path | None, settings: dict | None = None):
    c = dataclasses.replace(ctx(reader.PLUGIN, path, settings),
                            port_table=config.load_port_encryption())
    return reader.step(c)


def _req(agent: str, host: str, port: str, n: int, program: str = WIDGET) -> dict:
    return {"aid": agent, "ComputerName": f"ws-{agent}", "HttpHost": host, "RemotePort": port,
            "ImageFileName": program, "_count": str(n)}


def test_the_reader_is_in_the_library():
    assert library()["falcon_http"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_no_export_named_gives_one_gap_and_no_rows():
    out = _run(None)
    assert out.records == [] and len(out.gaps) == 1
    assert coverage.kind_of(out.gaps[0]) == coverage.NOT_COLLECTED


def test_split_host_reads_the_forms_a_host_header_takes():
    assert reader.split_host("Intranet.Example.Test") == ("intranet.example.test", "")
    assert reader.split_host("intranet.example.test.:8000") == ("intranet.example.test", "8000")
    assert reader.split_host("[2001:db8::5]:8443") == ("2001:db8::5", "8443")
    assert reader.split_host("[2001:db8::5]") == ("2001:db8::5", "")
    assert reader.split_host("2001:db8::5") == ("2001:db8::5", "")
    assert reader.split_host("  ") == ("", "")


def test_each_request_is_one_of_four_kinds():
    assert reader.classify("updates.example.test:443", "8443") == reader.TUNNEL
    assert reader.classify("updates.example.test:443", "443") == reader.CLEARTEXT
    assert reader.classify("localhost:8000", "8000") == reader.LOOPBACK
    assert reader.classify("api.localhost", "80") == reader.LOOPBACK
    assert reader.classify("[::1]:80", "80") == reader.LOOPBACK
    assert reader.classify("", "80") == reader.NO_HOST
    assert reader.classify("intranet.example.test", "80") == reader.CLEARTEXT


def test_a_port_the_table_calls_cleartext_is_graded_elsewhere(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [_req("a1", "intranet.example.test", "80", 6)]))
    rows = by_name(out.records)
    assert "Cleartext HTTP on 80/tcp" not in rows
    detail = rows["Cleartext HTTP to intranet.example.test:80"]
    assert detail.verdict == "n/a" and detail.flags == ["cleartext-http-detail:80"]
    assert detail.host == "" and detail.extra["destination"] == "intranet.example.test"
    assert detail.extra["graded_on"] == (
        "the outbound-connection row for port 80/tcp (falcon_connections)")
    assert detail.extra["programs"] == "widget.exe (6)"


def test_a_port_the_table_does_not_call_cleartext_gets_one_weak_row(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [
        _req("a1", "app.example.test", "8000", 4),
        _req("a2", "app.example.test", "8000", 3, AGENT),
        _req("a2", "198.51.100.20:8000", "8000", 2),
    ]))
    rows = by_name(out.records)
    port = rows["Cleartext HTTP on 8000/tcp"]
    assert port.verdict == "weak"
    assert port.flags == ["cleartext-http:8000", "cleartext-exposure:content"]
    assert port.usage_count == 9 and port.hosts_count == 2
    assert port.extra["destinations"] == "2"
    assert port.extra["destinations_top"] == "app.example.test (7); 198.51.100.20 (2)"
    assert port.extra["programs"] == "widget.exe (6); agentd (3)"
    detail = rows["Cleartext HTTP to app.example.test:8000"]
    assert detail.extra["graded_on"] == 'the row "Cleartext HTTP on 8000/tcp"'


def test_a_host_header_naming_another_port_is_noted(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [_req("a1", "backend.example.test:8443", "80", 2)]))
    detail = by_name(out.records)["Cleartext HTTP to backend.example.test:80"]
    assert detail.extra["host_header_port"] == "8443"
    assert "names port 8443" in detail.notes


def test_a_link_local_destination_is_flagged(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [_req("a1", LINK_LOCAL, "80", 1)]))
    detail = by_name(out.records)[f"Cleartext HTTP to {LINK_LOCAL}:80"]
    assert detail.flags == ["cleartext-http-detail:80", "http-link-local"]


def test_a_proxy_port_is_split_into_tunnels_and_plain_requests(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [
        _req("a1", "updates.example.test:443", "8443", 6),
        _req("a2", "docs.example.test:443", "8443", 2),
        _req("a1", "pages.example.test", "8443", 1),
        _req("a2", "", "8443", 1),
    ]))
    split = by_name(out.records)["Proxy traffic on 8443/tcp — tunnelled against plain requests"]
    assert split.verdict == "n/a" and split.flags == ["http-connect-tunnel:8443"]
    assert split.usage_count == 10 and split.hosts_count == 2
    assert split.extra["tunnel_requests"] == "8" and split.extra["tunnel_share"] == "80.0%"
    assert split.extra["plain_requests"] == "1" and split.extra["no_host_requests"] == "1"
    assert split.extra["tunnel_targets_top"] == "updates.example.test (6); docs.example.test (2)"
    assert split.extra["loopback_requests"] == "0"


def test_loopback_and_no_host_requests_are_counted_not_graded(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [
        _req("a1", "localhost:8000", "8000", 5),
        _req("a1", "", "80", 3), _req("a2", "", "8000", 2),
    ]))
    rows = by_name(out.records)
    lb = rows["HTTP on the loopback interface"]
    assert lb.verdict == "n/a" and lb.flags == ["http-loopback"] and lb.usage_count == 5
    nh = rows["HTTP requests with no Host recorded"]
    assert nh.verdict == "unknown" and nh.flags == ["http-host-unrecorded"]
    assert nh.extra["ports"] == "2" and nh.extra["ports_top"] == "80 (3); 8000 (2)"
    assert not any(a.verdict == "weak" for a in out.records)


def test_the_scope_row_is_always_written(tmp_path):
    out = _run(_export(tmp_path / "h.csv", [_req("a1", "intranet.example.test", "80", 1),
                                            _req("a2", "", "80", 1)]))
    scope = by_name(out.records)["HTTP request export scope"]
    assert scope.verdict == "n/a" and scope.flags == ["scope-observed-not-enumerated"]
    assert scope.extra == {"machines": "2", "destinations": "1", "rows": "2"}


def test_other_headings_are_named_in_settings(tmp_path):
    path = _export(tmp_path / "h.csv",
                   [{"Agent": "a1", "Host": "app.example.test", "Port": "8000", "N": "4"}],
                   ("Agent", "Host", "Port", "N"))
    out = _run(path, {"columns": {"agent_id": "Agent", "host_header": "Host", "port": "Port",
                                  "count": "N"}})
    port = by_name(out.records)["Cleartext HTTP on 8000/tcp"]
    assert port.usage_count == 4 and port.extra["programs"] == ""
