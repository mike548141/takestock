"""One count over an observation: service findings by what could be put in front of them.

Every row, protocol and host is invented. The protocols ``alpha``, ``beta`` and
``gamma`` stand in for real ones so no test depends on the bundled table's
content, apart from the one test that reads the bundled table on purpose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takestock import config, fronting, plaintext
from takestock.model import CryptoAsset

HEADER = ("port", "transport", "protocol", "posture", "exposure", "remediability", "frontable", "notes")


def row(port, protocol, posture, frontable="n/a", exposure="n/a") -> dict[str, str]:
    return dict(zip(HEADER, (port, "tcp", protocol, posture, exposure, "n/a", frontable, ""),
                    strict=True))


TABLE = plaintext.build_index([
    row("61", "alpha", "cleartext", "reverse-web-proxy", exposure="content"),
    row("62", "beta", "opportunistic", "ssh-tunnel-only"),
    row("63", "gamma", "cleartext", "unresearched", exposure="content"),
    row("64", "delta", "opportunistic", "reverse-web-proxy"),
])


def svc(host, *flags, name="") -> CryptoAsset:
    return CryptoAsset(name=name or f"service on {host}", data_state="in-transit",
                       host=host, flags=list(flags))


def test_a_finding_is_counted_under_the_class_its_protocol_names():
    b = fronting.fronting_breakdown([svc("a.example.test", "plaintext:alpha")], TABLE)
    assert set(b.by_class) == {"reverse-web-proxy"}
    assert b.by_class["reverse-web-proxy"].findings == 1
    assert b.by_class["reverse-web-proxy"].protocols == {"alpha": 1}


def test_both_finding_flags_count_and_nothing_else_does():
    assets = [svc("a.example.test", "plaintext:alpha", "unverified-encryption:beta",
                  "cleartext-exposure:alpha", "no-encrypted-alternative:alpha",
                  "weak-floor:tls")]
    b = fronting.fronting_breakdown(assets, TABLE)
    assert b.total == 2
    assert (b.cleartext, b.opportunistic) == (1, 1)


def test_the_split_always_sums_to_the_total():
    assets = [svc(f"h{i}.example.test", "plaintext:alpha", "unverified-encryption:delta",
                  "unverified-encryption:beta") for i in range(7)]
    b = fronting.fronting_breakdown(assets, TABLE)
    assert b.total == b.cleartext + b.opportunistic == 21
    assert sum(c.findings for c in b.by_class.values()) == b.total
    for c in b.by_class.values():
        assert c.findings == c.cleartext + c.opportunistic


def test_hosts_are_distinct_per_class_and_the_total_is_their_union():
    assets = [svc("a.example.test", "plaintext:alpha", "unverified-encryption:beta"),
              svc("a.example.test", "plaintext:alpha"),
              svc("b.example.test", "unverified-encryption:beta")]
    b = fronting.fronting_breakdown(assets, TABLE)
    assert b.by_class["reverse-web-proxy"].host_count == 1
    assert b.by_class["ssh-tunnel-only"].host_count == 2
    assert b.total_hosts == 2
    assert sum(c.host_count for c in b.by_class.values()) == 3  # one machine sits in two classes


def test_an_asset_with_no_host_is_counted_by_its_name():
    b = fronting.fronting_breakdown([svc("", "plaintext:alpha", name="appliance-1")], TABLE)
    assert b.by_class["reverse-web-proxy"].hosts == {"appliance-1"}


def test_a_protocol_with_no_row_is_a_visible_class_not_a_dropped_finding():
    b = fronting.fronting_breakdown([svc("a.example.test", "plaintext:unlisted")], TABLE)
    assert b.total == 1
    assert b.by_class[fronting.NO_ROW].findings == 1


def test_an_observation_with_no_findings_counts_nothing():
    b = fronting.fronting_breakdown([svc("a.example.test", "weak-floor:tls")], TABLE)
    assert (b.total, b.cleartext, b.opportunistic, b.total_hosts, b.by_class) == (0, 0, 0, 0, {})


def test_a_protocol_with_two_answers_is_refused_rather_than_resolved_by_row_order():
    ambiguous = {"1/tcp": {"protocol": "alpha", "frontable": "reverse-web-proxy"},
                 "1/udp": {"protocol": "alpha", "frontable": "ssh-tunnel-only"}}
    with pytest.raises(ValueError, match="alpha.*two frontable answers"):
        fronting.frontable_by_protocol(ambiguous)
    with pytest.raises(ValueError):
        fronting.fronting_breakdown([], ambiguous)


def test_rows_without_a_protocol_are_ignored_by_the_index():
    table = {"1/tcp": {"protocol": "", "frontable": "n/a"},
             "2/tcp": {"protocol": "alpha", "frontable": "reverse-web-proxy"}}
    assert fronting.frontable_by_protocol(table) == {"alpha": "reverse-web-proxy"}


def test_the_bundled_table_is_unambiguous_and_every_class_it_names_is_valid():
    answers = fronting.frontable_by_protocol(config.load_port_encryption())
    assert answers
    valid = {*plaintext.VALID_FRONTABILITIES, plaintext.FRONTABLE_NOT_APPLICABLE}
    assert set(answers.values()) <= valid


def test_the_markdown_carries_the_split_beside_the_total_largest_class_first():
    assets = [svc("a.example.test", "plaintext:alpha", "plaintext:alpha"),
              svc("b.example.test", "unverified-encryption:beta")]
    lines = fronting.fronting_breakdown(assets, TABLE).markdown().splitlines()
    assert lines[0].startswith("| Class | Findings | Distinct hosts | Cleartext by port")
    assert lines[2].startswith("| `reverse-web-proxy` | 2 | 1 | 2 | 0 |")
    assert lines[3].startswith("| `ssh-tunnel-only` | 1 | 1 | 0 | 1 |")
    assert lines[-1] == "| **Total** | **3** | **2** | **2** | **1** |"


def _observation(tmp_path: Path, assets: list[CryptoAsset]) -> Path:
    from dataclasses import asdict
    (tmp_path / "assets.json").write_text(json.dumps([asdict(a) for a in assets]))
    return tmp_path


def test_a_stored_observation_gives_the_same_count_as_the_assets_it_holds(tmp_path):
    assets = [svc("a.example.test", "plaintext:alpha"), svc("b.example.test", "unverified-encryption:beta")]
    stored = fronting.breakdown_for_observation(_observation(tmp_path, assets), TABLE)
    direct = fronting.fronting_breakdown(assets, TABLE)
    assert stored.markdown() == direct.markdown()


def test_the_command_prints_the_table_and_refuses_a_wrong_argument_count(tmp_path, capsys):
    port = config.load_port_encryption()
    protocol = next(r["protocol"] for r in port.values() if r.get("protocol"))
    obs = _observation(tmp_path, [svc("a.example.test", f"plaintext:{protocol}")])
    assert fronting.main([str(obs)]) == 0
    assert "| **Total** | **1** |" in capsys.readouterr().out
    assert fronting.main([]) == 2
    assert "usage" in capsys.readouterr().err
