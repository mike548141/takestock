"""Requirements derived from findings, on a synthetic observation of Example Widgets Ltd.

Every host is under example.test and every address is a documentation address.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from openpyxl import load_workbook

from takestock import config, coverage, requirements
from takestock.model import CryptoAsset, dump_assets
from takestock.requirements import derive, load_catalogue, validate_catalogue


@pytest.fixture(scope="module")
def catalogue() -> list[dict]:
    return load_catalogue(config.BUNDLED_DATA_DIR / requirements.CATALOGUE_FILE)


def ids(reqs) -> list[str]:
    return [r.id for r in reqs]


def by_id(reqs, rid):
    return next(r for r in reqs if r.id == rid)


def tls(host: str, *, versions=("TLSv1.2", "TLSv1.3"), flags=(), verdict="acceptable",
        port="443", **kw) -> CryptoAsset:
    return CryptoAsset(name=f"TLS {host}:{port}", data_state="in-transit", protocol="tls",
                       host=host, port=port, protocol_versions=list(versions),
                       flags=list(flags), verdict=verdict, **kw)


def mail(protocol: str, domain: str = "example.test", flags=(), **kw) -> CryptoAsset:
    return CryptoAsset(name=f"{protocol} {domain}", data_state="email-auth",
                       protocol=protocol, host=domain, flags=list(flags), **kw)


def clean_mail(domain: str = "example.test") -> list[CryptoAsset]:
    """A domain whose mail records trigger nothing."""
    return [mail("mx", domain), mail("spf", domain, ["hardfail-all"]),
            mail("dmarc", domain, ["dmarc-reject"]), mail("mta-sts", domain, ["enforce"]),
            mail("tls-rpt", domain)]


# ── the catalogue itself ──

def test_the_bundled_catalogue_loads_and_every_entry_cites_a_standard(catalogue):
    assert catalogue
    for e in catalogue:
        assert e["level"] in requirements.LEVELS
        assert e["standards"], e["id"]
        assert re.fullmatch(r"[A-Z]+\.\d+", e["id"]), e["id"]


def test_the_catalogue_covers_the_areas_it_is_written_for(catalogue):
    prefixes = {e["id"].split(".")[0] for e in catalogue}
    assert {"TLS", "CERT", "WEB", "MAIL", "SSH", "VPN", "CLR", "DNS", "KEY", "PQC",
            "GAP"} <= prefixes


def test_the_catalogue_uses_every_trigger_kind(catalogue):
    keys = {k for e in catalogue for c in e["triggered_by"] for k in c}
    assert {"verdict", "protocol", "flags_any", "flags_prefix_any", "disposition",
            "gap_kinds", "absent", "versions_none", "extra_true"} <= keys


def _source_text() -> str:
    pkg = Path(requirements.__file__).parent
    return "\n".join(p.read_text() for p in pkg.rglob("*.py") if p.name != "requirements.py")


def test_every_flag_the_catalogue_names_is_one_takestock_can_raise(catalogue):
    """A misspelt flag would make a clause that can never fire."""
    src = _source_text()

    def whole(word: str) -> bool:
        return re.search(rf"(?<![a-z0-9-]){re.escape(word)}(?![a-z0-9-])", src) is not None

    exact, prefixes = set(), set()
    for e in catalogue:
        for c in e["triggered_by"]:
            for key in ("flags_any", "flags_all", "flags_none"):
                exact.update(c.get(key, []))
            for key in ("flags_prefix_any", "flags_prefix_none"):
                prefixes.update(c.get(key, []))
    missing = []
    for flag in sorted(exact):
        head, _, tail = flag.partition(":")
        if not (whole(flag) or (tail and whole(head) and whole(tail))):
            missing.append(flag)
    missing += [p for p in sorted(prefixes) if p.rstrip(":") not in src]
    assert not missing


@pytest.mark.parametrize("entry, message", [
    ({"level": "MAY"}, "level"),
    ({"triggered_by": [{"flags_any": ["expired"]}]}, "finding phrase"),
    ({"triggered_by": [{"colour": "red", "finding": "x"}]}, "unknown trigger keys"),
    ({"triggered_by": [{"gap_kinds": ["not-collected"], "protocol": "tls",
                        "finding": "x"}]}, "cannot be combined"),
    ({"triggered_by": [{"gap_kinds": ["missing"], "finding": "x"}]}, "unknown gap kinds"),
    ({"triggered_by": [{"absent": {"anchor": "mx"}, "finding": "x"}]}, "anchor and missing"),
    ({"standards": [{"ref": "RFC 0000"}]}, "ref, level and says"),
    ({"statement": ""}, "missing"),
])
def test_a_malformed_entry_is_refused(entry, message):
    base = {"id": "X.1", "level": "MUST", "area": "a", "name": "n", "statement": "s",
            "standards": [{"ref": "r", "level": "MUST", "says": "s"}],
            "selection_test": "t", "acceptance_test": "t",
            "triggered_by": [{"flags_any": ["expired"], "finding": "f"}]}
    with pytest.raises(ValueError, match=message):
        validate_catalogue([{**base, **entry}])


def test_a_duplicate_id_is_refused():
    e = {"id": "X.1", "level": "MUST", "area": "a", "name": "n", "statement": "s",
         "standards": [{"ref": "r", "level": "MUST", "says": "s"}],
         "selection_test": "t", "acceptance_test": "t",
         "triggered_by": [{"flags_any": ["expired"], "finding": "f"}]}
    with pytest.raises(ValueError, match="duplicate"):
        validate_catalogue([e, dict(e)])


# ── nothing is emitted without a finding ──

def test_an_empty_observation_triggers_nothing(catalogue):
    assert derive([], catalogue) == []


def test_a_clean_estate_triggers_nothing(catalogue):
    assets = [tls("www.example.test", verdict="strong"),
              tls("portal.example.test", verdict="strong"),
              *clean_mail(),
              CryptoAsset(name="DNSSEC example.test", data_state="in-transit",
                          protocol="dnssec", host="example.test", verdict="strong")]
    assert derive(assets, catalogue, [coverage.Gap(coverage.UNCLASSIFIED, "an old note")]) == []


def test_only_triggered_requirements_are_emitted(catalogue):
    reqs = derive([tls("old.example.test", versions=["TLSv1.0", "TLSv1.2", "TLSv1.3"],
                       flags=["deprecated-protocol:TLSv1.0"])], catalogue)
    assert ids(reqs) == ["TLS.1"]


# ── each trigger kind fires, and does not fire ──

def test_verdict_trigger(catalogue):
    weak = tls("legacy.example.test", verdict="weak", flags=["weak-floor"])
    assert "KEY.1" in ids(derive([weak], catalogue))
    assert "KEY.1" not in ids(derive([tls("legacy.example.test")], catalogue))


def test_verdict_trigger_skips_rows_with_no_cryptography(catalogue):
    cleartext = CryptoAsset(name="telnet", data_state="in-transit", host="printer.example.test",
                            port="23", verdict="weak", flags=["plaintext:telnet", "weak-floor"])
    reqs = derive([cleartext], catalogue)
    assert "KEY.1" not in ids(reqs)
    assert "CLR.1" in ids(reqs)


def test_exact_flag_trigger(catalogue):
    cert = CryptoAsset(name="certificate shop.example.test", data_state="certificate",
                       protocol="tls", host="shop.example.test", flags=["expired"])
    assert ids(derive([cert], catalogue)) == ["CERT.1"]
    cert.flags = []
    assert derive([cert], catalogue) == []


def test_flag_prefix_trigger_respects_the_protocol(catalogue):
    smb = CryptoAsset(name="SMB files.example.test", data_state="in-transit", protocol="smb",
                      host="files.example.test", port="445",
                      flags=["deprecated-protocol:SMB1"])
    assert "TLS.1" not in ids(derive([smb], catalogue))
    old = tls("files.example.test", versions=["TLSv1.1", "TLSv1.3"],
              flags=["deprecated-protocol:TLSv1.1"])
    assert "TLS.1" in ids(derive([old], catalogue))


def test_protocol_trigger(catalogue):
    lax = [a for a in clean_mail() if a.protocol != "dmarc"] + [mail("dmarc", flags=[])]
    reqs = derive(lax, catalogue)
    assert ids(reqs) == ["MAIL.6"]
    assert "DMARC policy is not p=reject" in by_id(reqs, "MAIL.6").evidence
    assert derive(clean_mail(), catalogue) == []


def test_absent_trigger(catalogue):
    no_dmarc = [a for a in clean_mail() if a.protocol != "dmarc"]
    reqs = derive(no_dmarc, catalogue)
    assert ids(reqs) == ["MAIL.6"]
    assert "1 domain where MX records are published and no DMARC record is " \
           "(example.test)" in by_id(reqs, "MAIL.6").evidence


def test_absent_trigger_ignores_case_and_trailing_dots(catalogue):
    assets = clean_mail()
    for a in assets:
        if a.protocol == "dmarc":
            a.host = "Example.Test."
    assert derive(assets, catalogue) == []


def test_disposition_trigger(catalogue):
    accepted = CryptoAsset(name="tftp", data_state="in-transit", host="pxe.example.test",
                           port="69", verdict="weak", flags=["plaintext:tftp"],
                           disposition="accept-no-alternative")
    clr2 = by_id(derive([accepted], catalogue), "CLR.2")
    assert [m.finding for m in clr2.matches] == [
        "a cleartext service is accepted because no alternative exists"]
    accepted.disposition = ""
    assert "CLR.2" not in ids(derive([accepted], catalogue))


def test_gap_kind_trigger(catalogue):
    not_collected = coverage.gap(coverage.NOT_COLLECTED,
                                 "Print-server export for `print-01` not supplied")
    could_not_test = coverage.gap(coverage.COULD_NOT_TEST,
                                  "2 hosts refused the probe on port 443")
    reqs = derive([], catalogue, [not_collected])
    assert ids(reqs) == ["GAP.1"]
    assert '1 coverage gap where an input was not collected or is known to be incomplete ' \
           '(for example: "Print-server export for `print-01` not supplied")' \
           in by_id(reqs, "GAP.1").evidence
    assert ids(derive([], catalogue, [could_not_test])) == ["GAP.2"]


def test_plain_string_gaps_read_as_unclassified_and_trigger_nothing(catalogue):
    assert derive([], catalogue, ["something was not read"]) == []


def test_versions_trigger(catalogue):
    assert "TLS.2" in ids(derive([tls("a.example.test", versions=["TLSv1.2"])], catalogue))
    assert "TLS.2" not in ids(derive([tls("a.example.test")], catalogue))
    unread = tls("a.example.test", versions=[])
    assert "TLS.2" not in ids(derive([unread], catalogue))


def test_versions_trigger_reads_scanner_spellings(catalogue):
    assert "TLS.2" not in ids(derive([tls("a.example.test", versions=["TLS1.2", "TLS1.3"])],
                                     catalogue))


def test_extra_trigger(catalogue):
    gw = CryptoAsset(name="IKE vpn.example.test:500", data_state="in-transit", protocol="ike",
                     host="vpn.example.test", ip="192.0.2.10", port="500",
                     verdict="strong", extra={"responded": True})
    assert "VPN.2" in ids(derive([gw], catalogue))
    gw.extra = {"responded": False}
    assert "VPN.2" not in ids(derive([gw], catalogue))


def test_internet_facing_key_matches_only_a_known_true():
    clause = {"internet_facing": True, "finding": "f"}
    assert requirements.asset_matches(tls("a.example.test", internet_facing=True), clause)
    assert not requirements.asset_matches(tls("a.example.test"), clause)


# ── evidence carries the run's own counts ──

def test_evidence_counts_and_hosts_come_from_the_observation(catalogue):
    hosts = [f"web-{n:02d}.example.test" for n in range(1, 8)]
    assets = [tls(h, versions=["TLSv1.0", "TLSv1.2"], flags=["deprecated-protocol:TLSv1.0"])
              for h in hosts]
    ev = by_id(derive(assets, catalogue), "TLS.1").evidence
    assert ev.startswith("Triggered by 7 assets where SSL or a TLS version below 1.2 is "
                         "accepted (web-01.example.test:443, ")
    assert "and 2 more)." in ev

    ev_one = by_id(derive(assets[:1], catalogue), "TLS.1").evidence
    assert ev_one == ("Triggered by 1 asset where SSL or a TLS version below 1.2 is accepted "
                      "(web-01.example.test:443).")


def test_evidence_names_each_clause_that_matched(catalogue):
    spf = mail("spf", flags=["softfail-all", "duplicate-spf"])
    assets = [a for a in clean_mail() if a.protocol != "spf"] + [spf, mail("mx", "example.com")]
    ev = by_id(derive(assets, catalogue), "MAIL.4").evidence
    assert "1 asset where the SPF record ends in a soft fail" in ev
    assert "1 asset where more than one SPF record is published" in ev
    assert "1 domain where MX records are published and no SPF record is (example.com)" in ev


def test_findings_count_sums_the_clauses(catalogue):
    certs = [CryptoAsset(name=f"certificate {h}", data_state="certificate", protocol="tls",
                         host=h, flags=[f])
             for h, f in (("a.example.test", "expired"), ("b.example.test", "expiry-soon"),
                          ("c.example.test", "expiry-soon"))]
    r = by_id(derive(certs, catalogue), "CERT.1")
    assert r.findings_count == 3
    assert [m.count for m in r.matches] == [1, 2]


# ── outputs ──

def _write_observation(d: Path) -> None:
    assets = [tls("www.example.test", versions=["TLSv1.0", "TLSv1.2"],
                  flags=["deprecated-protocol:TLSv1.0", "cbc-mode"], ip="203.0.113.5"),
              mail("mx"), mail("spf", flags=["hardfail-all"]),
              mail("dkim", flags=["weak-key-1024"])]
    d.mkdir()
    (d / "assets.json").write_text(json.dumps(dump_assets(assets)))
    (d / "summary.json").write_text(json.dumps({
        "gaps": ["Badge-reader export for 12 doors not supplied", "an unclassified note"],
        "gap_kinds": [coverage.NOT_COLLECTED]}))


def test_load_observation_reads_gaps_and_their_kinds(tmp_path):
    obs = tmp_path / "obs"
    _write_observation(obs)
    assets, gaps = requirements.load_observation(obs)
    assert len(assets) == 4
    assert coverage.kinds(gaps) == [coverage.NOT_COLLECTED, coverage.UNCLASSIFIED]


def test_command_writes_markdown_workbook_and_json(tmp_path, capsys):
    obs, out = tmp_path / "obs", tmp_path / "out"
    _write_observation(obs)
    assert requirements.main([str(obs), str(out)]) == 0
    expected = ["TLS.1", "TLS.2", "TLS.4", "MAIL.5", "MAIL.6", "GAP.1"]
    assert f"{len(expected)} requirements triggered" in capsys.readouterr().out

    data = json.loads((out / "requirements.json").read_text())
    assert [r["id"] for r in data["requirements"]] == expected
    assert data["source"] == "obs"

    md = (out / "requirements.md").read_text()
    assert "### TLS.1 · MUST — Refuse SSL and every TLS version below 1.2" in md
    assert "- **Evidence:** Triggered by 1 asset where SSL or a TLS version below 1.2 " \
           "is accepted (www.example.test:443)." in md
    assert md.count("\n### ") == len(expected)

    ws = load_workbook(out / "requirements.xlsx")["Requirements"]
    header = [c.value for c in ws[1]]
    assert header[:2] == ["ID", "Level"]
    assert header[-3:] == list(requirements.RESPONSE_COLUMNS)
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert [r[0] for r in rows] == expected
    assert all(r[-3:] == (None, None, None) for r in rows)


def test_the_command_refuses_the_wrong_arguments(capsys):
    assert requirements.main(["only-one"]) == 2
    assert "usage" in capsys.readouterr().err


def test_an_empty_register_still_writes_all_three(tmp_path):
    paths = requirements.write_outputs([], tmp_path)
    assert "No finding in this observation triggers" in paths["md"].read_text()
    assert json.loads(paths["json"].read_text())["requirements"] == []
    assert load_workbook(paths["xlsx"])["Requirements"].max_row == 1
