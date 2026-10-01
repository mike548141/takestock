"""Zone files read against the rest of a run: dangling records, delegation, coverage, services."""

from __future__ import annotations

from datetime import UTC, datetime

from dnsfake import RESOLVERS, dig_text, table_reader

from takestock import config, coverage
from takestock.collectors import dns_zones
from takestock.model import CryptoAsset

NOW = datetime(2030, 6, 15, tzinfo=UTC)

APEX = """\
$TTL 300
@        IN SOA ns1.example.com. host.example.com. 1 2 3 4 5
@        IN NS  ns1.example.com.
@        IN CAA 0 issue "ca.example.net"
@        IN TXT "v=spf1 -all"
@        IN TXT "v=spf1 ~all"
@        IN TXT "example-site-verification=token123"
@        IN TXT "widget-proof=token456"
www      IN A 192.0.2.10
old      IN CNAME gone.apps-host.example.
stale    IN CNAME missing.example.org.
shop     IN CNAME shops.hosting.example.net.
mail     IN A 192.0.2.25
_tls._tcp IN SRV 0 0 443 www.example.com.
"""

LAB = "@ IN SOA ns1.example.com. host.example.com. 1 2 3 4 5\nhost IN A 192.0.2.50\n"


def _inbox(tmp_path, stamp: bool = True):
    d = tmp_path / "inbox" / "dns-zones"
    (d / "private").mkdir(parents=True)
    (d / "example.com.zone").write_text(APEX)
    (d / "lab.example.com.zone").write_text(LAB)
    (d / "corp.test.zone").write_text("@ IN A 192.0.2.60\n")
    (d / "private" / "internal.example.json").write_text(
        '[{"fqdn": "internal.example.", "type": "x/SOA", "soaRecord": {}}]')
    if stamp:
        (d / dns_zones.STAMP_FILE).write_text("2030-06-01T00:00:00Z\n")
    config.set_workspace(tmp_path)
    return d


def _reader():
    table = {}
    for r in RESOLVERS:
        for name in ("gone.apps-host.example", "missing.example.org"):
            table[(name, r)] = dig_text("NXDOMAIN")
        for name in ("shops.hosting.example.net", "www.example.com"):
            table[(name, r)] = dig_text("NOERROR", answer=[f"{name}. 60 IN A 192.0.2.1"])
    return table_reader(table, "__ERROR__ timed out")


def _collect(tmp_path, population=(), target=None):
    target = target or {
        "dns": {"takeover_namespaces": {"apps-host.example": "Example Cloud web app"}},
        "dns_zones": {"proof_prefixes": {"widget-proof": "Widget Proofs Inc"},
                      "resolved_names": "inbox/resolved.csv"},
        "third_party": [{"name": "Example Hosting", "domains": ["hosting.example.net"]}],
    }
    return dns_zones.collect(target, tmp_path, list(population), NOW, reader=_reader(),
                             resolvers=RESOLVERS)


def test_dangling_records_and_claimable_namespaces(tmp_path):
    _inbox(tmp_path)
    assets, _ = _collect(tmp_path)
    dangling = {a.host: a for a in assets if dns_zones.DANGLING in a.flags}
    assert set(dangling) == {"old.example.com", "stale.example.com"}
    assert dns_zones.CLAIMABLE_FLAG in dangling["old.example.com"].flags
    assert "Example Cloud web app" in dangling["old.example.com"].notes
    assert dns_zones.NOT_LISTED in dangling["stale.example.com"].flags
    assert dangling["old.example.com"].verdict == "n/a"


def test_an_undelegated_zone_is_reported(tmp_path):
    _inbox(tmp_path)
    assets, _ = _collect(tmp_path)
    nd = next(a for a in assets if dns_zones.NOT_DELEGATED in a.flags)
    assert nd.host == "lab.example.com" and "1 A" in nd.notes
    assert nd.extra["parent_zone"] == "example.com"


def test_names_measured_elsewhere_and_by_endpoints(tmp_path):
    _inbox(tmp_path)
    (tmp_path / "inbox" / "resolved.csv").write_text("name\nmail.example.com\n")
    population = [CryptoAsset(name="certificate www.example.com", data_state="certificate",
                              host="www.example.com")]
    assets, _ = _collect(tmp_path, population)
    row = next(a for a in assets if a.name == "DNS names nobody measured")
    assert row.extra["resolved_by_endpoints_only"] == ["mail.example.com"]
    assert [u["name"] for u in row.extra["unmeasured"]] == [
        "old.example.com", "shop.example.com", "stale.example.com"]


def test_outside_services_and_the_scope_row(tmp_path):
    _inbox(tmp_path)
    caa = CryptoAsset(name="CAA example.com", data_state="email-auth", protocol="caa",
                      host="example.com", source="caa",
                      extra={"records": [{"flags": 0, "tag": "issue", "value": "other.example"}]})
    assets, gaps = _collect(tmp_path, [caa])
    services = next(a for a in assets if a.name.startswith("Outside services")).extra["services"]
    assert "Widget Proofs Inc" in services and "example-site-verification" in services
    assert services["Example Hosting"] == ["CNAME shop.example.com"]
    assert "example.org" in services  # an unknown target is named by its registered domain
    scope = assets[0]
    assert scope.name == "DNS zone files — scope"
    assert {dns_zones.SCOPE_FLAG, dns_zones.DUPLICATE_SPF, dns_zones.CAA_DIFFERS} <= set(scope.flags)
    assert scope.extra["reserved_zones"] == ["corp.test"]
    assert scope.extra["undelegated"] == {"lab.example.com": "example.com"}
    assert scope.extra["private_zones"] == {"internal.example": 1}
    assert scope.collected_at == "2030-06-01"
    assert any("internal DNS zone" in g for g in gaps)


def test_no_zone_files_is_a_gap(tmp_path):
    config.set_workspace(tmp_path)
    assets, gaps = dns_zones.collect({}, tmp_path, [], NOW, reader=_reader(), resolvers=RESOLVERS)
    assert assets == []
    assert coverage.kind_of(gaps[0]) == coverage.NOT_COLLECTED
    assert gaps[0].startswith("inbox/dns-zones/")


def test_helpers():
    assert dns_zones.verdict_of({"a": "NXDOMAIN"}) == "unverified"
    assert dns_zones.verdict_of({"a": "NXDOMAIN", "b": "NXDOMAIN", "c": "error: x"}) == "nxdomain"
    assert dns_zones.verdict_of({"a": "NOERROR", "b": "NXDOMAIN"}) == "exists"
    assert dns_zones.registrable("a.b.example.ac.zz") == "example.ac.zz"
    assert dns_zones.registrable("a.example.com") == "example.com"
    assert dns_zones.registrable("a.example.gen.zz", {"gen"}) == "example.gen.zz"
    assert dns_zones.proof_service("v=spf1 -all") == ""
    assert dns_zones.proof_service("plain text") == ""
    assert dns_zones.claimable("x.apps-host.example", {"apps-host.example": "C"}) == "C"
    assert dns_zones.declared_vendor_domains(
        {"scan_targets": {"saas_443": [{"vendor": "Example SaaS", "domains": ["saas.example"]}]}}
    ) == {"saas.example": "Example SaaS"}
