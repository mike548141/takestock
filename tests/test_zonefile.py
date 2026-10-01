"""Zone-file and private-zone export reading."""

from __future__ import annotations

import json

from takestock import zonefile

ZONE = """\
; Zone name: example.com
; Date and time (UTC): 2030-01-01 00:00
$TTL 600
@   IN SOA ns1.example.com. hostmaster.example.com. (
        1 3600 600 86400 300 )
    IN NS  ns1.example.com.
www 300 IN A 192.0.2.10
    IN AAAA 2001:db8::10
shop IN CNAME shops.example.net.
@   IN MX 10 mail.example.com.
@   IN TXT "v=spf1 " "ip4:192.0.2.0/28 -all" ; joined strings
_sip._tcp IN SRV 10 5 5060 sip.example.org.
odd IN WEIRD something
absolute.example.com. IN A 192.0.2.20
$INCLUDE other.zone
"""


def test_owners_ttls_and_types_are_read():
    z = zonefile.parse(ZONE, "example.com")
    assert z.origin == "example.com"
    assert z.header == {"Zone name": "example.com", "Date and time (UTC)": "2030-01-01 00:00"}
    www = [r for r in z.records if r.owner == "www.example.com"]
    assert [(r.rtype, r.ttl) for r in www] == [("A", 300), ("AAAA", 600)]
    soa = z.by_type("SOA")[0]
    assert soa.owner == "example.com" and soa.rdata[-1] == "300"
    assert z.by_type("NS")[0].owner == "example.com"
    assert any(r.owner == "absolute.example.com" for r in z.by_type("A"))


def test_pointer_targets_and_txt_text():
    z = zonefile.parse(ZONE, "example.com")
    assert z.by_type("CNAME")[0].target() == "shops.example.net"
    assert z.by_type("MX")[0].target() == "mail.example.com"
    assert z.by_type("SRV")[0].target() == "sip.example.org"
    assert z.by_type("TXT")[0].text == "v=spf1 ip4:192.0.2.0/28 -all"


def test_lines_not_understood_are_kept():
    z = zonefile.parse(ZONE, "example.com")
    assert any("WEIRD" in u for u in z.unparsed)
    assert any(u.startswith("$INCLUDE") for u in z.unparsed)


def test_origin_directive_and_record_sets():
    z = zonefile.parse("$ORIGIN example.test.\na IN A 192.0.2.1\na IN A 192.0.2.2\n")
    assert z.origin == "example.test"
    assert len(z.record_sets()[("a.example.test", "A")]) == 2


def test_read_takes_the_origin_from_the_file_name(tmp_path):
    p = tmp_path / "example.test.zone"
    p.write_text("@ IN A 192.0.2.1\n")
    assert zonefile.read(p).records[0].owner == "example.test"


def test_private_export_is_read(tmp_path):
    p = tmp_path / "internal.example.json"
    p.write_text(json.dumps([
        {"fqdn": "app.internal.example.", "type": "Provider/privateDnsZones/A", "ttl": 10,
         "isAutoRegistered": True, "aRecords": [{"ipv4Address": "192.0.2.5"}]},
        {"fqdn": "internal.example.", "type": "Provider/privateDnsZones/SOA",
         "soaRecord": {"host": "ns.example.test", "email": "admin.example.test"}},
        {"fqdn": "x.internal.example.", "type": "Provider/privateDnsZones/UNKNOWN"},
        "not a record set",
    ]))
    zone, sets, error = zonefile.read_private(p)
    assert (zone, error) == ("internal.example", "")
    assert [(s.fqdn, s.rtype, s.records) for s in sets] == [
        ("app.internal.example", "A", [("192.0.2.5",)]),
        ("internal.example", "SOA", [("ns.example.test", "admin.example.test")]),
        ("x.internal.example", "UNKNOWN", []),
    ]
    assert sets[0].auto_registered and sets[0].ttl == 10


def test_private_export_errors_are_reported(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert zonefile.read_private(bad)[2]
    obj = tmp_path / "obj.json"
    obj.write_text("{}")
    assert zonefile.read_private(obj)[2] == "not a JSON list of record sets"
