"""takestock mailpath: header routes, DMARC aggregates, trace volumes, DNS posture, the page.

The header fixtures are written by hand, because the mail servers whose
Received lines they imitate (a hosted mailbox platform, Postfix with its TLS
clause, a relay that writes plain ESMTP) cannot be stood up here. They are
generic shapes of those lines, not copies of any server's output. Every name is
under example.test or another reserved name, and every address is from a
documentation range.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock.mailpath import cloudflare, dmarc, dnsposture, headers, paths, report, run, systems, trace

CAT = systems.load()

OVERLAY = """systems:
  - name: Example relay
    kind: relay
    host_suffixes: [relay.example.test]
    addresses: [192.0.2.0/28]
  - name: Example gateway
    kind: gateway
    host_suffixes: [gw.example.net]
"""


@pytest.fixture()
def cat(tmp_path: Path) -> systems.Catalogue:
    p = tmp_path / "overlay.yaml"
    p.write_text(OVERLAY)
    return systems.load([p])


# A message from example.test, written in an Outlook client on a hosted
# platform, relayed through the organisation's relay, a gateway, and delivered
# to a mailbox at example.org. Newest Received first, as on the wire.
OUTBOUND = """# sizeEstimate 20480
# internalDate 2026-01-02T03:04:05.000Z
# labels INBOX

Delivered-To: person@example.org
Authentication-Results: mx.google.com;       dkim=pass header.i=@example.test header.s=s1
    header.b=AAAA;       spf=pass (google.com: domain of a@example.test designates 198.51.100.7
    as permitted sender) smtp.mailfrom=a@example.test;       dmarc=pass (p=REJECT sp=REJECT
    dis=NONE) header.from=example.test
Received: from out1.gw.example.net (out1.gw.example.net. [198.51.100.7])        by mx.google.com
    with ESMTPS id abc        for <person@example.org>        (version=TLS1_3
    cipher=TLS_AES_256_GCM_SHA384 bits=256/256);        Fri, 2 Jan 2026 03:04:06 -0800 (PST)
Received: from relay.example.test (relay.example.test [192.0.2.5]) (using TLSv1.2 with cipher
    ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits)) by in.gw.example.net (Postfix) with ESMTPS id 4AbCd;
    Fri, 2 Jan 2026 11:04:06 +0000
Received: from host.outbound.protection.outlook.com ([203.0.113.9]) by relay.example.test
    with ESMTP id 5F2A1 for <person@example.org>; Fri, 2 Jan 2026 11:04:05 +0000
Received: from AB1PR01MB0001.prod.outlook.com ([2001:db8::1]) by AB1PR01MB0001.prod.outlook.com
    ([2001:db8::1]) with mapi id 15.20.1; Fri, 2 Jan 2026 11:04:05 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=s1; h=from; bh=x; b=y
From: A Person <a@example.test>
Date: Fri, 2 Jan 2026 11:04:05 +0000
Message-ID: <AB1PR01MB0001ABCDEF@AB1PR01MB0001.prod.outlook.com>
X-Mailer: Microsoft Outlook 16.0
X-Google-Smtp-Source: ZZZ
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="b"
X-Protective-Marking: VER=2018.1, NS=example.test, SEC=IN-CONFIDENCE, ORIGIN=a@example.test

This line is a body and must never be read.
Subject: not a header
"""

# Mail from outside, redistributed by a group at example.test, which rewrote From.
GROUP = """# labels INBOX
Delivered-To: me@example.test
ARC-Authentication-Results: i=2; mx.google.com; dkim=pass header.i=@example.test; dmarc=pass
    header.from=example.test
Received: from mail-x.google.com (mail-x.google.com. [198.51.100.20]) by mx.google.com with
    SMTPS id q (Google Transport Security); Fri, 2 Jan 2026 03:04:06 -0800 (PST)
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@vendor.example; spf=pass
    smtp.mailfrom=bounce@vendor.example; dmarc=pass (p=NONE) header.from=vendor.example
Received: from a1-2.smtp-out.amazonses.com (a1-2.smtp-out.amazonses.com. [198.51.100.30]) by
    mx.google.com with ESMTPS id r (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
    Fri, 2 Jan 2026 03:04:05 -0800 (PST)
From: "'Vendor' via Team" <team@example.test>
List-Id: <team.example.test>
"""

SENT = """# labels SENT
Received: from 123456789 named unknown by gmailapi.google.com with HTTPREST; Fri, 2 Jan 2026 03:04:05 -0800
From: me@example.test
"""


def test_header_block_stops_at_the_body_and_reads_the_comment_lines():
    meta, hs = headers.read_block(OUTBOUND)
    assert meta == {"sizeEstimate": "20480", "internalDate": "2026-01-02T03:04:05.000Z", "labels": "INBOX"}
    names = [n for n, _ in hs]
    assert "Subject" not in names and names[-1] == "X-Protective-Marking"


def test_received_tls_clauses_are_read_in_each_servers_form():
    gmail = headers.parse_received("from h (h. [198.51.100.7]) by mx.google.com with ESMTPS id a "
                                   "(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); d")
    assert (gmail.tls, gmail.cipher, gmail.from_ip) == ("TLS 1.3", "TLS_AES_256_GCM_SHA384", "198.51.100.7")
    postfix = headers.parse_received("from a.example.test (a.example.test [192.0.2.1]) by b.example.test "
                                      "(Postfix) with ESMTPS id 1 "
                                      "(using TLSv1.2 with cipher X (256/256 bits)); d")
    assert postfix.tls == "TLS 1.2" and postfix.from_rdns == "a.example.test"
    exchange = headers.parse_received("from A (2001:db8::1) by B (2001:db8::2) with Microsoft SMTP Server "
                                       "(version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) "
                                       "id 15; d")
    assert exchange.tls == "TLS 1.2" and exchange.protocol == "ESMTP"
    unstated = headers.parse_received("from x by mx.google.com with SMTPS id q "
                                      "(Google Transport Security); d")
    assert unstated.tls == headers.TLS_UNSTATED
    assert headers.parse_received("from a by b with ESMTPS (TLS13) tls x; d").tls == "TLS 1.3"
    assert CAT.by_asn_org("Amazon.com, Inc.") is None      # a cloud network names no service


def test_a_mailer_string_loses_its_per_message_token():
    assert headers.mailer_name("Example Mailer (dGVzdGluZ3Rva2VuMTIzNDU2Nzg5MA==; +https://x)") == \
        "Example Mailer"
    assert headers.mailer_name("Example Mailer 2.1") == "Example Mailer 2.1"


def test_plain_esmtp_is_not_recorded_rather_than_cleartext():
    hop = headers.parse_received("from a.example.test ([192.0.2.5]) by b.example.test with ESMTP id 7; d")
    assert hop.tls == headers.TLS_NOT_RECORDED and hop.plain_keyword


def test_a_message_becomes_a_route_with_its_transport_signing_and_software(cat):
    m = headers.parse(OUTBOUND, cat)
    route, legs = paths.stations(m)
    assert route == ["Microsoft 365 / Exchange Online", "Example relay", "Example gateway",
                     "Google Workspace / Gmail"]
    assert [leg[0] for leg in legs] == ["not recorded", "TLS 1.2", "TLS 1.3"]
    assert legs[0][2] is True                     # the relay wrote plain ESMTP
    assert m.submission == "Outlook desktop (MAPI)"
    assert "Microsoft Outlook" in m.generators
    # The receiving platform stamps its own header: it says nothing about the sender.
    assert "Google Workspace / Gmail" not in m.generators
    assert m.protection == "S/MIME signed" and m.marking == "IN-CONFIDENCE"
    assert headers.marking("VER=2018.1, NS=example.test, UNCLASSIFIED") == "UNCLASSIFIED"
    assert (m.results.spf, m.results.dmarc, m.results.dkim) == ("pass", "pass", ["pass"])
    assert m.size == 20480 and m.recipient_domain == "example.org"


def test_direction_flows_and_aggregates(cat):
    owned = {"example.test"}
    m = headers.parse(OUTBOUND, cat)
    g = headers.parse(GROUP, cat)
    s = headers.parse(SENT, cat)
    assert paths.direction(m, owned) == paths.OUTBOUND
    assert g.original_from_domain == "vendor.example"
    assert paths.direction(g, owned) == paths.INBOUND        # From was rewritten by the group
    assert paths.direction(s, owned) == paths.SENT_COPY
    assert paths.stations(s)[0] == ["Google Workspace / Gmail"]
    assert paths.direction(m, {"elsewhere.example"}) is None
    flows = paths.flows([m, m, g, s], owned)
    out = next(f for f in flows if f.direction == paths.OUTBOUND)
    d = out.as_dict()
    assert d["messages"] == 2 and d["bytes"] == 40960 and d["dkim_aligned_pass"] == 2
    assert d["legs"][0]["esmtp_without_tls_claim"] == 2
    assert d["legs"][2]["weakest"] == "TLS 1.3"
    inbound = next(f for f in flows if f.direction == paths.INBOUND)
    assert inbound.sender_domain == "vendor.example" and inbound.rewritten == 1


def test_internal_hosts_and_unknown_hosts_are_named_honestly():
    assert CAT.name_host("scanner01", "", "192.0.2.200") == "internal host scanner01"
    assert CAT.name_host("", "", "198.51.100.5").startswith("internal host")
    assert CAT.name_host("a9-14.smtp-out.amazonses.com") == "Amazon SES"
    assert systems.registrable("a.b.example.com") == "example.com"


def test_an_overlay_replaces_a_bundled_entry_and_matches_by_address(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text("systems:\n  - name: Amazon SES\n    kind: relay\n    host_suffixes: [other.example]\n"
                 "    addresses: [198.51.100.0/24]\n")
    c = systems.load([p])
    assert c.by_host("x.amazonses.com") is None
    assert c.by_address("198.51.100.9") == "Amazon SES"
    with pytest.raises(ValueError):
        p.write_text("systems:\n  - name: X\n    colour: red\n")
        systems.load([p])


REPORT = b"""<?xml version="1.0"?>
<feedback><report_metadata><org_name>receiver.example</org_name>
<date_range><begin>1767225600</begin><end>1767311999</end></date_range></report_metadata>
<policy_published><domain>example.test</domain><p>reject</p></policy_published>
<record><row><source_ip>198.51.100.7</source_ip><count>12</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>example.test</header_from><envelope_from>example.test</envelope_from></identifiers></record>
<record><row><source_ip>203.0.113.66</source_ip><count>3</count>
<policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>example.test</header_from></identifiers></record>
</feedback>"""


def test_dmarc_reports_from_xml_gzip_and_cloudflare_rows(tmp_path, cat):
    (tmp_path / "r.xml.gz").write_bytes(gzip.compress(REPORT))
    rows = [{"headerFrom": "example.test", "sourceIP": "192.0.2.3", "matchingMessages": 5, "spf": "pass",
             "dkim": "fail", "disposition": "none", "orgName": "receiver2.example",
             "sourcePTR": "", "sourceOrgName": "Example Org", "spfMFromDomain": "example.test",
             "reportBegin": "2026-01-01T00:00:00Z", "reportEnd": "2026-01-02T00:00:00Z"}]
    (tmp_path / "cf.json").write_text(json.dumps(rows))
    recs = dmarc.load([tmp_path])
    assert sum(r.count for r in recs) == 20
    srcs = {s.system: s for s in dmarc.sources(recs, cat)}
    assert srcs["Example relay"].dmarc_pass == 5          # matched by the overlay's range
    unknown = srcs["address 203.0.113.66"]
    assert unknown.messages == 3 and unknown.dmarc_pass == 0 and unknown.dispositions["reject"] == 3


def test_cloudflare_fetch_walks_back_to_the_retention_edge(monkeypatch):
    calls = []

    def fake_post(query, bearer, timeout=60):
        calls.append(query)
        if len(calls) == 2:
            return {"errors": [{"message": 'zone "z" cannot request data older than 4w4d, but ...'}]}
        return {"data": {"viewer": {"zones": [{"dmarcReportsAdaptive": [{"matchingMessages": 1}]}]}}}
    monkeypatch.setattr(cloudflare, "_post", fake_post)
    rows, stop = cloudflare.fetch("z", "t", now=datetime(2026, 3, 1, tzinfo=UTC))
    assert len(rows) == 2 and "retention" in stop and len(calls) == 3
    assert cloudflare._retention("older than 4w4d").days == 32
    assert cloudflare._retention("something else") is None


def test_cloudflare_token_is_required(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    with pytest.raises(cloudflare.FetchError):
        cloudflare.token()


V2 = ('Received,SenderAddress,RecipientAddress,Subject,Status,ToIP,FromIP,Size,MessageId\n'
      '1/2/2026 3:04:05 AM,app@example.test,a@example.org,secret words,Delivered,,192.0.2.200,1000,<m1>\n'
      '1/2/2026 3:04:05 AM,app@example.test,b@example.org,secret words,Delivered,,192.0.2.200,1000,<m1>\n'
      '1/3/2026 3:04:05 AM,x@example.org,a@example.test,s,Delivered,,198.51.100.1,500,<m2>\n')

EXTENDED = ('origin_timestamp_utc,sender_address,recipient_status,message_subject,total_bytes,'
            'original_client_ip,directionality,connector_id,network_message_id,tls_version\n'
            '2026-01-02T03:04:05Z,a@example.test,b@example.test##Deliver,s,2000,,Originating,,n1,No Tls\n'
            '2026-01-02T03:04:05Z,svc@example.test,c@example.test##Deliver,s,10,,Inbound,Partner in,'
            'n2,TLS1.2\n')


def test_trace_counts_messages_once_and_never_keeps_the_subject(tmp_path):
    p = tmp_path / "t.csv"
    p.write_bytes(V2.encode("utf-16"))
    rows = [t.as_dict() for t in trace.read(p, {"example.test"})]
    assert "secret words" not in json.dumps(rows)
    out = next(r for r in rows if r["direction"] == "outbound")
    assert (out["messages"], out["recipients"], out["bytes"]) == (1, 2, 1000)
    assert out["origin"] == "internal host 192.0.2.200" and out["first"].startswith("2026-01-02")
    p.write_text(EXTENDED)
    rows = {r.connector: r for r in trace.read(p, {"example.test"})}
    assert rows[""].tls == {"none": 1} and rows[""].origin == "a mailbox on the platform"
    assert rows["Partner in"].origin.startswith("from outside the platform")
    p.write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        trace.read(p, {"example.test"})


def _resolver(table: dict[tuple[str, str], list[str]]):
    return lambda name, rtype: table.get((name, rtype), [])


def test_dns_posture_reads_every_record_and_collapses_a_wildcard_key(cat):
    t = {
        ("example.test", "MX"): ["10 mx1.gw.example.net."],
        ("example.test", "TXT"): ['"v=spf1 include:_spf.google.com include:spf.relay.example.test -all"'],
        ("_dmarc.example.test", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:x@valimail.com!10m"'],
        ("s1._domainkey.example.test", "TXT"): ['"v=DKIM1; k=ed25519; p=abc"'],
        ("_mta-sts.example.test", "TXT"): ['"v=STSv1; id=1"'],
        ("_smtp._tls.example.test", "TXT"): ['"v=TLSRPTv1; rua=mailto:t@example.test"'],
        ("example.test", "DS"): ["1 13 2 ABCD"],
        ("_25._tcp.mx1.gw.example.net", "TLSA"): ["3 1 1 ABCD"],
        ("parked.example", "MX"): ["0 ."],
        ("parked.example", "TXT"): ['"v=spf1 -all"'],
        ("takestock-wildcard-check._domainkey.parked.example", "TXT"): ['"v=DKIM1; p="'],
    }
    p = dnsposture.read("example.test", cat, selectors=["s1"], resolve=_resolver(t), fetch_policy=False)
    assert p.mx_systems == ["Example gateway"]
    assert p.spf_systems == ["Google Workspace / Gmail", "Example relay"]
    assert p.dmarc_tags["p"] == "reject" and p.dmarc_reporting == ["rua: Valimail"]
    assert p.dkim == {"s1": "ed25519"} and p.mta_sts_txt and p.tls_rpt and p.dnssec
    assert p.tlsa == {"mx1.gw.example.net": 1}
    q = dnsposture.read("parked.example", cat, resolve=_resolver(t), fetch_policy=False)
    assert q.null_mx and q.dkim == {"*": "wildcard: revoked (empty key)"} and not q.sends


def test_run_and_render_offline(tmp_path):
    hdr = tmp_path / "h"
    hdr.mkdir()
    (hdr / "1.headers.txt").write_text(OUTBOUND)
    (hdr / "2.headers.txt").write_text(GROUP)
    overlay = tmp_path / "o.yaml"
    overlay.write_text(OVERLAY)
    inp = run.Inputs(organisation="Example", domains=["example.test"], header_paths=[hdr],
                     overlays=[overlay], out=tmp_path / "out")
    result = run.run(inp, now=datetime(2026, 1, 5, tzinfo=UTC), resolve=_resolver({}))
    assert result["evidence"]["headers"]["messages_in_scope"] == 2
    j, h = run.write(result, tmp_path / "out")
    page = h.read_text()
    assert "<svg" in page and "Example relay" in page and "a@example.test" not in page
    assert "person@example.org" not in j.read_text()
    assert "This line is a body" not in j.read_text()


def test_report_route_drawing_marks_each_leg():
    svg = report.route_svg(["A", "B"], [{"weakest": "none", "tls": {"none": 1}}], {})
    assert 'class="leg-bad"' in svg and ">none<" in svg


def test_cli_wires_the_command(tmp_path, monkeypatch):
    from takestock import cli
    hdr = tmp_path / "h"
    hdr.mkdir()
    (hdr / "1.headers.txt").write_text(OUTBOUND)
    monkeypatch.setattr(dnsposture, "default_resolve", lambda n, t: [])
    monkeypatch.setattr(run.dnsposture, "default_resolve", lambda n, t: [])
    code = cli.main(["mailpath", "--organisation", "Example", "--domain", "example.test",
                     "--headers", str(hdr), "--out", str(tmp_path / "o")])
    assert code == 0 and (tmp_path / "o" / "mailpath.html").exists()
    assert cli.main(["mailpath", "--organisation", "E", "--domain", "example.test",
                     "--cloudflare-zone", "nozone", "--out", str(tmp_path / "o")]) != 0
