"""takestock.mailpath.m365: the Microsoft 365 mail flow export and Defender's EmailEvents.

No tenant can be stood up here, so every fixture is written by hand in the
shape Microsoft documents, with invented values: the ``Get-*`` objects as
``ConvertTo-Json`` writes them, with property names from the Exchange
PowerShell pages for Get-AcceptedDomain, Set-InboundConnector,
Set-OutboundConnector, Get-DkimSigningConfig, Get-TransportRule and
Get-MailFlowStatusReport; the trace CSV with the columns the export script
selects from Get-MessageTraceV2's output; and EmailEvents rows with the column
names of *EmailEvents table in the advanced hunting schema* and the response
shape of Microsoft Graph's *security: runHuntingQuery*. Every name is under a
reserved domain, every address is from a documentation range, and every GUID
is synthetic.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import pytest

from takestock.mailpath import m365

GUID = "00000000-0000-4000-8000-0000000000{:02d}"

ACCEPTED = [
    {"Name": "example.test", "DomainName": "example.test", "DomainType": "Authoritative",
     "Default": True, "InitialDomain": False},
    {"Name": "example.net", "DomainName": "example.net", "DomainType": "InternalRelay",
     "Default": False, "InitialDomain": False},
]
INBOUND = [{
    "Name": "From gateway", "Identity": "From gateway", "Enabled": True, "ConnectorType": "Partner",
    "ConnectorSource": "Default", "RequireTls": True, "RestrictDomainsToCertificate": True,
    "RestrictDomainsToIPAddresses": False, "TlsSenderCertificateName": "*.gw.example.net",
    "SenderDomains": ["*"], "SenderIPAddresses": [], "EFSkipLastIP": False,
    "EFSkipIPs": ["198.51.100.0/24"], "TrustedOrganizations": [], "TreatMessagesAsInternal": False,
}]
OUTBOUND = [{
    "Name": "To gateway", "Identity": "To gateway", "Enabled": True, "ConnectorType": "Partner",
    "ConnectorSource": "Default", "UseMXRecord": False, "SmartHosts": ["out.gw.example.net"],
    "TlsSettings": "DomainValidation", "TlsDomain": "*.gw.example.net", "RecipientDomains": ["*"],
    "IsTransportRuleScoped": False, "AllAcceptedDomains": False, "RouteAllMessagesViaOnPremises": False,
    "TestMode": False, "MtaStsMode": "Opportunistic", "SmtpDaneMode": "Opportunistic",
    "ValidationRecipients": ["checker@example.org"], "Comment": "a note naming checker@example.org",
}, {
    "Name": "Partner direct", "Enabled": False, "ConnectorType": "Partner", "UseMXRecord": True,
    "SmartHosts": [], "TlsSettings": None, "RecipientDomains": ["example.org"],
}]
DKIM = [{
    "Domain": "example.test", "Enabled": True, "Status": "Valid", "Selector1KeySize": 2048,
    "Selector2KeySize": 2048, "Selector1CNAME": "selector1-example-test._domainkey.tenant.example.com",
    "Selector2CNAME": "selector2-example-test._domainkey.tenant.example.com",
    "SelectorBeforeRotateOnDate": "selector2", "SelectorAfterRotateOnDate": "selector1",
}, {"Domain": "example.net", "Enabled": False, "Status": "CnameMissing", "Selector1KeySize": 1024}]
RULES = [{
    "Name": "Route all outbound through the gateway", "State": "Enabled", "Mode": "Enforce",
    "Priority": 1, "Uses": ["SentToScope", "RouteMessageOutboundConnector",
                            "RouteMessageOutboundRequireTls"],
    "Values": {"SentToScope": "NotInOrganization", "RouteMessageOutboundConnector": "To gateway",
               "RouteMessageOutboundRequireTls": "True"},
}, {
    "Name": "Tag external", "State": "Disabled", "Mode": "Audit", "Priority": 0,
    "Uses": ["FromScope", "PrependSubject"], "Values": {"FromScope": "NotInOrganization"},
}]
STATUS = [
    {"Date": "2030-01-01T00:00:00", "Direction": "Inbound", "EventType": "GoodMail", "MessageCount": 120},
    {"Date": "/Date(1893542400000)/", "Direction": "Inbound", "EventType": "EdgeBlockSpam",
     "MessageCount": 30},
    {"Date": "2030-01-02T00:00:00", "Direction": "Outbound", "EventType": "GoodMail", "MessageCount": 80},
]
TRACE_HEADER = "Received,SenderAddress,RecipientAddress,Status,FromIP,ToIP,Size,MessageId,MessageTraceId"
TRACE_ROWS = [
    f'"2030-01-02T03:04:05Z","a@example.test","b@example.org","Delivered","192.0.2.10",'
    f'"203.0.113.5","20480","<m1@example.test>","{GUID.format(1)}"',
    f'"2030-01-02T03:05:00Z","c@example.org","a@example.test","Delivered","203.0.113.7","",'
    f'"4096","<m2@example.org>","{GUID.format(2)}"',
]
EVENTS_HEADER = ("Timestamp,NetworkMessageId,EmailDirection,SenderFromDomain,SenderMailFromDomain,"
                 "RecipientDomain,DeliveryAction,DeliveryLocation,Connectors,AuthenticationDetails,"
                 "SenderIPv4,SenderIPv6,EmailSize,AttachmentCount")
AUTH = '"{""SPF"":""pass"",""DKIM"":""pass"",""DMARC"":""pass"",""CompAuth"":""pass""}"'
EVENTS_ROWS = [
    f'2030-01-02T03:05:00.1234567Z,{GUID.format(3)},Inbound,example.org,example.org,example.test,'
    f'Delivered,Inbox/Folder,From gateway,{AUTH},203.0.113.7,,4096,0',
    f'2030-01-02T03:05:01.0000000Z,{GUID.format(3)},Inbound,example.org,example.org,example.net,'
    f'Delivered,Inbox/Folder,From gateway,{AUTH},203.0.113.7,,4096,0',
    f'2030-01-02T03:04:05Z,{GUID.format(4)},Outbound,example.test,example.test,example.org,'
    f'Delivered,On-premises/External,To gateway,,,2001:db8::5,20480,1',
    f'2030-01-02T03:06:00Z,{GUID.format(5)},Intra-org,example.test,example.test,example.test,'
    f'Delivered,Inbox/Folder,,"{{""SPF"":""none"",""DKIM"":""none"",""DMARC"":""none""}}",,,,0',
]


def _manifest(**failed: str) -> dict:
    readings = [{"part": "exchange", "command": c, "ok": True, "count": 1, "file": f"{c}.json"}
                for c in m365.READINGS]
    readings.append({"part": "trace", "command": "Get-MessageTraceV2", "ok": True, "count": 2,
                     "file": "message-trace.csv", "domains_only": False,
                     "failed_windows": [{"start": "2030-01-01T00:00:00Z", "end": "2030-01-11T00:00:00Z",
                                         "error": "The request was throttled."}]})
    readings.append({"part": "defender", "command": "EmailEvents", "ok": True, "count": 4,
                     "file": "EmailEvents.csv", "truncated_hours": [], "failed_windows": []})
    for r in readings:
        if r["command"] in failed:
            r.update(ok=False, count=0, error=failed[r["command"]])
            r.pop("file", None)
    return {"pulled_utc": "2030-01-03T0000Z", "script": "export-m365-mail-flow.ps1", "readings": readings}


def _write_json(path: Path, value: object, bom: bool = False) -> None:
    text = json.dumps(value, indent=2)
    path.write_bytes(("﻿" + text).encode("utf-8") if bom else text.encode("utf-8"))


def _bundle(root: Path, *, utf16_trace: bool = False) -> Path:
    root.mkdir()
    _write_json(root / "manifest.json", _manifest())
    for name, value in (("Get-AcceptedDomain", ACCEPTED), ("Get-InboundConnector", INBOUND[0]),
                        ("Get-OutboundConnector", OUTBOUND), ("Get-DkimSigningConfig", DKIM),
                        ("Get-TransportRule", RULES), ("Get-RemoteDomain",
                        [{"Name": "Default", "DomainName": "*", "AutoForwardEnabled": False}]),
                        ("Get-ArcConfig", [{"Identity": "default", "ArcTrustedSealers": "gw.example.net"}]),
                        ("Get-HostedContentFilterPolicy", [{"Name": "Default", "IsDefault": True,
                                                            "MarkAsSpamSpfRecordHardFail": "Off",
                                                            "PhishSpamAction": "Quarantine"}]),
                        ("Get-MailFlowStatusReport", STATUS)):
        # Windows PowerShell 5.1's Set-Content -Encoding utf8 writes a byte order mark.
        _write_json(root / f"{name}.json", value, bom=name == "Get-DkimSigningConfig")
    text = "\r\n".join([TRACE_HEADER, *TRACE_ROWS]) + "\r\n"
    (root / "message-trace.csv").write_bytes(
        b"\xff\xfe" + text.encode("utf-16-le") if utf16_trace else text.encode("utf-8"))
    (root / "EmailEvents.csv").write_text("\n".join([EVENTS_HEADER, *EVENTS_ROWS]) + "\n", encoding="utf-8")
    return root


def _zip(folder: Path) -> Path:
    out = folder.with_suffix(".zip")
    with zipfile.ZipFile(out, "w") as z:
        for p in sorted(folder.iterdir()):
            z.write(p, p.name)
    return out


def test_a_bundle_reads_every_setting(tmp_path: Path) -> None:
    b = m365.read_bundle(_bundle(tmp_path / "m365-mail-flow-2030-01-03T0000Z"))
    assert b["pulled"] == "2030-01-03T0000Z"
    assert [d["domain"] for d in b["accepted_domains"]] == ["example.test", "example.net"]
    inbound, gateway, direct = b["connectors"]
    assert inbound["direction"] == "inbound" and inbound["tls"] == "required"
    assert inbound["certificate_validation"] == "certificate name"
    assert inbound["certificate_name"] == "*.gw.example.net"
    assert inbound["restrictions"] == ["sender certificate"] and inbound["enhanced_filtering"] is True
    assert gateway["tls"] == "DomainValidation" and gateway["certificate_validation"] == "chain and name"
    assert gateway["smart_hosts"] == ["out.gw.example.net"] and gateway["use_mx"] is False
    assert direct["tls"] == "not set" and direct["certificate_validation"] == ""
    assert direct["enabled"] is False
    dkim = {d["domain"]: d for d in b["dkim"]}
    assert dkim["example.test"]["key_size"] == 2048
    assert dkim["example.test"]["selectors"] == ["selector2", "selector1"]
    assert dkim["example.net"]["enabled"] is False and dkim["example.net"]["key_size"] == 1024
    assert [r["name"] for r in b["transport_rules"]] == ["Tag external",
                                                         "Route all outbound through the gateway"]
    route = b["transport_rules"][1]
    assert "routes to connector To gateway" in route["summary"]
    assert "requires TLS outbound" in route["summary"]
    assert b["arc_trusted_sealers"] == ["gw.example.net"]
    assert b["content_filter"][0]["phish_action"] == "Quarantine"
    assert b["traffic"]["totals"] == {"Inbound": {"GoodMail": 120, "EdgeBlockSpam": 30},
                                      "Outbound": {"GoodMail": 80}}
    assert (b["traffic"]["first"], b["traffic"]["last"]) == ("2030-01-01", "2030-01-02")
    assert len(b["trace_files"]) == 1 and b["trace_files"][0].endswith("message-trace.csv")
    assert len(b["email_events_files"]) == 1
    assert any("Get-MessageTraceV2: 1 window(s) failed" in n for n in b["notes"])
    flat = json.dumps(b)
    assert "checker@example.org" not in flat and "a note" not in flat


def test_a_zip_reads_the_same_and_names_members_inside_it(tmp_path: Path) -> None:
    folder = _bundle(tmp_path / "bundle")
    zipped = _zip(folder)
    a, z = m365.read_bundle(folder), m365.read_bundle(zipped)
    for key in ("accepted_domains", "connectors", "dkim", "transport_rules", "traffic", "notes"):
        assert a[key] == z[key]
    assert z["trace_files"] == [f"{zipped}::message-trace.csv"]
    assert len(m365.email_events(zipped)) == len(m365.email_events(folder)) == 3


@pytest.mark.parametrize("utf16", [False, True])
def test_trace_csvs_are_read_by_the_trace_reader(tmp_path: Path, utf16: bool) -> None:
    folder = _bundle(tmp_path / "bundle", utf16_trace=utf16)
    for source in (folder, _zip(folder)):
        flows = {f.direction: f for f in m365.trace_flows(source, {"example.test"})}
        assert flows["outbound"].bytes == 20480 and flows["outbound"].origin == "internal host 192.0.2.10"
        assert flows["inbound"].messages == 1 and flows["inbound"].first == "2030-01-02T03:05:00"


def test_a_bundle_with_missing_and_refused_parts_says_so(tmp_path: Path) -> None:
    root = tmp_path / "partial"
    root.mkdir()
    _write_json(root / "manifest.json", _manifest(**{
        "Get-InboundConnector": "The term 'Get-InboundConnector' is not recognized",
        "EmailEvents": "Forbidden"}))
    _write_json(root / "Get-AcceptedDomain.json", ACCEPTED[0])  # one object, not a list
    _write_json(root / "Get-DkimSigningConfig.json", DKIM)
    b = m365.read_bundle(root)
    assert b["accepted_domains"][0]["domain"] == "example.test"
    assert b["connectors"] == [] and b["transport_rules"] == [] and b["trace_files"] == []
    assert b["traffic"] == {"rows": [], "totals": {}, "first": "", "last": ""}
    notes = "\n".join(b["notes"])
    assert "Get-InboundConnector: refused or failed: The term" in notes
    assert "Get-OutboundConnector: not in the export" in notes
    assert "Get-ArcConfig: not in the export (optional)" in notes
    assert "Get-MessageTraceV2: not in the export" in notes
    assert "EmailEvents: refused or failed: Forbidden" in notes
    assert m365.email_events(root) == []


def test_a_bundle_without_a_manifest_is_read_by_file_name(tmp_path: Path) -> None:
    root = tmp_path / "bare"
    root.mkdir()
    _write_json(root / "Get-OutboundConnector.json", OUTBOUND)
    b = m365.read_bundle(root)
    assert [c["name"] for c in b["connectors"]] == ["To gateway", "Partner direct"]
    assert b["pulled"] == ""


def test_nothing_readable_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        m365.read_bundle(tmp_path / "empty")
    (tmp_path / "file.txt").write_text("x")
    with pytest.raises(OSError):
        m365.read_bundle(tmp_path / "file.txt")


def test_a_whole_transport_rule_is_reduced_to_names() -> None:
    whole = {"Name": "Hold project mail", "State": "Enabled", "Mode": "Enforce", "Priority": 2,
             "Description": "If the message: Is sent to 'someone@example.org' and includes 'Secret plan'",
             "SentTo": ["someone@example.org"], "SubjectContainsWords": ["Secret plan"],
             "SetSCL": "-1", "StopRuleProcessing": False, "Comments": "asked for by someone@example.org",
             "RouteMessageOutboundConnector": None, "RuleErrorAction": "Ignore"}
    r = m365.rule_summary(whole)
    assert r["uses"] == ["SentTo", "SubjectContainsWords", "SetSCL"]
    assert r["values"] == {"SetSCL": "-1"}
    assert "Secret" not in json.dumps(r) and "someone" not in json.dumps(r)


def test_email_events_are_one_per_message_in_the_shared_schema(tmp_path: Path) -> None:
    events = m365.email_events(_bundle(tmp_path / "bundle"))
    assert [e["time"] for e in events] == ["2030-01-02T03:04:05Z", "2030-01-02T03:05:00Z",
                                           "2030-01-02T03:06:00Z"]
    out, inbound, internal = events
    assert set(inbound) == {"time", "direction", "sender_domain", "recipient_domains", "size", "tls",
                            "spf", "dkim", "dmarc", "remote_host", "remote_ip", "connector", "delivery",
                            "source"}
    assert inbound["direction"] == "inbound"
    assert inbound["recipient_domains"] == ["example.net", "example.test"]
    assert (inbound["spf"], inbound["dkim"], inbound["dmarc"]) == ("pass", "pass", "pass")
    assert inbound["remote_ip"] == "203.0.113.7" and inbound["connector"] == "From gateway"
    assert inbound["delivery"] == "Delivered to Inbox/Folder" and inbound["size"] == 4096
    assert inbound["tls"] == "" and inbound["remote_host"] == "" and inbound["source"] == "m365-emailevents"
    assert out["direction"] == "outbound" and out["remote_ip"] == "2001:db8::5" and out["spf"] == ""
    assert internal["direction"] == "internal" and internal["size"] is None and internal["dmarc"] == "none"


def test_a_graph_response_keeps_no_subject_or_address(tmp_path: Path) -> None:
    """A runHuntingQuery response for an unprojected query: camelCase keys, whole addresses, a subject."""
    response = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.security.huntingQueryResults",
        "schema": [{"name": "Timestamp", "type": "DateTime"}],
        "results": [{
            "timestamp": "2030-01-02T03:05:00.1234567Z", "networkMessageId": GUID.format(6),
            "emailDirection": "Inbound", "senderFromAddress": "Pat.Example@example.org",
            "senderMailFromAddress": "bounce@mail.example.org", "senderDisplayName": "Pat Example",
            "recipientEmailAddress": "Lee.Example@example.test", "subject": "Quarterly secret numbers",
            "deliveryAction": "Blocked", "deliveryLocation": "Quarantine",
            "authenticationDetails": "SPF=fail; DKIM=none; DMARC=fail; CompAuth=fail",
            "senderIPv4": "198.51.100.20", "emailSize": 1234, "attachmentCount": 1,
            "to": "Lee.Example@example.test",
        }],
    }
    path = tmp_path / "EmailEvents.json"
    path.write_text(json.dumps(response), encoding="utf-8")
    [event] = m365.email_events(path)
    assert event["sender_domain"] == "example.org" and event["recipient_domains"] == ["example.test"]
    assert (event["spf"], event["dkim"], event["dmarc"]) == ("fail", "none", "fail")
    assert event["delivery"] == "Blocked to Quarantine" and event["size"] == 1234
    flat = json.dumps(event).lower()
    for leaked in ("pat", "lee", "bounce", "quarterly", "secret", "@"):
        assert leaked not in flat


def test_a_portal_csv_with_utf16_and_whole_addresses(tmp_path: Path) -> None:
    """The Defender portal's CSV export of an unprojected query, saved as UTF-16."""
    text = ("Timestamp,NetworkMessageId,SenderFromAddress,RecipientEmailAddress,Subject,EmailDirection,"
            "DeliveryAction\r\n"
            f"2030-01-02 03:05:00,{GUID.format(7)},a@example.org,b@example.test,Hello there,Inbound,"
            "Delivered\r\n")
    path = tmp_path / "EmailEvents.csv"
    path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    [event] = m365.email_events(path)
    assert event["time"] == "2030-01-02T03:05:00Z" and event["delivery"] == "Delivered"
    assert "Hello" not in json.dumps(event) and "@" not in json.dumps(event)


def test_the_export_script_is_packaged_and_changes_nothing() -> None:
    """Every command that could change something is a local file write, a pause or the script's own."""
    script = Path(m365.__file__).parent.parent / "data" / "exports" / "export-m365-mail-flow.ps1"
    code = re.sub(r"(?m)#.*$", "", re.sub(r"<#[\s\S]*?#>", "", script.read_text(encoding="utf-8")))
    verbs = set(re.findall(r"\b(?:New|Set|Remove|Add|Enable|Disable|Start|Stop|Update|Invoke|Clear|"
                           r"Import|Export|Install|Grant|Revoke)-\w+", code))
    assert verbs == {"New-Item", "Set-Content", "Add-Failure", "Start-Sleep", "Export-Reading",
                     "Export-Csv", "Invoke-MgGraphRequest", "Invoke-EmailEvents"}
    assert "Subject" not in code
    gets = set(re.findall(r"'(Get-[A-Za-z]+)'", code)) | set(re.findall(r"\b(Get-MessageTraceV2|"
                                                                       r"Get-MailFlowStatusReport)\b", code))
    assert set(m365.READINGS) | {"Get-MessageTraceV2"} <= gets
