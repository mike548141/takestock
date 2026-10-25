"""The Exchange Online settings reader, and the three SGE requirements graded from it.

The fixture, ``fixtures/exchange_online/example-widgets/``, is an export
written by hand in the shape the export script in
``docs/EXCHANGE-ONLINE-EXPORT.md`` writes: one ``<cmdlet>.json`` per cmdlet
and a ``manifest.json``. Each object holds only properties the cmdlets'
Microsoft Learn pages document (and a few the reader ignores); every domain,
connector and address in it is synthetic.
The quarantine permissions appear both as the text PowerShell's JSON export
gives for ``EndUserQuarantinePermissions`` and as the documented
``EndUserQuarantinePermissionsValue`` number. The accepted domains file starts
with a byte-order mark.

The evaluator tests build smaller exports in a temporary folder, one setting
at a time, so each test states the configuration it grades.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import pytest

from takestock import config, coverage, sge
from takestock.model import CryptoAsset
from takestock.plugins import Context, StepResult
from takestock.policy import Policy
from takestock.readers import exchange_online as eo
from takestock.readers import library

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "exchange_online" / "example-widgets"
NOW = datetime(2030, 1, 31, 9, 30, tzinfo=UTC)
D = "example.test"
GATEWAY_MX = "mx1.gateway.example.net"
MICROSOFT_MX = "example-test.o-v1.mx.microsoft"
STD = sge.load_standard()


def _ctx(path: Path | None) -> Context:
    return Context(plugin=eo.PLUGIN, target={}, settings={}, input=path, ref_time=NOW,
                   raw_dir=Path("."), policy=Policy(config.load_baseline()), baseline={},
                   dictionary={}, port_table={}, collected_on="2030-01-31")


@pytest.fixture()
def result() -> StepResult:
    return eo.read(_ctx(FIXTURE))


def _by_name(rows: list) -> dict[str, CryptoAsset]:
    return {a.name: a for a in rows}


# ── The reader ────────────────────────────────────────────────────────

def test_one_row_per_object_and_a_scope_row(result):
    names = [a.name for a in result.records]
    assert len(names) == 22 and len(set(names)) == 22
    assert names[0] == "Exchange Online accepted domain example.test"
    assert names[-1] == eo.SCOPE_ROW
    assert result.gaps == []
    for a in result.records:
        assert (a.data_state, a.protocol, a.source, a.verdict, a.collected_at) == (
            "email-auth", "mail-policy", "exchange_online", "n/a", "2030-01-31")
        assert Policy.is_non_crypto_record(a)
        json.dumps(a.extra)


def test_the_properties_each_row_keeps(result):
    rows = _by_name(result.records)
    default = rows["Exchange Online anti-phishing policy Default anti-phishing policy"].extra
    assert default == {
        "setting": "anti-phishing-policy", "policy": "Default anti-phishing policy",
        "is_default": True, "preset": "", "honor_dmarc": True, "dmarc_reject_action": "Reject",
        "dmarc_quarantine_action": "Quarantine", "authentication_fail_action": "Quarantine",
        "spoof_intelligence": True, "spoof_quarantine_tag": "DefaultFullAccessPolicy"}
    assert rows["Exchange Online anti-phishing policy Strict Preset Security Policy"
                ].extra["preset"] == "strict"
    rule = rows["Exchange Online anti-phishing rule Finance anti-phishing"].extra
    assert (rule["state"], rule["priority"], rule["sent_to_member_of"], rule["sent_to"]) == (
        "Enabled", 0, ["finance@example.test"], [])
    preset = rows["Exchange Online preset security policy rule Standard Preset Security Policy"]
    assert (preset.extra["preset"], preset.extra["recipient_domain_is"]) == (
        "standard", ["example.test"])
    conn = rows["Exchange Online inbound connector From the mail gateway (previous)"].extra
    assert (conn["enabled"], conn["ef_skip_ips"], conn["ef_users"]) == (
        False, ["198.51.100.0/24"], [])
    initial = rows["Exchange Online accepted domain examplewidgets.example.com"].extra
    assert initial["initial_domain"] is True


def test_quarantine_release_rights_from_both_forms(result):
    rows = _by_name(result.records)
    q = {n.removeprefix("Exchange Online quarantine policy "): a.extra for n, a in rows.items()
         if a.extra["setting"] == "quarantine-policy"}
    assert (q["DefaultFullAccessPolicy"]["release"],
            q["DefaultFullAccessPolicy"]["permissions_basis"]) == (
        True, "EndUserQuarantinePermissions")
    assert q["AdminOnlyAccessPolicy"]["release"] is False
    # 43 is the documented Limited access value: request release, not release.
    assert (q["LimitedAccess"]["release"], q["LimitedAccess"]["request_release"],
            q["LimitedAccess"]["permissions_basis"]) == (
        False, True, "EndUserQuarantinePermissionsValue")
    assert eo.release_rights({"EndUserQuarantinePermissions": {"PermissionToRelease": "False"}}
                             )[0] is False
    assert eo.release_rights({}) == (None, None, "")


def test_the_scope_row_records_the_export(result):
    scope = _by_name(result.records)[eo.SCOPE_ROW].extra
    assert scope["pulled_utc"] == "2030-01-31T0900Z"
    assert scope["counts"]["Get-ATPProtectionPolicyRule"] == 0
    assert scope["counts"]["Get-AntiPhishPolicy"] == 4
    assert scope["failed"] == {} and scope["missing"] == []


def test_a_zip_reads_as_the_folder_does(tmp_path, result):
    z = tmp_path / "export.zip"
    with zipfile.ZipFile(z, "w") as out:
        for p in FIXTURE.iterdir():
            out.write(p, f"exchange-online-settings/{p.name}")
    zipped = eo.read(_ctx(z))
    assert [a.extra for a in zipped.records[:-1]] == [a.extra for a in result.records[:-1]]


def _write(folder: Path, readings: dict[str, list], failed: dict[str, str] | None = None,
           pulled: str = "2030-01-31T0900Z") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    manifest = []
    for cmdlet, objs in readings.items():
        (folder / f"{cmdlet}.json").write_text(json.dumps(objs), encoding="utf-8")
        manifest.append({"command": cmdlet, "ok": True, "count": len(objs),
                         "file": f"{cmdlet}.json"})
    for cmdlet, error in (failed or {}).items():
        manifest.append({"command": cmdlet, "ok": False, "count": 0, "error": error})
    (folder / "manifest.json").write_text(json.dumps({"pulled_utc": pulled,
                                                      "readings": manifest}))
    return folder


def test_a_failed_or_missing_reading_is_a_gap(tmp_path):
    folder = _write(tmp_path / "x", {"Get-AcceptedDomain": []},
                    failed={"Get-ATPProtectionPolicyRule": "not licensed"})
    got = eo.read(_ctx(folder))
    kinds = {g.split("`")[1]: coverage.kind_of(g) for g in got.gaps}
    assert kinds["Get-ATPProtectionPolicyRule"] == coverage.COULD_NOT_TEST
    assert "not licensed" in next(g for g in got.gaps if "Get-ATP" in g)
    assert kinds["Get-AntiPhishPolicy"] == coverage.NOT_COLLECTED
    assert len(got.gaps) == len(eo.READINGS) - 1
    assert [a.name for a in got.records] == [eo.SCOPE_ROW]


@pytest.mark.parametrize("make, why", [
    (lambda p: None, "no input was given"),
    (lambda p: p / "absent", "could not be read"),
    (lambda p: (p / "empty").mkdir() or p / "empty", "holds none of the readings"),
])
def test_nothing_read_is_one_gap(tmp_path, make, why):
    got = eo.read(_ctx(make(tmp_path)))
    assert got.records == [] and len(got.gaps) == 1 and why in got.gaps[0]
    assert coverage.kind_of(got.gaps[0]) == coverage.NOT_COLLECTED


def test_the_declaration():
    assert library()["exchange_online"] is eo.PLUGIN
    assert (eo.PLUGIN.kind, eo.PLUGIN.input, eo.PLUGIN.gap_prefix) == ("general", "", False)


# ── Grading: helpers ──────────────────────────────────────────────────

def policy(name: str = "Default anti-phishing policy", default: bool = True, kind: str = "Custom",
           honour: bool = True, reject: str = "Reject", quarantine: str = "Quarantine",
           fail: str = "Quarantine", tag: str = "AdminOnlyAccessPolicy") -> dict:
    return {"Name": name, "IsDefault": default, "RecommendedPolicyType": kind,
            "HonorDmarcPolicy": honour, "DmarcRejectAction": reject,
            "DmarcQuarantineAction": quarantine, "AuthenticationFailAction": fail,
            "SpoofQuarantineTag": tag, "EnableSpoofIntelligence": True}


def rule(name: str, policy_name: str | None = None, state: str = "Enabled", priority: int = 0,
         **conditions) -> dict:
    out = {"Name": name, "State": state, "Priority": priority, **conditions}
    if policy_name:
        out["AntiPhishPolicy"] = policy_name
    return out


def connector(name: str = "From the mail gateway", enabled: bool = True, last_ip: bool = False,
              skip: list | None = None, users: list | None = None, cert: str | None = None) -> dict:
    return {"Name": name, "Enabled": enabled, "ConnectorType": "Partner",
            "EFSkipLastIP": last_ip, "EFSkipIPs": skip or [], "EFUsers": users or [],
            "TlsSenderCertificateName": cert}


QUARANTINE = [
    {"Name": "AdminOnlyAccessPolicy", "EndUserQuarantinePermissionsValue": 0},
    {"Name": "DefaultFullAccessPolicy", "EndUserQuarantinePermissionsValue": 4},
    {"Name": "LimitedAccess", "EndUserQuarantinePermissionsValue": 43},
]


def export(tmp_path: Path, *, domains=(D,), dkim=None, policies=None, rules=(), presets=(),
           inbound=(), outbound=(), quarantine=None, **extra) -> list:
    readings = {
        "Get-AcceptedDomain": [{"DomainName": d, "DomainType": "Authoritative",
                                "InitialDomain": False} for d in domains]
        + list(extra.get("initial", [])),
        "Get-DkimSigningConfig": [{"Domain": d, "Enabled": True, "Status": "Valid"}
                                  for d in domains] if dkim is None else dkim,
        "Get-AntiPhishPolicy": [policy()] if policies is None else policies,
        "Get-AntiPhishRule": list(rules),
        "Get-EOPProtectionPolicyRule": list(presets),
        "Get-ATPProtectionPolicyRule": [],
        "Get-InboundConnector": list(inbound),
        "Get-OutboundConnector": list(outbound),
        "Get-QuarantinePolicy": QUARANTINE if quarantine is None else quarantine,
    }
    got = eo.read(_ctx(_write(tmp_path / "export", readings)))
    return [asdict(a) for a in got.records]


def mx(domain: str, *hosts: str) -> dict:
    return {"name": f"MX {domain}", "protocol": "mx", "host": domain,
            "extra": {"records": [f"10 {h}." for h in hosts]}}


def spf_row(domain: str, record: str) -> dict:
    return {"name": f"SPF {domain}", "protocol": "spf", "host": domain,
            "extra": {"record": record}}


def rows(req_id: str, assets: list, domains=(D,), parked=()) -> list:
    report = sge.evaluate(assets, list(domains), STD, parked=list(parked))
    return [r for r in report.rows if r.requirement == req_id]


def one(req_id: str, assets: list, **kw):
    got = rows(req_id, assets, **kw)
    assert len(got) == 1, got
    return got[0]


def text(row) -> str:
    return row.reason if row.status != sge.NOT_MEASURED else row.evidence


# ── With no export ────────────────────────────────────────────────────

@pytest.mark.parametrize("req_id", ["SGE-DKIM-01", "SGE-DMARC-02", "SGE-DMARC-R04"])
def test_no_export_leaves_the_requirement_with_no_instrument(req_id):
    r = one(req_id, [mx(D, MICROSOFT_MX)])
    assert (r.status, r.reason, r.subject) == (sge.NOT_MEASURED, sge.NO_INSTRUMENT, "")
    assert "exchange_online reader" in r.evidence


# ── SGE-DMARC-02 ──────────────────────────────────────────────────────

def test_dmarc_honoured_with_mx_at_microsoft_is_met(tmp_path):
    r = one("SGE-DMARC-02", export(tmp_path) + [mx(D, MICROSOFT_MX)])
    assert (r.status, r.subject) == (sge.PASS, D)
    assert "point to Microsoft 365" in r.reason and "taken 2030-01-31T0900Z" in r.reason
    assert "cannot see" in r.reason


def test_behind_another_mx_with_no_enhanced_filtering_is_not_measured(tmp_path):
    # The platform does not apply the policy on this route, but the requirement
    # is the organisation's, and the service the MX names may check DMARC first.
    assets = export(tmp_path, inbound=[connector(), connector("Old gateway", enabled=False,
                                                              skip=["198.51.100.0/24"])])
    r = one("SGE-DMARC-02", assets + [mx(D, GATEWAY_MX)])
    assert (r.status, r.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    assert not r.breaches_must
    assert r.observed == ("policy: honours DMARC; platform: not applied on this route; "
                          "the service in front of the platform: not measured")
    assert r.evidence.startswith("not measured: the mail reaches the platform through a "
                                 "service in front of it")
    assert "Enhanced Filtering for Connectors on the connector that receives" in r.evidence
    assert eo.EF_CONDITION in r.evidence
    assert "1 disabled connector(s) carry Enhanced Filtering settings (Old gateway)" \
        in r.evidence
    assert GATEWAY_MX in r.evidence


def test_behind_another_mx_does_not_mark_the_policy_row_non_conformant(tmp_path):
    assets = export(tmp_path, inbound=[connector()]) + [mx(D, GATEWAY_MX)]
    sge.apply_conformance(assets, [D], STD)
    row = next(a for a in assets if a["name"].endswith("Default anti-phishing policy"))
    assert row.get("standards_verdict") != sge.NON_CONFORMANT


def test_a_policy_ignoring_dmarc_behind_another_mx_is_still_not_met(tmp_path):
    assets = export(tmp_path, policies=[policy(honour=False)], inbound=[connector()])
    r = one("SGE-DMARC-02", assets + [mx(D, GATEWAY_MX)])
    assert r.status == sge.FAIL and "HonorDmarcPolicy is false" in r.reason


def test_enhanced_filtering_on_the_connector_for_the_mx_host_is_met(tmp_path):
    assets = export(tmp_path, inbound=[connector(last_ip=True, cert="*.gateway.example.net")])
    r = one("SGE-DMARC-02", assets + [mx(D, GATEWAY_MX)])
    assert r.status == sge.PASS
    assert "From the mail gateway has Enhanced Filtering on" in r.reason


def test_enhanced_filtering_on_a_connector_not_tied_to_the_mx_host_is_unsettled(tmp_path):
    assets = export(tmp_path, inbound=[connector(skip=["198.51.100.10"])])
    r = one("SGE-DMARC-02", assets + [mx(D, GATEWAY_MX)])
    assert (r.status, r.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE)
    assert "nothing in this reading ties that connector to the MX host" in r.evidence


def test_enhanced_filtering_for_listed_recipients_only_is_not_measured(tmp_path):
    assets = export(tmp_path, inbound=[connector(last_ip=True, users=["it@example.test"],
                                                 cert="*.gateway.example.net")])
    r = one("SGE-DMARC-02", assets + [mx(D, GATEWAY_MX)])
    assert r.status == sge.NOT_MEASURED and "only for listed recipients" in r.evidence
    assert r.observed.endswith("the service in front of the platform: not measured")


def test_no_mx_reading_is_unsettled_not_guessed(tmp_path):
    r = one("SGE-DMARC-02", export(tmp_path))
    assert r.status == sge.NOT_MEASURED
    assert "holds no MX reading for the domain" in r.evidence


def test_a_default_policy_ignoring_dmarc_is_not_met_whatever_the_route(tmp_path):
    assets = export(tmp_path, policies=[policy(honour=False)])
    r = one("SGE-DMARC-02", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.FAIL and "HonorDmarcPolicy is false" in r.reason


def test_a_preset_covering_the_domain_takes_precedence_over_the_default(tmp_path):
    assets = export(tmp_path, policies=[
        policy(honour=False), policy("Strict Preset Security Policy", default=False,
                                     kind="Strict"),
        policy("Standard Preset Security Policy", default=False, kind="Standard",
               honour=False)],
        presets=[rule("Strict Preset Security Policy", RecipientDomainIs=[D]),
                 rule("Standard Preset Security Policy", state="Disabled",
                      RecipientDomainIs=[D])],
        rules=[rule("Off", "Default anti-phishing policy", state="Disabled",
                    RecipientDomainIs=[D])])
    r = one("SGE-DMARC-02", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.PASS
    assert r.reason.count("the Strict preset security policy") == 1
    assert "default policy" not in r.reason and "Standard" not in r.reason


def test_a_preset_with_no_rule_applies_to_no_one(tmp_path):
    assets = export(tmp_path, policies=[
        policy(), policy("Standard Preset Security Policy", default=False, kind="Standard",
                         honour=False)])
    assert one("SGE-DMARC-02", assets + [mx(D, MICROSOFT_MX)]).status == sge.PASS


def test_a_disabled_preset_rule_applies_to_no_one(tmp_path):
    assets = export(tmp_path, policies=[
        policy(), policy("Standard Preset Security Policy", default=False, kind="Standard",
                         honour=False)],
        presets=[rule("Standard Preset Security Policy", state="Disabled",
                      RecipientDomainIs=[D])])
    r = one("SGE-DMARC-02", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.PASS and "Standard" not in r.reason


def test_a_rule_naming_a_group_cannot_settle_a_failure(tmp_path):
    assets = export(tmp_path, policies=[policy(), policy("Finance", default=False,
                                                         honour=False)],
                    rules=[rule("Finance", "Finance", SentToMemberOf=["finance@example.test"])])
    r = one("SGE-DMARC-02", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.NOT_MEASURED
    assert "for the recipients its rule names: HonorDmarcPolicy is false" in r.evidence


def test_a_domain_the_platform_does_not_accept_is_out_of_this_reading(tmp_path):
    got = rows("SGE-DMARC-02", export(tmp_path) + [mx(D, MICROSOFT_MX)],
               domains=(D, "other.example.test"))
    assert [(r.subject, r.status) for r in got] == [
        (D, sge.PASS), ("other.example.test", sge.NOT_MEASURED)]
    assert "not an accepted domain" in got[1].evidence


def test_an_unmet_dmarc_02_marks_the_policy_row(tmp_path):
    assets = export(tmp_path, policies=[policy(honour=False)]) + [mx(D, MICROSOFT_MX)]
    marked = sge.apply_conformance(assets, [D], STD)
    row = next(a for a in assets if a["name"].endswith("Default anti-phishing policy"))
    assert marked >= 1 and row["standards_verdict"] == sge.NON_CONFORMANT
    assert "SGE-DMARC-02" in row["standards_requirement"]


# ── SGE-DMARC-R04 ─────────────────────────────────────────────────────

def test_quarantine_only_an_administrator_releases_from_is_met(tmp_path):
    r = one("SGE-DMARC-R04", export(tmp_path) + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.PASS
    assert "AdminOnlyAccessPolicy does not let recipients release" in r.reason


def test_a_quarantine_recipients_release_from_is_not_met(tmp_path):
    assets = export(tmp_path, policies=[policy(tag="DefaultFullAccessPolicy")])
    r = one("SGE-DMARC-R04", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.FAIL and not r.breaches_must
    assert "lets recipients release their own quarantined mail" in r.reason


def test_junk_for_p_quarantine_is_not_met(tmp_path):
    assets = export(tmp_path, policies=[policy(quarantine="MoveToJmf")])
    r = one("SGE-DMARC-R04", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.FAIL and "Junk Email folder" in r.reason


def test_request_release_only_is_met(tmp_path):
    # The reading decision: an administrator still releases (docs/COLLECTORS.md).
    assets = export(tmp_path, policies=[policy(tag="LimitedAccess")])
    r = one("SGE-DMARC-R04", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.PASS and "only request release" in r.reason


def test_an_unrecorded_spoof_quarantine_policy_is_microsofts_full_access_default(tmp_path):
    assets = export(tmp_path, policies=[policy(tag="")])
    r = one("SGE-DMARC-R04", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.FAIL and "DefaultFullAccessPolicy or NotificationEnabledPolicy" \
        in r.reason


def test_a_quarantine_policy_missing_from_the_export_is_unsettled(tmp_path):
    assets = export(tmp_path, policies=[policy(tag="Custom quarantine")])
    r = one("SGE-DMARC-R04", assets + [mx(D, MICROSOFT_MX)])
    assert r.status == sge.NOT_MEASURED and "is not in the export" in r.evidence


def test_where_dmarc_is_not_applied_the_spoof_action_decides(tmp_path):
    # The spoof action passes here, so the route's service is not needed.
    assets = export(tmp_path, policies=[policy(fail="Quarantine")])
    r = one("SGE-DMARC-R04", assets + [mx(D, GATEWAY_MX)])
    assert r.status == sge.PASS
    assert "HonorDmarcPolicy is true but is not applied on this route" in r.reason


def test_a_platform_failure_behind_another_mx_is_not_measured(tmp_path):
    # The service the MX names may reject or quarantine failing mail first.
    for name, pol in (("junk", policy(fail="MoveToJmf")),
                      ("release", policy(tag="DefaultFullAccessPolicy"))):
        assets = export(tmp_path / name, policies=[pol])
        r = one("SGE-DMARC-R04", assets + [mx(D, GATEWAY_MX)])
        assert (r.status, r.reason) == (sge.NOT_MEASURED, sge.INCONCLUSIVE), name
        assert r.observed == ("platform: failing mail can reach a recipient (DMARC not "
                              "applied on this route); the service in front of the "
                              "platform: not measured")
        assert r.evidence.startswith("not measured: at the mail platform, failing mail can "
                                     "reach a recipient")
        assert "Enhanced Filtering for Connectors" in r.evidence
        assert "HonorDmarcPolicy is true but is not applied on this route" in r.evidence


def test_an_unsettled_route_settles_only_when_both_answers_agree(tmp_path):
    agree = export(tmp_path / "a")          # Quarantine either way, admin-only
    assert one("SGE-DMARC-R04", agree).status == sge.PASS
    differ = export(tmp_path / "b", policies=[policy(fail="MoveToJmf")])
    r = one("SGE-DMARC-R04", differ)
    assert r.status == sge.NOT_MEASURED and "turns on whether the route" in r.evidence


# ── SGE-DKIM-01 ───────────────────────────────────────────────────────

def test_signing_enabled_with_no_outbound_gateway_is_met(tmp_path):
    r = one("SGE-DKIM-01", export(tmp_path))
    assert (r.status, r.subject) == (sge.PASS, D) and "DKIM signing is enabled" in r.reason


def test_signing_off_on_a_sending_domain_is_not_met(tmp_path):
    assets = export(tmp_path, dkim=[{"Domain": D, "Enabled": False, "Status": "Valid"}])
    r = one("SGE-DKIM-01", assets)
    assert r.status == sge.FAIL and r.breaches_must
    assert "discovery.email_domains" in r.reason


def test_no_signing_configuration_is_unsigned(tmp_path):
    r = one("SGE-DKIM-01", export(tmp_path, dkim=[]))
    assert r.status == sge.FAIL and "no DKIM signing occurs" in r.reason


@pytest.mark.parametrize("parked, spf, status, words", [
    (["x.example.test"], None, sge.NOT_MEASURED, "parked domain"),
    ([], "v=spf1 -all", sge.NOT_MEASURED, "declares that it sends no mail"),
    ([], "v=spf1 include:_spf.example.net -all", sge.FAIL, "authorises senders"),
    ([], None, sge.NOT_MEASURED, "nothing in this observation shows whether it sends"),
])
def test_signing_off_is_a_failure_only_where_the_domain_sends(tmp_path, parked, spf, status,
                                                               words):
    x = "x.example.test"
    assets = export(tmp_path, domains=(x,), dkim=[{"Domain": x, "Enabled": False}])
    assets += [spf_row(x, spf)] if spf else []
    r = one("SGE-DKIM-01", assets, domains=(), parked=parked)
    assert r.status == status and words in text(r)


def test_the_initial_domain_is_signed_by_default(tmp_path):
    assets = export(tmp_path, domains=(), dkim=[], initial=[
        {"DomainName": "examplewidgets.example.com", "InitialDomain": True}])
    r = one("SGE-DKIM-01", assets, domains=())
    assert r.status == sge.PASS and "automatically DKIM signs" in r.reason


def test_an_outbound_gateway_leaves_signing_at_the_last_hop_unsettled(tmp_path):
    gateway = {"Name": "To the mail gateway", "Enabled": True, "UseMXRecord": False,
               "SmartHosts": ["smtp.gateway.example.net"], "RecipientDomains": [],
               "IsTransportRuleScoped": True}
    r = one("SGE-DKIM-01", export(tmp_path, outbound=[gateway]))
    assert r.status == sge.NOT_MEASURED
    assert "the mail a mail flow rule routes to it" in r.evidence
    assert "DKIM signing must happen at that point" in r.evidence


def test_an_outbound_gateway_may_sign_what_the_platform_does_not(tmp_path):
    gateway = {"Name": "To the mail gateway", "Enabled": True, "UseMXRecord": False,
               "SmartHosts": ["smtp.gateway.example.net"], "RecipientDomains": ["*"]}
    assets = export(tmp_path, dkim=[{"Domain": D, "Enabled": False}], outbound=[gateway])
    r = one("SGE-DKIM-01", assets)
    assert r.status == sge.NOT_MEASURED
    assert "mail to every domain" in r.evidence and "may sign" in r.evidence


def test_signing_enabled_but_not_valid_is_unsettled(tmp_path):
    assets = export(tmp_path, dkim=[{"Domain": D, "Enabled": True, "Status": "CnameMissing"}])
    assert one("SGE-DKIM-01", assets).status == sge.NOT_MEASURED


def test_a_profile_domain_the_platform_does_not_accept(tmp_path):
    got = rows("SGE-DKIM-01", export(tmp_path), domains=(D, "other.example.test"))
    assert [(r.subject, r.status) for r in got] == [
        (D, sge.PASS), ("other.example.test", sge.NOT_MEASURED)]
