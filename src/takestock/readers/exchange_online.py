"""Exchange Online mail settings: DKIM signing, inbound DMARC handling and quarantine rights.

Three Secure Government Email requirements are settled by a mail platform's
own configuration, which nothing outside the organisation can see: whether
outbound mail is DKIM signed (SGE-DKIM-01), whether inbound mail is checked
for DMARC and acted on (SGE-DMARC-02), and whether mail failing DMARC goes to
a quarantine only an administrator releases from (SGE-DMARC-R04). This reader
reads those settings from an export of Exchange Online PowerShell, and
:mod:`takestock.sge` grades the three requirements from its rows.

**The input** is the folder, or a zip of it, that the read-only script in
``docs/EXCHANGE-ONLINE-EXPORT.md`` writes: one JSON file per
``Get-*`` cmdlet, each object exported whole, and a ``manifest.json`` naming
each cmdlet's file, whether it ran, how many objects it returned and any
error. A file is found through the manifest's ``command`` and ``file``
entries, so a folder written by another script with the same manifest shape
is read the same way; with no manifest entry, ``<cmdlet>.json`` is tried.

**Rows.** One per object read, named ``Exchange Online <setting> <name>``,
with data state ``email-auth``, protocol :data:`PROTOCOL`, verdict ``n/a``
(a setting carries no cryptographic primitive to grade) and, in ``extra``,
``setting`` (which kind of object) and the properties the evaluators read,
renamed in lower case. A scope row, ``Exchange Online settings export scope``,
records when the export was taken and each cmdlet's count or error. A cmdlet
that failed or is missing is a coverage gap.

**What the settings mean** is decided here, from Microsoft's documentation,
so :mod:`takestock.sge` can ask plain questions of them:
:func:`policies_for` (which anti-phishing policies govern mail to a domain's
recipients), :func:`route_for` (whether the platform can honour a sender's
DMARC policy, given where the domain's MX records point),
:func:`release_rights` (whether recipients can release their own quarantined
mail) and :func:`signing_for` (whether the platform DKIM signs a domain's
mail). Each answer carries the sentence it rests on.

Pages read, on Microsoft Learn (learn.microsoft.com), by title:

* *Anti-phishing policies in Microsoft 365* (A): the default policy,
  recipient conditions, the DMARC actions and the Enhanced Filtering
  condition;
* *Preset security policies* (P): the order of precedence and the preset
  rules;
* *Quarantine policies* (Q): end-user permissions;
* *Enhanced filtering for connectors in Exchange Online* (E);
* *How to use DKIM for email in your custom domain* (D): DKIM signing;
* *How SMTP DNS-based Authentication of Named Entities (DANE) works* (N):
  Microsoft 365's MX host names;
* the Exchange PowerShell cmdlet pages for Set-AntiPhishPolicy,
  Set-AntiPhishRule, Get-EOPProtectionPolicyRule, Set-InboundConnector and
  Set-OutboundConnector: the properties and their values.

**Cannot see.** Anything outside Exchange Online: a mail gateway in front of
it or behind it, and any other service that sends as the organisation's
domains. Overrides Microsoft lists for the DMARC setting (A: safe sender
lists, the spoof intelligence insight, the Tenant Allow/Block List, allowed
sender lists in anti-spam policies, and mail flow rules) are not exported.
Group membership is not exported, so a rule naming users or groups is read
as covering some recipients, never all.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import coverage
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "exchange_online"
#: The protocol of every row: a mail platform setting.
PROTOCOL = "mail-policy"
DATA_STATE = "email-auth"
SCOPE_ROW = "Exchange Online settings export scope"

#: Each cmdlet read, and the ``setting`` its rows carry.
READINGS: dict[str, str] = {
    "Get-AcceptedDomain": "accepted-domain",
    "Get-DkimSigningConfig": "dkim-signing",
    "Get-AntiPhishPolicy": "anti-phishing-policy",
    "Get-AntiPhishRule": "anti-phishing-rule",
    "Get-EOPProtectionPolicyRule": "preset-rule",
    "Get-ATPProtectionPolicyRule": "preset-rule-defender",
    "Get-InboundConnector": "inbound-connector",
    "Get-OutboundConnector": "outbound-connector",
    "Get-QuarantinePolicy": "quarantine-policy",
}

LABELS = {
    "accepted-domain": "accepted domain",
    "dkim-signing": "DKIM signing",
    "anti-phishing-policy": "anti-phishing policy",
    "anti-phishing-rule": "anti-phishing rule",
    "preset-rule": "preset security policy rule",
    "preset-rule-defender": "preset security policy rule (Defender for Office 365)",
    "inbound-connector": "inbound connector",
    "outbound-connector": "outbound connector",
    "quarantine-policy": "quarantine policy",
}

#: The host-name endings of Microsoft 365's own MX records (N: the legacy
#: records end "mail.protection.outlook.com", "mail.eo.outlook.com" or
#: "mail.protection.outlook.de"; a DNSSEC-signed one ends "mx.microsoft").
MICROSOFT_MX_SUFFIXES = ("mail.protection.outlook.com", "mail.eo.outlook.com",
                         "mail.protection.outlook.de", "mx.microsoft")

STRICT, STANDARD = "strict", "standard"

# ── Reading the export ────────────────────────────────────────────────


@dataclass
class Export:
    """What one export folder or zip holds."""

    name: str
    pulled: str = ""
    readings: dict[str, list[dict]] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)


def _files(path: Path) -> dict[str, bytes]:
    """Every ``.json`` file in a folder (and one level below) or a zip, by base name."""
    out: dict[str, bytes] = {}
    if path.is_file() and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                if base.lower().endswith(".json") and not info.is_dir():
                    out.setdefault(base, z.read(info))
        return out
    if path.is_dir():
        for p in sorted(path.glob("*.json")) + sorted(path.glob("*/*.json")):
            out.setdefault(p.name, p.read_bytes())
        return out
    raise OSError(f"{path.name} is neither a folder nor a zip file")


def _json(raw: bytes) -> Any:
    text = raw.decode("utf-8-sig").strip()
    return json.loads(text) if text else []


def _objects(value: Any) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def load(path: Path) -> Export:
    """Read an export. Raises ``OSError`` or ``ValueError`` when nothing can be read."""
    files = _files(path)
    manifest = _json(files["manifest.json"]) if "manifest.json" in files else {}
    if not isinstance(manifest, dict):
        manifest = {}
    entries = {str(r.get("command") or ""): r for r in manifest.get("readings") or []
               if isinstance(r, dict)}
    export = Export(name=path.name, pulled=str(manifest.get("pulled_utc") or ""))
    for cmdlet in READINGS:
        entry = entries.get(cmdlet)
        if entry is not None and entry.get("ok") is False:
            export.failed[cmdlet] = str(entry.get("error") or "no error recorded")
            continue
        file = str((entry or {}).get("file") or f"{cmdlet}.json")
        if file not in files:
            export.missing.append(cmdlet)
            continue
        try:
            export.readings[cmdlet] = _objects(_json(files[file]))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            export.failed[cmdlet] = f"{file} is not readable JSON ({exc})"
    if not export.readings:
        raise ValueError(f"{path.name} holds none of the readings this reader reads")
    return export


# ── Normalising one object ────────────────────────────────────────────


def _text(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _flag(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    t = _text(v).lower()
    return True if t == "true" else False if t == "false" else None


def _list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [_text(x) for x in v if _text(x)]
    return [_text(v)] if _text(v) else []


def _ident(obj: dict) -> str:
    return _text(obj.get("Name")) or _text(obj.get("Identity"))


def preset_of(name: str, recommended: str = "") -> str:
    """``strict``, ``standard`` or "" for a policy or rule, by its type or its name."""
    r = recommended.strip().lower()
    if r in (STRICT, STANDARD):
        return r
    n = name.strip().lower()
    if n.startswith("strict preset security policy"):
        return STRICT
    if n.startswith("standard preset security policy"):
        return STANDARD
    return ""


_PERMISSION = re.compile(r"(PermissionTo\w+)\s*[:=]\s*(True|False)", re.IGNORECASE)
#: Q: the bits of ``EndUserQuarantinePermissionsValue``.
RELEASE_BIT, REQUEST_RELEASE_BIT = 4, 8


def release_rights(obj: dict) -> tuple[bool | None, bool | None, str]:
    """(recipients may release, may request release, where that was read) for a quarantine policy.

    ``EndUserQuarantinePermissions`` is read as exported, either a mapping or
    the text PowerShell prints (``PermissionToRelease: True`` and so on);
    failing that, ``EndUserQuarantinePermissionsValue``, whose bit 4 is
    release and bit 8 request release (Q).
    """
    perms = obj.get("EndUserQuarantinePermissions")
    found: dict[str, bool] = {}
    if isinstance(perms, dict):
        found = {k.lower(): f for k, f in ((k, _flag(v)) for k, v in perms.items())
                 if isinstance(f, bool)}
    elif perms:
        found = {m.group(1).lower(): m.group(2).lower() == "true"
                 for m in _PERMISSION.finditer(str(perms))}
    if "permissiontorelease" in found:
        return (found["permissiontorelease"], found.get("permissiontorequestrelease"),
                "EndUserQuarantinePermissions")
    value = obj.get("EndUserQuarantinePermissionsValue")
    if isinstance(value, int) and not isinstance(value, bool):
        return (bool(value & RELEASE_BIT), bool(value & REQUEST_RELEASE_BIT),
                "EndUserQuarantinePermissionsValue")
    return None, None, ""


def _rule_extra(obj: dict) -> dict[str, Any]:
    priority = obj.get("Priority")
    return {
        "state": _text(obj.get("State")),
        "priority": priority if isinstance(priority, int) and not isinstance(priority, bool)
        else None,
        "sent_to": _list(obj.get("SentTo")),
        "sent_to_member_of": _list(obj.get("SentToMemberOf")),
        "recipient_domain_is": [d.lower() for d in _list(obj.get("RecipientDomainIs"))],
        "except_sent_to": _list(obj.get("ExceptIfSentTo")),
        "except_sent_to_member_of": _list(obj.get("ExceptIfSentToMemberOf")),
        "except_recipient_domain_is": [d.lower() for d in
                                       _list(obj.get("ExceptIfRecipientDomainIs"))],
    }


def extra_for(setting: str, obj: dict) -> dict[str, Any]:
    """The properties a row keeps for one exported object, by setting."""
    name = _ident(obj)
    if setting == "accepted-domain":
        return {"domain": (_text(obj.get("DomainName")) or name).lower(),
                "domain_type": _text(obj.get("DomainType")),
                "initial_domain": _flag(obj.get("InitialDomain")),
                "default": _flag(obj.get("Default"))}
    if setting == "dkim-signing":
        return {"domain": (_text(obj.get("Domain")) or name).lower(),
                "enabled": _flag(obj.get("Enabled")), "status": _text(obj.get("Status"))}
    if setting == "anti-phishing-policy":
        return {"policy": name, "is_default": _flag(obj.get("IsDefault")),
                "preset": preset_of(name, _text(obj.get("RecommendedPolicyType"))),
                "honor_dmarc": _flag(obj.get("HonorDmarcPolicy")),
                "dmarc_reject_action": _text(obj.get("DmarcRejectAction")),
                "dmarc_quarantine_action": _text(obj.get("DmarcQuarantineAction")),
                "authentication_fail_action": _text(obj.get("AuthenticationFailAction")),
                "spoof_intelligence": _flag(obj.get("EnableSpoofIntelligence")),
                "spoof_quarantine_tag": _text(obj.get("SpoofQuarantineTag"))}
    if setting == "anti-phishing-rule":
        return {"rule": name, "policy": _text(obj.get("AntiPhishPolicy")), **_rule_extra(obj)}
    if setting in ("preset-rule", "preset-rule-defender"):
        return {"rule": name, "preset": preset_of(name), **_rule_extra(obj)}
    if setting == "inbound-connector":
        return {"connector": name, "enabled": _flag(obj.get("Enabled")),
                "connector_type": _text(obj.get("ConnectorType")),
                "ef_skip_last_ip": _flag(obj.get("EFSkipLastIP")),
                "ef_skip_ips": _list(obj.get("EFSkipIPs")),
                "ef_users": _list(obj.get("EFUsers")),
                "tls_sender_certificate_name": _text(obj.get("TlsSenderCertificateName")),
                "sender_ip_addresses": _list(obj.get("SenderIPAddresses"))}
    if setting == "outbound-connector":
        return {"connector": name, "enabled": _flag(obj.get("Enabled")),
                "use_mx_record": _flag(obj.get("UseMXRecord")),
                "smart_hosts": _list(obj.get("SmartHosts")),
                "recipient_domains": [d.lower() for d in _list(obj.get("RecipientDomains"))],
                "transport_rule_scoped": _flag(obj.get("IsTransportRuleScoped"))}
    if setting == "quarantine-policy":
        release, request, basis = release_rights(obj)
        return {"policy": name, "release": release, "request_release": request,
                "permissions_basis": basis}
    raise ValueError(f"unknown setting {setting!r}")  # pragma: no cover


def _key(extra: dict) -> str:
    return str(extra.get("domain") or extra.get("rule") or extra.get("policy")
               or extra.get("connector") or "(unnamed)")


def row_name(extra: dict) -> str:
    """The name of the row a setting's ``extra`` came from."""
    return f"Exchange Online {LABELS[str(extra.get('setting'))]} {_key(extra)}"


def _row(setting: str, obj: dict, source_name: str, when: str) -> CryptoAsset:
    extra = {"setting": setting, **extra_for(setting, obj)}
    return CryptoAsset(
        name=row_name(extra), data_state=DATA_STATE,
        protocol=PROTOCOL, software="Exchange Online", source=NAME, source_class="private",
        source_name=source_name, collected_at=when, verdict="n/a",
        flags=[f"mail-policy:{setting}"], extra=extra)


def rows_for(export: Export, when: str) -> list[CryptoAsset]:
    """Every setting row, then the scope row."""
    source_name = (f"Exchange Online settings export {export.name}, "
                   + (f"taken {export.pulled}" if export.pulled else "time taken not recorded"))
    out = [_row(READINGS[c], obj, source_name, when)
           for c in READINGS for obj in export.readings.get(c, [])]
    out.append(CryptoAsset(
        name=SCOPE_ROW, data_state=DATA_STATE, protocol=PROTOCOL, software="Exchange Online",
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a", flags=["mail-policy:scope"],
        extra={"setting": "scope", "pulled_utc": export.pulled,
               "counts": {c: len(v) for c, v in export.readings.items()},
               "failed": dict(export.failed), "missing": list(export.missing)}))
    return out


def _when(export: Export, path: Path) -> str:
    m = re.match(r"(\d{4}-\d{2}-\d{2})", export.pulled)
    return m.group(1) if m else (file_mtime_date(path) or "")


def read(ctx: Context) -> StepResult:
    """The plug-in's step: one row per setting read, a scope row, and a gap per reading missed."""
    if ctx.input is None:
        return StepResult(gaps=[_none_read("no input was given")])
    path: Path = ctx.input
    try:
        export = load(path)
    except (OSError, ValueError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        return StepResult(gaps=[_none_read(f"{path.name} could not be read ({exc})")])
    gaps = [coverage.gap(
        coverage.COULD_NOT_TEST if cmdlet in export.failed else coverage.NOT_COLLECTED,
        f"the Exchange Online export {export.name} holds no `{cmdlet}` reading"
        + (f": {export.failed[cmdlet]}" if cmdlet in export.failed else ""),
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("A Secure Government Email requirement graded from this export reads as "
                "unsettled where it needs this reading."),
        harvest=f"Run `{cmdlet}` again and add its JSON to the export.",
        nature=coverage.NO_DATA)
        for cmdlet in READINGS if cmdlet not in export.readings]
    return StepResult(records=rows_for(export, _when(export, path)), gaps=gaps)


def _none_read(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no Exchange Online settings export was read: {why}",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Whether outbound mail is DKIM signed, whether inbound mail is checked for "
                "DMARC and acted on, and who can release mail that fails it are settings of "
                "the mail platform; without them those Secure Government Email requirements "
                "stay unmeasured."),
        harvest=("An Exchange administrator runs the read-only export script in "
                 "docs/EXCHANGE-ONLINE-EXPORT.md and names its folder or zip as the reader's "
                 "input."),
        nature=coverage.NO_DATA)


#: The declaration. It names no default input: with none given in the
#: profile, the step still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=read,
                title="Exchange Online settings export", gap_prefix=False)


# ── What the settings mean ────────────────────────────────────────────


@dataclass
class Settings:
    """The export's rows, grouped by setting."""

    by_setting: dict[str, list[dict]] = field(default_factory=dict)
    scope: dict = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def of(self, setting: str) -> list[dict]:
        return self.by_setting.get(setting, [])

    def read(self, cmdlet: str) -> bool:
        """Whether the export holds this cmdlet's reading (an empty one counts)."""
        return cmdlet in (self.scope.get("counts") or {})


def _get(asset: Any, key: str) -> Any:
    return asset.get(key) if isinstance(asset, dict) else getattr(asset, key, None)


def settings(assets: Iterable[Any]) -> Settings | None:
    """The settings this reader wrote among ``assets``, or None when there are none."""
    out = Settings()
    seen = False
    for a in assets:
        if _get(a, "source") != NAME or _get(a, "protocol") != PROTOCOL:
            continue
        extra = dict(_get(a, "extra") or {})
        seen = True
        if extra.get("setting") == "scope":
            out.scope = extra
        else:
            out.by_setting.setdefault(str(extra.get("setting")), []).append(extra)
        out.evidence.append(str(_get(a, "name") or ""))
    return out if seen else None


def taken(s: Settings) -> str:
    """When the export was taken, for a sentence."""
    pulled = str(s.scope.get("pulled_utc") or "")
    return f"the Exchange Online settings export taken {pulled}" if pulled else \
        "the Exchange Online settings export (time taken not recorded)"


@dataclass
class Governing:
    """One anti-phishing policy that governs mail to some or all of a domain's recipients."""

    policy: dict | None
    via: str
    #: True when it governs every recipient no earlier entry takes; False when
    #: its rule names users or groups (or excepts some), so it governs some.
    whole: bool
    #: True when no earlier entry names users or groups, so it is certain to
    #: govern the recipients it names; False when an earlier one may take them.
    certain: bool
    name: str = ""


def _applies_to_domain(rule: dict, domain: str) -> bool:
    domains = rule.get("recipient_domain_is") or []
    if domains and domain not in domains:
        return False
    return domain not in (rule.get("except_recipient_domain_is") or [])


def _whole_domain(rule: dict) -> bool:
    """A rule takes every recipient of a domain it applies to: no user or group condition or exception."""
    return not any(rule.get(k) for k in ("sent_to", "sent_to_member_of", "except_sent_to",
                                          "except_sent_to_member_of"))


def _enabled(rule: dict) -> bool:
    return str(rule.get("state") or "").lower() == "enabled"


def policies_for(s: Settings, domain: str) -> list[Governing]:
    """The anti-phishing policies that govern mail to ``domain``'s recipients, in order.

    P, *Order of precedence*: "the policies are applied in the following
    order": the Strict preset, the Standard preset, custom policies "based on
    the priority of the policy (a lower number indicates a higher priority)",
    then the default policy. A preset with no rule applies to no one ("Until
    you turn on the profiles and assign users to them, the Standard and
    Strict preset security policies are assigned to no one"), and a disabled
    rule applies to no one (Set-AntiPhishPolicy: "whether the anti-phishing
    policy is enabled or disabled is visible in the State property" of the
    rule). The default "applies to all recipients" (A).

    A preset is in effect when either of its rules is enabled: the rule for
    "the built-in security features for all cloud mailboxes"
    (Get-EOPProtectionPolicyRule), which carries the spoof settings, or the
    Defender for Office 365 rule, whose anti-phishing policy carries "the same
    spoof settings" (P). Conditions of different types use AND logic and
    exceptions OR logic (Set-AntiPhishRule), so a rule limited by domain alone
    takes every recipient of the domains it names; one naming users or groups
    takes some. Walking stops at the first entry that takes every recipient.
    """
    policies = s.of("anti-phishing-policy")
    by_name = {str(p.get("policy") or "").lower(): p for p in policies}
    out: list[Governing] = []

    entries: list[tuple[dict | None, str, dict]] = []
    for preset in (STRICT, STANDARD):
        rules = [r for r in s.of("preset-rule") + s.of("preset-rule-defender")
                 if r.get("preset") == preset and _enabled(r)]
        rules = [r for r in rules if _applies_to_domain(r, domain)]
        if not rules:
            continue
        # The EOP rule's recipients govern the spoof settings; the Defender
        # rule stands in only when the EOP rule is not enabled.
        rule = next((r for r in rules if r in s.of("preset-rule")), rules[0])
        policy = next((p for p in policies if p.get("preset") == preset), None)
        entries.append((policy, f"the {preset.title()} preset security policy", rule))
    custom = sorted((r for r in s.of("anti-phishing-rule") if _enabled(r)),
                    key=lambda r: (r.get("priority") is None, r.get("priority") or 0))
    for r in custom:
        if _applies_to_domain(r, domain):
            entries.append((by_name.get(str(r.get("policy") or "").lower()),
                            f"the custom rule {r.get('rule')}", r))

    certain = True
    for policy, via, rule in entries:
        whole = _whole_domain(rule)
        out.append(Governing(policy, via, whole, certain,
                             str((policy or {}).get("policy") or rule.get("policy") or "")))
        if whole:
            return out
        certain = False
    default = next((p for p in policies if p.get("is_default")), None)
    out.append(Governing(default, "the default policy", True, certain,
                         str((default or {}).get("policy") or "")))
    return out


def _is_microsoft_mx(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == sfx or h.endswith("." + sfx) for sfx in MICROSOFT_MX_SUFFIXES)


def _cert_matches(name: str, host: str) -> bool:
    n, h = name.lower().rstrip("."), host.lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    return bool(n) and (h == n or h.endswith("." + n))


def enhanced_filtering(connector: dict) -> bool:
    """E: on when ``EFSkipLastIP`` is true, or it is false and ``EFSkipIPs`` lists addresses."""
    return connector.get("ef_skip_last_ip") is True or bool(connector.get("ef_skip_ips"))


@dataclass
class Route:
    """Whether the platform can apply a sender's DMARC policy to a domain's inbound mail."""

    #: True: it can; False: it cannot; None: this reading cannot tell.
    honours: bool | None
    reason: str
    connectors: list[str] = field(default_factory=list)


#: A, the note under *Spoof protection and sender DMARC policies*.
EF_CONDITION = ("Microsoft: \"If the MX record for the Microsoft 365 domain points to a "
                "non-Microsoft service or device that sits in front of Microsoft 365, the Honor "
                "DMARC policy setting is applied only if Enhanced Filtering for Connectors is "
                "enabled for the connector that receives inbound messages\"")


def route_for(s: Settings, mx_hosts: list[str] | None) -> Route:
    """Whether DMARC can be honoured on mail arriving by ``mx_hosts`` (None: no MX reading)."""
    if mx_hosts is None:
        return Route(None, "this observation holds no MX reading for the domain, so whether "
                           "its mail reaches the platform directly or through another "
                           "service first is unknown, and the Enhanced Filtering condition "
                           "cannot be settled")
    if not mx_hosts:
        return Route(None, "the domain's MX reading names no mail host, so no inbound route "
                           "to read")
    if all(_is_microsoft_mx(h) for h in mx_hosts):
        return Route(True, f"its MX records ({', '.join(mx_hosts)}) point to Microsoft 365, "
                           "so mail reaches the platform directly")
    front = [h for h in mx_hosts if not _is_microsoft_mx(h)]
    if not s.read("Get-InboundConnector"):
        return Route(None, f"its MX records point to {', '.join(front)}, not Microsoft 365, "
                           "and the export holds no inbound connector reading")
    enabled = [c for c in s.of("inbound-connector") if c.get("enabled") is True]
    filtering = [c for c in enabled if enhanced_filtering(c)]
    disabled_ef = [c for c in s.of("inbound-connector")
                   if c.get("enabled") is not True and enhanced_filtering(c)]
    lead = f"its MX records point to {', '.join(front)}, not Microsoft 365. {EF_CONDITION}"
    if not filtering:
        note = (f"; {len(disabled_ef)} disabled connector(s) carry Enhanced Filtering "
                f"settings ({', '.join(str(c.get('connector')) for c in disabled_ef)}), which "
                "a disabled connector does not apply" if disabled_ef else "")
        return Route(False, f"{lead}. None of the {len(enabled)} enabled inbound "
                            f"connector(s) has Enhanced Filtering on (EFSkipLastIP true, or "
                            f"EFSkipIPs listing addresses){note}")
    whole = [c for c in filtering if not c.get("ef_users")]
    matched = [c for c in whole if c.get("tls_sender_certificate_name")
               and all(_cert_matches(str(c["tls_sender_certificate_name"]), h) for h in front)]
    names = [str(c.get("connector")) for c in filtering]
    if matched:
        return Route(True, f"{lead}. The enabled connector "
                           f"{matched[0].get('connector')} has Enhanced Filtering on for every "
                           "recipient, and its sender certificate name "
                           f"({matched[0].get('tls_sender_certificate_name')}) covers the MX "
                           "host(s), so it is the connector that receives that mail",
                     [str(matched[0].get("connector"))])
    if not whole:
        return Route(False, f"{lead}. Enhanced Filtering is on only for listed recipients "
                            f"(EFUsers) on {', '.join(names)}; Microsoft: it \"is effective "
                            "only on messages where all recipients are specified here\", so "
                            "mail to any other recipient is filtered without it", names)
    return Route(None, f"{lead}. Enhanced Filtering is on for every recipient on "
                       f"{', '.join(str(c.get('connector')) for c in whole)}, and nothing in "
                       "this reading ties that connector to the MX host(s): its sender "
                       "certificate name does not cover them, and the hosts' addresses are not "
                       "resolved here to compare with its sender addresses", names)


@dataclass
class Handling:
    """What happens to mail failing DMARC under one policy."""

    #: The action for a sender's p=quarantine and for its p=reject.
    quarantine_action: str
    reject_action: str
    #: Whether the sender's DMARC policy decides those actions.
    honoured: bool
    basis: str


def handling(policy: dict, route_honours: bool) -> Handling:
    """The actions in effect for mail failing DMARC, under ``policy`` on a route that honours or not.

    Set-AntiPhishPolicy, HonorDmarcPolicy: "$true: If a message fails DMARC
    and the sender's DMARC policy is p=quarantine or p=reject, the
    DmarcQuarantineAction or DmarcRejectAction parameters specify the action
    to take on the message"; "$false: If the message fails DMARC, ignore the
    action in the sender's DMARC policy. The AuthenticationFailAction
    parameter specifies the action to take on the message." Where the route
    does not honour DMARC (:func:`route_for`), the setting is not applied, and
    this reads that as the ``$false`` case.
    """
    fail_action = str(policy.get("authentication_fail_action") or "")
    if policy.get("honor_dmarc") is True and route_honours:
        return Handling(str(policy.get("dmarc_quarantine_action") or ""),
                        str(policy.get("dmarc_reject_action") or ""), True,
                        "HonorDmarcPolicy is true")
    why = ("HonorDmarcPolicy is true but is not applied on this route"
           if policy.get("honor_dmarc") is True else "HonorDmarcPolicy is false")
    return Handling(fail_action, fail_action, False,
                    f"{why}, so the spoof intelligence action (AuthenticationFailAction) "
                    "applies")


#: Set-AntiPhishPolicy: the values each action takes.
QUARANTINE_ACTIONS = ("Quarantine", "MoveToJmf")
REJECT_ACTIONS = ("Quarantine", "Reject")


def quarantine_policy(s: Settings, name: str) -> dict | None:
    """The quarantine policy of that name, or None."""
    return next((q for q in s.of("quarantine-policy")
                 if str(q.get("policy") or "").lower() == name.lower()), None)


@dataclass
class Signing:
    """Whether the platform DKIM signs one accepted domain's outbound mail."""

    #: True: signs; False: does not; None: this reading cannot tell.
    signs: bool | None
    reason: str


def signing_for(s: Settings, domain: dict) -> Signing:
    """D: custom domains are signed only once signing is enabled; the initial domain always is."""
    name = str(domain.get("domain") or "")
    if domain.get("initial_domain") is True:
        return Signing(True, "it is the tenant's initial domain, and Microsoft: \"Microsoft "
                             "365 automatically DKIM signs outbound mail from senders in the "
                             "initial *.onmicrosoft.com domain\"")
    config = next((c for c in s.of("dkim-signing") if c.get("domain") == name), None)
    if config is None:
        if not s.read("Get-DkimSigningConfig"):
            return Signing(None, "the export holds no DKIM signing reading")
        return Signing(False, "the export holds no DKIM signing configuration for it, and "
                              "Microsoft: \"Currently, no DKIM signing occurs for outbound "
                              "mail from custom domains\" until signing is configured")
    status = str(config.get("status") or "")
    if config.get("enabled") is True:
        if status and status.lower() != "valid":
            return Signing(None, f"signing is enabled with status {status}, which this "
                                 "reading does not read as signing")
        return Signing(True, "DKIM signing is enabled" + (f" (status {status})" if status
                                                           else ""))
    if config.get("enabled") is False:
        return Signing(False, "DKIM signing is disabled"
                              + (f" (status {status})" if status else ""))
    return Signing(None, "the DKIM signing configuration records no Enabled value")


def outbound_gateways(s: Settings) -> list[dict]:
    """Enabled outbound connectors that hand mail to smart hosts rather than to the recipient's MX.

    Set-OutboundConnector: UseMXRecord "$false: The connector delivers email
    to one or more smart hosts"; RecipientDomains "specifies the domain that
    the Outbound connector routes mail to"; IsTransportRuleScoped "$true: The
    connector is associated with a transport rule", which routes the messages
    matching its conditions. Any such connector means some outbound mail
    leaves through another service, whichever mail its scope picks.
    """
    return [c for c in s.of("outbound-connector")
            if c.get("enabled") is True and c.get("use_mx_record") is False
            and c.get("smart_hosts")]


def gateway_scope(connector: dict) -> str:
    """Which outbound mail a smart-host connector carries, in words."""
    domains = connector.get("recipient_domains") or []
    if connector.get("transport_rule_scoped") is True:
        return "the mail a mail flow rule routes to it"
    if "*" in domains:
        return "mail to every domain"
    return f"mail to {', '.join(domains)}" if domains else "mail its scope picks"
