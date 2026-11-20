"""Microsoft 365 mail flow: the settings that route and protect mail, the volumes, and Defender's events.

**Input.** The folder, or a zip of it, that ``data/exports/export-m365-mail-flow.ps1``
writes (docs/EXCHANGE-ONLINE-EXPORT.md): one ``<cmdlet>.json`` per Exchange
Online ``Get-*`` cmdlet, as ``ConvertTo-Json`` writes it; ``message-trace.csv``
from ``Get-MessageTraceV2``; optionally ``EmailEvents.csv`` from Defender for
Office 365's advanced hunting; and a ``manifest.json`` recording each command's
count, or the error it met. A file is found by its base name, so a folder
holding the same files written another way is read the same.

**What it shows.** Which domains the organisation accepts mail for; who may
hand mail in through a connector, and the TLS and certificate asked of them;
where mail is handed out (smart hosts or MX) and the TLS level demanded; which
domains are DKIM signed, with what key size and selectors; which mail flow
rules exist and which conditions and actions each sets (by name); the
authentication-failure handling of the anti-spam policies; the ARC sealers
trusted; the daily message counts by direction and event type; and, from
Defender, one event per message with its direction, sending domain, recipient
domains, size, the receiver's SPF, DKIM and DMARC verdicts, the relaying
address, the connector and what was done with it.

**What it cannot show.** Any hop before Microsoft 365 received a message or
after it left; the TLS version of any delivery (neither the trace nor
EmailEvents records it; the connector report read by
``readers.exo_connector_messages`` does); mail older than the platform keeps
(90 days of trace, 30 days of advanced hunting); a gateway's own settings.

**What it never keeps.** A subject, a body, an attachment, or a person's
address. Defender rows are reduced to domains here even when an export
carries whole addresses, and a mail flow rule is reduced to the names of the
properties it sets, with values kept only for routing and transport settings,
even when an export carries the whole rule. The message trace CSVs are left to
:mod:`takestock.mailpath.trace`, which keeps domains only.

Pages read, on Microsoft Learn (learn.microsoft.com), by title: the Exchange
PowerShell pages for Get-MessageTraceV2, Get-MailFlowStatusReport,
Set-InboundConnector and Set-OutboundConnector (the properties and their
values); *EmailEvents table in the advanced hunting schema*; *security:
runHuntingQuery* (Microsoft Graph).
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import trace

#: The ``source`` of every event :func:`email_events` returns.
SOURCE = "m365-emailevents"

#: The settings readings, and whether an export without one is incomplete.
READINGS: dict[str, bool] = {
    "Get-AcceptedDomain": True,
    "Get-InboundConnector": True,
    "Get-OutboundConnector": True,
    "Get-DkimSigningConfig": True,
    "Get-TransportRule": True,
    "Get-RemoteDomain": False,
    "Get-ArcConfig": False,
    "Get-HostedContentFilterPolicy": False,
    "Get-MailFlowStatusReport": False,
}

#: A mail flow rule's properties that describe the rule rather than what it does.
_RULE_META = {
    "name", "identity", "guid", "distinguishedname", "immutableid", "state", "mode", "priority",
    "comments", "description", "ruleversion", "whenchanged", "whenchangedutc", "whencreated",
    "whencreatedutc", "exchangeversion", "organizationid", "isvalid", "objectstate", "runspaceid",
    "conditions", "exceptions", "actions", "manuallymodified", "ruleerroraction", "rulesubtype",
    "senderaddresslocation", "exchangeobjectid", "id", "originatingserver", "activationdate",
    "expirydate", "uselegacyregex", "isruleconfigurationsupported", "uses", "values",
}
#: The rule properties whose values are kept: routing and transport, never content.
_RULE_VALUES = {
    "routemessageoutboundconnector", "routemessageoutboundrequiretls", "setscl", "applyome",
    "removeome", "applyrightsprotectiontemplate", "stopruleprocessing", "setheadername",
    "removeheader", "fromscope", "senttoscope", "exceptiffromscope", "exceptifsenttoscope",
    "messagetypematches",
}

_DIRECTIONS = {"inbound": "inbound", "outbound": "outbound", "intra-org": "internal",
               "intraorg": "internal", "internal": "internal"}


# ── Reading the bundle ───────────────────────────────────────────────


class _Bundle:
    """The files of an export folder (and one level below) or zip, by base name."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._zip: zipfile.ZipFile | None = None
        self.members: dict[str, str] = {}
        if path.is_file() and zipfile.is_zipfile(path):
            self._zip = zipfile.ZipFile(path)
            for info in self._zip.infolist():
                if not info.is_dir():
                    self.members.setdefault(info.filename.rsplit("/", 1)[-1], info.filename)
        elif path.is_dir():
            for p in sorted(path.iterdir()) + sorted(path.glob("*/*")):
                if p.is_file():
                    self.members.setdefault(p.name, str(p))
        else:
            raise OSError(f"{path.name} is neither a folder nor a zip file")

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()

    def has(self, name: str) -> bool:
        return name in self.members

    def read(self, name: str) -> bytes:
        if self._zip is not None:
            return self._zip.read(self.members[name])
        return Path(self.members[name]).read_bytes()

    def where(self, name: str) -> str:
        """A file's location: its path, or ``<zip>::<member>`` inside a zip."""
        return f"{self.path}::{self.members[name]}" if self._zip is not None else self.members[name]

    def named(self, test: Any) -> list[str]:
        return sorted(n for n in self.members if test(n.lower()))


def _json(raw: bytes) -> Any:
    text = trace._decode(raw).strip()
    return json.loads(text) if text else []


def _objects(value: Any) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


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
    t = _text(v)
    return [x.strip() for x in t.split(",") if x.strip()] if t else []


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    t = _text(v).replace(",", "")
    return int(t) if t.isdigit() else None


def _get(obj: dict, *names: str) -> Any:
    """A property by any of ``names``, case-insensitively (Graph returns either case)."""
    low = {k.lower(): v for k, v in obj.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return None


def _domain(address: str) -> str:
    """The domain of an address, or the value itself when it is already a domain."""
    a = address.strip().strip("<>").lower()
    return a.rpartition("@")[2] if "@" in a else a


# ── Normalising the settings ─────────────────────────────────────────


def _accepted(obj: dict) -> dict:
    return {"domain": (_text(obj.get("DomainName")) or _text(obj.get("Name"))).lower(),
            "type": _text(obj.get("DomainType")), "default": _flag(obj.get("Default")),
            "initial": _flag(obj.get("InitialDomain"))}


#: Set-OutboundConnector, TlsSettings: what each level checks of the receiving server.
_OUTBOUND_VALIDATION = {"encryptiononly": "none", "certificatevalidation": "chain",
                        "domainvalidation": "chain and name"}


def _inbound(obj: dict) -> dict:
    """Set-InboundConnector: RequireTls "Reject messages if they aren't sent over TLS"
    (Partner connectors); RestrictDomainsToCertificate checks the sender certificate's Subject
    against TlsSenderCertificateName; RestrictDomainsToIPAddresses rejects unknown sources."""
    require = _flag(obj.get("RequireTls"))
    cert = _text(obj.get("TlsSenderCertificateName"))
    restrictions = [label for key, label in (
        ("RestrictDomainsToCertificate", "sender certificate"),
        ("RestrictDomainsToIPAddresses", "sender addresses"),
        ("TreatMessagesAsInternal", "treated as internal"),
        ("CloudServicesMailEnabled", "hybrid cross-premises headers kept"),
    ) if _flag(obj.get(key)) is True]
    if _list(obj.get("TrustedOrganizations")):
        restrictions.append("trusted organisations")
    if _list(obj.get("AssociatedAcceptedDomains")):
        restrictions.append("associated accepted domains")
    return {
        "name": _text(obj.get("Name")) or _text(obj.get("Identity")), "direction": "inbound",
        "enabled": _flag(obj.get("Enabled")), "type": _text(obj.get("ConnectorType")),
        "created_by": _text(obj.get("ConnectorSource")),
        "tls": "required" if require is True else "not required" if require is False else "",
        "certificate_validation": ("certificate name" if cert else "none") if require is not None else "",
        "certificate_name": cert,
        "smart_hosts": [], "use_mx": None,
        "domains": [d.lower() for d in _list(obj.get("SenderDomains"))],
        "addresses": _list(obj.get("SenderIPAddresses")),
        "restrictions": restrictions,
        "enhanced_filtering": bool(_flag(obj.get("EFSkipLastIP")) or _list(obj.get("EFSkipIPs"))),
    }


def _outbound(obj: dict) -> dict:
    """Set-OutboundConnector: TlsSettings EncryptionOnly ("No certificate authentication"),
    CertificateValidation (chain and revocation), DomainValidation (and the certificate's FQDN
    against TlsDomain), or blank, the default; UseMXRecord false delivers to SmartHosts."""
    level = _text(obj.get("TlsSettings"))
    restrictions = [label for key, label in (
        ("IsTransportRuleScoped", "transport rule scoped"),
        ("AllAcceptedDomains", "all accepted domains"),
        ("RouteAllMessagesViaOnPremises", "routes via on-premises"),
        ("SenderRewritingEnabled", "sender rewriting"),
        ("CloudServicesMailEnabled", "hybrid cross-premises headers kept"),
        ("TestMode", "test mode"),
    ) if _flag(obj.get(key)) is True]
    return {
        "name": _text(obj.get("Name")) or _text(obj.get("Identity")), "direction": "outbound",
        "enabled": _flag(obj.get("Enabled")), "type": _text(obj.get("ConnectorType")),
        "created_by": _text(obj.get("ConnectorSource")),
        "tls": level or "not set",
        "certificate_validation": _OUTBOUND_VALIDATION.get(level.lower(), "") if level else "",
        "certificate_name": _text(obj.get("TlsDomain")),
        "smart_hosts": _list(obj.get("SmartHosts")),
        "use_mx": _flag(obj.get("UseMXRecord")),
        "domains": [d.lower() for d in _list(obj.get("RecipientDomains"))],
        "addresses": [],
        "restrictions": restrictions,
        "mta_sts_mode": _text(obj.get("MtaStsMode")),
        "dane_mode": _text(obj.get("SmtpDaneMode")),
    }


def _selector(cname: str) -> str:
    """``selector1`` from a selector CNAME target such as ``selector1-example-test._domainkey...``."""
    first = cname.strip().lower().split(".", 1)[0]
    return first.split("-", 1)[0] if first else ""


def _dkim(obj: dict) -> dict:
    sizes = [s for s in (_int(obj.get(k)) for k in ("Selector1KeySize", "Selector2KeySize", "KeySize"))
             if s]
    targets = [t for t in (_text(obj.get("Selector1CNAME")), _text(obj.get("Selector2CNAME"))) if t]
    named = [_text(obj.get(k)) for k in ("SelectorBeforeRotateOnDate", "SelectorAfterRotateOnDate")]
    selectors = list(dict.fromkeys(s for s in named + [_selector(t) for t in targets] if s))
    return {"domain": (_text(obj.get("Domain")) or _text(obj.get("Name"))).lower(),
            "enabled": _flag(obj.get("Enabled")), "status": _text(obj.get("Status")),
            "key_size": max(sizes) if sizes else None, "selectors": selectors,
            "selector_targets": targets}


def _set(v: Any) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (str, list, tuple, dict)):
        return bool(v)
    return True


def rule_summary(obj: dict) -> dict:
    """A mail flow rule as its name, state and the names of what it sets, never what it matches.

    Reads the script's reduced form (``Uses``, ``Values``) or a whole
    ``Get-TransportRule`` object, which is reduced here the same way.
    """
    if "Uses" in obj:
        uses = _list(obj.get("Uses"))
        raw_values = obj.get("Values") if isinstance(obj.get("Values"), dict) else {}
    else:
        uses = [k for k, v in obj.items() if k.lower() not in _RULE_META
                and not k.startswith("PS") and _set(v)]
        raw_values = {k: obj[k] for k in uses}
    values = {k: _text(v) for k, v in (raw_values or {}).items() if k.lower() in _RULE_VALUES}
    parts = []
    if values.get("RouteMessageOutboundConnector"):
        parts.append(f"routes to connector {values['RouteMessageOutboundConnector']}")
    if _flag(values.get("RouteMessageOutboundRequireTls")) is True:
        parts.append("requires TLS outbound")
    if values.get("SetSCL"):
        parts.append(f"sets spam confidence {values['SetSCL']}")
    if _flag(values.get("ApplyOME")) is True:
        parts.append("applies message encryption")
    rest = [u for u in uses if u not in ("RouteMessageOutboundConnector", "RouteMessageOutboundRequireTls",
                                          "SetSCL", "ApplyOME")]
    if rest:
        parts.append("sets " + ", ".join(rest))
    return {"name": _text(obj.get("Name")), "state": _text(obj.get("State")),
            "mode": _text(obj.get("Mode")), "priority": _int(obj.get("Priority")),
            "uses": uses, "values": values, "summary": "; ".join(parts) or "sets nothing readable"}


_MS_DATE = re.compile(r"^/Date\((-?\d+)[^)]*\)/$")


def _date(value: str) -> str:
    """A report date as ``YYYY-MM-DD``, from ISO 8601 (PowerShell 7's ``ConvertTo-Json``) or
    ``/Date(ms)/`` (Windows PowerShell 5.1's), or the value as given."""
    m = _MS_DATE.match(value.strip())
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC).strftime("%Y-%m-%d")
    iso = _time(value) if re.match(r"^\d{4}-\d\d-\d\d[T ]", value.strip()) else trace._iso(value)
    return iso[:10] if re.match(r"^\d{4}-\d\d-\d\d", iso) else iso


def _traffic(rows: list[dict]) -> dict:
    out: list[dict] = []
    totals: dict[str, dict[str, int]] = {}
    for r in rows:
        count = _int(_get(r, "MessageCount", "Count"))
        direction = _text(_get(r, "Direction"))
        event = _text(_get(r, "EventType"))
        when = _date(_text(_get(r, "Date")))
        out.append({"date": when, "direction": direction, "event_type": event, "messages": count})
        if count is not None:
            d = totals.setdefault(direction or "not stated", {})
            d[event or "not stated"] = d.get(event or "not stated", 0) + count
    dates = sorted(r["date"] for r in out if r["date"])
    return {"rows": out, "totals": totals, "first": dates[0] if dates else "",
            "last": dates[-1] if dates else ""}


# ── The bundle ───────────────────────────────────────────────────────


def _manifest(b: _Bundle) -> tuple[dict, dict[str, dict]]:
    if not b.has("manifest.json"):
        return {}, {}
    try:
        m = _json(b.read("manifest.json"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, {}
    if not isinstance(m, dict):
        return {}, {}
    return m, {_text(r.get("command")): r for r in m.get("readings") or [] if isinstance(r, dict)}


def _refused(command: str, entry: dict) -> str:
    return f"{command}: refused or failed: {_text(entry.get('error')) or 'no error recorded'}"


def _window_notes(command: str, entry: dict) -> list[str]:
    notes = []
    failed = [w for w in entry.get("failed_windows") or [] if isinstance(w, dict)]
    if failed:
        notes.append(f"{command}: {len(failed)} window(s) failed and are missing, first "
                     f"{_text(failed[0].get('start'))} to {_text(failed[0].get('end'))}: "
                     f"{_text(failed[0].get('error'))}")
    if entry.get("truncated_hours"):
        notes.append(f"{command}: {len(entry['truncated_hours'])} hour(s) reached the 100,000-row "
                     "limit and are incomplete")
    return notes


def _is_trace(name: str) -> bool:
    return name.endswith(".csv") and (name.startswith("message-trace") or name.startswith("messagetrace"))


def _is_events(name: str) -> bool:
    return name.startswith("emailevents") and name.endswith((".csv", ".json"))


def read_bundle(path: Path) -> dict:
    """Everything an export holds except the per-message rows, normalised.

    ``trace_files`` and ``email_events_files`` name the per-message files:
    paths, or ``<zip>::<member>`` inside a zip. Read them with
    :func:`trace_flows` and :func:`email_events`. ``notes`` says what was
    missing, refused or incomplete. Raises ``OSError`` for a path that is
    neither a folder nor a zip and ``ValueError`` for one holding nothing
    this reader reads.
    """
    b = _Bundle(path)
    try:
        manifest, entries = _manifest(b)
        notes: list[str] = []
        readings: dict[str, list[dict]] = {}
        for cmdlet, needed in READINGS.items():
            entry = entries.get(cmdlet)
            if entry is not None and entry.get("ok") is False:
                notes.append(_refused(cmdlet, entry))
                continue
            file = _text((entry or {}).get("file")) or f"{cmdlet}.json"
            if not b.has(file):
                notes.append(f"{cmdlet}: not in the export" + ("" if needed else " (optional)"))
                continue
            try:
                readings[cmdlet] = _objects(_json(b.read(file)))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                notes.append(f"{cmdlet}: {file} is not readable JSON ({exc})")
                continue
            if entry:
                notes += _window_notes(cmdlet, entry)
        trace_files = [b.where(n) for n in b.named(_is_trace)]
        events_files = [b.where(n) for n in b.named(_is_events)]
        for command, files, optional in (("Get-MessageTraceV2", trace_files, False),
                                         ("EmailEvents", events_files, True)):
            entry = entries.get(command)
            if entry is not None and entry.get("ok") is False:
                notes.append(_refused(command, entry))
            elif not files:
                notes.append(f"{command}: not in the export" + (" (optional)" if optional else ""))
            if entry:
                notes += _window_notes(command, entry)
                if entry.get("domains_only") is True:
                    notes.append(f"{command}: addresses were reduced to domains when exported")
        if not readings and not trace_files and not events_files:
            raise ValueError(f"{path.name} holds none of the readings this reader reads")
        content_filter = [{"name": _text(o.get("Name")), "is_default": _flag(o.get("IsDefault")),
                           "spf_hard_fail_as_spam": _text(o.get("MarkAsSpamSpfRecordHardFail")),
                           "from_auth_fail_as_spam": _text(o.get("MarkAsSpamFromAddressAuthFail")),
                           "phish_action": _text(o.get("PhishSpamAction")),
                           "high_confidence_phish_action": _text(o.get("HighConfidencePhishAction"))}
                          for o in readings.get("Get-HostedContentFilterPolicy", [])]
        return {
            "source": path.name,
            "pulled": _text(manifest.get("pulled_utc")),
            "accepted_domains": [_accepted(o) for o in readings.get("Get-AcceptedDomain", [])],
            "connectors": [_inbound(o) for o in readings.get("Get-InboundConnector", [])]
            + [_outbound(o) for o in readings.get("Get-OutboundConnector", [])],
            "dkim": [_dkim(o) for o in readings.get("Get-DkimSigningConfig", [])],
            "transport_rules": sorted((rule_summary(o) for o in readings.get("Get-TransportRule", [])),
                                      key=lambda r: (r["priority"] is None, r["priority"] or 0)),
            "remote_domains": [{"name": _text(o.get("Name")),
                                "domain": _text(o.get("DomainName")).lower(),
                                "auto_forward": _flag(o.get("AutoForwardEnabled"))}
                               for o in readings.get("Get-RemoteDomain", [])],
            "arc_trusted_sealers": sorted({s.lower() for o in readings.get("Get-ArcConfig", [])
                                           for s in _list(o.get("ArcTrustedSealers"))}),
            "content_filter": content_filter,
            "traffic": _traffic(readings.get("Get-MailFlowStatusReport", [])),
            "trace_files": trace_files,
            "email_events_files": events_files,
            "notes": notes,
        }
    finally:
        b.close()


def trace_flows(path: Path, owned: set[str]) -> list[trace.TraceFlow]:
    """The message trace flows of every trace CSV in an export, read by :mod:`.trace`."""
    b = _Bundle(path)
    try:
        flows: list[trace.TraceFlow] = []
        for name in b.named(_is_trace):
            raw = b.read(name)
            if trace._decode(raw).strip():
                flows += trace.read_bytes(raw, name, owned)
        return flows
    finally:
        b.close()


# ── Defender EmailEvents ─────────────────────────────────────────────


def _time(value: str) -> str:
    """ISO 8601 in UTC from advanced hunting's timestamps (up to seven fractional digits)."""
    v = value.strip()
    m = re.match(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?$", v)
    if m:
        zone = m.group(3) or "Z"
        dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{'+00:00' if zone == 'Z' else zone}")
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    iso = trace._iso(v)
    return iso + "Z" if re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$", iso) else iso


_AUTH = re.compile(r"\b(SPF|DKIM|DMARC)\b\s*[=:]\s*\"?([A-Za-z]+)", re.IGNORECASE)


def _auth(value: Any) -> dict[str, str]:
    """The SPF, DKIM and DMARC verdicts from ``AuthenticationDetails`` (a JSON object as text)."""
    found: dict[str, str] = {}
    data = value
    if isinstance(value, str):
        try:
            data = json.loads(value) if value.strip().startswith("{") else value
        except json.JSONDecodeError:
            data = value
    if isinstance(data, dict):
        found = {k.lower(): _text(v).lower() for k, v in data.items()
                 if k.lower() in ("spf", "dkim", "dmarc")}
    else:
        found = {m.group(1).lower(): m.group(2).lower() for m in _AUTH.finditer(_text(data))}
    return found


def _event(row: dict) -> dict:
    direction = _DIRECTIONS.get(_text(_get(row, "EmailDirection")).lower().replace(" ", ""), "unknown")
    sender = _text(_get(row, "SenderFromDomain", "SenderMailFromDomain",
                        "SenderFromAddress", "SenderMailFromAddress"))
    recipient = _text(_get(row, "RecipientDomain", "RecipientEmailAddress"))
    auth = _auth(_get(row, "AuthenticationDetails"))
    action = _text(_get(row, "DeliveryAction"))
    location = _text(_get(row, "DeliveryLocation"))
    return {
        "time": _time(_text(_get(row, "Timestamp", "TimeGenerated"))),
        "direction": direction,
        "sender_domain": _domain(sender) if sender else "",
        "recipient_domains": [_domain(recipient)] if recipient else [],
        "size": _int(_get(row, "EmailSize")),
        "tls": "",
        "spf": auth.get("spf", ""), "dkim": auth.get("dkim", ""), "dmarc": auth.get("dmarc", ""),
        "remote_host": "",
        "remote_ip": _text(_get(row, "SenderIPv4", "SenderIPv6")),
        "connector": _text(_get(row, "Connectors")),
        "delivery": f"{action} to {location}" if action and location else action or location,
        "source": SOURCE,
    }


def _rows_from(raw: bytes, name: str) -> list[dict]:
    if name.lower().endswith(".json"):
        data = _json(raw)
        if isinstance(data, dict):
            data = _get(data, "results") or []
        return _objects(data)
    text = trace._decode(raw)
    return [dict(r) for r in csv.DictReader(io.StringIO(text))]


def _merge(rows: Iterable[dict]) -> list[dict]:
    """One event per message: rows are one per recipient, joined by ``NetworkMessageId``."""
    out: dict[str, dict] = {}
    for n, row in enumerate(rows):
        event = _event(row)
        key = _text(_get(row, "NetworkMessageId")) or f"row {n}"
        have = out.get(key)
        if have is None:
            out[key] = event
            continue
        for d in event["recipient_domains"]:
            if d not in have["recipient_domains"]:
                have["recipient_domains"].append(d)
        if event["time"] and (not have["time"] or event["time"] < have["time"]):
            have["time"] = event["time"]
    events = list(out.values())
    for e in events:
        e["recipient_domains"].sort()
    return sorted(events, key=lambda e: e["time"])


def email_events(path: Path) -> list[dict]:
    """Defender for Office 365 ``EmailEvents`` rows as one normalised event per message.

    ``path`` is an export folder or zip (its ``EmailEvents*.csv`` or
    ``.json``), or one such file: the script's CSV, the Defender portal's CSV
    export, or a Microsoft Graph ``runHuntingQuery`` response saved as JSON.
    Only the fields of the shared event schema are kept, so a subject or an
    address in the input never reaches the output.
    """
    if path.is_file() and not zipfile.is_zipfile(path):
        return _merge(_rows_from(path.read_bytes(), path.name))
    b = _Bundle(path)
    try:
        rows: list[dict] = []
        for name in b.named(_is_events):
            rows += _rows_from(b.read(name), name)
        return _merge(rows)
    finally:
        b.close()
