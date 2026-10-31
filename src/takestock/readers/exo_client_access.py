"""Exchange Online mailbox access: which ways in are switched on, and password-only mail submission.

**The inputs** are CSVs written by Exchange Online PowerShell (the script is
in ``docs/COLLECTORS.md``):

* **per mailbox** (``input:``, or ``settings: {mailboxes: ...}``): one row per
  mailbox, ``PrimarySmtpAddress``, ``RecipientTypeDetails``, the seven access
  switches ``ImapEnabled``, ``PopEnabled``, ``ActiveSyncEnabled``,
  ``MAPIEnabled``, ``OWAEnabled``, ``EwsEnabled`` and ``ECPEnabled``, and
  ``Cmdlet``, the command that read the row (``Get-EXOCasMailbox``, or
  ``Get-CASMailbox``). A ``SmtpClientAuthenticationDisabled`` column, when
  present, is read as each mailbox's override of the organisation setting;
* **the organisation** (``settings: {transport: ...}``): one row,
  ``SmtpClientAuthenticationDisabled``, from ``Get-TransportConfig``;
* **authentication policies** (``settings: {policies: ...}``): one row per
  policy, from ``Get-AuthenticationPolicy``. The script writes this file only
  when a policy exists, so when none is read the reader takes it that there
  is no policy, and the scope row says so.

A setting may be a path, a list or a pattern. Where one names several files
and the mailbox file's name carries a date (``2030-01-31``), the organisation
and policy files of the same date are read, because a mailbox read paired
with another day's organisation setting describes no moment that existed;
with no file of that date, none is read. Without a date, the last in name
order is read.

**What "switched on" means.** A switch says Exchange Online will serve that
protocol to that mailbox, not how the caller proves who it is. Microsoft has
retired password-only ("Basic") sign-in for IMAP, POP, Exchange ActiveSync,
Exchange Web Services, Outlook's protocols, the Offline Address Book,
Autodiscover and remote PowerShell in every tenant, and says no one (the
tenant or Microsoft support) can turn it back on (*Deprecation of Basic
authentication in Exchange Online*, :data:`BASIC_AUTH_RETIRED_URL`). Each of
those protocols, switched on, takes only a token from the directory, which
passes the directory's sign-in controls. Outlook on the web is not on that
list: it is used in a browser, which Conditional Access counts as a modern
authentication client (*How to Use Conditions in Conditional Access
Policies*, :data:`CA_CLIENT_APPS_URL`), so its row says that instead.

**Authenticated SMTP submission is the exception**, and the one row this
reader grades ``weak``. Microsoft's timeline (Exchange Team blog,
:data:`SMTP_BASIC_TIMELINE_URL`, published 2026-01-27) says: "Now to December
2026: SMTP AUTH Basic Authentication behavior remains unchanged"; at the end
of December 2026 it is "disabled by default for existing tenants", and
"Administrators will still be able to enable it if needed"; a final removal
date is to be announced in the second half of 2027. So, in an export dated on
or before :data:`SMTP_BASIC_DEFAULT_OFF`, the organisation switch turned on
means a mailbox's password alone can send mail as that mailbox, unless a
mailbox override or an authentication policy blocks it.

Grades:

* IMAP and POP: ``acceptable``, token-only; flagged
  ``exo-legacy-protocol-enabled:<protocol>`` when on, because Microsoft calls
  them legacy protocols, security defaults switch them off, and on is the
  default for every mailbox (:data:`POP_IMAP_URL`).
* Exchange ActiveSync, MAPI, Exchange Web Services: ``acceptable``, token-only.
* Outlook on the web: ``acceptable``, signed in through a browser.
* ECP: ``unknown``; Microsoft documents ``ECPEnabled`` as available only in
  on-premises Exchange.
* Organisation SMTP submission: ``weak`` when on. A password alone can send
  mail, and NZISM v3.9 16.7.42.C.01 (MUST) requires multifactor
  authentication for user accounts on cloud-based services.

The SMTP row is ``unknown`` instead of ``weak`` when an authentication policy
exists (the export does not say which mailboxes each covers) or when the
export is dated after :data:`SMTP_BASIC_DEFAULT_OFF`, after which this
reading of Microsoft's position must be checked again before it grades. The
export's date is the date in the mailbox file's name or, when the name has
none, the file's modification date. When no policy file is read, the row says
whether one was named and not found (the script writes none when no policy
exists, so none is taken to exist) or never named. Never named, policies were
not read at all, so the row is ``unknown``, as it is when a policy is read but
its coverage is not known. A row's ``collected_at`` is the mailbox file's
modification date; the scope row states both dates, each labelled.
Microsoft documents TLS 1.2 or 1.3 as required for SMTP submission and SSL/TLS
on the IMAP and POP ports; that is Microsoft's statement, not a measurement,
so these rows have data state ``identity``: they are about who can sign in,
and how.

**Rows.** One per protocol, never per mailbox: switching a protocol off by
default and on by exception is decided per protocol, and the split by mailbox
kind (user, shared, room, equipment and so on) goes in ``extra``. Addresses
never leave the reading loop. Then the organisation SMTP row and a scope row.

**Cannot see.** Use: a switch says a protocol is permitted, not that anyone
uses it (the sign-in logs answer that; :mod:`entra_signins` reads legacy
clients). The organisation-level Exchange Web Services switch, which
Microsoft changes from October 2026 to turn the protocol off. Conditional
Access policies that would block a legacy sign-in. Each is a coverage gap.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "exo_client_access"

SCOPE_FLAG = "exo-client-access-scope"
#: Not a count: a flag carrying a number that moves when a mailbox is created
#: would read as the estate getting worse.
LEGACY_PROTOCOL_FLAG = "exo-legacy-protocol-enabled:"
SMTP_AUTH_FLAG = "exo-smtp-auth-enabled-tenant-wide"

register_informational_prefixes(SCOPE_FLAG)

# ── Microsoft's position, read on Microsoft Learn and the Exchange Team blog ──
BASIC_AUTH_RETIRED_URL = (
    "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-"
    "online/deprecation-of-basic-authentication-exchange-online")
SMTP_BASIC_TIMELINE_URL = (
    "https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-"
    "smtp-auth-basic-authentication-deprecation-timeline/4489835")
SMTP_AUTH_SETTING_URL = (
    "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-"
    "online/authenticated-client-smtp-submission")
EWS_RETIREMENT_URL = (
    "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-"
    "online/deprecation-of-ews-exchange-online")
POP_IMAP_URL = (
    "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-"
    "online/pop3-and-imap4/pop3-and-imap4")
CA_CLIENT_APPS_URL = (
    "https://learn.microsoft.com/en-us/entra/identity/conditional-access/"
    "concept-conditional-access-conditions")
#: When the pages above were last read, and found to say what this module says.
VERIFIED_ON = "2026-11-01"

#: The last day of Microsoft's announced "behavior remains unchanged" period
#: for SMTP AUTH Basic authentication. An export dated after it is graded
#: ``unknown`` until Microsoft's position is read again: the default changes
#: then, and the date has moved before.
SMTP_BASIC_DEFAULT_OFF = "2026-12-31"

#: NZISM v3.9 controls, read from the manual's published CSV.
NZISM_MFA_CLOUD = "16.7.42.C.01"
NZISM_REMOTE_SUBMISSION = "15.2.46.C.01"

BASIC_RETIRED = (
    "Password-only (Basic) sign-in for this protocol has been retired in every Exchange "
    "Online tenant and cannot be turned back on, so a mailbox with it switched on accepts "
    "only a sign-in token from the directory, and the directory's sign-in controls apply "
    f"(Microsoft, {BASIC_AUTH_RETIRED_URL}, read {VERIFIED_ON})")

#: How each protocol is named on its row.
SHORT_NAME = {"imap": "IMAP", "pop": "POP", "activesync": "Exchange ActiveSync",
              "mapi": "MAPI (Outlook for Windows)", "owa": "Outlook on the web",
              "ews": "Exchange Web Services",
              "ecp": "ECP (administration and settings pages)"}

_LEGACY = ("Microsoft calls IMAP and POP legacy protocols, security defaults switch them off, "
           f"and switched on is the default for every mailbox ({POP_IMAP_URL}).")

#: Outlook on the web is not on Microsoft's list of protocols whose Basic
#: sign-in was retired; this is what is known about how it signs in.
BROWSER_SIGN_IN = (
    "Outlook on the web is not on Microsoft's list of protocols whose Basic sign-in was "
    "retired: it is used in a browser, which Conditional Access counts as a modern "
    f"authentication client ({CA_CLIENT_APPS_URL}, read {VERIFIED_ON})")

#: What each graded protocol's row says about password-only sign-in, and its
#: ``basic_sign_in`` value.
SIGN_IN = {"owa": (BROWSER_SIGN_IN, "browser sign-in; modern authentication client")}
RETIRED = (BASIC_RETIRED, "retired by Microsoft; token-only")

#: (column, key, what the protocol is for, verdict, flagged when on?, further sentence)
PROTOCOLS: tuple[tuple[str, str, str, str, bool, str], ...] = (
    ("ImapEnabled", "imap", "How older and third-party mail programs read a mailbox (IMAP)",
     "acceptable", True,
     f"{_LEGACY} Microsoft documents SSL/TLS on port 993; this reader has not tested it."),
    ("PopEnabled", "pop", "How older mail programs download mail (POP)", "acceptable", True,
     f"{_LEGACY} Microsoft documents SSL/TLS on port 995; this reader has not tested it."),
    ("ActiveSyncEnabled", "activesync",
     "How phones' built-in mail apps keep a mailbox in step (Exchange ActiveSync)",
     "acceptable", False, ""),
    ("MAPIEnabled", "mapi", "How Outlook for Windows reaches a mailbox (MAPI)",
     "acceptable", False, ""),
    ("OWAEnabled", "owa", "Outlook in a browser (Outlook on the web)",
     "acceptable", False, ""),
    ("EwsEnabled", "ews",
     "The programming interface applications and Outlook for Mac use to reach a mailbox "
     "(Exchange Web Services)",
     "acceptable", False,
     "Microsoft is retiring Exchange Web Services: it starts turning it off for all "
     "organisations in October 2026, and turns it off fully in April 2027 "
     f"({EWS_RETIREMENT_URL}, read {VERIFIED_ON}). This export reads the per-mailbox "
     "switch only, not the organisation switch."),
    ("ECPEnabled", "ecp",
     "Access to the Exchange administration and settings pages in a browser (ECP)",
     "unknown", False,
     "Microsoft documents this switch as available only in on-premises Exchange, so what it "
     "governs in Exchange Online is not established, and the row is not graded."),
)

_TRUE = {"true", "1", "yes"}
_FALSE = {"false", "0", "no"}
_OVERRIDE = "SmtpClientAuthenticationDisabled"


def state(value: str) -> str:
    """``on``, ``off`` or ``unrecorded`` for a switch's value."""
    v = value.strip().lower()
    if v in _TRUE:
        return "on"
    if v in _FALSE:
        return "off"
    return "unrecorded"


def read_csv(path: Path | None) -> tuple[list[dict], str]:
    """Rows, or (``[]``, why); a byte-order mark is removed."""
    if path is None or not path.exists():
        return [], ""
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh)), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def date_in_name(path: Path) -> str:
    """The first ``YYYY-MM-DD`` in a file's name, or ""."""
    m = re.search(r"(\d{4}-\d{2}-\d{2})", path.name)
    return m.group(1) if m else ""


def _newest(found: list[Path]) -> Path | None:
    return max(found, key=lambda p: (date_in_name(p), p.name)) if found else None


def _plain(value: object) -> bool:
    """Whether a setting names one file, with no pattern."""
    return isinstance(value, str) and not any(ch in Path(value).name for ch in "*?[")


def files(ctx: Context) -> tuple[Path | None, Path | None, Path | None]:
    """The mailbox, organisation and policy files, paired by the date in their names."""
    settings = ctx.settings or {}
    mailbox = ctx.input if ctx.input is not None else _newest(_entra.paths(ctx, "mailboxes"))
    stamp = date_in_name(mailbox) if mailbox is not None else ""

    def partner(key: str) -> Path | None:
        found = _entra.paths(ctx, key)
        if not found:
            return None
        if _plain(settings.get(key)):
            return found[0]
        if stamp:
            same = [p for p in found if date_in_name(p) == stamp]
            return same[-1] if same else None
        return _newest(found)

    return mailbox, partner("transport"), partner("policies")


def source_name(path: Path, when: str) -> str:
    return (f"Exchange Online mailbox access settings ({path.name}, "
            + (f"file dated {when})" if when else "file date unavailable)"))


def protocol_rows(rows: list[dict], name: str, when: str) -> list[CryptoAsset]:
    """One row per protocol switch."""
    total = len(rows)
    out: list[CryptoAsset] = []
    for column, key, what, verdict, flagged, sentence in PROTOCOLS:
        basis, sign_in = SIGN_IN.get(key, RETIRED)
        by_kind: dict[str, Counter[str]] = {}
        for r in rows:
            kind = (r.get("RecipientTypeDetails") or "").strip() or "Unrecorded"
            by_kind.setdefault(kind, Counter())[state(r.get(column) or "")] += 1
        on = sum(c["on"] for c in by_kind.values())
        off = sum(c["off"] for c in by_kind.values())
        unrec = sum(c["unrecorded"] for c in by_kind.values())
        split = "; ".join(
            f"{kind} {c['on']} on" + (f", {c['off']} off" if c["off"] else "")
            + (f", {c['unrecorded']} unrecorded" if c["unrecorded"] else "")
            for kind, c in sorted(by_kind.items(), key=lambda kv: -sum(kv[1].values())))
        notes = (f"On for {on:,} of {total:,} mailboxes"
                 + (f", off for {off:,}" if off else "")
                 + (f", not recorded for {unrec:,}" if unrec else "")
                 + f" ({split}). "
                 + (basis + ". " if verdict == "acceptable" else "")
                 + (sentence + " " if sentence else "")
                 + "A switch says the protocol is permitted, not that anyone uses it.")
        out.append(CryptoAsset(
            name=f"Mailbox access — {SHORT_NAME[key]}", data_state="identity",
            protocol="mailbox-access", role=roles.mailbox_access_method(what, on, total),
            source=NAME, source_class="private", source_name=name, collected_at=when,
            verdict=verdict, flags=[f"{LEGACY_PROTOCOL_FLAG}{key}"] if flagged and on else [],
            hosts_count=on, notes=notes,
            extra={"setting": column, "mailboxes": total, "mailboxes_on": on,
                   "mailboxes_off": off, "mailboxes_unrecorded": unrec,
                   "by_mailbox_kind": split,
                   "basic_sign_in": sign_in if verdict == "acceptable" else "not graded",
                   "microsoft_position_read": VERIFIED_ON}))
    return out


def smtp_row(transport: list[dict], policies: list[dict], mailboxes: list[dict], name: str,
             when: str, dated: str = "", policies_named: bool = True) -> CryptoAsset | None:
    """The organisation's authenticated SMTP switch, graded; None without the organisation file.

    ``dated`` is the export's date for the cut-off (default ``when``);
    ``policies_named`` says whether the profile named a policy file at all.
    """
    dated = dated or when
    if not transport:
        return None
    raw = (transport[0].get(_OVERRIDE) or "").strip()
    disabled = state(raw)
    total = len(mailboxes)
    has_override = any(_OVERRIDE in r for r in mailboxes)
    overrides = (Counter(state(r.get(_OVERRIDE) or "") for r in mailboxes)
                 if has_override else Counter())
    flags: list[str] = []
    basis = (f"Microsoft's timeline ({SMTP_BASIC_TIMELINE_URL}, published 2026-01-27, read "
             f"{VERIFIED_ON}): \"Now to December 2026: SMTP AUTH Basic Authentication behavior "
             "remains unchanged\"; at the end of December 2026 it is \"disabled by default for "
             "existing tenants\", and administrators can turn it back on. Microsoft recommends "
             "turning SMTP AUTH off for the organisation and on only for the mailboxes that "
             f"need it ({SMTP_AUTH_SETTING_URL}). Microsoft requires TLS 1.2 or 1.3 on this "
             "path, so the password does not cross in clear; the weakness is that a password "
             "alone is enough.")
    standard = (f"NZISM v3.9 {NZISM_MFA_CLOUD} (MUST) requires multifactor authentication for "
                "user accounts on cloud-based services. A path that accepts a password alone "
                "does not ask whoever uses it for a second factor; a Conditional Access policy "
                "blocking legacy sign-in would close it, and those policies are not in this "
                f"export. NZISM v3.9 {NZISM_REMOTE_SUBMISSION} (MUST: an authenticated and "
                "encrypted channel for mail sent from outside the network) is met on "
                "Microsoft's own documentation.")
    if disabled == "on":
        verdict = "acceptable"
        finding = ("Authenticated SMTP submission is off for the organisation, as Microsoft "
                   "recommends. A mailbox can still override it to on; "
                   + ("the per-mailbox counts follow." if has_override
                      else "this export did not read that per-mailbox setting."))
    elif disabled == "off":
        flags.append(SMTP_AUTH_FLAG)
        if policies:
            verdict = "unknown"
            why = (f"{len(policies)} authentication polic{'y' if len(policies) == 1 else 'ies'} "
                   "exist, and the export does not say which mailboxes each covers, so whether "
                   "a policy blocks password-only submission for a mailbox cannot be read from "
                   "it.")
        elif not policies_named:
            verdict = "unknown"
            why = ("no authentication policy file was named, so whether a policy blocks "
                   "password-only submission was not read, the same doubt as when a policy is "
                   "read but its coverage is not known.")
        elif dated and dated > SMTP_BASIC_DEFAULT_OFF:
            verdict = "unknown"
            why = (f"the export is dated {dated}, after {SMTP_BASIC_DEFAULT_OFF}, when Microsoft "
                   "announced Basic sign-in on this path would be off by default, so this "
                   "reading of Microsoft's position must be checked again before it grades.")
        else:
            verdict = "weak"
            why = ("no authentication policy file was found for this export, and the export "
                   "script writes one only when a policy exists, so none is taken to exist; and "
                   "on this date Microsoft still accepts password-only sign-in on this path.")
        finding = ("Authenticated SMTP submission is on for the whole organisation "
                   f"({_OVERRIDE} = False). Each of the {total:,} mailboxes read follows that "
                   "setting unless it overrides it, so whoever holds the password of an "
                   "account with a mailbox can send mail as that mailbox with the password "
                   "alone, unless a mailbox override or a Conditional Access policy blocks it. "
                   f"Graded {verdict} because {why}")
    else:
        verdict = "unknown"
        finding = (f"The organisation export has no readable value ({raw!r}), so the "
                   "organisation setting is not known.")
    if has_override:
        finding += (f" Mailbox overrides: {overrides['on']:,} turned off, {overrides['off']:,} "
                    f"turned on, {overrides['unrecorded']:,} following the organisation "
                    "setting.")
    return CryptoAsset(
        name="Mail submission by password — organisation setting", data_state="identity",
        protocol="smtp-submission", role=roles.mail_submission_setting(), source=NAME,
        source_class="private", source_name=name, collected_at=when, verdict=verdict,
        flags=flags, notes=f"{finding} {basis} {standard}",
        extra={_OVERRIDE: raw or "blank", "mailboxes_read": total,
               "authentication_policies": len(policies),
               "per_mailbox_override_read": "yes" if has_override else "no",
               "microsoft_basic_default_off": SMTP_BASIC_DEFAULT_OFF,
               "microsoft_position_read": VERIFIED_ON,
               "nzism_controls": f"{NZISM_MFA_CLOUD}; {NZISM_REMOTE_SUBMISSION}"})


def scope_row(rows: list[dict], mailbox: Path, transport: Path | None, policy: Path | None,
              policies: list[dict], name: str, when: str,
              policies_named: bool = True) -> CryptoAsset:
    """What the export covers, and what it cannot say."""
    kinds = Counter((r.get("RecipientTypeDetails") or "").strip() or "Unrecorded" for r in rows)
    cmdlets = Counter((r.get("Cmdlet") or "").strip() or "unrecorded" for r in rows)
    kinds_s = ", ".join(f"{n:,} {k}" for k, n in kinds.most_common())
    cmd_s = ", ".join(f"{n:,} by {c}" for c, n in cmdlets.most_common())
    policy_s = (f"{len(policies)} authentication polic{'y' if len(policies) == 1 else 'ies'} "
                f"read from {policy.name}" if policy is not None and policies else
                ("no authentication policy file was found; the export script writes one only "
                 "when a policy exists, so this is read as no policy" if policies_named else
                 "no authentication policy file was named, so policies were not read"))
    named_date = date_in_name(mailbox)
    dates = ((f"dated {named_date} by its file name" if named_date else "")
             + (" and " if named_date and when else "")
             + (f"last modified {when}" if when else "")) or "with no recorded date"
    notes = (f"The export covers {len(rows):,} mailboxes ({kinds_s}), {dates} ({cmd_s}), "
             "and the organisation's authenticated "
             "SMTP switch"
             + (f" from {transport.name}" if transport is not None else ", which was not read")
             + f"; {policy_s}. It records what each mailbox is permitted to do, not what any "
               "client did: which clients sign in over these protocols is a question for the "
               "sign-in logs. It does not read the organisation-level Exchange Web Services "
               "switch, or the Conditional Access policies that could block a legacy sign-in"
             + ("" if any(_OVERRIDE in r for r in rows) else
                ", or each mailbox's SMTP override")
             + ". Transport encryption on these protocols is Microsoft's documented behaviour, "
               "not something this reader measured.")
    return CryptoAsset(
        name="Mailbox access settings — scope", data_state="identity", protocol="mailbox-access",
        role=roles.mailbox_access_scope(), source=NAME, source_class="private",
        source_name=name, collected_at=when, verdict="n/a", flags=[SCOPE_FLAG],
        hosts_count=len(rows), notes=notes,
        extra={"mailboxes": len(rows), "by_mailbox_kind": kinds_s, "read_by": cmd_s,
               "mailbox_export": mailbox.name,
               "tenant_export": transport.name if transport else "not held",
               "policy_export": policy.name if policy else "none",
               "pull_date_in_file_name": date_in_name(mailbox) or "none"})


def _mailbox_gap(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no Exchange Online mailbox access export was read: per mailbox, whether IMAP, POP, "
        "Exchange ActiveSync, MAPI, Outlook on the web and Exchange Web Services are switched "
        "on, with the organisation's authenticated SMTP switch beside it"
        + (f"; {why}" if why else ""),
        impact=("The sign-in logs show which protocols were used in the period they cover; only "
                "this says which the tenant still accepts, including whether a program can "
                "send mail with a password alone."),
        impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
        harvest=("Run the read-only Exchange Online PowerShell script in docs/COLLECTORS.md "
                 "and name its files in the profile."))


def gaps_for(rows: list[dict], smtp: CryptoAsset | None) -> list[str]:
    """What the export leaves unread, beside its rows."""
    out: list[str] = []
    if smtp is None:
        out.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"the organisation's authenticated SMTP switch ({_OVERRIDE}, from "
            "Get-TransportConfig) for the same export as the mailbox file: whether a program "
            "can send mail as a mailbox by signing in with its password alone",
            impact=("The one mailbox path on which Microsoft still accepts a password alone "
                    "cannot be graded, so the reading of mail sign-in is incomplete."),
            impact_kind=coverage.CHANGES_CONCLUSION, nature=coverage.NO_DATA,
            harvest=("Run the export script again; it writes the organisation file beside the "
                     "mailbox file, with the same date in its name.")))
    if not any(_OVERRIDE in r for r in rows):
        out.append(coverage.gap(
            coverage.NOT_MEASURED,
            f"which of the {len(rows):,} mailboxes override the organisation's authenticated "
            f"SMTP switch: the per-mailbox {_OVERRIDE} column is not in the mailbox file",
            impact=("The organisation setting gives every mailbox's default; a mailbox "
                    "overriding it either way is not seen, so the number of mailboxes that "
                    "accept a password for sending is an upper bound when the organisation "
                    "switch is on, and a lower bound when it is off."),
            impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
            harvest=(f"Add {_OVERRIDE} to the mailbox file's columns; the reader reads it "
                     "when present.")))
    out.append(coverage.gap(
        coverage.NOT_MEASURED,
        "the organisation-level Exchange Web Services switch (Get-OrganizationConfig "
        "EwsEnabled), which Microsoft changes from October 2026 to turn the protocol off; the "
        "mailbox file has only the per-mailbox switch",
        impact=("Whether Exchange Web Services is still served after Microsoft turns it off "
                "cannot be read from the per-mailbox switch, which can say on either way."),
        impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.LOW_FIDELITY,
        harvest="Add Get-OrganizationConfig, selecting EwsEnabled, to the export script."))
    out.append(coverage.gap(
        coverage.NOT_COLLECTED,
        "which clients sign in over IMAP, POP, Exchange ActiveSync and authenticated SMTP: "
        "the use behind the mailbox access settings, which say only what is permitted",
        impact=("Turning a protocol off is safe only where nothing uses it, and these settings "
                "cannot show use."),
        impact_kind=coverage.NARROWS_CONFIDENCE, nature=coverage.NO_DATA,
        harvest=("A sign-in log download filtered to those client apps over the tenant's full "
                 "retention, interactive and non-interactive (read by entra_signins and "
                 "entra_workload_signins).")))
    return out


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the protocol rows, the SMTP row and the scope row, or a gap."""
    mailbox, transport, policy = files(ctx)
    rows, unreadable = read_csv(mailbox)
    if not rows:
        why = ("none was named, as the reader's input or under settings: mailboxes"
               if mailbox is None else
               f"{mailbox.name} could not be read ({unreadable})" if unreadable else
               f"{mailbox.name} does not exist" if not mailbox.exists() else
               f"{mailbox.name} holds no rows")
        return StepResult(gaps=[_mailbox_gap(why)])
    assert mailbox is not None
    when = file_mtime_date(mailbox) or ""
    name = source_name(mailbox, when)
    transport_rows, _ = read_csv(transport)
    policy_rows, _ = read_csv(policy)
    assets = protocol_rows(rows, name, when)
    named = bool((ctx.settings or {}).get("policies"))
    smtp = smtp_row(transport_rows, policy_rows, rows, name, when,
                    dated=date_in_name(mailbox) or when, policies_named=named)
    if smtp is not None:
        assets.append(smtp)
    assets.append(scope_row(rows, mailbox, transport if transport_rows else None, policy,
                            policy_rows, name, when, policies_named=named))
    return StepResult(records=assets, gaps=gaps_for(rows, smtp))


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Exchange Online mailbox access settings", gap_prefix=False)
