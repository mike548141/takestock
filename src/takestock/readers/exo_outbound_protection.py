"""Exchange Online outbound mail by security type: was the receiving domain authenticated?

**The input** is a CSV of outbound message counts by security type, one row
per hour per type, in the columns ``Date``, ``SecurityType`` and
``CountOfSecuredMessages`` (UTF-8, with or without a byte-order mark, or
UTF-16 with one). The types this reader places are ``DANE``, ``MTA-STS``,
both together and ``TLS-only``. How the combined value is spelt is not
documented: ``DANE and MTA-STS`` and ``DANE+MTA-STS`` are guesses, and any
other value, a different spelling of it included, is counted apart, never
placed.

**What it adds to the per-message record.** :mod:`exo_connector_messages`
reads which TLS version each delivery negotiated. This export says something
else about the same deliveries: whether the sender authenticated the
receiving server by a policy the receiving domain publishes (MTA-STS, or DANE
over DNSSEC), or encrypted the connection without that check. A sender that
does not authenticate the receiver can be steered to an impostor, or to
cleartext, by anyone on the path.

**What it cannot say, and the row says on every run.** Which path a delivery
took: a recipient's published policy applies when mail is delivered to the
recipient's own mail servers, while mail sent through a connector to a smart
host is governed by the connector's settings and may still be counted as
TLS alone. So, when the per-message export is named (``settings: {messages:
<file>}``), the row counts how many outbound messages on the same calendar
dates went through a connector, and says how much of "TLS alone" that can
explain. The export records no TLS version, and its count column is named for
secured messages, so whether a delivery made in clear would appear at all is
not established.

**Row.** One, ``n/a``: it grades no primitive, and a judgement on it would
judge a path it cannot name. A security type not listed above is counted,
placed in neither figure and flagged ``ungraded:mail-security-type:<types>``.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from .exo_connector_messages import load as load_messages

#: The plug-in's name, and so the ``source`` of the row it writes.
NAME = "exo_outbound_protection"

SCOPE_FLAG = "mail-outbound-protection-scope"
UNGRADED_FLAG = "ungraded:mail-security-type:"

register_informational_prefixes(SCOPE_FLAG)

#: The security types placed, and whether each means the receiving domain was
#: authenticated by a policy it publishes. Any other value is counted apart:
#: counted as TLS alone it would understate authenticated delivery, and
#: counted as authenticated it would overstate it.
AUTHENTICATED = {"DANE": True, "MTA-STS": True, "DANE and MTA-STS": True,
                 "DANE+MTA-STS": True, "TLS-only": False}


def load(path: Path) -> tuple[list[dict], str]:
    """The export's rows, or (``[]``, why) when it cannot be read; (``[]``, "") when absent."""
    if not path.exists():
        return [], ""
    try:
        raw = path.read_bytes()
        text = (raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
                else raw.decode("utf-8-sig"))
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if "SecurityType" not in (reader.fieldnames or []):
            return [], "the header row has no SecurityType column"
        return list(reader), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def _int(v: object) -> int:
    try:
        return int(str(v or "").strip() or 0)
    except ValueError:
        return 0


def reconcile(path: Path | None, first: str, last: str) -> tuple[int, int]:
    """(outbound messages, of which through a connector) in the per-message export, ``first..last``.

    Dates only, inclusive: the per-message export carries no hour.
    """
    if path is None:
        return 0, 0
    rows, _ = load_messages(path)
    total = via = 0
    for r in rows:
        if str(r.get("direction", "")).strip() != "Outbound":
            continue
        day = str(r.get("date_utc", "")).strip()[:10]
        if not first <= day <= last:
            continue
        total += 1
        if str(r.get("connector_name", "")).strip():
            via += 1
    return total, via


def _gap(unreadable: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no export of outbound mail by security type was read: whether outbound deliveries "
        "authenticated the receiving domain by a policy it publishes, or were encrypted "
        "without that check"
        + (f"; the file named could not be read ({unreadable})" if unreadable else ""),
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("The per-message record says which TLS version each delivery negotiated; "
                "without this, nothing says whether the receiving server was authenticated, "
                "which decides whether a delivery could be steered to an impostor."),
        harvest=("Export the outbound messages report by security type from the Exchange "
                 "admin centre as CSV and name it in the profile."),
        nature=coverage.NO_DATA)


def _path_note(per_msg: int, via: int, tls_alone: int, named: bool) -> str:
    if not per_msg:
        return ("The per-message export " + ("holds no outbound message on these dates"
                                             if named else "was not named")
                + ", so how much of the TLS-alone figure went through a connector, where a "
                "recipient's published policy does not apply, is not known here.")
    direct = per_msg - via
    share = via / per_msg
    pct = f"{share:.0%}" if share in (0, 1) else f"{share:.1%}"
    note = (f"On the same calendar dates the per-message export holds {per_msg:,} outbound "
            f"messages: {via:,} ({pct}) through a connector to a smart host and {direct:,} "
            "delivered direct. ")
    if tls_alone > direct:
        note += (f"The TLS-alone figure is larger than all the direct deliveries, so, if both "
                 f"exports count the same messages, at least {tls_alone - direct:,} of it is "
                 "connector traffic, where the connector's "
                 "own TLS and certificate settings, not a recipient's published policy, decide "
                 "whether the next hop is authenticated. That part of the TLS-alone figure is "
                 "not evidence that a receiver went unauthenticated. ")
    else:
        note += ("The TLS-alone figure is no larger than the direct deliveries, so all of it "
                 "could be direct delivery to receivers that publish no policy. ")
    return note + ("The per-message export has dates without hours, so these are the same "
                   "days, not the same hours.")


def read(path: Path, messages: Path | None) -> tuple[list[CryptoAsset], list[str]]:
    """The row and gaps for one export; ``messages`` is the per-message export, if named."""
    rows, unreadable = load(path)
    if not rows:
        return [], [_gap(unreadable)]
    when = file_mtime_date(path) or ""
    source_name = ("Exchange Online outbound-messages report ("
                   + (f"file dated {when})" if when else "file date unavailable)"))

    by_type: Counter[str] = Counter()
    stamps: list[str] = []
    for r in rows:
        kind = str(r.get("SecurityType", "")).strip() or "(blank)"
        by_type[kind] += _int(r.get("CountOfSecuredMessages"))
        stamp = str(r.get("Date", "")).strip()
        if stamp:
            stamps.append(stamp)
    total = sum(by_type.values())
    authenticated = sum(n for k, n in by_type.items() if AUTHENTICATED.get(k))
    tls_alone = sum(n for k, n in by_type.items() if AUTHENTICATED.get(k) is False)
    unplaced = sorted(k for k in by_type if k not in AUTHENTICATED)
    first, last = (min(stamps), max(stamps)) if stamps else ("", "")
    window = f"{first} → {last}" if first else "an unstated window"
    dist = ", ".join(f"{n:,} {k}" for k, n in by_type.most_common())

    flags = [SCOPE_FLAG]
    if unplaced:
        flags.append(UNGRADED_FLAG + ",".join(unplaced))
    per_msg, via = reconcile(messages, first[:10], last[:10]) if first else (0, 0)

    notes = (f"{total:,} outbound messages over {window}, the export's own hourly span: {dist}. "
             f"{authenticated:,} were delivered under a policy the receiving domain publishes; "
             f"{tls_alone:,} were encrypted without that check. "
             + _path_note(per_msg, via, tls_alone, messages is not None)
             + " The export records no TLS version, and its count column is named for secured "
               "messages, so whether a delivery made in clear would appear in it is not "
               "established."
             + (f" {len(unplaced)} security type(s) this reader does not place "
                f"({', '.join(unplaced)}) are in the total and in neither figure."
                if unplaced else ""))
    return [CryptoAsset(
        name="Outbound mail — delivery protection by recipient policy",
        data_state="in-transit", protocol="smtp", role=roles.mail_outbound_protection(total),
        source=NAME, source_class="private", source_name=source_name, collected_at=when,
        verdict="n/a", flags=flags, usage_count=total, notes=notes,
        extra={"window": window, "messages": str(total),
               "recipient_policy_messages": str(authenticated),
               "tls_alone_messages": str(tls_alone),
               "security_type_distribution": "; ".join(f"{k}={n}"
                                                       for k, n in by_type.most_common()),
               "per_message_outbound_same_dates": str(per_msg),
               "per_message_via_connector_same_dates": str(via)})], []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: one row, or a gap."""
    if ctx.input is None:
        return StepResult(gaps=[_gap("")])
    assets, gaps = read(ctx.input, _entra.newest(ctx, "messages"))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Exchange Online outbound messages by security type", gap_prefix=False)
