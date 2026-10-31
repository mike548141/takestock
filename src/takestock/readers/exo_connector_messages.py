"""Exchange Online per-message transport: whether each message left or arrived encrypted, and on which path.

**The input** is a CSV with one row per message, in the columns
``date_utc``, ``message_id``, ``direction`` (``Inbound`` or ``Outbound``),
``sender_address``, ``recipient_address``, ``connector_name``,
``connector_type``, ``tls_version`` (such as ``TLS1.2``, or ``No Tls`` for a
delivery made with no transport encryption) and ``tls_cipher``. One file may
hold both directions. It may be UTF-16 (little-endian, with or without a
byte-order mark) or UTF-8; the encoding is worked out from the bytes, because
a UTF-16 file with no byte-order mark carries nothing that names it.

**Why it is read beside the connector settings.** A connector's settings say
what the platform is configured to enforce. Opportunistic transport security
and enforced transport security look the same from the sending side until a
far end offers no TLS, so only a count of what each message negotiated shows
whether any delivery fell back to cleartext.

**Rows.** One per direction and path (a connector, or ``direct (no
connector)``), named ``<Direction> mail — <path>``, and a scope row. Never one
per message: the finding is the path ("this route carried n messages, this
many in clear"), and who mailed whom is not. Addresses never leave the
reading loop; ``extra`` holds counts, the number of counterparty domains, and
for each delivery made in clear its date and the counterparty's domain.

Every row has data state ``in-transit``, protocol ``smtp`` and source
``mail_transport``: the reader is declared with the ``mail-transport`` kind,
which fixes that source, because it is what the Secure Government Email
reading (:mod:`takestock.sge`) takes the sending half of SGE-TLS-01 and the
SGE-ITLS-01 population from. The rows are written finished, in the field
names that reading uses (``docs/PLUGINS.md``, ``mail-transport``).

**Grading.** Each TLS version is graded as the baseline grades it (TLS 1.3
strong, TLS 1.2 acceptable, older weak), and ``No Tls`` is weak because it is
the absence of transport encryption. A path takes the weakest grade it
carried. Flags: ``mail-cleartext-delivery:<count>`` for messages delivered in
clear, ``mail-legacy-tls:<version>`` for each weak version seen, and
``ungraded:mail-tls-version:<versions>`` for a version this reader does not
know. All three are findings; the scope row's ``mail-flow-scope`` is not.

**Mail with government organisations.** SGE-ITLS-01 is about mail exchanged
between government organisations, and the counterparty's domain is the only
identifier the export carries. A counterparty is counted as a government
organisation when its domain ends in one of the suffixes in ``settings:
{government_suffixes: [...]}``, by default New Zealand's ``.govt.nz``,
``.mil.nz`` and ``.parliament.nz``, and is not one of the organisation's own
domains (``discovery.domains`` and ``discovery.email_domains`` in the target
profile), which may sit under the same suffixes. This is a lower bound: a
government organisation mailing from a domain outside the suffixes is not
counted.

**Cannot see.** What any message contained; the onward legs (for mail sent
through a connector, the peer is the smart host, not the final recipient);
anything outside the export's own dates, which the scope row states.
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

#: The plug-in's name. Its rows' source is :data:`SOURCE`, which its kind fixes.
NAME = "exo_connector_messages"
SOURCE = "mail_transport"
KIND = "mail-transport"

CLEARTEXT_FLAG = "mail-cleartext-delivery:"
LEGACY_TLS_FLAG = "mail-legacy-tls:"
UNGRADED_FLAG = "ungraded:mail-tls-version:"
SCOPE_FLAG = "mail-flow-scope"

register_informational_prefixes(SCOPE_FLAG)

DIRECT_PATH = "direct (no connector)"
NO_TLS = "No Tls"

#: The government domain suffixes used when the profile names none: New
#: Zealand's moderated second-level domains for government, defence and
#: Parliament.
GOVERNMENT_SUFFIXES = (".govt.nz", ".mil.nz", ".parliament.nz")

#: Each ``tls_version`` value the export writes, graded as the baseline grades
#: the version; ``No Tls`` is not a version but its absence.
VERSION_GRADE = {"TLS1.3": "strong", "TLS1.2": "acceptable", "TLS1.1": "weak",
                 "TLS1.0": "weak", NO_TLS: "weak"}
_GRADE_RANK = {"strong": 0, "acceptable": 1, "unknown": 2, "weak": 3}

LIMIT = ("A TLS version here is the transport negotiated with the immediate peer for that "
         "delivery; it says nothing about what any message contained.")


def load(path: Path) -> tuple[list[dict], str]:
    """The export's rows, or (``[]``, why) when it cannot be read; (``[]``, "") when absent.

    A byte-order mark selects the UTF-16 codec that reads it. With none, the
    file is read as UTF-16 little-endian first, then as UTF-8, and whichever
    gives a ``date_utc`` heading is used.
    """
    if not path.exists():
        return [], ""
    try:
        raw = path.read_bytes()
        enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-16-le"
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            text = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if "date_utc" not in (reader.fieldnames or []):
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
        if "date_utc" not in (reader.fieldnames or []):
            return [], "the header row has no date_utc column"
        return list(reader), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


def own_domains(target: dict) -> tuple[str, ...]:
    """The organisation's own domains, from the target profile's ``discovery`` block."""
    d = target.get("discovery") or {}
    return tuple(sorted({str(x).strip().lower()
                         for x in list(d.get("domains") or []) + list(d.get("email_domains") or [])
                         if str(x).strip()}))


def government_suffixes(settings: dict) -> tuple[str, ...]:
    """The suffixes ``settings: government_suffixes`` names, each with a leading dot."""
    value = settings.get("government_suffixes")
    if not value:
        return GOVERNMENT_SUFFIXES
    values = [value] if isinstance(value, str) else list(value)
    out = []
    for v in values:
        s = str(v).strip().lower()
        if s:
            out.append(s if s.startswith(".") else "." + s)
    return tuple(out) or GOVERNMENT_SUFFIXES


def classifier(suffixes: tuple[str, ...]) -> str:
    """How a government counterparty was identified, in words, for every row that counts one."""
    shown = ", ".join(suffixes[:-1]) + (f" or {suffixes[-1]}" if len(suffixes) > 1
                                        else suffixes[-1])
    return f"counterparty domain ending {shown}, with our own domains excluded"


def is_government(domain: str, own: tuple[str, ...], suffixes: tuple[str, ...]) -> bool:
    """Whether ``domain`` ends in a government suffix and is not one of the organisation's own."""
    if not domain or any(domain == o or domain.endswith("." + o) for o in own):
        return False
    return domain.endswith(suffixes)


class _Path:
    def __init__(self, connector_type: str) -> None:
        self.messages = 0
        self.versions: Counter[str] = Counter()
        self.domains: set[str] = set()
        self.clear: list[tuple[str, str]] = []
        self.type = connector_type
        self.govt = 0
        self.govt_versions: Counter[str] = Counter()
        self.govt_domains: set[str] = set()
        self.govt_days: set[str] = set()


def _verdict(versions: Counter[str]) -> str:
    grades = [VERSION_GRADE.get(v, "unknown") for v in versions]
    return max(grades, key=lambda g: _GRADE_RANK[g])


def _flags(versions: Counter[str]) -> list[str]:
    flags: list[str] = []
    clear = versions.get(NO_TLS, 0)
    if clear:
        flags.append(f"{CLEARTEXT_FLAG}{clear}")
    for v in versions:
        if VERSION_GRADE.get(v) == "weak" and v != NO_TLS:
            flags.append(f"{LEGACY_TLS_FLAG}{v}")
    unknown = sorted(v for v in versions if v not in VERSION_GRADE)
    if unknown:
        flags.append(UNGRADED_FLAG + ",".join(unknown))
    return flags


def _finding(p: _Path, verb: str) -> str:
    total, versions = p.messages, p.versions
    clear = versions.get(NO_TLS, 0)
    dist = ", ".join(f"{n:,} at {v}" if v != NO_TLS else f"{n:,} with no TLS"
                     for v, n in versions.most_common())
    if clear:
        text = (f"{clear:,} of the {total:,} messages on this path {verb} with no transport "
                "encryption, so anyone on the network path could read them. The path "
                "negotiates encryption when the far end offers it, so a delivery in clear is "
                f"allowed, and these messages show it happened. All versions: {dist}.")
        domains = sorted({d for _, d in p.clear if d})
        if domains:
            text += " The deliveries in clear were with: " + ", ".join(domains) + "."
        return text
    if set(versions) == {"TLS1.3"}:
        return f"All {total:,} messages on this path {verb} at TLS 1.3, with no exception."
    return f"{total:,} messages {verb} on this path: {dist}. None was delivered in clear."


def _gap(unreadable: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no per-message mail transport export was read: the TLS version each message "
        "negotiated, in both directions and per path"
        + (f"; the file named could not be read ({unreadable})" if unreadable else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, a path that encrypts only when the far end offers TLS, and "
                "delivers in clear otherwise, cannot be told from one that enforces "
                "encryption: a check that only watches successful sends passes both."),
        harvest=("Export the per-message transport report from the Exchange admin centre as "
                 "CSV and name it in the profile."),
        nature=coverage.NO_DATA)


def read(path: Path, target: dict, settings: dict) -> tuple[list[CryptoAsset], list[str]]:
    """The rows and gaps for one export."""
    rows, unreadable = load(path)
    if not rows:
        return [], [_gap(unreadable)]
    when = file_mtime_date(path) or ""
    source_name = ("Exchange Online per-message transport report ("
                   + (f"file dated {when})" if when else "file date unavailable)"))
    suffixes = government_suffixes(settings)
    basis = classifier(suffixes)
    own = own_domains(target)

    paths: dict[tuple[str, str], _Path] = {}
    first = last = ""
    by_direction: Counter[str] = Counter()
    for r in rows:
        direction = str(r.get("direction", "")).strip() or "Unknown"
        connector = str(r.get("connector_name", "")).strip() or DIRECT_PATH
        version = str(r.get("tls_version", "")).strip() or NO_TLS
        date = str(r.get("date_utc", "")).strip()
        if date:
            first = min(first or date, date)
            last = max(last, date)
        by_direction[direction] += 1
        p = paths.setdefault((direction, connector),
                             _Path(str(r.get("connector_type", "")).strip()))
        p.messages += 1
        p.versions[version] += 1
        # The counterparty: the recipient of outbound mail, the sender of
        # inbound mail. Only its domain is kept.
        other = _domain(str(r.get("recipient_address", "") if direction == "Outbound"
                            else r.get("sender_address", "")))
        if other:
            p.domains.add(other)
            if is_government(other, own, suffixes):
                p.govt += 1
                p.govt_versions[version] += 1
                p.govt_domains.add(other)
                if date:
                    p.govt_days.add(date)
        if version == NO_TLS:
            p.clear.append((date, other))

    assets: list[CryptoAsset] = []
    for (direction, connector), p in sorted(paths.items(), key=lambda kv: -kv[1].messages):
        verb = {"Outbound": "left", "Inbound": "arrived"}.get(direction, "moved")
        assets.append(CryptoAsset(
            name=f"{direction} mail — {connector}", data_state="in-transit", protocol="smtp",
            role=roles.mail_flow(direction, connector, p.messages, direct=DIRECT_PATH),
            source=SOURCE, source_class="private", source_name=source_name, collected_at=when,
            verdict=_verdict(p.versions), flags=_flags(p.versions), usage_count=p.messages,
            notes=f"{_finding(p, verb)} {LIMIT}",
            extra={"direction": direction, "connector": connector,
                   "connector_type": p.type or "none",
                   "connector_present": "no" if connector == DIRECT_PATH else "yes",
                   "messages": str(p.messages),
                   "no_tls_messages": str(p.versions.get(NO_TLS, 0)),
                   "tls_distribution": "; ".join(f"{v}={n}"
                                                 for v, n in p.versions.most_common()),
                   "counterparty_domains": str(len(p.domains)),
                   "govt_messages": str(p.govt),
                   "govt_no_tls_messages": str(p.govt_versions.get(NO_TLS, 0)),
                   "govt_tls_distribution": "; ".join(
                       f"{v}={n}" for v, n in p.govt_versions.most_common()) or "none",
                   "govt_counterparty_domains": str(len(p.govt_domains)),
                   "govt_days": str(len(p.govt_days)),
                   "govt_identified_by": basis,
                   "no_tls_events": "; ".join(
                       f"{d or 'undated'} → {dom or 'unknown domain'}"
                       for d, dom in sorted(p.clear)) or "none"}))

    window = f"{first} → {last}" if first else "an unstated window"
    total = sum(by_direction.values())
    shown = ", ".join(f"{n:,} {d.lower()}" for d, n in by_direction.most_common())
    # The union across paths: one counterparty seen on two paths is counted once.
    govt_domains = set().union(*(p.govt_domains for p in paths.values()))
    assets.append(CryptoAsset(
        name="Per-message mail transport scope", data_state="in-transit", protocol="smtp",
        role=roles.mail_flow_scope(), source=SOURCE, source_class="private",
        source_name=source_name, collected_at=when, verdict="n/a", flags=[SCOPE_FLAG],
        usage_count=total,
        notes=(f"The export covers {total:,} messages ({shown}) over {window}, its own first "
               "and last dates, and every path row is bounded by it. Each message's reading is "
               "the transport negotiated with the immediate peer for that delivery: for mail "
               "through a connector that peer is the smart host, not the final recipient. "
               "Nothing here says what a message contained."),
        extra={"window": window, "messages": str(total),
               "govt_messages_total": str(sum(p.govt for p in paths.values())),
               "govt_counterparty_domains_total": str(len(govt_domains)),
               "govt_identified_by": basis,
               **{f"messages_{d.lower()}": str(n) for d, n in by_direction.items()}}))
    return assets, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the path rows and the scope row, or a gap."""
    if ctx.input is None:
        return StepResult(gaps=[_gap("")])
    assets, gaps = read(ctx.input, ctx.target, ctx.settings or {})
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind=KIND, step=step,
                title="Exchange Online per-message transport report", gap_prefix=False)
