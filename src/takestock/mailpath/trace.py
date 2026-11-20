"""Exchange Online message trace: every message the platform handled, with its size.

**Input.** A CSV exported from message trace, in either of two shapes:

* ``Get-MessageTraceV2 | Export-Csv``: ``Received``, ``SenderAddress``,
  ``RecipientAddress``, ``Status``, ``FromIP``, ``ToIP``, ``Size``,
  ``MessageId``;
* the admin centre's downloadable extended report:
  ``origin_timestamp_utc``, ``sender_address``, ``recipient_status``
  (``address##status``), ``total_bytes``, ``original_client_ip``,
  ``directionality``, ``connector_id``, ``network_message_id``.

A ``Subject`` or ``message_subject`` column is ignored and never kept.

**What it adds that headers and DMARC cannot.** Every message, in every
direction, with its size: the volume of each flow in messages and bytes, and
where a message entered the platform. A sending address on a private network
is an internal host relaying through the platform (an application, a
scanner, an appliance), which no outside source can see.

**What it cannot see.** Anything before the platform received the message
(the hops on an internal network, the software that wrote it) or after it
left (the recipient's side), and the transport of each delivery unless the
export carries it (the connector report does; see the
``exo_connector_messages`` reader). A trace is limited to the dates asked
for, and the platform keeps 90 days.

Rows are one per recipient; a message sent to several recipients is counted
once and its size once, and its recipients are counted separately.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .paths import INBOUND, INTERNAL, OUTBOUND, owning
from .systems import is_internal_address

_ALIASES = {
    "date": ("received", "origin_timestamp_utc", "date_utc", "date"),
    "sender": ("senderaddress", "sender_address"),
    "recipient": ("recipientaddress", "recipient_address", "recipient_status"),
    "size": ("size", "total_bytes"),
    "from_ip": ("fromip", "original_client_ip", "client_ip"),
    "to_ip": ("toip",),
    "status": ("status",),
    "direction": ("directionality", "direction"),
    "connector": ("connector_id", "connector_name", "connector"),
    "message_id": ("messageid", "message_id", "network_message_id"),
    "tls": ("tls_version", "tlsversion"),
}


def _decode(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if len(raw) > 3 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le")
    return raw.decode("utf-8-sig", errors="replace")


def _columns(header: list[str]) -> dict[str, str]:
    low = {h.strip().lower(): h for h in header}
    return {key: low[a] for key, names in _ALIASES.items() for a in names if a in low}


def _domain(address: str) -> str:
    addr = address.split("##")[0].strip().strip("<>").lower()
    return addr.rpartition("@")[2] if "@" in addr else ""


@dataclass
class TraceFlow:
    direction: str
    domain: str
    origin: str               # where the message entered the platform
    connector: str
    messages: int = 0
    recipients: int = 0
    bytes: int = 0
    sized: int = 0
    counterparty_domains: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    tls: Counter = field(default_factory=Counter)
    first: str = ""
    last: str = ""

    def as_dict(self) -> dict:
        return {"direction": self.direction, "domain": self.domain, "origin": self.origin,
                "connector": self.connector, "messages": self.messages,
                "recipients": self.recipients, "bytes": self.bytes, "sized": self.sized,
                "counterparty_domains": len(self.counterparty_domains),
                "statuses": dict(self.statuses), "tls": dict(self.tls),
                "first": self.first, "last": self.last}


def _iso(value: str) -> str:
    """ISO 8601 from the date forms trace exports use; the input if none fits."""
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            continue
    return value


def _tls(value: str) -> str:
    """TLS 1.2 for ``TLS1.2``; none for ``No Tls`` or an empty cell."""
    v = value.strip().lower().replace(" ", "")
    if not v or v in ("notls", "none"):
        return "none"
    m = re.search(r"(\d\.\d)", v)
    return f"TLS {m.group(1)}" if m else value.strip()


def _origin(from_ip: str, direction: str, export_direction: str = "", connector: str = "") -> str:
    if direction == INBOUND:
        return "from outside the platform"
    if export_direction.lower().startswith("inbound"):
        # The platform received it from outside, though the addresses are ours:
        # an application, appliance or service sending as our domain.
        return "from outside the platform" + (" through a connector" if connector else "")
    if not from_ip:
        return "a mailbox on the platform"
    if is_internal_address(from_ip):
        return f"internal host {from_ip}"
    return f"external host {from_ip}"


def read(path: Path, owned: set[str]) -> list[TraceFlow]:
    """Trace flows for an organisation owning ``owned``."""
    text = _decode(path.read_bytes())
    reader = csv.DictReader(io.StringIO(text))
    cols = _columns(list(reader.fieldnames or []))
    if "sender" not in cols or "recipient" not in cols:
        raise ValueError(f"{path.name}: not a message trace export (no sender and recipient columns)")
    seen: set[tuple] = set()
    out: dict[tuple, TraceFlow] = {}
    for row in reader:
        def get(key: str, _row: dict = row) -> str:
            return (_row.get(cols[key]) or "").strip() if key in cols else ""
        sender, recipient = _domain(get("sender")), _domain(get("recipient"))
        mine_s, mine_r = owning(sender, owned), owning(recipient, owned)
        if mine_s and mine_r:
            d = INTERNAL
        elif mine_s:
            d = OUTBOUND
        elif mine_r:
            d = INBOUND
        else:
            continue
        key = (d, mine_s or mine_r, _origin(get("from_ip"), d, get("direction"), get("connector")),
               get("connector"))
        f = out.setdefault(key, TraceFlow(*key))
        f.recipients += 1
        f.statuses[get("status") or "not stated"] += 1
        f.counterparty_domains[recipient if d == OUTBOUND else sender] += 1
        mid = get("message_id") or f"{get('date')}|{get('sender')}"
        if (key, mid) in seen:
            continue
        seen.add((key, mid))
        f.messages += 1
        if "tls" in cols:
            f.tls[_tls(get("tls"))] += 1
        size = get("size")
        if size.isdigit():
            f.bytes += int(size)
            f.sized += 1
        when = _iso(get("date"))
        if when:
            f.first = min(f.first or when, when)
            f.last = max(f.last, when)
    return sorted(out.values(), key=lambda f: (f.direction, -f.messages))
