"""Per-message records from mail platforms' own logs, grouped into flows.

**What these sources are.** A mail platform records every message it handles:
Google Workspace's Gmail log events, Microsoft Defender for Office 365's
``EmailEvents``, Cloudflare Email Routing and Email Sending analytics. Each
source module normalises its rows into one schema, so they are read the same
way here::

    {"time": ISO 8601, "direction": "inbound" | "outbound" | "internal" | "unknown",
     "sender_domain": str, "recipient_domains": [str], "size": int | None,
     "tls": "TLS 1.2" | "TLS 1.3" | "none" | "", "spf": str, "dkim": str, "dmarc": str,
     "remote_host": str, "remote_ip": str, "connector": str, "delivery": str,
     "source": str}

An empty string means the source does not say. No source keeps a subject, a
body, a message identifier or a full address.

**What they add to headers and DMARC reports.** Every message the platform
handled, in every direction, from the organisation's side: sizes, the
platform's own record of transport and authentication, the far end it handed
to or took from, and what it did with the message. That is the census the
other sources cannot give.

**What they cannot see.** Hops before the platform received a message or after
it handed it on, and anything outside the dates and licence the source covers.
Each source states its own limits.

Flows are grouped by (source, direction, our domain, the far system, the
connector), and keep counts, bytes and tallies only.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .paths import owning
from .systems import Catalogue

FIELDS = ("time", "direction", "sender_domain", "recipient_domains", "size", "tls", "spf", "dkim",
          "dmarc", "remote_host", "remote_ip", "connector", "delivery", "source")


@dataclass
class PlatformFlow:
    source: str
    direction: str
    domain: str
    far_system: str
    connector: str
    messages: int = 0
    sized: int = 0
    bytes: int = 0
    tls: Counter = field(default_factory=Counter)
    spf: Counter = field(default_factory=Counter)
    dkim: Counter = field(default_factory=Counter)
    dmarc: Counter = field(default_factory=Counter)
    delivery: Counter = field(default_factory=Counter)
    counterparties: set[str] = field(default_factory=set)
    first: str = ""
    last: str = ""

    def as_dict(self) -> dict:
        return {"source": self.source, "direction": self.direction, "domain": self.domain,
                "far_system": self.far_system, "connector": self.connector,
                "messages": self.messages, "messages_with_size": self.sized, "bytes": self.bytes,
                "tls": dict(self.tls), "spf": dict(self.spf), "dkim": dict(self.dkim),
                "dmarc": dict(self.dmarc), "delivery": dict(self.delivery),
                "counterparty_domains": len(self.counterparties),
                "first": self.first, "last": self.last}


def _ours(row: dict, owned: set[str]) -> tuple[str, list[str]]:
    """(our domain on this message, the other side's domains)."""
    sender = str(row.get("sender_domain") or "").lower()
    recipients = [str(d).lower() for d in row.get("recipient_domains") or [] if d]
    direction = row.get("direction") or "unknown"
    if direction == "inbound":
        ours = next((owning(d, owned) for d in recipients if owning(d, owned)), "")
        return ours, [sender] if sender else []
    ours = owning(sender, owned)
    return ours, [d for d in recipients if not owning(d, owned)]


def flows(rows: list[dict], owned: set[str], catalogue: Catalogue) -> list[PlatformFlow]:
    """Group normalised platform rows into flows for an organisation owning ``owned``."""
    out: dict[tuple, PlatformFlow] = {}
    for row in rows:
        direction = row.get("direction") or "unknown"
        ours, others = _ours(row, owned)
        if not ours and direction != "unknown":
            continue
        far = ""
        if row.get("remote_host") or row.get("remote_ip"):
            far = catalogue.name_host(str(row.get("remote_host") or ""), "", str(row.get("remote_ip") or ""))
        key = (str(row.get("source") or ""), direction, ours, far, str(row.get("connector") or ""))
        f = out.setdefault(key, PlatformFlow(*key))
        f.messages += 1
        size = row.get("size")
        if isinstance(size, int):
            f.sized += 1
            f.bytes += size
        f.tls[row.get("tls") or "not recorded"] += 1
        for name in ("spf", "dkim", "dmarc", "delivery"):
            getattr(f, name)[row.get(name) or "not recorded"] += 1
        f.counterparties.update(others)
        when = str(row.get("time") or "")
        if when:
            f.first = min(f.first or when, when)
            f.last = max(f.last, when)
    return sorted(out.values(), key=lambda f: (f.source, f.direction, -f.messages))


def check(rows: list[dict]) -> list[str]:
    """Problems with rows that claim the schema (unknown keys, an address kept)."""
    problems = []
    for i, row in enumerate(rows):
        extra = set(row) - set(FIELDS)
        if extra:
            problems.append(f"row {i}: keys outside the schema {sorted(extra)}")
        for d in [row.get("sender_domain"), *(row.get("recipient_domains") or [])]:
            if d and "@" in str(d):
                problems.append(f"row {i}: an address where a domain belongs")
    return problems
