"""How many service findings could have something put in front of them.

``plaintext.py`` answers *can something be put in front of this service?* for
one service at a time, through the ``frontable`` column of the port table
(``port-encryption.csv``). This module does the arithmetic over a whole
observation, so that a count has exactly one producer and can be re-derived from the data.

## What is counted

A **service finding** is one ``(asset, flag)`` pair where the flag is
``plaintext:<protocol>`` or ``unverified-encryption:<protocol>``: the two flags
``plaintext.apply_posture`` raises, and the two ``normalise.plaintext_summary``
already reports separately. This total is their sum. There is no second
definition and no separate "service" unit: where each finding sits on a distinct
``(host, port)``, one finding is one listener on one host.

``cleartext-exposure:`` and ``no-encrypted-alternative:`` are deliberately not
counted. They classify a ``plaintext:`` finding rather than adding one, and
counting them would report one finding twice.

## Classified by protocol, not port

The flag carries the protocol the port-table row named, so the protocol is the
key back to that row and no transport guess is needed.
:func:`frontable_by_protocol` refuses to build an index in which one protocol
carries two answers, because the flag alone would then not determine the class
and the count would depend on which row was read first.

## The hedge travels with the total

The two flags are not one claim. ``plaintext:`` says the traffic is in clear.
``unverified-encryption:`` says only that nothing observed the negotiation on a
port whose protocol can run unencrypted. Every breakdown therefore carries
``cleartext`` and ``opportunistic`` beside the total, so a caller cannot quote
the total without being handed its split.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .model import CryptoAsset, load_assets
from .plaintext import CLEARTEXT, OPPORTUNISTIC, PLAINTEXT_FLAG, UNVERIFIED_FLAG, PortTable

#: The flag prefixes that are a service finding, each with the posture it asserts.
FINDING_FLAGS = ((PLAINTEXT_FLAG, CLEARTEXT), (UNVERIFIED_FLAG, OPPORTUNISTIC))

#: The class a finding lands in when its protocol has no row in the port table.
NO_ROW = "no-port-table-row"


@dataclass
class FrontingClass:
    """One ``frontable`` value's share of an observation.

    ``hosts`` is the set of distinct hosts in this class, so the host column of
    a breakdown never sums to the total: one machine appears in several classes.
    ``FrontingBreakdown.total_hosts`` is the union.
    """

    findings: int = 0
    cleartext: int = 0
    opportunistic: int = 0
    hosts: set[str] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)

    @property
    def host_count(self) -> int:
        return len(self.hosts)


def frontable_by_protocol(table: PortTable) -> dict[str, str]:
    """Map each protocol in the port table to its one ``frontable`` answer.

    Raises ``ValueError`` when a protocol carries two different answers. No
    bundled row is ambiguous; this stops a later edit making one silently.
    """
    seen: dict[str, str] = {}
    for row in table.values():
        protocol = row.get("protocol", "").strip()
        answer = row.get("frontable", "").strip()
        if not protocol:
            continue
        if protocol in seen and seen[protocol] != answer:
            raise ValueError(
                f"port-encryption.csv: protocol {protocol!r} carries two frontable answers "
                f"({seen[protocol]!r} and {answer!r}); a finding flag names the protocol, "
                f"not the port, so the class it belongs to would be ambiguous"
            )
        seen[protocol] = answer
    return seen


@dataclass
class FrontingBreakdown:
    """Every service finding in one observation, sorted by ``frontable`` class."""

    by_class: dict[str, FrontingClass]
    total: int
    cleartext: int
    opportunistic: int
    total_hosts: int

    def markdown(self) -> str:
        """The breakdown as a markdown table a document can carry verbatim."""
        lines = [
            "| Class | Findings | Distinct hosts | Cleartext by port | Not proven encrypted |",
            "|---|---:|---:|---:|---:|",
        ]
        for name, c in sorted(self.by_class.items(), key=lambda kv: (-kv[1].findings, kv[0])):
            lines.append(
                f"| `{name}` | {c.findings} | {c.host_count} | {c.cleartext} | {c.opportunistic} |"
            )
        lines.append(
            f"| **Total** | **{self.total}** | **{self.total_hosts}** | "
            f"**{self.cleartext}** | **{self.opportunistic}** |"
        )
        return "\n".join(lines)


def fronting_breakdown(assets: list[CryptoAsset], table: PortTable) -> FrontingBreakdown:
    """Count every service finding in ``assets`` by its ``frontable`` class.

    A protocol with no row in the port table lands under :data:`NO_ROW` rather
    than being dropped: a finding the classification cannot place is a hole in
    it, and silence would report that hole as an absence.
    """
    answers = frontable_by_protocol(table)
    by_class: dict[str, FrontingClass] = defaultdict(FrontingClass)
    total = posture_cleartext = posture_opportunistic = 0
    all_hosts: set[str] = set()
    for asset in assets:
        for flag in asset.flags:
            for prefix, posture in FINDING_FLAGS:
                if not flag.startswith(prefix):
                    continue
                protocol = flag[len(prefix):]
                entry = by_class[answers.get(protocol) or NO_ROW]
                entry.findings += 1
                entry.protocols[protocol] += 1
                host = asset.host or asset.name
                entry.hosts.add(host)
                all_hosts.add(host)
                total += 1
                if posture == CLEARTEXT:
                    entry.cleartext += 1
                    posture_cleartext += 1
                else:
                    entry.opportunistic += 1
                    posture_opportunistic += 1
    return FrontingBreakdown(
        by_class=dict(by_class),
        total=total,
        cleartext=posture_cleartext,
        opportunistic=posture_opportunistic,
        total_hosts=len(all_hosts),
    )


def breakdown_for_observation(observation: Path, table: PortTable) -> FrontingBreakdown:
    """The breakdown for an observation directory (its ``assets.json``)."""
    rows = json.loads((observation / "assets.json").read_text())
    return fronting_breakdown(load_assets(rows), table)


def main(argv: list[str] | None = None) -> int:
    """``python3 -m takestock.fronting <observation-dir>``: print the table."""
    from .config import load_port_encryption

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python3 -m takestock.fronting <observation-dir>", file=sys.stderr)
        return 2
    print(breakdown_for_observation(Path(args[0]), load_port_encryption()).markdown())
    return 0


if __name__ == "__main__":  # pragma: no cover - a convenience entry point
    raise SystemExit(main())
