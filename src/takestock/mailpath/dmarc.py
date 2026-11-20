"""DMARC aggregate reports: who sends as a domain, how much, and whether it authenticates.

**What a report is.** A receiving mail service that checks DMARC sends the
domain's owner a daily summary (RFC 7489 § 7.2, RFC 9990): for each source
address that sent mail claiming the domain in its From header, how many
messages, and whether SPF and DKIM passed *in alignment* with that domain.
It is the only source that sees mail an organisation sends to the whole
internet, including mail sent by services acting for it, and mail sent by
someone impersonating it.

**What it cannot see.** Message sizes, transport encryption, routes, and any
mail delivered to a receiver that does not send reports (many smaller
services do not). Mail between two of the organisation's own mailboxes
inside one platform is usually never reported, because no outside receiver
saw it. The counts are what reporters chose to report.

**Inputs.** RFC 7489 XML reports (``.xml``, ``.xml.gz``, ``.zip``) and the rows
Cloudflare's DMARC Management analytics return (see :mod:`.cloudflare`).
Both become :class:`Record`; :func:`sources` groups records by the system
that sent them.
"""

from __future__ import annotations

import gzip
import io
import json
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from .systems import Catalogue, registrable


@dataclass
class Record:
    header_from: str
    source_ip: str
    count: int
    spf: str                 # policy-evaluated (aligned) SPF result
    dkim: str                # policy-evaluated (aligned) DKIM result
    disposition: str = "none"
    reporter: str = ""
    source_ptr: str = ""
    source_org: str = ""
    envelope_from: str = ""
    begin: str = ""
    end: str = ""
    policy: str = ""

    @property
    def passed(self) -> bool:
        return self.spf == "pass" or self.dkim == "pass"


def _text(node: ElementTree.Element | None, path: str) -> str:
    if node is None:
        return ""
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else ""


def parse_xml(data: bytes) -> list[Record]:
    """Records from one RFC 7489 aggregate report."""
    root = ElementTree.fromstring(data)
    reporter = _text(root, "report_metadata/org_name")
    begin = _text(root, "report_metadata/date_range/begin")
    end = _text(root, "report_metadata/date_range/end")
    policy = _text(root, "policy_published/p")
    out: list[Record] = []
    for rec in root.findall("record"):
        row = rec.find("row")
        out.append(Record(
            header_from=_text(rec, "identifiers/header_from").lower(),
            source_ip=_text(row, "source_ip"),
            count=int(_text(row, "count") or 0),
            spf=_text(row, "policy_evaluated/spf") or "fail",
            dkim=_text(row, "policy_evaluated/dkim") or "fail",
            disposition=_text(row, "policy_evaluated/disposition") or "none",
            reporter=reporter,
            envelope_from=_text(rec, "identifiers/envelope_from").lower(),
            begin=begin, end=end, policy=policy))
    return out


def read_report(path: Path) -> list[Record]:
    """Records from an XML, gzipped XML or zipped XML report file."""
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        return parse_xml(gzip.decompress(raw))
    if raw[:2] == b"PK":
        out: list[Record] = []
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in z.namelist():
                if name.lower().endswith(".xml"):
                    out += parse_xml(z.read(name))
        return out
    return parse_xml(raw)


def from_cloudflare_rows(rows: list[dict]) -> list[Record]:
    """Records from Cloudflare's ``dmarcReportsAdaptive`` analytics rows."""
    return [Record(
        header_from=(r.get("headerFrom") or "").lower(),
        source_ip=r.get("sourceIP") or "",
        count=int(r.get("matchingMessages") or 0),
        spf=(r.get("spf") or "fail").lower(),
        dkim=(r.get("dkim") or "fail").lower(),
        disposition=(r.get("disposition") or "none").lower(),
        reporter=r.get("orgName") or "",
        source_ptr=(r.get("sourcePTR") or "").rstrip(".").lower(),
        source_org=r.get("sourceOrgName") or "",
        envelope_from=(r.get("spfMFromDomain") or r.get("envelopeFrom") or "").lower(),
        begin=r.get("reportBegin") or r.get("datetime") or "",
        end=r.get("reportEnd") or "",
        policy=(r.get("policyDomain") or "").lower(),
    ) for r in rows]


def load(paths: list[Path]) -> list[Record]:
    """Records from report files and saved Cloudflare row files (``.json``)."""
    out: list[Record] = []
    for p in paths:
        if p.is_dir():
            out += load(sorted(x for x in p.iterdir() if x.is_file()
                               and x.name.lower().endswith((".xml", ".xml.gz", ".gz", ".zip", ".json"))))
        elif p.suffix.lower() == ".json":
            out += from_cloudflare_rows(json.loads(p.read_text(encoding="utf-8")))
        else:
            out += read_report(p)
    return out


def system_of(rec: Record, catalogue: Catalogue) -> str:
    """The sending system: by reverse DNS, a declared address range, or a network
    whose only traffic is one service's mail; otherwise the network's owner."""
    if rec.source_ptr:
        named = catalogue.by_host(rec.source_ptr)
        if named:
            return named
    if rec.source_ip:
        named = catalogue.by_address(rec.source_ip)
        if named:
            return named
    if rec.source_org:
        named = catalogue.by_asn_org(rec.source_org)
        if named:
            return named
    if rec.source_ptr:
        return registrable(rec.source_ptr)
    # A registry name says who owns the network, not which service sent.
    return f"network: {rec.source_org}" if rec.source_org else f"address {rec.source_ip}"


@dataclass
class Source:
    """Everything one system sent as one domain, as receivers reported it."""

    header_from: str
    system: str
    messages: int = 0
    spf_pass: int = 0
    dkim_pass: int = 0
    dmarc_pass: int = 0
    dispositions: Counter = field(default_factory=Counter)
    reporters: Counter = field(default_factory=Counter)
    addresses: set[str] = field(default_factory=set)
    envelope_domains: Counter = field(default_factory=Counter)
    first: str = ""
    last: str = ""

    def as_dict(self) -> dict:
        return {"header_from": self.header_from, "system": self.system,
                "messages": self.messages, "spf_aligned_pass": self.spf_pass,
                "dkim_aligned_pass": self.dkim_pass, "dmarc_pass": self.dmarc_pass,
                "dispositions": dict(self.dispositions),
                "reporters": dict(self.reporters.most_common()),
                "source_addresses": len(self.addresses),
                "envelope_domains": dict(self.envelope_domains.most_common(8)),
                "first": self.first, "last": self.last}


def sources(records: list[Record], catalogue: Catalogue) -> list[Source]:
    """Group records by (domain, sending system), largest first."""
    out: dict[tuple[str, str], Source] = {}
    for r in records:
        key = (r.header_from, system_of(r, catalogue))
        s = out.setdefault(key, Source(*key))
        s.messages += r.count
        s.spf_pass += r.count if r.spf == "pass" else 0
        s.dkim_pass += r.count if r.dkim == "pass" else 0
        s.dmarc_pass += r.count if r.passed else 0
        s.dispositions[r.disposition] += r.count
        if r.reporter:
            s.reporters[r.reporter] += r.count
        if r.source_ip:
            s.addresses.add(r.source_ip)
        s.envelope_domains[r.envelope_from or "(empty)"] += r.count
        for when in (r.begin, r.end):
            if when:
                s.first = min(s.first or when, when)
                s.last = max(s.last, when)
    return sorted(out.values(), key=lambda s: (s.header_from, -s.messages))
