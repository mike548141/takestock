"""A self-contained HTML note: Secure Government Email conformance for one organisation.

The note is built from :func:`takestock.sge.evaluate` results and the
requirement set in ``data/secure-government-email.yaml``. It carries:

* a summary: how many requirements are met, not met and not measured, at each
  level, which unmet requirements are stated as *must*, and why the
  unmeasured ones could not be measured;
* every requirement, grouped by level, with the sentence that decides its
  level, its source, and the reading for each domain or host;
* the requirements left unmeasured, each with the evidence that would settle
  it;
* the DNS record text read for each domain, where the results carry it;
* the limits of reading a mail configuration from outside;
* an appendix listing the evidence files the results were read from.

A requirement counts as met only when every reading of it passed. One reading
that could not be measured leaves the requirement *not measured*, never met.

Run as ``python -m takestock.sge_note <observation_dir> <target.yaml> <out.html>``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config, htmlpage, sge
from .exits import EXIT_CLEAN, EXIT_FINDINGS, guarded
from .htmlpage import esc

STATUS_LABEL = {sge.PASS: "Met", sge.FAIL: "Not met", sge.NOT_MEASURED: "Not measured"}
STATUS_ORDER = (sge.PASS, sge.FAIL, sge.NOT_MEASURED)

LEVELS = {
    "must": ("Must", "Requirements the framework states as must. An unmet one is a breach "
                     "of the framework."),
    "recommended": ("Recommended", "Requirements stated as should or recommended, and bare "
                                   "instructions that carry no keyword. An unmet one is a "
                                   "recommendation not followed, never a breach."),
}

SCOPE_LABEL = {
    "email-domain": "each email-enabled domain",
    "non-email-domain": "each domain and sub-domain that sends no mail",
    "organisation": "the organisation as a whole",
    "mail-path": "each mail path, receiving and sending",
}

# The order unmeasured reasons are named in, most fundamental first.
_REASON_ORDER = (sge.NO_INSTRUMENT, sge.NOT_COLLECTED, sge.INCONCLUSIVE)

# Short names for the DNS record a requirement family reads.
_RECORD_LABEL = {
    "SPF": "SPF", "DMARC": "DMARC", "MTASTS": "MTA-STS", "TLSRPT": "TLS-RPT",
    "DKIM": "DKIM", "NED": "Sub-domain records", "TLS": "TLS", "ITLS": "TLS",
}

_LIMITS = [
    ("Accepting is not using.",
     "A receiving server that still accepts an old TLS version permits what the framework "
     "forbids, but a probe cannot see what senders actually negotiate. What the "
     "organisation sends is visible only through its own transport records."),
    ("DKIM selectors cannot be listed.",
     "DNS offers no way to enumerate the names under _domainkey, so keys are checked only "
     "at selectors already known. No answer at a guessed selector proves nothing."),
    ("A published key is not a signed message.",
     "A DKIM key in DNS shows that signing is possible, not that every service signs."),
    ("Sub-domain checks can fail but never pass.",
     "The sub-domains read are those found in public certificate-transparency logs, a floor, "
     "not the full set. One name without a required record settles a requirement as unmet; "
     "any number of compliant names cannot settle it as met."),
    ("Some conditions are invisible from outside.",
     "Whether a domain sends bulk mail, or sends mail at all, decides which rules apply to "
     "it, and neither shows in DNS. Where such a condition is unsettled, the reading is "
     "reported and the verdict left unmeasured."),
    ("The inside is not visible.",
     "Inbound DMARC handling, report review, data loss prevention, keyword blocking, "
     "quarantine practice and TLS monitoring are the organisation's own configuration "
     "and practice. They are listed so the note covers every requirement, and each says "
     "what evidence would settle it."),
]


@dataclass(frozen=True)
class EvidenceFile:
    """One file the results were read from: its path within the observation, size and digest."""

    path: str
    size: int
    sha256: str


def evidence_files(observation_dir: Path) -> list[EvidenceFile]:
    """The observation's ``assets.json`` and every file under its ``raw/`` and ``evidence/``."""
    root = Path(observation_dir)
    found = [root / "assets.json"] if (root / "assets.json").is_file() else []
    for sub in ("raw", "evidence"):
        d = root / sub
        if d.is_dir():
            found += sorted(p for p in d.rglob("*") if p.is_file())
    out = []
    for p in found:
        digest = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                digest.update(chunk)
        out.append(EvidenceFile(p.relative_to(root).as_posix(), p.stat().st_size,
                                digest.hexdigest()))
    return out


def requirement_status(rows: Iterable[sge.Conformance]) -> str:
    """One requirement's result over all its readings.

    Not met if any reading failed; met only if there is at least one reading
    and every one passed; otherwise not measured.
    """
    statuses = [r.status for r in rows]
    if sge.FAIL in statuses:
        return sge.FAIL
    if statuses and all(s == sge.PASS for s in statuses):
        return sge.PASS
    return sge.NOT_MEASURED


def _main_reason(rows: list[sge.Conformance]) -> str:
    reasons = [r.reason for r in rows if r.status == sge.NOT_MEASURED]
    if not reasons:
        return ""
    rank = {k: i for i, k in enumerate(_REASON_ORDER)}
    candidates = sorted(set(reasons), key=lambda k: (rank.get(k, len(rank)), k))
    return max(candidates, key=reasons.count)


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _sentence(text: str) -> str:
    text = text.strip()
    return text[:1].upper() + text[1:]


def _subject(row: sge.Conformance) -> str:
    return (row.subject or "the organisation") + (" (parked)" if row.parked else "")


def _badge(status: str) -> str:
    return f'<span class="status status-{esc(status)}">{esc(STATUS_LABEL[status])}</span>'


def _table(head: list[str], rows: list[list[str]], caption: str = "",
           num: tuple[int, ...] = ()) -> str:
    def cell(tag: str, i: int, value: str) -> str:
        cls = ' class="num"' if i in num else ""
        return f"<{tag}{cls}>{value}</{tag}>"

    out = ['<div class="table-wrap"><table>']
    if caption:
        out.append(f"<caption>{esc(caption)}</caption>")
    out.append("<thead><tr>" + "".join(cell("th", i, esc(h)) for i, h in enumerate(head))
               + "</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(cell("td", i, v) for i, v in enumerate(r)) + "</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def _explanation(row: sge.Conformance) -> str:
    if row.status == sge.NOT_MEASURED:
        label = sge.UNMEASURED_LABEL.get(row.reason, row.reason)
        text = f"<strong>{esc(_sentence(label))}.</strong> {esc(_sentence(row.evidence))}"
    else:
        text = esc(_sentence(row.reason))
        if row.evidence:
            text += f'<br><small>Read from: {esc(row.evidence)}</small>'
    if row.subject_note:
        text += f"<br><small>{esc(row.subject_note)}</small>"
    return text


def _settled_by(req: dict, subject: str) -> str:
    text = " ".join(str(req.get("settled_by") or "").split())
    if not text:
        return "Not stated in the requirement set."
    return text.replace("<domain>", subject) if subject else text


class _Note:
    """The note's content, worked out once from the results and the requirement set."""

    def __init__(self, results: sge.Report, target: dict, standard: dict,
                 evidence: list[EvidenceFile], observation: str) -> None:
        self.results = results
        self.standard = standard
        self.std = results.standard or standard.get("standard", {})
        self.organisation = htmlpage.organisation_name(target)
        self.evidence = evidence
        self.observation = observation
        self.reqs: dict[str, dict] = {r["id"]: r for r in standard.get("requirements", [])}
        self.rows: dict[str, list[sge.Conformance]] = {}
        for row in results.rows:
            self.rows.setdefault(row.requirement, []).append(row)
        for rid, rows in self.rows.items():
            self.reqs.setdefault(rid, {"id": rid, "title": rows[0].title,
                                       "level": rows[0].level, "scope": rows[0].scope})
        self.order = [rid for rid in self.reqs if rid in self.rows]
        self.status = {rid: requirement_status(self.rows[rid]) for rid in self.order}
        discovered = (target.get("discovery") or {}).get("email_domains") or []
        self.domains = [str(d) for d in discovered] or sorted({
            r.subject for r in results.rows
            if r.scope in ("email-domain", "non-email-domain") and r.subject and not r.parked})
        beneath = sge.parked_subdomains_subject("")
        self.parked = list(results.parked) or [
            sge.ParkedDomain(d) for d in dict.fromkeys(
                r.subject for r in results.rows
                if r.parked and not r.subject.startswith(beneath))]

    def levels(self) -> list[str]:
        seen = [str(self.reqs[rid].get("level") or "") for rid in self.order]
        known = [lv for lv in LEVELS if lv in seen]
        return known + sorted(set(seen) - set(known))

    def in_level(self, level: str) -> list[str]:
        return [rid for rid in self.order if str(self.reqs[rid].get("level") or "") == level]

    def title(self, rid: str) -> str:
        return str(self.reqs[rid].get("title") or rid)

    def link(self, rid: str) -> str:
        return f'<a href="#{esc(rid)}">{esc(rid)}</a> {esc(self.title(rid))}'

    # ── sections ──────────────────────────────────────────────────────

    def summary(self) -> str:
        total = len(self.order)
        counts = {s: sum(1 for rid in self.order if self.status[rid] == s) for s in STATUS_ORDER}
        name = self.std.get("name", "Secure Government Email Common Implementation Framework")
        version = self.std.get("version", "")
        out = ['<section id="summary" aria-labelledby="summary-h">',
               '<h2 id="summary-h">Summary</h2>',
               f"<p>This note reads the organisation's mail configuration against the {esc(name)}"
               + (f" v{esc(version)}" if version else "")
               + f". Of its {_n(total, 'requirement')}: {counts[sge.PASS]} met, "
                 f"{counts[sge.FAIL]} not met, {counts[sge.NOT_MEASURED]} not measured. A "
                 "requirement is met only when every reading of it passed; one reading that "
                 "could not be measured leaves it unmeasured.</p>"]
        rows = []
        for level in self.levels():
            ids = self.in_level(level)
            label = LEVELS.get(level, (level.capitalize(), ""))[0]
            rows.append([esc(label)] + [str(sum(1 for rid in ids if self.status[rid] == s))
                                        for s in STATUS_ORDER] + [str(len(ids))])
        rows.append(["<strong>All</strong>"] + [f"<strong>{counts[s]}</strong>"
                                                for s in STATUS_ORDER]
                    + [f"<strong>{total}</strong>"])
        out.append(_table(["Level", "Met", "Not met", "Not measured", "Requirements"], rows,
                          caption="Requirements by level and result", num=(1, 2, 3, 4)))

        breaches = [rid for rid in self.order if self.status[rid] == sge.FAIL
                    and str(self.reqs[rid].get("level")) == "must"]
        out.append("<h3>Unmet requirements stated as must</h3>")
        if breaches:
            items = []
            for rid in breaches:
                subjects = [_subject(r) for r in self.rows[rid] if r.status == sge.FAIL]
                items.append(f"<li>{self.link(rid)}: {esc(', '.join(subjects))}</li>")
            verb = "is" if len(breaches) == 1 else "are"
            out.append(f"<p>{_n(len(breaches), 'requirement')} the framework states as must "
                       f"{verb} not met:</p><ul>" + "".join(items) + "</ul>")
        else:
            out.append("<p>No requirement stated as must was found unmet. That is not the "
                       f"same as conformance: {_n(counts[sge.NOT_MEASURED], 'requirement')} "
                       "could not be measured.</p>")

        unmeasured = [rid for rid in self.order if self.status[rid] == sge.NOT_MEASURED]
        out.append("<h3>Why requirements could not be measured</h3>")
        if unmeasured:
            by_reason: dict[str, int] = {}
            for rid in unmeasured:
                key = _main_reason(self.rows[rid])
                by_reason[key] = by_reason.get(key, 0) + 1
            items = [f"<li>{by_reason[k]}: {esc(sge.UNMEASURED_LABEL.get(k, k))}</li>"
                     for k in (*_REASON_ORDER, *sorted(set(by_reason) - set(_REASON_ORDER)))
                     if k in by_reason]
            out.append("<ul>" + "".join(items) + '</ul><p>Each is listed under '
                       '<a href="#not-measured">Not measured</a> with the evidence that would '
                       "settle it.</p>")
        else:
            out.append("<p>Every requirement was measured.</p>")

        facts = [("Organisation", esc(self.organisation)),
                 ("Domains read", esc(", ".join(self.domains)) or "none named")]
        if self.parked:
            facts.append(("Parked domains", f'{esc(", ".join(p.domain for p in self.parked))} '
                                            '(<a href="#parked">read separately</a>)'))
        if self.observation:
            facts.append(("Evidence", f"observation <code>{esc(self.observation)}</code>"))
        if self.std.get("deadline_note"):
            facts.append(("The framework's own date", esc(" ".join(
                str(self.std["deadline_note"]).split()))))
        out.append('<dl class="facts">' + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
                   + "</dl>")
        out.append("</section>")
        return "\n".join(out)

    def requirement(self, rid: str) -> str:
        req = self.reqs[rid]
        basis = req.get("level_basis") or {}
        status = self.status[rid]
        out = [f'<article class="card" id="{esc(rid)}" aria-labelledby="{esc(rid)}-h">',
               f'<h4 id="{esc(rid)}-h">{_badge(status)} {esc(rid)} {esc(self.title(rid))}</h4>']
        if basis.get("quote"):
            out.append(f"<blockquote><p>{esc(basis['quote'])}</p></blockquote>")
        facts = []
        if basis.get("where"):
            facts.append(("Deciding sentence", esc(basis["where"])))
        if basis.get("judgement"):
            facts.append(("Level judged", esc(basis["judgement"])))
        if req.get("scope"):
            facts.append(("Applies to", esc(SCOPE_LABEL.get(req["scope"], req["scope"]))))
        cite = next((r.citation for r in self.rows[rid] if r.citation), "")
        if req.get("source") or cite:
            facts.append(("Source", esc("; ".join(x for x in (str(req.get("source") or ""), cite)
                                                  if x))))
        out.append('<dl class="facts">' + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
                   + "</dl>")
        rows = [[esc(_subject(r)), _badge(r.status), esc(r.observed), _explanation(r)]
                for r in self.rows[rid]]
        out.append(_table(["Subject", "Result", "Observed", "Explanation"], rows))
        out.append("</article>")
        return "\n".join(out)

    def requirements(self) -> str:
        out = ['<section id="requirements" aria-labelledby="requirements-h">',
               '<h2 id="requirements-h">Requirement by requirement</h2>']
        for level in self.levels():
            label, intro = LEVELS.get(level, (level.capitalize(), ""))
            ids = self.in_level(level)
            out.append(f'<h3 id="level-{esc(level)}">{esc(label)} ({len(ids)})</h3>')
            if intro:
                out.append(f"<p>{esc(intro)}</p>")
            out += [self.requirement(rid) for rid in ids]
        out.append("</section>")
        return "\n".join(out)

    def parked_section(self) -> str:
        if not self.parked:
            return ""
        out = ['<section id="parked" aria-labelledby="parked-h">',
               '<h2 id="parked-h">Parked domains</h2>',
               "<p>A parked domain is one the organisation holds that sends and receives no "
               "mail: the profile lists it among its domains and not among its email "
               "domains. The framework's rules for domains that send no mail apply to it, so "
               "it is read against those requirements here rather than against the rules for "
               "mail domains. Whether a domain sends mail cannot be seen in DNS, so which "
               "domains are parked is taken from the profile, not measured. The names "
               "beneath a parked domain that certificate transparency found are read on a "
               "line of their own: that list is incomplete, so a name without the record "
               "shows a breach and names carrying it show nothing. Each result below also "
               "appears in its requirement's card above.</p>"]
        cols = [rid for rid in dict.fromkeys((*sge.PARKED_REQUIREMENTS,
                                              *sge.PARKED_SUBDOMAIN_REQUIREMENTS))
                if any(r.parked for r in self.rows.get(rid, []))]
        head = ["Domain", *(f"{rid}" for rid in cols), "Null MX"]
        rows = []
        for p in self.parked:
            for subject, null_mx in ((p.domain, esc(p.observed or "not read")),
                                     (sge.parked_subdomains_subject(p.domain), "")):
                cells = [f"<code>{esc(subject)}</code>"]
                found = False
                for rid in cols:
                    mine = [r for r in self.rows[rid] if r.parked and r.subject == subject]
                    found = found or bool(mine)
                    cells.append(_badge(requirement_status(mine)) + (
                        f"<br><small>{esc(mine[0].observed)}</small>"
                        if mine[0].observed else "") if mine else "")
                if subject == p.domain or found:
                    rows.append([*cells, null_mx])
        out.append(_table(head, rows, caption="Each parked domain, requirement by requirement"))
        out.append("<p>" + " ".join(f'<a href="#{esc(rid)}">{esc(rid)}</a> '
                                    f"{esc(self.title(rid))}." for rid in cols) + "</p>")
        out.append(f"<h3>Null MX</h3><p>{esc(sge.NULL_MX_GUIDANCE)}</p>")
        records = [[f"<code>{esc(r.subject)}</code>", esc(r.requirement),
                    f"<code>{esc(r.record)}</code>"]
                   for rid in cols for r in self.rows[rid] if r.parked and r.record.strip()]
        records += [[f"<code>{esc(p.domain)}</code>", "MX",
                     f"<code>{esc('; '.join(p.records))}</code>"]
                    for p in self.parked if p.records]
        if records:
            out.append("<h3>Records read</h3>")
            out.append(_table(["Domain", "Read for", "Text as read"], records))
        out.append("</section>")
        return "\n".join(out)

    def not_measured(self) -> str:
        out = ['<section id="not-measured" aria-labelledby="not-measured-h">',
               '<h2 id="not-measured-h">Not measured, and what would settle it</h2>']
        rows = []
        for rid in self.order:
            req = self.reqs[rid]
            level = LEVELS.get(str(req.get("level")), (str(req.get("level")), ""))[0]
            for r in self.rows[rid]:
                if r.status != sge.NOT_MEASURED:
                    continue
                label = sge.UNMEASURED_LABEL.get(r.reason, r.reason)
                rows.append([f"{self.link(rid)}<br><small>{esc(level)}</small>",
                             esc(_subject(r)),
                             f"<strong>{esc(_sentence(label))}.</strong> "
                             f"{esc(_sentence(r.evidence))}",
                             esc(_settled_by(req, r.subject))])
        if rows:
            out.append("<p>Every reading that could not be settled, with the reason and the "
                       "evidence that would settle it. None of these is counted as met.</p>")
            out.append(_table(["Requirement", "Subject", "Why not measured",
                               "What would settle it"], rows))
        else:
            out.append("<p>Every reading was settled.</p>")
        out.append("</section>")
        return "\n".join(out)

    def dns_records(self) -> str:
        out = ['<section id="dns-records" aria-labelledby="dns-records-h">',
               '<h2 id="dns-records-h">DNS records read, per domain</h2>',
               "<p>The record text as read, for each domain the results carry it for. A record "
               "that was not read is not shown.</p>"]
        for domain in self.domains:
            seen: dict[str, list[str]] = {}
            labels: dict[str, str] = {}
            for rid in self.order:
                for r in self.rows[rid]:
                    if r.subject != domain or not r.record.strip():
                        continue
                    text = r.record.strip()
                    seen.setdefault(text, [])
                    if rid not in seen[text]:
                        seen[text].append(rid)
                    family = rid.split("-")[1] if rid.count("-") >= 2 else rid
                    labels.setdefault(text, _RECORD_LABEL.get(family, family))
            out.append(f"<h3>{esc(domain)}</h3>")
            if not seen:
                out.append("<p>No record text was carried for this domain.</p>")
                continue
            rows = [[esc(labels[text]), f"<code>{esc(text)}</code>",
                     ", ".join(f'<a href="#{esc(rid)}">{esc(rid)}</a>' for rid in ids)]
                    for text, ids in seen.items()]
            out.append(_table(["Record", "Text as read", "Read for"], rows))
        if not self.domains:
            out.append("<p>No email domains were named.</p>")
        out.append("</section>")
        return "\n".join(out)

    def limits(self) -> str:
        items = "".join(f"<li><strong>{esc(h)}</strong> {esc(t)}</li>" for h, t in _LIMITS)
        return ('<section id="limits" aria-labelledby="limits-h">'
                '<h2 id="limits-h">What this note cannot show</h2>'
                "<p>DNS, TLS and policy readings are taken from the public internet, without "
                "credentials. A mail transport export, where one was supplied, is the "
                "organisation's own record and is named in the row that uses it.</p>"
                f"<ul>{items}</ul></section>")

    def appendix(self) -> str:
        out = ['<section id="evidence" aria-labelledby="evidence-h">',
               '<h2 id="evidence-h">Appendix: evidence files</h2>']
        if not self.evidence:
            out.append("<p>No evidence files were listed with these results.</p>")
        else:
            where = (f" within observation <code>{esc(self.observation)}</code>"
                     if self.observation else "")
            out.append(f"<p>The files the results were read from{where}, with each file's "
                       "SHA-256 digest so a reader can confirm they hold the same file.</p>")
            out.append(_table(
                ["File", "Bytes", "SHA-256"],
                [[f"<code>{esc(e.path)}</code>", f"{e.size:,}", f"<code>{esc(e.sha256)}</code>"]
                 for e in self.evidence], num=(1,)))
        out.append("</section>")
        return "\n".join(out)

    def footer(self) -> str:
        home = str(self.std.get("home") or "")
        link = (f' The framework is published at <a href="{esc(home)}">{esc(home)}</a>.'
                if home.startswith("https://") else "")
        return ("<p>Generated by takestock from its Secure Government Email requirement set, "
                "in which every level rests on a quoted sentence from the framework's "
                f"published documents.{link}</p>")


def build_note(results: sge.Report, target: dict, *, standard: dict | None = None,
               evidence: list[EvidenceFile] | None = None, observation: str = "",
               theme: htmlpage.Theme | None = None) -> str:
    """The note as an HTML string."""
    std = standard or sge.load_standard()
    note = _Note(results, target, std, list(evidence or []), observation)
    body = "\n".join(x for x in [note.summary(), note.requirements(), note.parked_section(),
                                 note.not_measured(), note.dns_records(), note.limits(),
                                 note.appendix()] if x)
    title = f"Secure Government Email conformance for {note.organisation}"
    lead = ("Each requirement of the Secure Government Email Common Implementation "
            "Framework, read against the organisation's published mail configuration: met, "
            "not met, or not measured, with the reason.")
    return htmlpage.page(title, body, theme=theme or htmlpage.theme_from_target(target),
                         lead=lead, description=title, footer=note.footer())


def render_note(results: sge.Report, target: dict, out_path: str | Path, *,
                standard: dict | None = None, evidence: list[EvidenceFile] | None = None,
                observation: str = "", theme: htmlpage.Theme | None = None) -> Path:
    """Write the note for ``results`` to ``out_path`` and return the path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_note(results, target, standard=standard, evidence=evidence,
                              observation=observation, theme=theme), encoding="utf-8")
    return out


def _load_assets(observation_dir: Path) -> list[Any]:
    path = observation_dir / "assets.json"
    with path.open(encoding="utf-8") as f:
        assets = json.load(f)
    if not isinstance(assets, list):
        raise ValueError(f"{path}: expected a list of asset rows")
    return assets


def main(argv: list[str] | None = None) -> int:
    """Write the conformance note for one observation and one target profile.

    Exits as ``takestock sge-note`` does: 1 when a MUST requirement is unmet,
    0 when none is, and 2 for wrong arguments or an unreadable input.
    """
    return guarded("takestock.sge_note", _main, argv)


def _main(argv: list[str] | None) -> int:
    ap = argparse.ArgumentParser(prog="takestock.sge_note",
                                 description=(__doc__ or "").split("\n")[0])
    ap.add_argument("observation_dir", help="observation directory holding assets.json")
    ap.add_argument("target", help="target profile (YAML)")
    ap.add_argument("out", help="where to write the HTML note")
    args = ap.parse_args(argv)

    obs = Path(args.observation_dir)
    target = config.load_target(args.target)
    domains = [str(d) for d in (target.get("discovery") or {}).get("email_domains") or []]
    results = sge.evaluate(_load_assets(obs), domains,
                           bulk_mail_domains=sge.bulk_mail_domains(target),
                           parked=sge.parked_domains(target))
    theme = htmlpage.theme_from_target(target)
    for problem in theme.contrast_failures():
        print(f"warning: branding contrast: {problem}", file=sys.stderr)
    out = render_note(results, target, args.out, evidence=evidence_files(obs),
                      observation=obs.resolve().name, theme=theme)
    print(out)
    return EXIT_FINDINGS if results.breaches() else EXIT_CLEAN


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
