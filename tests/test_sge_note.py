"""The Secure Government Email conformance note: structure, content and honesty of its verdicts."""

from __future__ import annotations

import hashlib
import json
import re
from html.parser import HTMLParser

import yaml

from takestock import sge, sge_note
from takestock.sge import FAIL, NOT_MEASURED, PASS, Conformance, Report

STD = sge.load_standard()
REQS = {r["id"]: r for r in STD["requirements"]}
ORG = "Example Widgets Ltd"
DOMAINS = ["example.com", "example.net"]
TARGET = {"organisation": {"name": ORG}, "discovery": {"email_domains": DOMAINS}}


def row(rid: str, subject: str, status: str, **kw) -> Conformance:
    r = REQS[rid]
    return Conformance(rid, r["title"], r["level"], r["scope"], subject, status,
                       source=r["source"], citation=sge.citation(STD, r), **kw)


def synthetic_report() -> Report:
    """A hand-made result set covering every outcome the note distinguishes."""
    return Report(standard=STD["standard"], rows=[
        # A must met on both domains.
        row("SGE-SPF-01", "example.com", PASS, observed="-all (hardfail)",
            evidence="SPF example.com", record="v=spf1 mx -all"),
        row("SGE-SPF-01", "example.net", PASS, observed="-all (hardfail)",
            evidence="SPF example.net", record="v=spf1 -all"),
        # A must breached on one domain.
        row("SGE-DMARC-01", "example.com", PASS, observed="p=reject; pct=100",
            record="v=DMARC1; p=reject; rua=mailto:reports@example.com"),
        row("SGE-DMARC-01", "example.net", FAIL, observed="p=none; pct=100",
            reason="policy is p=none; the standard requires p=reject",
            evidence="DMARC example.net", record="v=DMARC1; p=none"),
        # A must passed on one domain and unmeasured on the other: not measured overall.
        row("SGE-MTASTS-01", "example.com", PASS, observed="mode=enforce",
            record="v=STSv1; id=20300101"),
        row("SGE-MTASTS-01", "example.net", NOT_MEASURED, reason=sge.INCONCLUSIVE,
            evidence="the policy file could not be fetched from this machine"),
        # A must nobody outside can see.
        row("SGE-DLP-01", "", NOT_MEASURED, reason=sge.NO_INSTRUMENT,
            evidence="data loss prevention is the mail platform's own policy"),
        # A recommendation not followed: never a breach.
        row("SGE-DMARC-R02", "example.net", FAIL, observed="aspf=r",
            reason="relaxed SPF alignment is published"),
    ])


class _Balance(HTMLParser):
    VOID = {"meta", "br", "img", "hr", "input", "link"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.ids: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k == "id":
                self.ids.append(str(v))
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes {self.stack[-1:]}")
        else:
            self.stack.pop()


def parse(html_text: str) -> _Balance:
    p = _Balance()
    p.feed(html_text)
    p.close()
    return p


def text_of(html_text: str) -> str:
    body = html_text.split("</style>", 1)[-1]
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))


def article(html_text: str, rid: str) -> str:
    start = html_text.index(f'<article class="card" id="{rid}"')
    return html_text[start:html_text.index("</article>", start)]


# ── The roll-up ───────────────────────────────────────────────────────

def test_a_requirement_is_met_only_when_every_reading_passed():
    p, f, n = (row("SGE-SPF-01", "example.com", s) for s in (PASS, FAIL, NOT_MEASURED))
    assert sge_note.requirement_status([p, p]) == PASS
    assert sge_note.requirement_status([p, n]) == NOT_MEASURED
    assert sge_note.requirement_status([n]) == NOT_MEASURED
    assert sge_note.requirement_status([]) == NOT_MEASURED
    assert sge_note.requirement_status([p, n, f]) == FAIL


# ── The rendered note ─────────────────────────────────────────────────

def test_the_note_is_well_formed_and_titled_for_the_organisation():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    parsed = parse(out)
    assert parsed.errors == [] and parsed.stack == []
    assert f"<title>Secure Government Email conformance for {ORG}</title>" in out
    assert len(parsed.ids) == len(set(parsed.ids))
    for section in ("summary", "requirements", "not-measured", "dns-records", "limits",
                    "evidence"):
        assert section in parsed.ids


def test_a_partly_measured_requirement_is_reported_as_not_measured_never_met():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    card = article(out, "SGE-MTASTS-01")
    heading = card[:card.index("</h4>")]
    assert "status-not-measured" in heading and "Not measured" in heading
    assert "status-pass" not in heading
    nm = out[out.index('id="not-measured"'):out.index('id="dns-records"')]
    assert 'href="#SGE-MTASTS-01"' in nm
    assert "The check ran and could not settle it." in nm
    settle = " ".join(REQS["SGE-MTASTS-01"]["settled_by"].split())
    assert settle.replace("<domain>", "example.net") in text_of(nm).replace("&lt;", "<")
    # The domain that did pass is not listed as unmeasured.
    assert "example.com" not in text_of(nm.split('href="#SGE-MTASTS-01"')[1].split("</tr>")[0])


def test_the_summary_counts_requirements_by_level_and_result():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    summary = text_of(out[out.index('id="summary"'):out.index('id="requirements"')])
    assert "Of its 5 requirements: 1 met, 2 not met, 2 not measured." in summary
    assert "Must 1 1 2 4" in summary
    assert "Recommended 0 1 0 1" in summary
    assert "All 1 2 2 5" in summary
    # Only the must is listed as a breach; the recommendation is not.
    breaches = summary.split("Unmet requirements stated as must")[1].split("Why requirements")[0]
    assert "SGE-DMARC-01" in breaches and "example.net" in breaches
    assert "SGE-DMARC-R02" not in breaches
    assert "1: nothing outside the organisation can see this" in summary
    assert "1: the check ran and could not settle it" in summary
    assert ", ".join(DOMAINS) in summary


def test_requirements_are_grouped_by_level_with_their_deciding_sentence():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    must, rec = out.index('id="level-must"'), out.index('id="level-recommended"')
    assert must < out.index('id="SGE-DMARC-01"') < rec < out.index('id="SGE-DMARC-R02"')
    card = article(out, "SGE-DMARC-01")
    assert "All domains must have a p=reject DMARC policy." in card
    assert "DMARC Deployment Guide v1.0 (2025-11-04)" in card
    assert "Policy is p=none; the standard requires p=reject" in card
    assert "status-fail" in card[:card.index("</h4>")]
    assert 'id="SGE-DMARC-04"' not in out       # absent from the results, so not invented


def test_dns_record_text_is_shown_per_domain():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    dns = out[out.index('id="dns-records"'):out.index('id="limits"')]
    com, net = dns.index("<h3>example.com</h3>"), dns.index("<h3>example.net</h3>")
    assert com < dns.index("v=spf1 mx -all") < net < dns.index("v=DMARC1; p=none")
    assert "<code>v=STSv1; id=20300101</code>" in dns


def test_every_requirement_appears_even_with_no_evidence():
    report = sge.evaluate([], DOMAINS, STD)
    out = sge_note.build_note(report, TARGET, standard=STD)
    for rid in REQS:
        assert f'<article class="card" id="{rid}"' in out, rid
    summary = text_of(out[out.index('id="summary"'):out.index('id="requirements"')])
    assert f"Of its {len(REQS)} requirements: 0 met," in summary


def test_the_note_is_written_in_a_neutral_voice():
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD)
    prose = text_of(out)
    assert not re.search(r"\b(we|our|ours|us)\b", prose, re.IGNORECASE)
    assert "the organisation" in prose


def test_every_requirement_says_what_would_settle_it():
    for r in STD["requirements"]:
        assert " ".join(str(r.get("settled_by") or "").split()), r["id"]


def test_the_appendix_lists_each_evidence_file_with_its_digest(tmp_path):
    obs = tmp_path / "2030-01-01T0000Z"
    (obs / "raw").mkdir(parents=True)
    (obs / "assets.json").write_text("[]")
    (obs / "raw" / "dns-records.json").write_text('{"answer": []}')
    (obs / "unrelated.log").write_text("not evidence")
    files = sge_note.evidence_files(obs)
    assert [f.path for f in files] == ["assets.json", "raw/dns-records.json"]
    digest = hashlib.sha256(b'{"answer": []}').hexdigest()
    assert files[1].sha256 == digest and files[1].size == 14
    out = sge_note.build_note(synthetic_report(), TARGET, standard=STD, evidence=files,
                              observation=obs.name)
    appendix = out[out.index('id="evidence"'):]
    assert f"<code>{digest}</code>" in appendix
    assert "<code>raw/dns-records.json</code>" in appendix
    assert "2030-01-01T0000Z" in appendix


def test_the_command_reads_an_observation_and_writes_the_note(tmp_path):
    obs = tmp_path / "observations" / "2030-01-01T0000Z"
    obs.mkdir(parents=True)
    assets = [
        {"name": "SPF example.com", "protocol": "spf", "host": "example.com",
         "flags": ["hardfail-all"], "notes": "v=spf1 -all",
         "extra": {"record": "v=spf1 -all"}},
        {"name": "DMARC example.com", "protocol": "dmarc", "host": "example.com",
         "notes": "v=DMARC1; p=quarantine; rua=mailto:reports@example.com",
         "extra": {"record": "v=DMARC1; p=quarantine; rua=mailto:reports@example.com"}},
    ]
    (obs / "assets.json").write_text(json.dumps(assets))
    target_path = tmp_path / "widgets.yaml"
    target_path.write_text(yaml.safe_dump({
        "organisation": {"name": ORG},
        "discovery": {"email_domains": ["example.com"]},
        "branding": {"palette": {"accent": "#7a1f4d"}},
    }))
    out_path = tmp_path / "out" / "note.html"
    assert sge_note.main([str(obs), str(target_path), str(out_path)]) == 1   # DMARC unmet
    out = out_path.read_text()
    assert f"conformance for {ORG}</h1>" in out
    assert "--accent: #7a1f4d;" in out
    spf = article(out, "SGE-SPF-01")
    assert "status-pass" in spf[:spf.index("</h4>")]
    dmarc = article(out, "SGE-DMARC-01")
    assert "status-fail" in dmarc[:dmarc.index("</h4>")]
    assert "Policy is p=quarantine" in dmarc
    assert "<code>assets.json</code>" in out
    assert parse(out).errors == []


def test_unknown_palette_tokens_warn_once_and_the_note_is_still_written(tmp_path, capsys):
    from takestock import cli
    obs = tmp_path / "observations" / "2030-01-01T0000Z"
    obs.mkdir(parents=True)
    (obs / "assets.json").write_text("[]")
    target_path = tmp_path / "widgets.yaml"
    target_path.write_text(yaml.safe_dump({
        "organisation": {"name": ORG},
        "discovery": {"email_domains": ["example.com"]},
        "branding": {"palette": {"headline": "#123456", "accent": "#7a1f4d"}},
    }))
    for run in (lambda: cli.main(["sge-note", str(obs), str(target_path)]),
                lambda: sge_note.main([str(obs), str(target_path), str(obs / "sge-note.html")])):
        (obs / "sge-note.html").unlink(missing_ok=True)
        assert run() in (0, 1)
        err = capsys.readouterr().err
        warned = [line for line in err.splitlines() if "unknown colour token" in line]
        assert len(warned) == 1 and "palette.headline" in warned[0], err
        assert "--accent: #7a1f4d;" in (obs / "sge-note.html").read_text()
