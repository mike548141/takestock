"""Map an organisation's mail paths from every source it has, and say what each saw.

Sources, each optional, each with its own reach:

* **DNS** (always): what the domains publish (where mail is received, who may
  send, the policies, the keys). Intent, not traffic.
* **Probes** (``probe=True``): each MX host's STARTTLS, versions and
  certificate. What a sender meets on arrival.
* **Headers** (files of message headers): the route each message took, hop by
  hop, with transport, signing, the software that made it and whether its
  content was protected. Only for messages in the mailboxes read.
* **DMARC aggregate reports**: every source that sent as each domain to a
  receiver that reports, with counts and authentication results. No sizes,
  no routes.
* **Message trace** (an Exchange Online export): every message the platform
  handled, with sizes and the address it entered from. No hops outside the
  platform.
* **Platform logs** (:mod:`.platformlog`): Google Workspace's Gmail log events,
  Defender's ``EmailEvents`` from a Microsoft 365 export, Cloudflare Email
  Routing and Sending: every message the platform handled, with its transport,
  authentication and outcome as the platform recorded them. Beside them, the
  platform's own settings (Microsoft 365 connectors, DKIM, rules), Google's
  daily volumes and Postmaster Tools' view, and OnDMARC's source
  classification.

The output is one JSON document (counts and names, never a person's address)
that :mod:`.report` turns into a page.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import cloudflare, dmarc, dnsposture, headers, paths, platformlog, systems, trace

SCHEMA = "takestock.mailpath/1"


@dataclass
class Inputs:
    organisation: str
    domains: list[str]
    owned: list[str] = field(default_factory=list)       # extra domains counted as the org's own
    header_paths: list[Path] = field(default_factory=list)
    dmarc_paths: list[Path] = field(default_factory=list)
    cloudflare_zones: dict[str, str] = field(default_factory=dict)   # domain -> zone id
    cloudflare_token_env: str = "CLOUDFLARE_API_TOKEN"
    cloudflare_keychain: str = ""
    trace_paths: list[Path] = field(default_factory=list)
    overlays: list[Path] = field(default_factory=list)
    probe: bool = False
    out: Path = Path("mailpath")
    # Platforms' own records (see platformlog): saved row files, Cloudflare Email
    # Routing and Sending for the zones above, a Microsoft 365 export bundle, a
    # Google Workspace pull, and Red Sift OnDMARC (saved archives or live).
    platform_logs: list[Path] = field(default_factory=list)
    cloudflare_email: bool = False
    m365_bundles: list[Path] = field(default_factory=list)
    google_dirs: list[Path] = field(default_factory=list)
    ondmarc_archives: list[Path] = field(default_factory=list)
    ondmarc_domains: list[str] = field(default_factory=list)
    ondmarc_region: str = ""
    ondmarc_keychain: str = ""
    since: str = ""
    until: str = ""


def _header_files(paths_in: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths_in:
        if p.is_dir():
            out += sorted(x for x in p.rglob("*") if x.is_file() and x.suffix in (".txt", ".eml", ".headers"))
        elif p.is_file():
            out.append(p)
    return out


def _probe(host: str) -> dict:
    from ..collectors import smtp_starttls
    asset, failures = smtp_starttls.measure(host, None, None, role="mail exchanger")
    return {"host": host, "versions": asset.protocol_versions, "suites": asset.symmetric,
            "key_exchange": asset.key_exchange, "starttls": asset.extra.get("starttls", ""),
            "certificate_issuer": asset.extra.get("cert_issuer", ""),
            "certificate_expires": asset.extra.get("cert_not_after", ""),
            "flags": asset.flags, "failures": failures}


def _fill_reverse_dns(records: list[dmarc.Record]) -> None:
    """Look up the reverse DNS a report left out, so a sender can be named by its host."""
    from concurrent.futures import ThreadPoolExecutor

    from ..util import ERROR_PREFIX
    from ..util import run as sh
    missing = sorted({r.source_ip for r in records if r.source_ip and not r.source_ptr})

    def ptr(ip: str) -> tuple[str, str]:
        out = sh(["dig", "+short", "-x", ip], timeout=10)
        first = "" if out.startswith(ERROR_PREFIX) else (out.split() or [""])[0]
        return ip, first.rstrip(".").lower()
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = dict(pool.map(ptr, missing))
    for r in records:
        if not r.source_ptr and found.get(r.source_ip):
            r.source_ptr = found[r.source_ip]


def run(inp: Inputs, now: datetime | None = None,
        resolve: dnsposture.Resolve | None = None) -> dict:
    """The result document. ``resolve`` replaces live DNS (and skips fetching
    MTA-STS policies), for testing."""
    when = (now or datetime.now(UTC)).replace(microsecond=0)
    cat = systems.load(inp.overlays)
    owned = {d.lower() for d in [*inp.domains, *inp.owned]}
    inp.out.mkdir(parents=True, exist_ok=True)

    # Headers first: the DKIM selectors they name are worth trying in DNS.
    files = _header_files(inp.header_paths)
    messages = [headers.parse_file(p, cat) for p in files]
    flows = paths.flows(messages, owned)
    in_scope = sum(f.messages for f in flows)
    dates = sorted(m.date for m in messages if m.date and paths.direction(m, owned))
    seen_selectors: dict[str, set[str]] = {}
    for m in messages:
        for s in m.signatures:
            seen_selectors.setdefault(s.domain, set()).add(s.selector)

    # DMARC: saved files, then live Cloudflare zones (archived as fetched).
    records = dmarc.load(inp.dmarc_paths)
    fetch_notes: dict[str, str] = {}
    if inp.cloudflare_zones:
        bearer = cloudflare.token(inp.cloudflare_token_env, inp.cloudflare_keychain)
        for domain, zone in inp.cloudflare_zones.items():
            cf_rows, stop = cloudflare.fetch(zone, bearer, now=when)
            archive = inp.out / f"cloudflare-dmarc-{domain}-{when:%Y%m%dT%H%MZ}.json"
            archive.write_text(json.dumps(cf_rows), encoding="utf-8")
            fetch_notes[domain] = f"{len(cf_rows)} rows; {stop}; kept in {archive.name}"
            records += dmarc.from_cloudflare_rows(cf_rows)
    ondmarc_raw: list[dict] = []
    if inp.ondmarc_archives or inp.ondmarc_domains:
        from . import ondmarc
        for archive_file in inp.ondmarc_archives:
            saved, saved_notes = ondmarc.load_archive(Path(archive_file))
            ondmarc_raw += saved
            fetch_notes[f"ondmarc {Path(archive_file).name}"] = "; ".join(saved_notes) or "read"
        if inp.ondmarc_domains:
            key = ondmarc.token(keychain_item=inp.ondmarc_keychain)
            since = inp.since or (when - timedelta(days=30)).date().isoformat()
            until = inp.until or when.date().isoformat()
            region = inp.ondmarc_region or "uk"
            live, notes = ondmarc.fetch(key, inp.ondmarc_domains, region, since, until)
            archive = inp.out / f"ondmarc-{when:%Y%m%dT%H%MZ}.json"
            ondmarc.save(archive, live, notes, region)
            fetch_notes["ondmarc"] = f"{len(live)} records; {'; '.join(notes)}; kept in {archive.name}"
            ondmarc_raw += live
    ondmarc_sources: list[dict] = []
    if ondmarc_raw:
        from . import ondmarc
        records += ondmarc.to_records(ondmarc_raw)
        ondmarc_sources = ondmarc.sources_summary(ondmarc_raw)
    records = [r for r in records if paths.owns(r.header_from, owned)]
    if resolve is None:
        _fill_reverse_dns(records)
    sources = dmarc.sources(records, cat)

    postures = {}
    for d in inp.domains:
        sels = sorted(set().union(*(v for k, v in seen_selectors.items() if paths.owns(k, {d})))
                      if seen_selectors else set())
        postures[d] = dnsposture.read(d, cat, selectors=sels, resolve=resolve or dnsposture.default_resolve,
                                      fetch_policy=resolve is None)
    probes = {}
    if inp.probe:
        for p in postures.values():
            for _, host in p.mx:
                if host != "." and host not in probes:
                    probes[host] = _probe(host)

    rows: list[dict] = []
    for log_file in inp.platform_logs:
        rows += json.loads(Path(log_file).read_text(encoding="utf-8"))
    if inp.cloudflare_email and inp.cloudflare_zones:
        bearer = cloudflare.token(inp.cloudflare_token_env, inp.cloudflare_keychain)
        for domain, zone in inp.cloudflare_zones.items():
            for kind in ("routing", "sending"):
                got, stop = cloudflare.fetch_email(zone, bearer, kind, now=when)
                fetch_notes[f"email {kind} {domain}"] = f"{len(got)} messages; {stop}"
                rows += got
    trace_paths = list(inp.trace_paths)
    m365_settings: list[dict] = []
    bundle_traces: list[trace.TraceFlow] = []
    if inp.m365_bundles:
        from . import m365
        for bundle_path in inp.m365_bundles:
            bundle = m365.read_bundle(Path(bundle_path))
            bundle_traces += m365.trace_flows(Path(bundle_path), owned)
            rows += m365.email_events(Path(bundle_path))
            m365_settings.append({k: v for k, v in bundle.items()
                                  if k not in ("trace_files", "email_events_files")})
    google: dict[str, dict] = {}
    for google_dir in inp.google_dirs:
        for name in ("gmail-log", "usage", "postmaster"):
            f = Path(google_dir) / f"{name}.json"
            if not f.is_file():
                continue
            data = json.loads(f.read_text(encoding="utf-8"))
            if name == "gmail-log":
                rows += data["rows"] if isinstance(data, dict) else data
                if isinstance(data, dict) and data.get("notes"):
                    fetch_notes[f"gmail log {Path(google_dir).name}"] = "; ".join(data["notes"])
            else:
                google[name] = data
    problems = platformlog.check(rows)
    if problems:
        raise ValueError("platform rows outside the schema: " + "; ".join(problems[:5]))
    platform_flows = platformlog.flows(rows, owned, cat)
    traces = [t for p in trace_paths for t in trace.read(p, owned)] + bundle_traces

    return {
        "schema": SCHEMA,
        "generated": when.isoformat(),
        "organisation": inp.organisation,
        "domains": inp.domains,
        "owned": sorted(owned),
        "posture": {d: p.as_dict() for d, p in postures.items()},
        "probes": probes,
        "flows": [f.as_dict() for f in flows],
        "dmarc_sources": [s.as_dict() for s in sources],
        "trace": [t.as_dict() for t in traces],
        "platform_flows": [f.as_dict() for f in platform_flows],
        "m365_settings": m365_settings,
        "google": google,
        "ondmarc_sources": ondmarc_sources,
        "systems": {name: cat.kind_of(name) for name in
                    {s for f in flows for s in f.route} | {s.system for s in sources}},
        "evidence": {
            "headers": {"files_read": len(files), "messages_in_scope": in_scope,
                        "first": dates[0] if dates else "", "last": dates[-1] if dates else ""},
            "dmarc": {"records": len(records), "messages": sum(r.count for r in records),
                      "reporters": len({r.reporter for r in records}),
                      "first": min((r.begin for r in records if r.begin), default=""),
                      "last": max((r.end or r.begin for r in records), default=""),
                      "cloudflare": fetch_notes},
            "platform": {"messages": len(rows),
                         "sources": sorted({str(r.get("source") or "") for r in rows})},
            "trace": {"files": [p.name for p in trace_paths],
                      "messages": sum(t.messages for t in traces)},
            "probes": {"hosts": len(probes)},
        },
    }


def write(result: dict, out: Path) -> tuple[Path, Path]:
    from .report import render
    out.mkdir(parents=True, exist_ok=True)
    j = out / "mailpath.json"
    j.write_text(json.dumps(result, indent=1, sort_keys=True, default=list), encoding="utf-8")
    h = out / "mailpath.html"
    h.write_text(render(result), encoding="utf-8")
    return j, h
