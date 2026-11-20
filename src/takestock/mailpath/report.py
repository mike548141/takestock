"""Render a mail-path result as one self-contained page.

The page leads with what was found, then draws every route as a line of
systems with the transport of each crossing marked on the arrow, then the
domains' published posture, who sends as each domain, the platform's own
volumes, and last what each source could and could not see. Every number on
the page comes from the result document; nothing is computed that the
document cannot show.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from ..htmlpage import esc, page
from .paths import TLS_ORDER

_GOOD = {"TLS 1.3", "TLS 1.2"}
_WEAK = {"none", "SSLv3", "TLS 1.0", "TLS 1.1"}

_CSS = """
<style>
.mp-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap:.75rem;
  margin:0 0 1.25rem; }
.mp-stat { background:var(--surface); border-radius:6px; padding:.7rem .9rem; }
.mp-stat b { display:block; font-size:1.5rem; line-height:1.2; }
.mp-stat span { color:var(--muted); font-size:.9rem; }
.mp-route { background:var(--surface); border-radius:6px; padding:.75rem 1rem .5rem; margin:0 0 1rem; }
.mp-route h4 { margin:.1rem 0 .4rem; }
.mp-route svg { width:100%; height:auto; display:block; margin:.25rem 0 .5rem; }
.mp-route .facts { font-size:.92rem; color:var(--text); margin:0 0 .4rem; }
.mp-route .facts span { white-space:nowrap; margin-right:.9rem; }
.chip { display:inline-block; padding:.05em .45em; border-radius:3px; font-weight:600; font-size:.85rem;
  white-space:nowrap; }
.chip.ok { color:var(--pass-fg); background:var(--pass-bg); }
.chip.bad { color:var(--fail-fg); background:var(--fail-bg); }
.chip.unk { color:var(--unmeasured-fg); background:var(--unmeasured-bg); }
.mp-legend { font-size:.9rem; color:var(--muted); margin:.25rem 0 1rem; }
details.mp-more { margin:.25rem 0 .5rem; font-size:.92rem; }
details.mp-more summary { cursor:pointer; color:var(--accent); }
svg .box { fill:var(--bg); stroke:var(--border); stroke-width:1.5; }
svg .box.own { stroke:var(--accent); stroke-width:2; }
svg .box.internal { stroke:var(--accent); stroke-dasharray:5 3; stroke-width:2; }
svg .lbl { fill:var(--text); font:600 13px var(--font); }
svg .sub { fill:var(--muted); font:12px var(--font); }
svg .leg-ok { stroke:var(--pass-fg); fill:var(--pass-fg); }
svg .leg-bad { stroke:var(--fail-fg); fill:var(--fail-fg); }
svg .leg-unk { stroke:var(--unmeasured-fg); fill:var(--unmeasured-fg); }
svg .legtxt-ok { fill:var(--pass-fg); font:600 12px var(--font); }
svg .legtxt-bad { fill:var(--fail-fg); font:600 12px var(--font); }
svg .legtxt-unk { fill:var(--unmeasured-fg); font:600 12px var(--font); }
</style>
"""

DIRECTION_TITLE = {
    "outbound": "Outbound: our domains to the internet",
    "internal": "Internal: our domains to our domains",
    "inbound": "Inbound: the internet to our domains",
    "sent copy": "Sent from our mailboxes: the sender's copy",
}


def _mb(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1e9:.2f} GB"
    if n >= 1_000_000:
        return f"{n / 1e6:.1f} MB"
    return f"{n / 1e3:.0f} kB"


def _day(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%-d %b %Y")
    except ValueError:
        return iso[:10]


def _cls(tls: str) -> str:
    return "ok" if tls in _GOOD else ("bad" if tls in _WEAK else "unk")


def _leg_text(leg: dict) -> str:
    seen = [t for t in TLS_ORDER if leg["tls"].get(t)]
    if not seen:
        return "not recorded"
    if len(seen) == 1:
        t = seen[0]
        return "TLS, version not recorded" if t.startswith("TLS (") else t
    return f"{seen[0]} to {seen[-1]}"


def _wrap(name: str, width: int = 19) -> list[str]:
    words, lines, cur = [], [], ""
    for word in name.replace("/", "/ ").split():
        while len(word) > width:            # a long host name has no spaces to break at
            words.append(word[:width])
            word = word[width:]
        words.append(word)
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    lines.append(cur)
    out = [x.replace("/ ", "/") for x in lines]
    return out[:2] if len(out) <= 2 else [out[0], out[1][: width - 1] + "…"]


def route_svg(route: list[str], legs: list[dict], kinds: dict[str, str], first_note: str = "") -> str:
    """One route drawn as boxes joined by arrows, each arrow marked with its transport."""
    w, gap, h, top = 168, 92, 58, 22
    n = len(route)
    width = n * w + (n - 1) * gap + 4
    label = esc(" then ".join(route))
    parts = [f'<svg viewBox="0 0 {width} {h + top + 26}" style="max-width:{width}px" role="img" '
             f'aria-label="{label}">']
    for i, name in enumerate(route):
        x = 2 + i * (w + gap)
        kind = kinds.get(name, "")
        cls = "box internal" if name.startswith("internal host") else "box"
        parts.append(f'<rect class="{cls}" x="{x}" y="{top}" width="{w}" height="{h}" rx="7"/>')
        lines = _wrap(name)
        y0 = top + (h / 2) - (len(lines) - 1) * 8 + 4
        for j, line in enumerate(lines):
            parts.append(f'<text class="lbl" x="{x + w / 2}" y="{y0 + j * 16}" '
                         f'text-anchor="middle">{esc(line)}</text>')
        sub = first_note if i == 0 and first_note else (kind if kind and kind != "unknown" else "")
        if sub:
            parts.append(f'<text class="sub" x="{x + w / 2}" y="{top + h + 16}" '
                         f'text-anchor="middle">{esc(sub if len(sub) <= 30 else sub[:29] + "…")}</text>')
    for i, leg in enumerate(legs[: n - 1]):
        x1 = 2 + i * (w + gap) + w + 4
        x2 = x1 + gap - 10
        y = top + h / 2
        c = _cls(leg.get("weakest", "not recorded"))
        parts.append(f'<line class="leg-{c}" x1="{x1}" y1="{y}" x2="{x2 - 6}" y2="{y}" '
                     'stroke-width="2.5"/>')
        parts.append(f'<path class="leg-{c}" d="M{x2 - 8},{y - 6} L{x2 + 2},{y} '
                     f'L{x2 - 8},{y + 6} Z"/>')
        star = "*" if leg.get("esmtp_without_tls_claim") else ""
        text = _wrap(_leg_text(leg) + star, 14)
        for j, line in enumerate(text):
            ty = y - 10 - (len(text) - 1 - j) * 14
            parts.append(f'<text class="legtxt-{c}" x="{(x1 + x2) / 2}" y="{ty}" '
                         f'text-anchor="middle">{esc(line)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _pct(n: int, d: int) -> str:
    return f"{n}/{d}" if d else "–"


def _merge(flows: list[dict], by_sender: bool) -> list[dict]:
    """Merge flows sharing a route (and sender domain, when by_sender)."""
    out: dict[tuple, dict] = {}
    for f in flows:
        key = (f["direction"], f["sender_domain"] if by_sender else f["domain"], tuple(f["route"]))
        if key not in out:
            out[key] = {**f, "legs": [dict(leg, tls=Counter(leg["tls"])) for leg in f["legs"]],
                        "senders": Counter({f["sender_domain"]: f["messages"]})}
            for k in ("spf", "dkim", "dmarc", "generators", "submission", "content_protection",
                      "markings", "kinds", "sensitivity_labels", "signatures"):
                out[key][k] = Counter(f.get(k, {}))
            continue
        m = out[key]
        for k in ("messages", "messages_with_size", "bytes", "dkim_aligned_pass", "internal_origin",
                  "from_rewritten_by_list"):
            m[k] += f[k]
        m["first"] = min(m["first"] or f["first"], f["first"] or m["first"])
        m["last"] = max(m["last"], f["last"])
        for a, b in zip(m["legs"], f["legs"], strict=False):
            a["tls"].update(b["tls"])
            plain = "esmtp_without_tls_claim"
            a[plain] = a.get(plain, 0) + b.get(plain, 0)
            seen = [t for t in TLS_ORDER if a["tls"].get(t)]
            a["weakest"] = seen[0] if seen else "not recorded"
        for k in ("spf", "dkim", "dmarc", "generators", "submission", "content_protection",
                  "markings", "kinds", "sensitivity_labels", "signatures"):
            m[k].update(f.get(k, {}))
        m["senders"][f["sender_domain"]] += f["messages"]
    return sorted(out.values(), key=lambda x: -x["messages"])


def _li(label: str, items) -> str:
    return f"<li>{esc(label)}: " + ", ".join(f"{esc(k)} {v}" for k, v in items) + "</li>"


def _route_card(f: dict, kinds: dict[str, str], title: str) -> str:
    n = f["messages"]
    first_note = next(iter(f["submission"]), "") if f.get("submission") else ""
    if first_note in ("not recorded", "handed over by SMTP", "inside the sending platform"):
        first_note = ""
    facts = [f"<span><b>{n}</b> message{'s' if n != 1 else ''}</span>"]
    if f["messages_with_size"]:
        facts.append(f"<span><b>{_mb(f['bytes'])}</b>"
                     + (f" (size known for {f['messages_with_size']})" if f["messages_with_size"] < n else "")
                     + "</span>")
    if f["first"]:
        facts.append(f"<span>{_day(f['first'])} to {_day(f['last'])}</span>")
    checked = n - f["dmarc"].get("no result", 0)
    if not checked:
        facts.append('<span>authentication <span class="chip unk">not checked by any receiver'
                     "</span></span>")
    else:
        for name, passed in (("DKIM aligned", f["dkim_aligned_pass"]), ("SPF", f["spf"].get("pass", 0)),
                             ("DMARC", f["dmarc"].get("pass", 0))):
            cls = "ok" if passed == checked else ("bad" if passed == 0 else "unk")
            facts.append(f'<span>{name} <span class="chip {cls}">{_pct(passed, checked)}</span></span>')
        if checked < n:
            facts.append(f"<span>({n - checked} not checked)</span>")
    prot = {k: v for k, v in f["content_protection"].items() if k != "none visible"}
    facts.append("<span>content: " + (", ".join(f"{esc(k)} {v}" for k, v in prot.items())
                                      if prot else "no S/MIME or OpenPGP seen") + "</span>")
    more = []
    if f.get("senders") and len(f["senders"]) > 1:
        more.append("<li>sending domains: " + ", ".join(
            f"{esc(d)} {c}" for d, c in f["senders"].most_common(12))
            + (f" and {len(f['senders']) - 12} more" if len(f["senders"]) > 12 else "") + "</li>")
    if f["generators"]:
        more.append(_li("made by", f["generators"].most_common(8)))
    if f["submission"]:
        more.append("<li>entered the mail system by: "
                    + ", ".join(f"{esc(k)} {v}" for k, v in f["submission"].most_common()) + "</li>")
    if f["kinds"]:
        more.append("<li>kind: " + ", ".join(f"{esc(k)} {v}" for k, v in f["kinds"].most_common()) + "</li>")
    if f["signatures"]:
        more.append("<li>DKIM signatures (domain · selector · algorithm): "
                    + ", ".join(f"{esc(k)} {v}" for k, v in f["signatures"].most_common(8)) + "</li>")
    if f["markings"]:
        more.append(_li("protective markings", f["markings"].items()))
    if f["sensitivity_labels"]:
        more.append(_li("sensitivity labels", f["sensitivity_labels"].items()))
    for leg in f["legs"]:
        mix = ", ".join(f"{esc(k)} {v}" for k, v in Counter(leg["tls"]).most_common())
        note = (f"; {leg['esmtp_without_tls_claim']} written as plain ESMTP by the receiving server"
                if leg.get("esmtp_without_tls_claim") else "")
        more.append(f"<li>{esc(leg['from'])} → {esc(leg['to'])}: {mix}{note}</li>")
    return (f'<div class="mp-route"><h4>{esc(title)}</h4>'
            + route_svg(list(f["route"]), f["legs"], kinds, first_note)
            + f'<p class="facts">{"".join(facts)}</p>'
            + (f'<details class="mp-more"><summary>Detail</summary><ul>{"".join(more)}</ul>'
               "</details>" if more else "")
            + "</div>")


def _yes(ok: bool | None, yes: str = "yes", no: str = "no") -> str:
    if ok is None:
        return '<span class="chip unk">–</span>'
    return f'<span class="chip {"ok" if ok else "bad"}">{esc(yes if ok else no)}</span>'


def _posture_table(posture: dict) -> str:
    rows = []
    for d, p in posture.items():
        tags = p.get("dmarc_tags") or {}
        pol = tags.get("p", "")
        receives = "null MX (receives none)" if p.get("null_mx") else (
            ", ".join(p.get("mx_systems") or []) or "no MX")
        sends = ", ".join(p.get("spf_systems") or []) or (
            "sends none (SPF -all)" if (p.get("spf_all") == "-all") else "no SPF")
        pol_cls = "ok" if pol in ("reject", "quarantine") else "bad"
        dmarc_cell = (f'<span class="chip {pol_cls}">p={esc(pol)}</span>'
                      + (f' sp={esc(tags.get("sp"))}' if tags.get("sp") else "")
                      + (f' pct={esc(tags.get("pct"))}' if tags.get("pct") not in (None, "100") else "")
                      ) if p.get("dmarc") else '<span class="chip bad">none</span>'
        keys = p.get("dkim") or {}
        live = [f"{s} ({v})" for s, v in keys.items() if v and "revoked" not in v]
        wild = keys.get("*", "")
        dkim_cell = (esc(", ".join(live)) if live else
                     ('<span class="chip ok">empty at every selector</span>' if "revoked" in wild
                      else '<span class="chip unk">none found</span>'))
        sts = p.get("mta_sts_policy") or {}
        mode = str(sts.get("mode", "")) if p.get("mta_sts_txt") else ""
        sts_cls = "ok" if mode == "enforce" else "unk"
        sts_cell = (f'<span class="chip {sts_cls}">{esc(mode or "record only")}</span>'
                    if p.get("mta_sts_txt") else '<span class="chip bad">none</span>')
        tlsa = p.get("tlsa") or {}
        dane = None if not tlsa else all(v > 0 for v in tlsa.values())
        report = ", ".join(r.split(": ", 1)[1] for r in p.get("dmarc_reporting") or []
                           if r.startswith("rua")) or "–"
        rows.append(
            f"<tr><th scope='row'>{esc(d)}</th><td>{esc(receives)}</td><td>{esc(sends)}</td>"
            f"<td>{dmarc_cell}</td><td>{esc(report)}</td><td>{dkim_cell}</td><td>{sts_cell}</td>"
            f"<td>{_yes(bool(p.get('tls_rpt')))}</td><td>{_yes(p.get('dnssec'))}</td>"
            f"<td>{_yes(dane) if not p.get('null_mx') else '–'}</td>"
            f"<td>{_yes(bool(p.get('bimi')))}</td></tr>")
    return ('<div class="table-wrap"><table><thead><tr><th>Domain</th><th>Receives mail at</th>'
            "<th>Authorised to send (SPF)</th><th>DMARC</th><th>DMARC reports to</th><th>DKIM keys found</th>"
            "<th>MTA-STS</th><th>TLS reports</th><th>DNSSEC</th><th>DANE</th><th>BIMI</th>"
            "</tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div>")


def _dmarc_table(sources: list[dict]) -> str:
    if not sources:
        return "<p class='muted'>No DMARC aggregate data was supplied.</p>"
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for s in sources:
        by_domain[s["header_from"]].append(s)
    out = []
    for d, rows in sorted(by_domain.items(), key=lambda kv: -sum(r["messages"] for r in kv[1])):
        total = sum(r["messages"] for r in rows)
        body = []
        for r in rows:
            n = r["messages"]
            cls = "ok" if r["dmarc_pass"] == n else ("bad" if r["dmarc_pass"] == 0 else "unk")
            disp = ", ".join(f"{k} {v}" for k, v in r["dispositions"].items() if k != "none")
            body.append(f"<tr><td>{esc(r['system'])}</td><td class='num'>{n}</td>"
                        f"<td class='num'><span class='chip {cls}'>{_pct(r['dmarc_pass'], n)}</span></td>"
                        f"<td class='num'>{_pct(r['spf_aligned_pass'], n)}</td>"
                        f"<td class='num'>{_pct(r['dkim_aligned_pass'], n)}</td>"
                        f"<td>{esc(disp or '–')}</td><td class='num'>{r['source_addresses']}</td>"
                        f"<td>{esc(', '.join(list(r['reporters'])[:4]))}</td></tr>")
        out.append(f"<h3>{esc(d)} <small>· {total} messages reported</small></h3>"
                   "<div class='table-wrap'><table><thead><tr><th>Sending system</th>"
                   "<th class='num'>Messages</th><th class='num'>DMARC pass</th>"
                   "<th class='num'>SPF aligned</th><th class='num'>DKIM aligned</th>"
                   "<th>Quarantined or rejected</th><th class='num'>Addresses</th>"
                   "<th>Reported by</th></tr></thead>"
                   f"<tbody>{''.join(body)}</tbody></table></div>")
    return "".join(out)


def _trace_table(rows: list[dict]) -> str:
    if not rows:
        return ""
    body = "".join(
        f"<tr><td>{esc(r['direction'])}</td><td>{esc(r['domain'])}</td><td>{esc(r['origin'])}</td>"
        f"<td>{esc(r['connector'] or '–')}</td><td class='num'>{r['messages']}</td>"
        f"<td class='num'>{r['recipients']}</td>"
        f"<td class='num'>{_mb(r['bytes']) if r.get('sized') else '–'}</td>"
        f"<td class='num'>{r['counterparty_domains']}</td>"
        f"<td>{esc(', '.join(f'{k} {v}' for k, v in sorted(r.get('tls', {}).items())) or '–')}</td></tr>"
        for r in rows)
    return ("<h2 id='volumes'>Volumes the mail platform recorded</h2>"
            "<div class='table-wrap'><table><thead><tr><th>Direction</th><th>Our domain</th>"
            "<th>Entered from</th><th>Connector</th><th class='num'>Messages</th>"
            "<th class='num'>Recipients</th><th class='num'>Size</th><th class='num'>Other domains</th>"
            "<th>Transport recorded</th></tr></thead><tbody>" + body + "</tbody></table></div>")


def _counts(c: dict, top: int = 4) -> str:
    items = sorted(c.items(), key=lambda kv: -kv[1])
    return esc(", ".join(f"{k} {v}" for k, v in items[:top]) or "–")


def _platform_table(rows: list[dict]) -> str:
    if not rows:
        return ""
    body = "".join(
        f"<tr><td>{esc(r['source'])}</td><td>{esc(r['direction'])}</td><td>{esc(r['domain'] or '–')}</td>"
        f"<td>{esc(r['far_system'] or '–')}</td><td>{esc(r['connector'] or '–')}</td>"
        f"<td class='num'>{r['messages']}</td>"
        f"<td class='num'>{_mb(r['bytes']) if r.get('messages_with_size') else '–'}</td>"
        f"<td>{_counts(r['tls'])}</td><td>{_counts(r['dmarc'])}</td><td>{_counts(r['delivery'])}</td>"
        f"<td class='num'>{r['counterparty_domains']}</td></tr>" for r in rows)
    return ("<h2 id='platforms'>What the mail platforms recorded</h2>"
            "<p class='mp-legend'>Every message the platforms' own logs hold, grouped by direction, "
            "the far system and the connector. This is the census beside the routes above.</p>"
            "<div class='table-wrap'><table><thead><tr><th>Source</th><th>Direction</th>"
            "<th>Our domain</th><th>Far system</th><th>Connector</th><th class='num'>Messages</th>"
            "<th class='num'>Size</th><th>Transport</th><th>DMARC</th><th>Outcome</th>"
            "<th class='num'>Other domains</th></tr></thead><tbody>" + body + "</tbody></table></div>")


def _m365_settings(bundles: list[dict]) -> str:
    out = []
    for b in bundles:
        conns = b.get("connectors") or []
        if conns:
            body = "".join(
                f"<tr><td>{esc(c.get('name', ''))}</td><td>{esc(c.get('direction', ''))}</td>"
                f"<td>{esc(c.get('enabled', ''))}</td>"
                f"<td>{esc(c.get('tls', c.get('tls_requirement', '')))}</td>"
                f"<td>{esc(c.get('certificate_validation', ''))}</td>"
                f"<td>{esc(', '.join(c.get('smart_hosts') or []))}</td></tr>" for c in conns)
            out.append("<h3>Connectors</h3><div class='table-wrap'><table><thead><tr><th>Connector</th>"
                       "<th>Direction</th><th>On</th><th>TLS</th><th>Certificate check</th>"
                       f"<th>Smart hosts</th></tr></thead><tbody>{body}</tbody></table></div>")
        dkim = b.get("dkim") or []
        if dkim:
            body = "".join(
                f"<tr><td>{esc(d.get('domain', ''))}</td><td>{esc(d.get('enabled', ''))}</td>"
                f"<td>{esc(d.get('key_size', ''))}</td>"
                f"<td>{esc(', '.join(map(str, d.get('selectors') or [])))}</td>"
                "</tr>" for d in dkim)
            out.append("<h3>DKIM signing</h3><div class='table-wrap'><table><thead><tr><th>Domain</th>"
                       "<th>Signing on</th><th>Key size</th><th>Selectors</th></tr></thead>"
                       f"<tbody>{body}</tbody></table></div>")
        if b.get("transport_rules"):
            out.append(f"<p>{len(b['transport_rules'])} mail-flow rules exported.</p>")
        if b.get("notes"):
            out.append("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in b["notes"]) + "</ul>")
    return ("<h2 id='m365'>Microsoft 365 mail-flow settings</h2>" + "".join(out)) if out else ""


def _fmt(v: object) -> str:
    if isinstance(v, float):
        return f"{v:.1%}" if 0 <= v <= 1 else f"{v:,.0f}"
    if isinstance(v, dict):
        return ", ".join(f"{k} {_fmt(x)}" for k, x in v.items())
    return "–" if v in (None, "") else str(v)


def _google(google: dict) -> str:
    out = []
    pm = google.get("postmaster") or {}
    for domain, entry in (pm.get("domains") or {}).items():
        if entry.get("error"):
            out.append(f"<p><strong>{esc(domain)}</strong>: {esc(entry['error'])}</p>")
            continue
        days = entry.get("days") or {}
        metrics = sorted({m for d in days.values() for m in d})
        recent = sorted(days)[-14:]
        head = "".join(f"<th>{esc(m.replace('_', ' ').lower())}</th>" for m in metrics)
        body = "".join(f"<tr><th scope='row'>{esc(day)}</th>"
                       + "".join(f"<td class='num'>{esc(_fmt(days[day].get(m)))}</td>" for m in metrics)
                       + "</tr>" for day in recent)
        out.append(f"<h3>{esc(domain)} as Gmail sees it (Postmaster Tools)</h3>"
                   f"<div class='table-wrap'><table><thead><tr><th>Day</th>{head}</tr></thead>"
                   f"<tbody>{body}</tbody></table></div>")
        if entry.get("compliance"):
            out.append("<p>Sender requirements: " + esc(_fmt(entry["compliance"])) + "</p>")
    usage = google.get("usage") or {}
    per_day = usage.get("users") or {}
    if per_day:
        cols = ["sent", "received", "spam_received", "senders", "receivers", "users"]
        body = "".join(f"<tr><th scope='row'>{esc(day)}</th>"
                       + "".join(f"<td class='num'>{esc(_fmt(v.get(c)))}</td>" for c in cols) + "</tr>"
                       for day, v in sorted(per_day.items()))
        head = "".join(f"<th class='num'>{esc(c.replace('_', ' '))}</th>" for c in cols)
        out.append("<h3>Daily volumes across all mailboxes (Workspace usage reports)</h3>"
                   f"<div class='table-wrap'><table><thead><tr><th>Day</th>{head}</tr></thead>"
                   f"<tbody>{body}</tbody></table></div>")
    notes = [*(pm.get("notes") or []), *(usage.get("notes") or [])][:12]
    if notes:
        out.append("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in notes) + "</ul>")
    return ("<h2 id='google'>Google Workspace</h2>" + "".join(out)) if out else ""


def _ondmarc(rows: list[dict]) -> str:
    if not rows:
        return ""
    keys = [k for k in rows[0] if k not in ("raw",)][:8]
    head = "".join(f"<th>{esc(k.replace('_', ' '))}</th>" for k in keys)
    body = "".join("<tr>" + "".join(f"<td>{esc(r.get(k, ''))}</td>" for k in keys) + "</tr>"
                   for r in rows)
    return ("<h2 id='ondmarc'>Sending sources as Red Sift OnDMARC classifies them</h2>"
            f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}"
            "</tbody></table></div>")


def _headline(result: dict, merged: dict[str, list[dict]]) -> str:
    stats = []
    for d in ("outbound", "internal", "inbound", "sent copy"):
        fl = merged.get(d, [])
        n = sum(f["messages"] for f in fl)
        if not n:
            continue
        b = sum(f["bytes"] for f in fl)
        legs = [leg for f in fl for leg in f["legs"]]
        good = sum(sum(v for k, v in leg["tls"].items() if k in _GOOD) for leg in legs)
        total = sum(sum(leg["tls"].values()) for leg in legs)
        stats.append(f'<div class="mp-stat"><b>{n}</b><span>{esc(d)} messages measured on {len(fl)} '
                     f"route{'s' if len(fl) != 1 else ''}, {_mb(b)}; {good} of {total} "
                     "crossings recorded TLS 1.2 or 1.3"
                     "</span></div>")
    dm = result.get("dmarc_sources") or []
    if dm:
        tot = sum(s["messages"] for s in dm)
        ok = sum(s["dmarc_pass"] for s in dm)
        fails = [s for s in dm if s["dmarc_pass"] < s["messages"]]
        stats.append(f'<div class="mp-stat"><b>{ok} of {tot}</b><span>messages sent as our '
                     'domains passed DMARC, '
                     f"from {len({s['system'] for s in dm})} sending systems; {len(fails)} system and domain "
                     "pairs had failures</span></div>")
    return f'<div class="mp-grid">{"".join(stats)}</div>' if stats else ""


def _method(result: dict) -> str:
    ev = result.get("evidence", {})
    h, d, t = ev.get("headers", {}), ev.get("dmarc", {}), ev.get("trace", {})
    rows = [
        ("Public DNS", f"{len(result.get('posture', {}))} domains, read {_day(result['generated'])}",
         "Published intent: where mail is received, who may send, the policies and keys.",
         "Traffic. DKIM keys at selectors not tried."),
        ("Message headers",
         f"{h.get('messages_in_scope', 0)} messages in scope of {h.get('files_read', 0)} read"
         + (f", {_day(h['first'])} to {_day(h['last'])}" if h.get("first") else ""),
         "The route each message took, the TLS each hop recorded, signing, the software that made it.",
         "Only mailboxes that were read. A hop that records no TLS clause proves nothing either way; "
         "a recorded suite is what that hop chose, not the weakest it would accept."),
        ("DMARC aggregate reports", f"{d.get('messages', 0)} messages in {d.get('records', 0)} records from "
         f"{d.get('reporters', 0)} reporters"
         + (f", {_day(d['first'])} to {_day(d['last'])}" if d.get("first") else ""),
         "Every system that sent as our domains to a receiver that reports, and whether it authenticated.",
         "Sizes, routes, transport. Receivers that do not report. Mail inside one platform."),
        ("Mail platform trace", f"{t.get('messages', 0)} messages" if t.get("files") else "not supplied",
         "Every message the platform handled, its size, and where it entered.",
         "Hops before the platform received a message or after it left."),
        ("Probes of each MX", f"{ev.get('probes', {}).get('hosts', 0)} hosts" or "not run",
         "The TLS a sender meets on arrival, and the certificate.",
         "What senders actually negotiated."),
    ]
    body = "".join(f"<tr><th scope='row'>{esc(a)}</th><td>{esc(b)}</td><td>{esc(c)}</td>"
                   f"<td>{esc(e)}</td></tr>"
                   for a, b, c, e in rows)
    notes = "".join(f"<li>{esc(k)}: {esc(v)}</li>" for k, v in (d.get("cloudflare") or {}).items())
    return ("<h2 id='method'>What each source saw, and what it cannot see</h2>"
            "<div class='table-wrap'><table><thead><tr><th>Source</th><th>Read</th><th>Shows</th>"
            f"<th>Cannot show</th></tr></thead><tbody>{body}</tbody></table></div>"
            + (f"<p class='muted'>Cloudflare fetch:</p><ul>{notes}</ul>" if notes else ""))


def render(result: dict) -> str:
    kinds = result.get("systems", {})
    merged: dict[str, list[dict]] = {}
    for d in ("outbound", "internal", "inbound", "sent copy"):
        fl = [f for f in result.get("flows", []) if f["direction"] == d]
        merged[d] = _merge(fl, by_sender=(d != "inbound"))
    body = [_CSS, _headline(result, merged)]
    body.append("<h2 id='routes'>Routes measured from message headers</h2>"
                '<p class="mp-legend">Each box is a mail system; each arrow is a hand-over between two '
                'systems, marked with the transport the receiving server recorded. '
                '<span class="chip ok">TLS 1.2 or 1.3</span> <span class="chip unk">not recorded</span> '
                '<span class="chip bad">none or TLS 1.0/1.1</span>. A dashed box is a host on an internal '
                "network. * the receiving server wrote plain ESMTP, which RFC 3848 reserves for a session "
                "without TLS but which some servers write regardless: confirm from the sending system's "
                "own log before treating that leg as unencrypted.</p>")
    for d in ("outbound", "internal", "inbound", "sent copy"):
        fl = merged[d]
        if not fl:
            continue
        body.append(f"<h3>{esc(DIRECTION_TITLE[d])}</h3>")
        shown = fl[:12] if d == "inbound" else fl
        for f in shown:
            if d == "inbound":
                title = f"Into {f['domain']} by this route"
            else:
                title = f"From {f['sender_domain']}"
            body.append(_route_card(f, kinds, title))
        if len(fl) > len(shown):
            rest = fl[len(shown):]
            body.append(f"<p class='muted'>{len(rest)} further inbound routes carried "
                        f"{sum(f['messages'] for f in rest)} messages.</p>")
    body.append("<h2 id='domains'>What each domain publishes</h2>"
                + _posture_table(result.get("posture", {})))
    if result.get("probes"):
        rows = "".join(
            f"<tr><td>{esc(h)}</td><td>{esc(', '.join(p['versions']) or p['starttls'])}</td>"
            f"<td>{esc(', '.join(p['suites'][:3]))}</td><td>{esc(p['certificate_issuer'])}</td>"
            f"<td>{esc(p['certificate_expires'])}</td></tr>" for h, p in result["probes"].items())
        body.append("<h2 id='edge'>What a sender meets at each MX</h2><div class='table-wrap'><table><thead>"
                    "<tr><th>Host</th><th>TLS versions accepted</th><th>Suites</th>"
                    "<th>Certificate issuer</th>"
                    f"<th>Expires</th></tr></thead><tbody>{rows}</tbody></table></div>")
    body.append("<h2 id='senders'>Who sends as each domain (DMARC reports)</h2>"
                + _dmarc_table(result.get("dmarc_sources", [])))
    body.append(_trace_table(result.get("trace", [])))
    body.append(_platform_table(result.get("platform_flows", [])))
    body.append(_m365_settings(result.get("m365_settings", [])))
    body.append(_google(result.get("google", {})))
    body.append(_ondmarc(result.get("ondmarc_sources", [])))
    body.append(_method(result))
    title = f"Mail paths · {result.get('organisation', '')}"
    lead = (f"How mail moves for {len(result.get('domains', []))} domains: the routes measured, "
            "the transport and "
            "signing on each hand-over, who sends as each domain, and what each source can and cannot see.")
    return page(title, "\n".join(body), lead=lead, eyebrow="Mail path map",
                byline=f"Generated {_day(result['generated'])} by takestock mailpath",
                description=lead)
