"""The IP address plan as one self-contained HTML page.

The page is drawn entirely from the plan :func:`takestock.ipam.build` returns,
so it cannot disagree with the JSON and CSV written beside it. Every label,
count and section comes from that data: sites are counted by the kinds the
plan file gives them, sources are named by their declared labels, and a
section whose data is absent (segments, mirrors, public ranges, actions) is
not drawn at all.

Without scripts the page reads as one long document and prints that way. A
small inline script turns the sections into tabs, filters the subnet table,
and answers *which subnet holds this address?* from a subnet list embedded in
the page. Every value from the data is escaped before it reaches the markup.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from typing import Any

from . import htmlpage
from .htmlpage import esc

#: How each evidence class reads in the page.
EVIDENCE_WORDS = {"observed": "seen in use", "named": "named", "documented": "documented"}

#: Heading and one-line explanation for each check :func:`takestock.ipam.build` runs.
CHECKS: dict[str, tuple[str, str]] = {
    "name_conflicts": (
        "One address, several machine names",
        "Two or more machines are reported at the same address in a subnet with fixed "
        "addressing. One of the records is out of date, or the address is in conflict."),
    "vlan_conflicts": (
        "One VLAN carrying several subnets at a site",
        "Usually a typing slip in a record; occasionally a real second subnet on the VLAN."),
    "site_disagreements": (
        "A source places the address at another site",
        "The source's own site column names a site other than the one holding the subnet."),
    "not_in_authoritative_source": (
        "Missing from the site's authoritative source",
        "The address is inside a site whose authoritative source does not list it."),
    "only_in_superseded": (
        "Seen only in a source a newer one replaced",
        "The newer source no longer reports the address. The machine may have gone or "
        "moved."),
    "no_addresses_found": (
        "Subnets with no addresses found",
        "Either unused, or used by machines no source covers."),
    "documented_only": (
        "Subnets known only from documents",
        "Nothing read from the network confirms these subnets exist."),
    "unknown_addressing": (
        "Unknown addressing values",
        "The subnet's addressing is not static, dynamic, pool or overlay, so it is treated as "
        "static: two machine names on one address count as a conflict. Usually a typing slip."),
}

_EXTRA_CSS = """
.ipam-tabs { display: flex; flex-wrap: wrap; gap: .25rem; border-bottom: 1px solid var(--border);
  margin: 0 0 1.5rem; }
.ipam-tabs button { font: inherit; background: none; border: 0; border-bottom: 3px solid transparent;
  padding: .5rem .75rem; color: var(--muted); cursor: pointer; }
.ipam-tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent);
  font-weight: 600; }
.ipam-tabs button:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.ipam-tabs .n { font-weight: 400; margin-left: .3em; }
section.panel > h2:first-child { margin-top: 0; border-top: 0; padding-top: 0; }
.card > h3:first-child { margin-top: 0; }
code.cidr { white-space: nowrap; overflow-wrap: normal; }
details { margin: 0 0 .75rem; }
summary { cursor: pointer; }
input[type="search"] { font: inherit; padding: .35rem .5rem; border: 1px solid var(--muted);
  border-radius: 3px; background: var(--bg); color: var(--text); width: 22rem; max-width: 100%; }
label.field { display: block; font-weight: 600; margin: 0 0 .25rem; }
ul.flags { margin: 0; padding-left: 1.1rem; }
@media print { .ipam-tabs, .js-only { display: none !important; }
  section.panel[hidden] { display: block !important; } }
"""

_SCRIPT = r"""
(function () {
  var panels = Array.prototype.slice.call(document.querySelectorAll("section.panel"));
  var nav = document.getElementById("ipam-tabs");
  if (!nav || !panels.length) return;
  nav.hidden = false;
  document.querySelectorAll(".js-only").forEach(function (e) { e.hidden = false; });
  var buttons = panels.map(function (p) {
    var b = document.createElement("button");
    b.type = "button"; b.setAttribute("role", "tab"); b.id = "tab-" + p.id;
    b.setAttribute("aria-controls", p.id); b.textContent = p.getAttribute("data-label");
    var n = p.getAttribute("data-count");
    if (n) {
      var s = document.createElement("span");
      s.className = "n"; s.textContent = "(" + n + ")"; b.appendChild(s);
    }
    p.setAttribute("role", "tabpanel"); p.setAttribute("aria-labelledby", b.id);
    nav.appendChild(b); return b;
  });
  // The view is kept in the address (#<section>, #find=..., #filter=...) so a
  // link opens where it was copied. Some previews show the page in a sandboxed
  // frame where changing the address throws; the page must work there too.
  function remember(hash) {
    try { history.replaceState(null, "", hash); } catch (e) { /* the address stays as it is */ }
  }
  function show(id, focus) {
    panels.forEach(function (p, i) {
      var on = p.id === id;
      p.hidden = !on; buttons[i].setAttribute("aria-selected", on ? "true" : "false");
      buttons[i].tabIndex = on ? 0 : -1; if (on && focus) buttons[i].focus();
    });
  }
  function panelOf(el) {
    while (el && !(el.classList && el.classList.contains("panel"))) el = el.parentNode;
    return el;
  }
  function go(hash) {
    var m = /^#(find|filter)=(.*)$/.exec(hash || "");
    if (m) {
      var box = document.getElementById(m[1] === "find" ? "lookup" : "subnet-filter");
      var value = "";
      try { value = decodeURIComponent(m[2]); } catch (e) { value = m[2]; }
      if (box) {
        show(panelOf(box).id, false); box.value = value;
        box.dispatchEvent(new Event("input"));
        return;
      }
    }
    var el = hash && document.getElementById(hash.slice(1));
    var p = el && panelOf(el);
    show(p ? p.id : panels[0].id, false);
    if (el && el !== p) { if (el.tagName === "DETAILS") el.open = true; el.scrollIntoView(); }
  }
  nav.addEventListener("click", function (e) {
    var b = e.target.closest("[role=tab]");
    if (b) { show(b.getAttribute("aria-controls"), false); remember("#" + b.getAttribute("aria-controls")); }
  });
  nav.addEventListener("keydown", function (e) {
    var i = buttons.indexOf(document.activeElement); if (i < 0) return;
    var j = {ArrowRight: (i + 1) % buttons.length, ArrowLeft: (i - 1 + buttons.length) % buttons.length,
             Home: 0, End: buttons.length - 1}[e.key];
    if (j !== undefined) { e.preventDefault(); show(panels[j].id, true); remember("#" + panels[j].id); }
  });
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (a && a.getAttribute("href").length > 1) {
      e.preventDefault(); go(a.getAttribute("href")); remember(a.getAttribute("href"));
    }
  });

  var filter = document.getElementById("subnet-filter");
  if (filter) filter.addEventListener("input", function () {
    var q = filter.value.trim().toLowerCase(), shown = 0;
    var rows = document.querySelectorAll("#subnet-table tbody tr");
    rows.forEach(function (r) {
      var on = !q || r.getAttribute("data-search").indexOf(q) >= 0;
      r.hidden = !on; if (on) shown++;
    });
    document.getElementById("subnet-count").textContent = shown + " of " + rows.length + " shown";
    remember(q ? "#filter=" + encodeURIComponent(filter.value.trim()) : "#subnets");
  });

  var data = JSON.parse(document.getElementById("ipam-lookup").textContent);
  function parse(s) {
    s = s.trim().replace(/^\[|\]$/g, "");
    var m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      var n = BigInt(0);
      for (var k = 1; k <= 4; k++) {
        var o = Number(m[k]); if (o > 255) return null;
        n = n * BigInt(256) + BigInt(o);
      }
      return {v: 4, n: n, bits: 32};
    }
    if (s.indexOf(":") < 0 || !/^[0-9a-fA-F:]+$/.test(s)) return null;
    var halves = s.split("::"); if (halves.length > 2) return null;
    var head = halves[0] ? halves[0].split(":") : [];
    var tail = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
    var fill = halves.length > 1 ? 8 - head.length - tail.length : 0;
    if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
    var groups = head.concat(new Array(fill).fill("0"), tail), v = BigInt(0);
    for (var g = 0; g < groups.length; g++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(groups[g])) return null;
      v = v * BigInt(65536) + BigInt(parseInt(groups[g], 16));
    }
    return groups.length === 8 ? {v: 6, n: v, bits: 128} : null;
  }
  function mac(s) {
    var hex = s.trim().toLowerCase().replace(/[\s:.-]/g, "");
    return /^[0-9a-f]{12}$/.test(hex) ? hex : null;
  }
  function holder(ip) {
    var best = null;
    data.subnets.forEach(function (s) {
      if (s.v !== ip.v) return;
      var shift = BigInt(ip.bits - s.len);
      if ((ip.n >> shift) === (BigInt(s.base) >> shift) && (!best || s.len > best.len)) best = s;
    });
    return best;
  }
  function where(s) {
    return s.cidr + " (" + s.site + (s.purpose ? ", " + s.purpose : "") + ")";
  }
  function link(s) {
    var a = document.createElement("a"); a.href = "#" + s.anchor; a.textContent = " Open " + s.cidr;
    out.appendChild(a);
  }
  var input = document.getElementById("lookup"), out = document.getElementById("lookup-result");
  if (input) input.addEventListener("input", function () {
    var value = input.value.trim(), ip = parse(value); out.textContent = "";
    remember(value ? "#find=" + encodeURIComponent(value) : "#overview");
    if (!value) return;
    if (!ip) {
      var m = mac(value), seen = m && data.macs[m];
      if (!m) { out.textContent = "Not an IPv4 or IPv6 address, or a MAC address."; return; }
      if (!seen) { out.textContent = "No source reported that MAC address."; return; }
      out.textContent = "That MAC address was seen at " + seen.map(function (x) {
        return x[0] + " in " + where(data.subnets[x[1]]);
      }).join("; ") + ".";
      seen.forEach(function (x) { link(data.subnets[x[1]]); });
      return;
    }
    var best = holder(ip);
    if (!best) { out.textContent = "Not inside any subnet in the plan."; return; }
    var text = "Inside " + where(best) + ".";
    var known = data.addresses[ip.v + ":" + ip.n.toString()];
    text += known ? " Listed in the plan" + (known.length ? " as " + known.join(", ") : "") + "."
                  : " Not an address any source reported.";
    out.textContent = text;
    link(best);
  });

  // Last, once every control listens: open the view the address names.
  go(location.hash);
})();
"""


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def anchor(cidr: str) -> str:
    """The element id of a subnet's address list."""
    return "s-" + re.sub(r"[^0-9A-Za-z]+", "-", cidr).strip("-")


def _table(head: list[str], rows: list[str], *, caption: str = "", table_id: str = "",
           num: frozenset[int] = frozenset()) -> str:
    if not rows:
        return '<p class="muted">None found.</p>'
    num_class = ' class="num"'
    ths = "".join(f'<th scope="col"{num_class if i in num else ""}>{esc(h)}</th>'
                  for i, h in enumerate(head))
    cap = f"<caption>{esc(caption)}</caption>" if caption else ""
    tid = f' id="{esc(table_id)}"' if table_id else ""
    return (f'<div class="table-wrap"><table{tid}>{cap}<thead><tr>{ths}</tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>")


def _td(value: Any, *, num: bool = False, code: bool = False) -> str:
    text = esc(value if value not in (None, "") else "")
    inner = f"<code>{text}</code>" if code and text else text
    return f'<td class="num">{inner}</td>' if num else f"<td>{inner}</td>"


class _View:
    def __init__(self, plan: dict) -> None:
        self.plan = plan
        self.sources = {s["id"]: s for s in plan.get("sources") or []}
        self.sites = {s["id"]: s for s in plan.get("sites") or []}
        self.subnets: list[dict] = list(plan.get("subnets") or [])
        self.counts: dict = plan.get("counts") or {}
        self.checks: dict = plan.get("checks") or {}

    # -- helpers --
    def label(self, sid: str) -> str:
        return str(self.sources.get(sid, {}).get("label") or sid)

    def site_name(self, sid: str) -> str:
        site = self.sites.get(sid)
        return str(site["name"]) if site else "No site holds this range"

    def subnet_link(self, cidr: str) -> str:
        return f'<a href="#{anchor(cidr)}"><code class="cidr">{esc(cidr)}</code></a>'

    def labels(self, ids: list[str]) -> str:
        return esc(", ".join(self.label(s) for s in ids))

    def check_total(self) -> int:
        return sum(len(v) for v in self.checks.values())

    # -- sections: (id, tab label, count or None, html) --
    def sections(self) -> list[tuple[str, str, int | None, str]]:
        out: list[tuple[str, str, int | None, str]] = [
            ("overview", "Overview", None, self.overview()),
            ("sites", "Sites", len(self.sites), self.sites_section()),
            ("subnets", "Subnets", len(self.subnets), self.subnets_section()),
            ("addresses", "Addresses", int(self.counts.get("addresses", 0)),
             self.addresses_section()),
        ]
        vlan_rows = self.vlan_rows()
        if vlan_rows:
            out.append(("vlans", "VLANs and segments", len(vlan_rows), self.vlans_section(vlan_rows)))
        if self.plan.get("mirrors"):
            out.append(("mirrors", "Mirrored sites", len(self.plan["mirrors"]), self.mirrors_section()))
        public = [s for s in self.subnets if s.get("scope") == "public"]
        if public or self.plan.get("exposure_chains"):
            out.append(("public", "Public ranges", len(public), self.public_section(public)))
        out.append(("checks", "To look at", self.check_total(), self.checks_section()))
        aside = sum(sum(v.values()) for v in (self.plan.get("set_aside") or {}).values())
        out.append(("set-aside", "Set aside", aside, self.set_aside_section()))
        if self.plan.get("actions"):
            out.append(("actions", "Actions", len(self.plan["actions"]), self.actions_section()))
        out.append(("sources", "Sources", len(self.sources), self.sources_section()))
        return out

    def overview(self) -> str:
        c = self.counts
        parts = [f"<p>{esc(p)}</p>" for p in self.plan.get("summary") or []]
        if self.plan.get("audience"):
            parts.insert(0, f'<p class="audience">Written for {esc(self.plan["audience"])}.</p>')
        kinds = c.get("sites_by_kind") or {}
        site_text = _plural(int(c.get("sites", 0)), "site")
        if kinds:
            site_text += " (" + ", ".join(f"{k}: {n}" for k, n in kinds.items()) + ")"
        if c.get("sites_planned"):
            site_text += f", of which {c['sites_planned']} planned"
        addr = (f"{_plural(int(c.get('addresses', 0)), 'address', 'addresses')}: "
                f"{c.get('addresses_seen_in_use', 0):,} seen in use, "
                f"{c.get('addresses_named_only', 0):,} named but not seen in use, "
                f"{c.get('addresses_documented_only', 0):,} known only from documents")
        blocks = _plural(int(c.get("subnets", 0)), "subnet")
        if c.get("single_addresses"):
            blocks += f" and {_plural(int(c['single_addresses']), 'single address', 'single addresses')}"
        dates = sorted(s["as_of"] for s in self.sources.values() if s.get("as_of"))
        facts = [("Sites", site_text), ("Ranges", blocks), ("Addresses", addr)]
        if c.get("vlans") or c.get("segments"):
            vlan_text = _plural(int(c.get("vlans", 0)), "VLAN")
            if c.get("segments"):
                vlan_text += f", {_plural(int(c['segments']), 'segment')} reported by sources"
            facts.append(("VLANs", vlan_text))
        if dates:
            facts.append(("Evidence dated", dates[0] if dates[0] == dates[-1]
                          else f"{dates[0]} to {dates[-1]}"))
        facts.append(("Built", str(self.plan.get("built_on") or "")))
        dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in facts)
        look = [f'<li><a href="#check-{esc(k)}">{esc(CHECKS[k][0])}</a>: {len(v):,}</li>'
                for k, v in self.checks.items() if v and k in CHECKS]
        lookup = (
            '<section class="card js-only" hidden><h3>Find an address</h3>'
            '<label class="field" for="lookup">Which subnet holds this address?</label>'
            '<input type="search" id="lookup" autocomplete="off" spellcheck="false" '
            'placeholder="an IPv4, IPv6 or MAC address">'
            '<p id="lookup-result" class="lookup-result" aria-live="polite"></p></section>')
        return ("".join(parts) + f'<dl class="facts">{dl}</dl>' + lookup
                + "<h3>To look at</h3>"
                + (f"<ul>{''.join(look)}</ul>" if look else '<p class="muted">Nothing found.</p>'))

    def sites_section(self) -> str:
        out = []
        for site in self.sites.values():
            subs = [s for s in self.subnets if s["site"] == site["id"]]
            facts = [("Kind", site.get("kind")), ("Location", site.get("location")),
                     ("Operated by", site.get("operator")),
                     ("Ranges", ", ".join(site.get("ranges") or []) or "none stated"),
                     ("Subnets", str(len(subs))),
                     ("Addresses found", str(sum(s["address_count"] for s in subs)))]
            dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in facts if v)
            status = ("" if site.get("status", "in use") == "in use"
                      else f' <span class="status status-not-measured">{esc(site["status"])}</span>')
            desc = f"<p>{esc(site['description'])}</p>" if site.get("description") else ""
            out.append(f'<article class="card" id="site-{esc(site["id"])}"><h3>{esc(site["name"])}'
                       f'{status}</h3><dl class="facts">{dl}</dl>{desc}</article>')
        orphans = [s for s in self.subnets if s["site"] not in self.sites]
        if orphans:
            out.append("<h3>Ranges no site holds</h3><p>"
                       + ", ".join(self.subnet_link(s["cidr"]) for s in orphans) + "</p>")
        return "".join(out)

    def subnets_section(self) -> str:
        rows = []
        for s in self.subnets:
            vlans = sorted({v.split(":", 1)[1] for v in s.get("vlans") or []})
            search = " ".join([s["cidr"], self.site_name(s["site"]), str(s.get("purpose") or ""),
                               str(s.get("environment") or ""), *vlans]).lower()
            rows.append(
                f'<tr data-search="{esc(search)}"><td>{self.subnet_link(s["cidr"])}</td>'
                + _td(self.site_name(s["site"])) + _td(s.get("purpose")) + _td(s.get("environment"))
                + _td(", ".join(vlans)) + _td(f"{s['address_count']:,} of {s['usable']:,}", num=True)
                + _td(s.get("confidence")) + _td(s.get("newest_evidence"))
                + f"<td>{self.labels(s['evidence'])}</td></tr>")
        filt = ('<div class="js-only" hidden><label class="field" for="subnet-filter">Filter subnets'
                '</label><input type="search" id="subnet-filter" autocomplete="off" '
                'placeholder="address, site, purpose or VLAN"> '
                '<span id="subnet-count" class="muted" aria-live="polite"></span></div>')
        return filt + _table(["Subnet", "Site", "Purpose", "Environment", "VLAN",
                              "Addresses found of usable", "Confidence", "Newest evidence",
                              "Evidence"], rows, table_id="subnet-table", num=frozenset({5}))

    def _flags(self, a: dict) -> str:
        flags = []
        if a.get("name_conflict"):
            flags.append("Several machine names: " + ", ".join(a["name_conflict"]))
        if a.get("previous_names"):
            flags.append("Previously: " + ", ".join(a["previous_names"]))
        if a.get("not_in_authoritative_source"):
            flags.append(f"Not in {a['not_in_authoritative_source']}")
        if a.get("only_in_superseded"):
            flags.append(f"Not in the newer {a['only_in_superseded']}")
        if a.get("site_stated"):
            flags.append("Source says site: " + ", ".join(a["site_stated"]))
        if a.get("assignment"):
            flags.append(f"Assigned: {a['assignment']} ({'; '.join(a.get('assignment_basis') or [])})")
        if a.get("vlans"):
            flags.append("VLAN: " + ", ".join(str(v) for v in a["vlans"]))
        for sg in a.get("sightings") or []:
            for key, word in (("note", ""), ("device_kind", "Kind: "), ("record", "DNS record: ")):
                if sg.get(key):
                    text = f"{word}{sg[key]}"
                    if text not in flags:
                        flags.append(text)
        reg = a.get("internet_registry") or {}
        if reg.get("asn"):
            flags.append(f"AS{reg['asn']} {reg.get('as_name', '')}".strip())
        return ('<ul class="flags">' + "".join(f"<li>{esc(f)}</li>" for f in flags) + "</ul>"
                if flags else "")

    def addresses_section(self) -> str:
        by_site: dict[str, list[dict]] = defaultdict(list)
        for s in self.subnets:
            by_site[s["site"]].append(s)
        out = ["<p>Each address is listed under the most specific subnet holding it, with every "
               "source that reported it.</p>"]
        for sid, subs in by_site.items():
            with_addresses = [s for s in subs if s["addresses"]]
            if not with_addresses:
                continue
            out.append(f"<h3>{esc(self.site_name(sid))}</h3>")
            for s in with_addresses:
                rows = []
                for a in s["addresses"]:
                    when = a.get("last_observed") or (
                        f"documented {a['last_documented']}" if a.get("last_documented") else "")
                    rows.append("<tr>" + _td(a["ip"], code=True) + _td(", ".join(a["names"]))
                                + f"<td>{self.labels(a['sources'])}</td>"
                                + _td(", ".join(EVIDENCE_WORDS.get(e, e) for e in a["evidence"]))
                                + _td(when) + f"<td>{self._flags(a)}</td></tr>")
                purpose = f" {s['purpose']}" if s.get("purpose") else ""
                summary = (f"<code>{esc(s['cidr'])}</code>{esc(purpose)} "
                           f"({esc(_plural(s['address_count'], 'address', 'addresses'))})")
                out.append(f'<details id="{anchor(s["cidr"])}"><summary>{summary}</summary>'
                           + _table(["Address", "Names", "Reported by", "Evidence",
                                     "Last seen in use", "Notes"], rows) + "</details>")
        for s in self.subnets:
            if not s["addresses"]:
                out.append(f'<p id="{anchor(s["cidr"])}" class="muted"><code>{esc(s["cidr"])}</code>: '
                           "no addresses found.</p>")
        return "".join(out)

    def vlan_rows(self) -> list[tuple]:
        rows: list[tuple] = []
        for seg in self.plan.get("segments") or []:
            name = seg["name"]
            if seg.get("meaning"):
                name += " (" + ", ".join(seg["meaning"]) + ")"
            rows.append((seg["site"], seg.get("vlan"), seg.get("subnet") or "", name,
                         seg.get("switch") or "", self.label(seg["source"])))
        for s in self.subnets:
            if s.get("vlan") is not None:
                rows.append((s["site"], s["vlan"], s["cidr"], s.get("purpose") or "", "",
                             "plan file"))
        return sorted(rows, key=lambda r: (self.site_name(r[0]), r[1] if r[1] is not None else -1,
                                           r[2]))

    def vlans_section(self, rows: list[tuple]) -> str:
        body = ["<tr>" + _td(self.site_name(site)) + _td(vlan, num=True)
                + (f"<td>{self.subnet_link(cidr)}</td>" if cidr else "<td></td>")
                + _td(name) + _td(switch) + _td(src) + "</tr>"
                for site, vlan, cidr, name, switch, src in rows]
        return _table(["Site", "VLAN", "Subnet", "Name or purpose", "Switch", "Stated by"], body,
                      num=frozenset({1}))

    def mirrors_section(self) -> str:
        cidrs = {s["cidr"]: s for s in self.subnets}

        def cell(cidr: str | None) -> str:
            if not cidr:
                return '<td><span class="status status-not-measured">none</span></td>'
            s = cidrs[cidr]
            return (f"<td>{self.subnet_link(cidr)}<br>{esc(s.get('purpose') or '')}"
                    f'<br><small>{esc(_plural(s["address_count"], "address", "addresses"))}</small></td>')

        out = []
        for m in self.plan["mirrors"]:
            left, right = m["left"]["label"], m["right"]["label"]
            out.append(
                f"<h3>{esc(m['name'])}</h3><p>Subnets at the same position inside "
                f"<code>{esc(m['left']['prefix'])}</code> ({esc(left)}) and "
                f"<code>{esc(m['right']['prefix'])}</code> ({esc(right)}). "
                f"{esc(_plural(m['both'], 'position'))} at both, {m['left_only']:,} only at "
                f"{esc(left)}, {m['right_only']:,} only at {esc(right)}. A one-sided row is either "
                "a real difference or a network no source saw at one of them.</p>")
            rows = []
            for r in m["rows"]:
                present = ("both" if r["left"] and r["right"]
                           else f"{left} only" if r["left"] else f"{right} only")
                cls = "status-pass" if r["left"] and r["right"] else "status-not-measured"
                rows.append("<tr>" + _td(r["position"], code=True) + cell(r["left"])
                            + cell(r["right"])
                            + f'<td><span class="status {cls}">{esc(present)}</span></td></tr>')
            out.append(_table(["Position", f"{left}", f"{right}", "Present at"], rows))
        return "".join(out)

    def public_section(self, public: list[dict]) -> str:
        rows = []
        for s in public:
            reg = s.get("internet_registry") or {}
            rows.append(f"<tr><td>{self.subnet_link(s['cidr'])}</td>" + _td(self.site_name(s["site"]))
                        + _td(s.get("purpose")) + _td(f"{s['address_count']:,}", num=True)
                        + _td(f"AS{reg['asn']}" if reg.get("asn") else "")
                        + _td(reg.get("as_name")) + _td(reg.get("registrant"))
                        + _td(reg.get("looked_up")) + "</tr>")
        note = ("" if any(s.get("internet_registry") for s in public) else
                '<p class="muted">No internet-registry lookups are saved for these ranges.</p>')
        return (note + _table(["Range", "Site", "Purpose", "Addresses", "Announced by", "AS name",
                               "Registered to", "Looked up"], rows, num=frozenset({3}))
                + self.chains_section())

    def chains_section(self) -> str:
        out = []
        for c in self.plan.get("exposure_chains") or []:
            hops = "".join(
                "<li>" + esc(h.get("label") or "") + f": <code>{esc(h['address'])}</code>"
                + (f" ({esc(h['name'])})" if h.get("name") else "") + "</li>"
                for h in c.get("hops") or [])
            when = f", {c['as_of']}" if c.get("as_of") else ""
            out.append(f"<h3>{esc(c['name'])}</h3><p>The path a request takes from the internet, "
                       f"as {esc(self.label(c['source']))} describes it{esc(when)}.</p>"
                       f"<ol>{hops}</ol>")
        return "".join(out)

    def checks_section(self) -> str:
        out = []
        for key, (title, why) in CHECKS.items():
            items = self.checks.get(key) or []
            out.append(f'<h3 id="check-{esc(key)}">{esc(title)} '
                       f'<span class="muted">({len(items):,})</span></h3><p>{esc(why)}</p>')
            if key == "vlan_conflicts":
                rows = ["<tr>" + _td(self.site_name(i["site"])) + _td(i["vlan"], num=True)
                        + "<td>" + ", ".join(self.subnet_link(c) for c in i["subnets"]) + "</td></tr>"
                        for i in items]
                out.append(_table(["Site", "VLAN", "Subnets"], rows, num=frozenset({1})))
            elif key == "unknown_addressing":
                rows = [f"<tr><td>{self.subnet_link(i['subnet'])}</td>" + _td(i["addressing"], code=True)
                        + _td("treated as static") + "</tr>" for i in items]
                out.append(_table(["Subnet", "Addressing", "Read as"], rows))
            elif key in ("no_addresses_found", "documented_only"):
                out.append("<p>" + ", ".join(self.subnet_link(c) for c in items) + "</p>"
                           if items else '<p class="muted">None found.</p>')
            else:
                rows = [f"<tr><td>{self.subnet_link(i['subnet'])}</td>" + _td(i["ip"], code=True)
                        + _td(", ".join(i["names"])) + f"<td>{self.labels(i['sources'])}</td>"
                        + _td(self._check_detail(key, i)) + "</tr>" for i in items]
                out.append(_table(["Subnet", "Address", "Names", "Reported by", "Detail"], rows))
        return "".join(out)

    @staticmethod
    def _check_detail(key: str, item: dict) -> str:
        value = item.get(key)
        if key == "site_disagreements":
            return "the source says " + ", ".join(item.get("site_stated") or [])
        if key in ("not_in_authoritative_source", "only_in_superseded"):
            return f"not in {value}"
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        return str(value or "")

    def set_aside_section(self) -> str:
        rows = ["<tr>" + _td(self.label(sid)) + _td(reason) + _td(f"{n:,}", num=True) + "</tr>"
                for sid, reasons in (self.plan.get("set_aside") or {}).items()
                for reason, n in sorted(reasons.items())]
        return ("<p>Sightings that were read but not placed in the plan, and why. An address "
                "outside every subnet is never turned into a subnet of its own.</p>"
                + _table(["Source", "Reason", "Sightings"], rows, num=frozenset({2})))

    def actions_section(self) -> str:
        out = []
        for a in self.plan["actions"]:
            subs = ", ".join(self.subnet_link(str(c)) for c in a.get("subnets") or [])
            out.append(f'<article class="card" id="action-{esc(a.get("id"))}">'
                       f"<h3>{esc(a.get('id'))}: {esc(a.get('title') or '')}</h3>"
                       + (f"<p>{esc(a['detail'])}</p>" if a.get("detail") else "")
                       + (f"<p><small>Subnets: {subs}</small></p>" if subs else "") + "</article>")
        return "".join(out)

    def sources_section(self) -> str:
        rows = []
        for s in self.sources.values():
            when = f"{s.get('as_of_basis', 'dated')} {s['as_of']}" if s.get("as_of") else "undated"
            extra = [w for w, on in (("roams", s.get("roams")),
                                     ("authoritative for " + ", ".join(
                                         self.site_name(x) for x in s.get("authoritative_for") or []),
                                      s.get("authoritative_for")),
                                     ("replaces " + ", ".join(self.label(x) for x in
                                                              s.get("supersedes") or []),
                                      s.get("supersedes"))) if on]
            rows.append("<tr>" + _td(s["label"]) + _td(s["kind"])
                        + _td(EVIDENCE_WORDS.get(s.get("evidence_class", ""), ""))
                        + _td(when) + _td("; ".join(extra + list(s.get("notes") or []))) + "</tr>")
        return _table(["Source", "Kind", "What it shows", "Date", "Notes"], rows)


def mac_key(value: Any) -> str:
    """A MAC address as twelve lower-case hex digits, or "" when it is not one."""
    hex_digits = re.sub(r"[\s:.-]", "", str(value or "")).lower()
    return hex_digits if re.fullmatch(r"[0-9a-f]{12}", hex_digits) else ""


def _lookup_data(plan: dict, sites: dict) -> str:
    subnets: list[dict] = []
    addresses: dict[str, list[str]] = {}
    macs: dict[str, list[list[Any]]] = defaultdict(list)
    for s in plan.get("subnets") or []:
        net = ipaddress.ip_network(s["cidr"], strict=False)
        subnets.append({"cidr": s["cidr"], "v": net.version, "base": str(int(net.network_address)),
                        "len": net.prefixlen, "anchor": anchor(s["cidr"]),
                        "site": sites.get(s["site"], {}).get("name") or s["site"],
                        "purpose": s.get("purpose") or ""})
        for a in s["addresses"]:
            ip = ipaddress.ip_address(a["ip"])
            addresses[f"{ip.version}:{int(ip)}"] = a["names"]
            for key in sorted({mac_key(sg.get("mac")) for sg in a.get("sightings") or []} - {""}):
                macs[key].append([a["ip"], len(subnets) - 1])
    return json.dumps({"subnets": subnets, "addresses": addresses, "macs": macs},
                      ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")


def render(plan: dict, theme: htmlpage.Theme | None = None, *, part: str | None = None,
           author: str | None = None) -> str:
    """The plan as a complete HTML page.

    ``part`` is a short label shown above the title (the part of a larger set
    the page belongs to, say) and ``author`` a line shown under it; each
    defaults to the plan's own ``part`` and ``author``.
    """
    view = _View(plan)
    panels = []
    for sid, label, count, body in view.sections():
        n = f' data-count="{count:,}"' if count is not None else ""
        panels.append(f'<section class="panel" id="{sid}" data-label="{esc(label)}"{n}>'
                      f"<h2>{esc(label)}</h2>{body}</section>")
    body = (f"<style>{_EXTRA_CSS}</style>"
            '<nav class="ipam-tabs" id="ipam-tabs" role="tablist" aria-label="Sections" hidden></nav>'
            + "\n".join(panels)
            + f'<script type="application/json" id="ipam-lookup">{_lookup_data(plan, view.sites)}'
            + f"</script><script>{_SCRIPT}</script>")
    org = str(plan.get("organisation") or "")
    title = str(plan.get("title") or "IP address plan")
    if org and org not in title:
        title = f"{title}: {org}"
    sha = str(plan.get("plan_sha256") or "")
    footer = (f"<p>Built {esc(plan.get('built_on') or '')} from the plan file"
              + (f" (SHA-256 <code>{esc(sha[:16])}</code>…)" if sha else "")
              + " and the sources listed under Sources.</p>")
    return htmlpage.page(title, body, theme=theme, lead=str(plan.get("subtitle") or ""),
                         description=title, footer=footer,
                         eyebrow=str(plan.get("part") or "") if part is None else part,
                         byline=str(plan.get("author") or "") if author is None else author)
