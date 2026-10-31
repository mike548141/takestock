"""The IP address plan as one self-contained HTML page.

The page is drawn entirely from the plan :func:`takestock.ipam.build` returns,
so it cannot disagree with the JSON and CSV written beside it. Every label,
count and section comes from that data: sites are counted by the kinds the
plan file gives them, sources are named by their declared labels, and a
section whose data is absent (segments, mirrors, public ranges, actions) is
not drawn at all.

Its job is to answer an engineer's questions in the order they are asked:
*how big is this* (the headline), *which ranges are ours and where do they
live* (sites), *what is this subnet and what is on it* (the subnet table, each
subnet opening to its detail and its addresses), *is this address ours* (the
finder, and the subnet search, which take an address and say which subnet
holds it, or why none does), *do two sites laid out alike match* (mirrors),
*what faces the internet and who routes it*, and *what should I not trust
yet* (the checks and the actions).

Without scripts the page reads as one long document and prints that way. A
small inline script turns the sections into tabs, searches and filters the
subnet table, draws a map of the addresses in use when a subnet is opened,
and answers *which subnet holds this address?* from data embedded in the
page. Every value from the data is escaped before it reaches the markup.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from datetime import date
from typing import Any
from urllib.parse import quote

from . import htmlpage
from .htmlpage import esc

#: How each evidence class reads in the page.
EVIDENCE_WORDS = {"observed": "seen in use", "named": "named", "documented": "documented"}

#: What each confidence word the plan uses means. Any other word a plan file
#: gives is shown as written, without an explanation.
CONFIDENCE = {
    "measured": "an instrument or export states it",
    "inferred": "read from a pattern in the data, not stated by any source",
    "declared": "named in a document or record, not seen by an instrument",
}

#: The kinds an action may give (`kind:` in the plan file), in the order they
#: are listed, with a heading and what an action of that kind does. An action
#: of any other kind is listed after these under its own word.
ACTION_KINDS: dict[str, tuple[str, str]] = {
    "collect": ("Collect data", "closes a gap in what the sources can see"),
    "confirm": ("Confirm", "settles a fact the sources disagree on or only imply"),
    "decide": ("Decide", "needs someone to make a choice"),
    "tidy": ("Tidy up", "is housekeeping the data brought to light"),
}

#: How the addresses in a subnet are given out, by its ``addressing`` value.
ADDRESSING_TEXT = {
    "static": (
        "Fixed addressing: each address is configured on its machine. Two machine names on "
        "one address are a conflict to resolve. Where a source states how an address was "
        "assigned, the address says so."),
    "dynamic": (
        "Addresses here change hands, so two machine names on one address are expected rather "
        "than a conflict. They are most likely handed out by DHCP. The addresses below are the "
        "ones sources saw in use, not the range a DHCP server hands out."),
    "pool": (
        "Addresses here are handed out from a pool. The addresses below are the ones sources "
        "saw in use, not the pool's configured range."),
    "overlay": (
        "A container platform's internal network. Each node holds an address here that exists "
        "only inside the cluster, and the platform hands them out itself. Nothing on the routed "
        "network may use this range without breaking the cluster's traffic to it."),
}

#: The addressing text for a static or dynamic subnet at a site of kind ``cloud``.
CLOUD_ASSIGNED = (
    "The cloud platform assigns every address in this subnet, whether it holds the address as "
    "static or dynamic. There is no separate DHCP scope to export.")

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

#: Source kinds whose date is when a document was written, not when a system
#: was read; their age is not counted as staleness. (Matches ``ipam.DOCUMENT_KINDS``.)
_DOCUMENT_KINDS = frozenset({"document", "record"})

#: The sighting fields that only say where a sighting came from; every other
#: text field of a sighting is searchable.
_SIGHTING_PLUMBING = frozenset({"source", "observed", "name_is"})

#: IPv4 subnets this size or smaller (by prefix length) get a map of the
#: addresses in use when opened: /23 is 512 squares, /30 is four.
MAP_PREFIX = (23, 30)

_EXTRA_CSS = """
.ipam-tabs { display: flex; flex-wrap: wrap; gap: .25rem; border-bottom: 1px solid var(--border);
  margin: 0 0 1.5rem; position: sticky; top: 0; z-index: 2; background: var(--bg); }
.ipam-tabs button { font: inherit; background: none; border: 0; border-bottom: 3px solid transparent;
  padding: .5rem .75rem; color: var(--muted); cursor: pointer; }
.ipam-tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent);
  font-weight: 600; }
.ipam-tabs button:focus-visible, .ipam button:focus-visible, .ipam summary:focus-visible {
  outline: 3px solid var(--accent); outline-offset: 2px; }
.ipam-tabs .n { font-weight: 400; margin-left: .3em; }
section.panel > h2:first-child { margin-top: 0; border-top: 0; padding-top: 0; }
.card > h3:first-child, .card > h4:first-child { margin-top: 0; }
code.cidr { white-space: nowrap; overflow-wrap: normal; }
details { margin: 0 0 .75rem; scroll-margin-top: 7rem; }
details[open] { border-left: 3px solid var(--accent); padding-left: .75rem; }
summary { cursor: pointer; }
input[type="search"] { font: inherit; padding: .4rem .55rem; border: 1px solid var(--muted);
  border-radius: 3px; background: var(--bg); color: var(--text); width: 30rem; max-width: 100%; }
label.field { display: block; font-weight: 600; margin: 0 0 .25rem; }
ul.flags { margin: 0; padding-left: 1.1rem; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(10.5rem, 1fr)); gap: .75rem;
  margin: 0 0 1.5rem; }
.stat { background: var(--surface); border-left: 4px solid var(--accent); padding: .6rem .85rem;
  border-radius: 4px; }
.stat b { display: block; font-size: 1.5rem; line-height: 1.15; }
.stat span { color: var(--muted); }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(17rem, 1fr)); gap: .9rem;
  margin: 0 0 1rem; }
.cards > .card { margin: 0; }
.ipam .btn, .ipam .chip { font: inherit; color: var(--text); background: var(--bg);
  border: 1px solid var(--border); cursor: pointer; }
.ipam .btn { padding: .35rem .7rem; border-radius: 4px; }
.ipam .chip { padding: .1rem .6rem; border-radius: 2em; font-size: .9rem; margin: 0 .3rem .3rem 0; }
.ipam .chip[aria-pressed="true"] { background: var(--accent); color: var(--bg);
  border-color: var(--accent); }
.toolbar { display: flex; flex-wrap: wrap; gap: .5rem; align-items: flex-end; margin: 0 0 .5rem; }
.filters { margin: 0 0 .25rem; }
.filters .lbl { display: inline-block; min-width: 7rem; color: var(--muted); font-size: .9rem; }
.tag { display: inline-block; padding: 0 .45em; border-radius: 3px; font-size: .85rem;
  font-weight: 600; white-space: nowrap; border: 1px solid transparent; }
.tag-plain { color: var(--muted); border-color: var(--border); }
.bar { height: .35rem; background: var(--border); border-radius: 2px; overflow: hidden;
  min-width: 4rem; margin-top: .2rem; }
.bar i { display: block; height: 100%; background: var(--accent); }
.lookup-box { border: 1px solid var(--accent); border-left-width: 5px; border-radius: 4px;
  padding: .6rem .85rem; margin: .5rem 0 .75rem; }
.grid2 { display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr); gap: 1.25rem; }
.usemap { display: grid; grid-template-columns: repeat(32, 1fr); gap: 2px; max-width: 34rem;
  margin: .4rem 0; }
.usemap span { aspect-ratio: 1; border: 1px solid var(--border); border-radius: 2px; }
.usemap span.u, .legend i.u { background: var(--accent); border-color: var(--accent); }
.usemap span.n, .legend i.n { border: 2px solid var(--accent); }
.legend { font-size: .9rem; color: var(--muted); display: flex; flex-wrap: wrap; gap: 1rem; }
.legend i { display: inline-block; width: .7rem; height: .7rem; border-radius: 2px;
  margin-right: .3rem; border: 1px solid var(--border); vertical-align: -1px; }
article.action { border-left: 5px solid var(--border); }
article.action.k-collect { border-left-color: var(--accent); }
article.action.k-confirm { border-left-color: var(--pass-fg); }
article.action.k-decide { border-left-color: var(--unmeasured-fg); }
ol.chain { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: .4rem; }
ol.chain li { background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
  padding: .35rem .65rem; }
ol.chain li + li::before { content: "→"; color: var(--muted); margin-right: .5rem; }
tr.conflict td { background: var(--unmeasured-bg); }
@media (max-width: 50rem) { .grid2 { grid-template-columns: 1fr; } }
@media print { .ipam-tabs, .js-only { display: none !important; }
  section.panel[hidden] { display: block !important; } .ipam-tabs { position: static; } }
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
  var data = JSON.parse(document.getElementById("ipam-lookup").textContent);
  // The view is kept in the address (#<section>, #find=..., #filter=...) so a
  // link opens where it was copied. Some previews show the page in a sandboxed
  // frame where changing the address throws; the page must work there too.
  function remember(hash) {
    try { history.replaceState(null, "", hash); return true; } catch (e) { return false; }
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
  function decode(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }

  // -- addresses ------------------------------------------------------------
  function parse(s) {
    s = s.trim().replace(/^\[|\]$/g, "");
    var m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      var n = BigInt(0);
      for (var k = 1; k <= 4; k++) {
        var o = Number(m[k]); if (o > 255) return null;
        n = n * BigInt(256) + BigInt(o);
      }
      return {v: 4, n: n, bits: 32, text: s};
    }
    // An IPv4 address written in IPv6 form ("::ffff:" then a dotted quad).
    var quad = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (quad) {
      if ([2, 3, 4, 5].some(function (k) { return Number(quad[k]) > 255; })) return null;
      s = quad[1] + (Number(quad[2]) * 256 + Number(quad[3])).toString(16) + ":" +
          (Number(quad[4]) * 256 + Number(quad[5])).toString(16);
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
    return groups.length === 8 ? {v: 6, n: v, bits: 128, text: s} : null;
  }
  function parseCidr(s) {
    var m = /^(.+)\/(\d{1,3})$/.exec(s.trim()); if (!m) return null;
    var ip = parse(m[1]), len = Number(m[2]);
    if (!ip || len > ip.bits) return null;
    var shift = BigInt(ip.bits - len);
    return {v: ip.v, base: (ip.n >> shift) << shift, len: len, bits: ip.bits};
  }
  function mac(s) {
    var hex = s.trim().toLowerCase().replace(/[\s:.-]/g, "");
    return /^[0-9a-f]{12}$/.test(hex) ? hex : null;
  }
  function inside(s, ip) {
    if (s.v !== ip.v) return false;
    var shift = BigInt(ip.bits - s.len);
    return (ip.n >> shift) === (BigInt(s.base) >> shift);
  }
  function overlaps(s, net) {
    if (s.v !== net.v) return false;
    var len = Math.min(s.len, net.len), shift = BigInt(net.bits - len);
    return (BigInt(s.base) >> shift) === (net.base >> shift);
  }
  function holder(ip) {
    var best = null;
    data.subnets.forEach(function (s) { if (inside(s, ip) && (!best || s.len > best.len)) best = s; });
    return best;
  }
  // Why an address in no subnet of the plan is not there, from its kind.
  // Why an address in no subnet of the plan is not there: the most specific
  // special-purpose range holding it (``SPECIAL_RANGES``), or public.
  function whyNot(ip) {
    var best = null;
    data.special.forEach(function (r) {
      if (r[0] !== ip.v) return;
      var shift = BigInt(ip.bits - r[2]);
      if ((ip.n >> shift) === (BigInt(r[1]) >> shift) && (!best || r[2] > best[2])) best = r;
    });
    return data.kinds[best ? best[3] : "public"];
  }
  function where(s) {
    return s.cidr + " (" + s.site + (s.purpose ? ", " + s.purpose : "") + ")";
  }
  function link(out, s, label) {
    var a = document.createElement("a"); a.href = "#" + s.anchor;
    a.textContent = label || (" Open " + s.cidr); out.appendChild(a);
  }
  // Answers *where is this address?* into ``out``; true when ``value`` was an address or MAC.
  function answer(value, out) {
    out.textContent = "";
    var ip = parse(value);
    if (!ip) {
      var m = mac(value), seen = m && data.macs[m];
      if (!m) return false;
      if (!seen) { out.textContent = "No source reported that MAC address."; return true; }
      out.textContent = "That MAC address was seen at " + seen.map(function (x) {
        return x[0] + " in " + where(data.subnets[x[1]]);
      }).join("; ") + ".";
      seen.forEach(function (x) { link(out, data.subnets[x[1]]); });
      return true;
    }
    var best = holder(ip);
    if (!best) {
      out.textContent = value + " is not inside any subnet in the plan. " + whyNot(ip);
      return true;
    }
    var text = value + " is inside " + where(best) + ".";
    var known = data.addresses[ip.v + ":" + ip.n.toString()];
    if (known) {
      text += " Listed" + (known.names.length ? " as " + known.names.join(", ") : "") +
              ", reported by " + known.sources.join(", ") + "; " +
              (known.last ? "last seen in use " + known.last : "not seen in use by any source") +
              (known.documented ? " (last named " + known.documented + ")" : "") + ".";
    } else {
      text += " Not an address any source reported.";
    }
    out.textContent = text;
    link(out, best);
    return true;
  }

  // -- the subnet search ----------------------------------------------------
  var table = document.getElementById("subnet-table");
  var filter = document.getElementById("subnet-filter");
  var rows = table ? Array.prototype.slice.call(table.querySelectorAll("tbody tr")) : [];
  var chips = Array.prototype.slice.call(document.querySelectorAll("#subnet-chips .chip"));
  var norm = function (t) { return String(t).toLowerCase().replace(/_/g, " "); };
  function qualifiers(q) {
    var out = {terms: [], addr: null, block: null};
    q.trim().split(/\s+/).filter(Boolean).forEach(function (t) {
      var m = /^(site|env|conf|vlan|source|action):(.+)$/i.exec(t);
      if (m) { (out[m[1].toLowerCase()] = out[m[1].toLowerCase()] || []).push(norm(m[2])); return; }
      var ip = parse(t), net = t.indexOf("/") > 0 ? parseCidr(t) : null, hw = mac(t);
      if (ip) out.addr = ip; else if (net) out.block = net; else out.terms.push(hw || norm(t));
    });
    return out;
  }
  function pressed(kind) {
    return chips.filter(function (c) {
      return c.getAttribute("data-f") === kind && c.getAttribute("aria-pressed") === "true";
    }).map(function (c) { return c.getAttribute("data-v"); });
  }
  function matches(r, Q, on) {
    var s = data.subnets[Number(r.getAttribute("data-i"))], d = r.dataset;
    function any(list, test) { return !list || !list.length || list.some(test); }
    if (on.site.length && on.site.indexOf(s.site_id) < 0) return false;
    if (on.env.length && on.env.indexOf(s.env || "unstated") < 0) return false;
    if (on.conf.length && on.conf.indexOf(s.conf || "unstated") < 0) return false;
    if (on.flag.indexOf("actions") >= 0 && !s.actions.length) return false;
    if (on.flag.indexOf("empty") >= 0 && s.count) return false;
    if (on.flag.indexOf("vlan") >= 0 && !s.vlans.length) return false;
    if (!any(Q.site, function (x) {
      return norm(s.site_id).indexOf(x) >= 0 || norm(s.site).indexOf(x) >= 0;
    })) return false;
    if (!any(Q.env, function (x) { return norm(s.env).indexOf(x) >= 0; })) return false;
    if (!any(Q.conf, function (x) { return norm(s.conf).indexOf(x) === 0; })) return false;
    if (!any(Q.vlan, function (x) { return s.vlans.indexOf(x) >= 0; })) return false;
    if (!any(Q.action, function (x) { return s.actions.map(norm).indexOf(x) >= 0; })) return false;
    if (!any(Q.source, function (x) { return norm(d.sources).indexOf(x) >= 0; })) return false;
    if (Q.addr && !inside(s, Q.addr)) return false;
    if (Q.block && !overlaps(s, Q.block)) return false;
    return Q.terms.every(function (t) { return d.search.indexOf(t) >= 0; });
  }
  // Addresses whose names, MACs or address hold every free word, for the answer box.
  function namedAddresses(terms) {
    if (!terms.length) return [];
    var out = [];
    Object.keys(data.addresses).some(function (k) {
      var a = data.addresses[k];
      if (terms.every(function (t) { return a.find.indexOf(t) >= 0; })) out.push(a);
      return out.length > 10;
    });
    return out;
  }
  function apply(keep) {
    if (!table) return;
    var q = filter.value, Q = qualifiers(q), shown = 0, box = document.getElementById("subnet-answer");
    var on = {site: pressed("site"), env: pressed("env"), conf: pressed("conf"), flag: pressed("flag")};
    rows.forEach(function (r) { var ok = matches(r, Q, on); r.hidden = !ok; if (ok) shown++; });
    document.getElementById("subnet-count").textContent = "Showing " + shown + " of " + rows.length +
      " address blocks" + (q.trim() ? " for “" + q.trim() + "”" : "") + ".";
    box.hidden = true;
    var single = q.trim().split(/\s+/).length === 1 && q.trim();
    if (single && answer(single, box)) box.hidden = false;
    else {
      var named = namedAddresses(Q.terms);
      if (named.length) {
        box.hidden = false; box.textContent = "Addresses matching: ";
        named.slice(0, 10).forEach(function (a, i) {
          if (i) box.appendChild(document.createTextNode("; "));
          var hit = a.names.filter(function (x) {
            return Q.terms.every(function (t) { return norm(x).indexOf(t) >= 0; });
          })[0];
          link(box, data.subnets[a.s], (hit || a.names[0] || a.where) + " at " + a.where);
        });
        if (named.length > 10) box.appendChild(document.createTextNode("; and more."));
      }
    }
    var h = new URLSearchParams(), held = false;
    h.set("filter", q.trim());
    ["site", "env", "conf", "flag"].forEach(function (k) { if (on[k].length) h.set(k, on[k].join(",")); });
    var hash = h.toString() === "filter=" ? "#subnets" : "#" + h.toString();
    if (keep !== false) held = remember(hash);
    return held;
  }
  if (filter) {
    var timer = null;
    filter.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(apply, 120); });
    chips.forEach(function (c) {
      c.addEventListener("click", function () {
        c.setAttribute("aria-pressed", c.getAttribute("aria-pressed") === "true" ? "false" : "true");
        apply();
      });
    });
    document.getElementById("subnet-clear").addEventListener("click", function () {
      filter.value = ""; chips.forEach(function (c) { c.setAttribute("aria-pressed", "false"); }); apply();
    });
    document.getElementById("subnet-csv").addEventListener("click", function () {
      var cols = ["subnet", "site", "environment", "purpose", "vlans", "addresses_found", "usable",
                  "confidence", "newest_evidence", "actions"];
      var q = function (v) { return '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"'; };
      var lines = [cols.join(",")].concat(rows.filter(function (r) { return !r.hidden; }).map(function (r) {
        var s = data.subnets[Number(r.getAttribute("data-i"))];
        return [s.cidr, s.site, s.env, s.purpose, s.vlans.join("; "), s.count, s.usable, s.conf,
                s.newest, s.actions.join("; ")].map(q).join(",");
      }));
      var a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], {type: "text/csv"}));
      a.download = "subnets-shown.csv"; document.body.appendChild(a); a.click(); a.remove();
    });
    var copy = document.getElementById("subnet-link");
    copy.addEventListener("click", function () {
      var held = apply();
      if (held && navigator.clipboard) navigator.clipboard.writeText(location.href).catch(function () {});
      copy.textContent = held ? "Link copied" : "Open the file itself to copy a link";
      setTimeout(function () { copy.textContent = "Copy link to this view"; }, 2000);
    });
  }

  // -- a map of the addresses in use, drawn when a subnet is opened ----------
  document.querySelectorAll("details[data-map]").forEach(function (d) {
    d.addEventListener("toggle", function () {
      var box = d.querySelector(".usemap"); if (!d.open || !box || box.childNodes.length) return;
      var net = parseCidr(d.getAttribute("data-map")), size = 1 << (32 - net.len), used = {};
      d.querySelectorAll("tr[data-ip]").forEach(function (r) {
        var ip = parse(r.getAttribute("data-ip"));
        if (ip && ip.v === 4) used[Number(ip.n - net.base)] = r.getAttribute("data-seen") === "1" ? "u" : "n";
      });
      for (var i = 0; i < size; i++) {
        var c = document.createElement("span"); if (used[i]) c.className = used[i];
        box.appendChild(c);
      }
    });
  });

  // -- the VLAN filter --------------------------------------------------------
  var vf = document.getElementById("vlan-filter");
  if (vf) vf.addEventListener("input", function () {
    var q = norm(vf.value.trim());
    document.querySelectorAll("#vlan-table tbody tr").forEach(function (r) {
      r.hidden = q && norm(r.textContent).indexOf(q) < 0;
    });
  });

  // -- the address finder on the overview -------------------------------------
  var input = document.getElementById("lookup"), out = document.getElementById("lookup-result");
  if (input) input.addEventListener("input", function () {
    var value = input.value.trim();
    remember(value ? "#find=" + encodeURIComponent(value) : "#overview");
    out.textContent = "";
    if (value && !answer(value, out)) out.textContent = "Not an IPv4 or IPv6 address, or a MAC address.";
  });

  // -- navigation ---------------------------------------------------------------
  function go(hash) {
    var m = /^#(find|filter)=/.exec(hash || "");
    if (m && m[1] === "find" && input) {
      show(panelOf(input).id, false); input.value = decode(hash.slice(6));
      input.dispatchEvent(new Event("input")); return;
    }
    if (m && filter) {
      var h = new URLSearchParams(hash.slice(1));
      show(panelOf(filter).id, false); filter.value = h.get("filter") || "";
      chips.forEach(function (c) {
        var on = (h.get(c.getAttribute("data-f")) || "").split(",").indexOf(c.getAttribute("data-v")) >= 0;
        c.setAttribute("aria-pressed", on ? "true" : "false");
      });
      apply(false); return;
    }
    var el = hash && document.getElementById(decode(hash.slice(1)));
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
  window.addEventListener("hashchange", function () { go(location.hash); });

  // Last, once every control listens: open the view the address names.
  go(location.hash);
})();
"""


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def anchor(cidr: str) -> str:
    """The element id of a subnet's detail."""
    return "s-" + re.sub(r"[^0-9A-Za-z]+", "-", cidr).strip("-")


def _net(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(str(cidr), strict=False)


def headline(plan: dict) -> dict[str, int]:
    """The kinds of address block in ``plan``, and its current segments.

    A block in the plan is not always a subnet: a container platform's
    internal network (``addressing: overlay``), a single address (/32, /128)
    and a range a site holds as a whole (/16 or wider for IPv4, /48 or wider
    for IPv6) are recorded the same way. Each block is counted under exactly
    one of ``cluster_internal``, ``single_address``, ``site_range`` and
    ``subnet``, in that order. A segment only a replaced source lists
    (``superseded_by``) is left out, as the plan's own segment count leaves
    it out.
    """
    kinds = {"subnet": 0, "site_range": 0, "single_address": 0, "cluster_internal": 0}
    for s in plan.get("subnets") or []:
        n = _net(s["cidr"])
        if s.get("addressing") == "overlay":
            kinds["cluster_internal"] += 1
        elif n.num_addresses == 1:
            kinds["single_address"] += 1
        elif n.prefixlen <= (16 if n.version == 4 else 48):
            kinds["site_range"] += 1
        else:
            kinds["subnet"] += 1
    current = [e for e in plan.get("segments") or [] if not e.get("superseded_by")]
    return {**kinds, "segments": len(current),
            "segments_with_vlan": sum(1 for e in current if e.get("vlan") not in (None, 0))}


def _day(value: Any) -> date | None:
    """A source date (``2030``, ``2030-03`` or ``2030-03-02``) as its first day, or None."""
    parts = str(value or "").strip()[:10].split("-")
    try:
        nums = [int(p) for p in parts]
        return date(nums[0], *(nums[1:3] + [1, 1])[:2])
    except (ValueError, IndexError, TypeError):
        return None


def months_before(when: Any, built_on: Any) -> int | None:
    """Whole calendar months from ``when`` to ``built_on``, or None.

    A month is counted only once it has fully passed: 2030-01-15 is 0 months
    before 2030-02-14 and 1 month before 2030-02-15.
    """
    a, b = _day(when), _day(built_on)
    if a is None or b is None:
        return None
    return (b.year - a.year) * 12 + b.month - a.month - (1 if b.day < a.day else 0)


def age_text(when: Any, built_on: Any) -> str:
    """``when``'s age at the build, in words ("under a month old", "3 months old")."""
    m = months_before(when, built_on)
    if m is None:
        return ""
    return "under a month old" if m < 1 else f"{_plural(m, 'month')} old"


#: Special-purpose address ranges (the IANA registries of RFC 6890), most
#: specific match wins, as (IP version, first address as an integer, prefix
#: length, kind). An address in none of them is public. Written as integers
#: so the table reads the same in Python and in the page's script; a test
#: checks every row against the standard library's ``ipaddress`` flags.
SPECIAL_RANGES: list[tuple[int, int, int, str]] = [
    (4, 0x00000000, 8, "reserved"),        # "this network" (RFC 791)
    (4, 0x0A000000, 8, "private"),         # RFC 1918
    (4, 0x64400000, 10, "shared"),         # carrier-grade NAT (RFC 6598)
    (4, 0x7F000000, 8, "loopback"),        # RFC 1122
    (4, 0xA9FE0000, 16, "link-local"),     # RFC 3927
    (4, 0xAC100000, 12, "private"),        # RFC 1918
    (4, 0xC0000000, 24, "reserved"),       # IETF protocol assignments (RFC 6890)
    (4, 0xC0000200, 24, "documentation"),  # RFC 5737
    (4, 0xC0A80000, 16, "private"),        # RFC 1918
    (4, 0xC6120000, 15, "reserved"),       # benchmarking (RFC 2544)
    (4, 0xC6336400, 24, "documentation"),  # RFC 5737
    (4, 0xCB007100, 24, "documentation"),  # RFC 5737
    (4, 0xE0000000, 4, "multicast"),       # RFC 5771
    (4, 0xF0000000, 4, "reserved"),        # future use and broadcast (RFC 1112, RFC 919)
    (6, 0x0, 0, "reserved"),               # outside the global unicast space
    (6, 0x0, 128, "reserved"),             # unspecified (RFC 4291)
    (6, 0x1, 128, "loopback"),             # RFC 4291
    (6, 0xFFFF << 32, 96, "mapped"),       # IPv4-mapped (RFC 4291)
    (6, 0x2000 << 112, 3, "public"),      # global unicast (RFC 4291)
    (6, 0x2001 << 112, 23, "reserved"),    # IETF protocol assignments (RFC 2928)
    (6, 0x20010DB8 << 96, 32, "documentation"),  # RFC 3849
    (6, 0x2002 << 112, 16, "reserved"),    # 6to4 (RFC 3056)
    (6, 0x3FFF << 112, 20, "documentation"),  # RFC 9637
    (6, 0xFC << 120, 7, "private"),        # unique local (RFC 4193)
    (6, 0xFE80 << 112, 10, "link-local"),  # RFC 4291
    (6, 0xFF << 120, 8, "multicast"),      # RFC 4291
]

#: What the page says about an address in no subnet, by its kind.
ADDRESS_KINDS: dict[str, str] = {
    "private": ("It is a private address: if it is the organisation's, its subnet is missing from "
                "the plan; otherwise it belongs to another network, such as one a roaming device "
                "visited."),
    "shared": ("It is in the shared range an internet provider uses between itself and its "
               "customers, so it describes a provider's network."),
    "link-local": ("It is a self-assigned link-local address, which a device gives itself and "
                   "which describes no network."),
    "loopback": "It is a loopback address, which never leaves the device.",
    "multicast": ("It is a multicast address, which names a group of listeners rather than a "
                  "machine on a subnet."),
    "documentation": ("It is in a range reserved for documentation and examples, which no "
                      "network uses."),
    "mapped": ("It is an IPv4 address written in IPv6 form. Search for the IPv4 address "
               "itself (the part after the last colon) to find its subnet."),
    "reserved": ("It is in a range set aside for a special purpose, not for ordinary "
                 "addressing."),
    "public": ("It is a public address. Sightings outside every subnet are not kept in the "
               "plan, so the plan cannot say whether a source saw it."),
}


def address_kind(value: str) -> str:
    """The kind of ``value`` by :data:`SPECIAL_RANGES`, as the page's script reads it."""
    ip = ipaddress.ip_address(value)
    bits = 32 if ip.version == 4 else 128
    best: tuple[int, int, int, str] | None = None
    for row in SPECIAL_RANGES:
        version, base, length, _kind = row
        if version == ip.version and int(ip) >> (bits - length) == base >> (bits - length) \
                and (best is None or length > best[2]):
            best = row
    return best[3] if best else "public"


def mac_key(value: Any) -> str:
    """A MAC address as twelve lower-case hex digits, or "" when it is not one."""
    hex_digits = re.sub(r"[\s:.-]", "", str(value or "")).lower()
    return hex_digits if re.fullmatch(r"[0-9a-f]{12}", hex_digits) else ""


def _sentence_case(text: str) -> str:
    """``text`` with a capital first letter lowered, unless it starts an acronym."""
    if len(text) > 1 and text[0].isupper() and text[1].islower():
        return text[0].lower() + text[1:]
    return text


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


def _tag(text: str, cls: str = "tag-plain", title: str = "") -> str:
    t = f' title="{esc(title)}"' if title else ""
    return f'<span class="tag {cls}"{t}>{esc(text)}</span>'


def _confidence_tag(word: Any) -> str:
    word = str(word or "")
    if not word:
        return ""
    cls = {"measured": "status-pass", "inferred": "status-not-measured",
           "declared": "status-fail"}.get(word, "tag-plain")
    return _tag(word, cls, CONFIDENCE.get(word, ""))


def _registry_line(r: dict) -> str:
    asn = str(r.get("asn") or "")
    bits = [f"AS{asn} {r.get('as_name') or ''}".strip() if asn and asn != "NA"
            else "announced by no autonomous system"]
    if r.get("announced_prefix"):
        bits.append(f"announced as {r['announced_prefix']}")
    holder = r.get("registrant") or r.get("network_name")
    if holder:
        bits.append(f"registered to {holder}"
                    + (f" ({r['registered_range']})" if r.get("registered_range") else ""))
    if r.get("registry"):
        bits.append(str(r["registry"]).upper() + (f", {r['country']}" if r.get("country") else ""))
    return " · ".join(bits)


def _prefix_order(cidr: str) -> tuple:
    """Sort key putting networks in address order; anything unreadable last, as text."""
    try:
        n = _net(cidr)
    except ValueError:
        return (9, 0, cidr)
    return (n.version, int(n.network_address), "")


def _seen(a: dict) -> bool:
    """Seen in use by an instrument or export, not only named by DNS or a document."""
    return "observed" in (a.get("evidence") or [])


class _View:
    def __init__(self, plan: dict) -> None:
        self.plan = plan
        self.sources = {s["id"]: s for s in plan.get("sources") or []}
        self.sites = {s["id"]: s for s in plan.get("sites") or []}
        self.subnets: list[dict] = list(plan.get("subnets") or [])
        self.by_cidr = {s["cidr"]: s for s in self.subnets}
        self.counts: dict = plan.get("counts") or {}
        self.checks: dict = plan.get("checks") or {}
        self.actions: list[dict] = list(plan.get("actions") or [])
        self.built_on = str(plan.get("built_on") or "")
        self.children: dict[str, list[str]] = defaultdict(list)
        for s in self.subnets:
            if s.get("parent"):
                self.children[s["parent"]].append(s["cidr"])
        self._subtree: dict[str, int] = {}

    # -- helpers --
    def label(self, sid: str) -> str:
        return str(self.sources.get(sid, {}).get("label") or sid)

    def site_name(self, sid: str) -> str:
        site = self.sites.get(sid)
        return str(site["name"]) if site else "No site holds this range"

    def subnet_link(self, cidr: str) -> str:
        return f'<a href="#{anchor(cidr)}"><code class="cidr">{esc(cidr)}</code></a>'

    def action_link(self, aid: Any) -> str:
        return f'<a href="#action-{esc(aid)}">{esc(aid)}</a>'

    def labels(self, ids: list[str]) -> str:
        return esc(", ".join(self.label(s) for s in ids))

    def check_total(self) -> int:
        return sum(len(v) for v in self.checks.values())

    def in_children(self, cidr: str) -> int:
        """Addresses held by ``cidr``'s descendants in the plan."""
        if cidr not in self._subtree:
            self._subtree[cidr] = sum(self.by_cidr[k]["address_count"] + self.in_children(k)
                                      for k in self.children.get(cidr, []))
        return self._subtree[cidr]

    def addressing_text(self, s: dict) -> str:
        kind = str(s.get("addressing") or "static")
        if (kind in ("static", "dynamic")
                and self.sites.get(s["site"], {}).get("kind") == "cloud"):
            return CLOUD_ASSIGNED
        return ADDRESSING_TEXT.get(kind, ADDRESSING_TEXT["static"])

    def stale_sources(self) -> list[dict]:
        """Sources read from a system, a whole calendar month or more old at the build."""
        return [s for s in self.sources.values() if s.get("kind") not in _DOCUMENT_KINDS
                and (months_before(s.get("as_of"), self.built_on) or 0) >= 1]

    def set_aside_total(self) -> int:
        return sum(sum(v.values()) for v in (self.plan.get("set_aside") or {}).values())

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
        out.append(("set-aside", "Set aside", self.set_aside_total(), self.set_aside_section()))
        if self.actions:
            out.append(("actions", "Actions", len(self.actions), self.actions_section()))
        out.append(("sources", "Sources", len(self.sources), self.sources_section()))
        return out

    def stats(self) -> str:
        """The headline: a tile for each kind of thing the plan counts."""
        c, h = self.counts, headline(self.plan)
        tiles = []
        rest = [_plural(h["site_range"], "site-wide range") if h["site_range"] else "",
                _plural(h["single_address"], "single address", "single addresses")
                if h["single_address"] else "",
                _plural(h["cluster_internal"], "container platform internal network")
                if h["cluster_internal"] else ""]
        rest = [r for r in rest if r]
        tiles.append((_plural(h["subnet"], "subnet"),
                      ("plus " + (", ".join(rest[:-1]) + " and " + rest[-1] if len(rest) > 1
                                  else rest[0])) if rest else "address blocks in the plan"))
        used = {s["site"] for s in self.subnets}
        kinds = sorted({str(self.sites[x].get("kind") or "").replace("-", " ")
                        for x in used if x in self.sites} - {""})
        planned = int(c.get("sites_planned", 0))
        tiles.append((_plural(int(c.get("sites_with_subnets", len(used & set(self.sites)))), "site"),
                      (", ".join(kinds) if kinds else "holding subnets")
                      + (f"; plus {planned} planned" if planned else "")))
        if c.get("vlans") or h["segments"]:
            tiles.append((_plural(int(c.get("vlans", 0)), "VLAN"),
                          f"on {h['segments_with_vlan']:,} of the {h['segments']:,} segments "
                          "sources report" if h["segments"] else "stated in the plan file"))
        named, documented = int(c.get("addresses_named_only", 0)), int(c.get("addresses_documented_only", 0))
        more = ""
        if named or documented:
            more = (f"; {named + documented:,} more are only named, by DNS ({named:,}) or a "
                    f"document or record ({documented:,})")
        tiles.append((_plural(int(c.get("addresses_seen_in_use", 0)), "address", "addresses"),
                      "seen in use by an instrument or export" + more))
        if self.actions:
            tiles.append((_plural(len(self.actions), "action"), "for people to close"))
        return ('<div class="stats">' + "".join(
            f'<div class="stat"><b>{esc(b)}</b><span>{esc(s)}</span></div>' for b, s in tiles)
            + "</div>")

    def _example(self) -> tuple[str, str, str]:
        """An address, a subnet and a VLAN from the plan, for the help text."""
        busiest = sorted((s for s in self.subnets if s["addresses"] and s.get("ip_version") == 4),
                         key=lambda s: -s["address_count"]) or [s for s in self.subnets if s["addresses"]]
        ip = cidr = vlan = ""
        if busiest:
            s = busiest[0]
            cidr = s["cidr"]
            ip = next((a["ip"] for a in s["addresses"] if a.get("names")), s["addresses"][0]["ip"])
        for s in self.subnets:
            if s.get("vlans"):
                vlan = s["vlans"][0].split(":", 1)[1]
                break
        return ip, cidr, vlan

    def overview(self) -> str:
        c = self.counts
        parts = []
        for p in self.plan.get("summary") or []:
            if isinstance(p, dict):
                if p.get("heading"):
                    parts.append(f"<h3>{esc(p['heading'])}</h3>")
                parts.append(f"<p>{esc(p.get('text') or '')}</p>")
            else:
                parts.append(f"<p>{esc(p)}</p>")
        if self.plan.get("audience"):
            parts.insert(0, f'<p class="audience">Written for '
                            f'{esc(_sentence_case(str(self.plan["audience"])))}.</p>')
        kinds = c.get("sites_by_kind") or {}
        site_text = _plural(int(c.get("sites", 0)), "site")
        if kinds:
            site_text += " (" + ", ".join(f"{k}: {n}" for k, n in kinds.items()) + ")"
        if c.get("sites_planned"):
            site_text += f", of which {c['sites_planned']} planned"
        dates = sorted(s["as_of"] for s in self.sources.values() if s.get("as_of"))
        facts = [("Sites", site_text)]
        if c.get("vlans") or c.get("segments"):
            vlan_text = _plural(int(c.get("vlans", 0)), "VLAN")
            if c.get("segments"):
                vlan_text += f", {_plural(int(c['segments']), 'segment')} reported by sources"
            if c.get("segments_superseded"):
                vlan_text += (f" ({_plural(int(c['segments_superseded']), 'more segment')}"
                              " only in a replaced source, not counted)")
            facts.append(("VLANs", vlan_text))
        if dates:
            facts.append(("Evidence dated", dates[0] if dates[0] == dates[-1]
                          else f"{dates[0]} to {dates[-1]}"))
        facts.append(("Built", self.built_on))
        dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in facts)
        look = [f'<li><a href="#check-{esc(k)}">{esc(CHECKS[k][0])}</a>: {len(v):,}</li>'
                for k, v in self.checks.items() if v and k in CHECKS]
        lookup = (
            '<section class="card js-only" hidden><h3>Find an address</h3>'
            '<label class="field" for="lookup">Which subnet holds this address?</label>'
            '<input type="search" id="lookup" autocomplete="off" spellcheck="false" '
            'placeholder="an IPv4, IPv6 or MAC address">'
            '<p id="lookup-result" class="lookup-result" aria-live="polite"></p></section>')
        people = ""
        if self.actions:
            items = "".join(
                f"<li>{self.action_link(a.get('id'))} "
                + (f"<b>{esc(ACTION_KINDS.get(str(a.get('kind')), (str(a.get('kind')),))[0])}:</b> "
                   if a.get("kind") else "")
                + f"{esc(a.get('title') or '')}</li>" for a in self.actions[:6])
            more = (f" The first six are listed here; the Actions view has all {len(self.actions):,}."
                    if len(self.actions) > 6 else "")
            people = ("<h3>What needs a person</h3><p>The data cannot settle these on its own."
                      f"{esc(more)}</p><ul>{items}</ul>")
        ip, cidr, vlan = self._example()
        eg = ", ".join(f"<code>{esc(x)}</code>" for x in (ip, cidr, f"vlan:{vlan}" if vlan else "") if x)
        help_text = (
            '<div class="js-only" hidden><h3>How to use this page</h3>'
            "<p><b>The subnet search takes anything:</b> an address, to find the subnet that holds "
            "it; a subnet, to find every block overlapping it; a machine name, a MAC address, or "
            "words from a purpose" + (f" (for example {eg})" if eg else "") + ". Narrow it with "
            "<code>site:</code>, <code>env:</code>, <code>conf:</code>, <code>vlan:</code>, "
            "<code>source:</code> or <code>action:</code>, or with the buttons under it.</p>"
            "<p><b>Every subnet opens</b> under Addresses: how its addresses are given out, where "
            "its facts come from, its segments, a map of the addresses in use, and each address "
            "with the sources that reported it.</p>"
            "<p><b>Share a view.</b> The page's address holds the section, the search and the "
            "filters, so a copied link opens the same view.</p></div>")
        return ("".join(parts) + f'<dl class="facts">{dl}</dl>' + lookup + people
                + "<h3>To look at</h3>"
                + (f"<ul>{''.join(look)}</ul>" if look else '<p class="muted">Nothing found.</p>')
                + help_text)

    def sites_section(self) -> str:
        out = []
        for site in self.sites.values():
            subs = [s for s in self.subnets if s["site"] == site["id"]]
            newest = max((s.get("newest_evidence") or "" for s in subs), default="")
            facts = [("Kind", site.get("kind")), ("Location", site.get("location")),
                     ("Operated by", site.get("operator")),
                     ("Ranges", ", ".join(site.get("ranges") or []) or "none stated"),
                     ("Subnets", str(len(subs))),
                     ("Addresses found", str(sum(s["address_count"] for s in subs))),
                     ("Newest evidence", newest)]
            dl = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in facts if v)
            status = ("" if site.get("status", "in use") == "in use"
                      else f' <span class="status status-not-measured">{esc(site["status"])}</span>')
            desc = f"<p>{esc(site['description'])}</p>" if site.get("description") else ""
            href = "#filter=site%3A" + quote(str(site["id"]), safe="")
            show = (f'<p class="js-only" hidden><a href="{esc(href)}">Show its subnets</a></p>'
                    if subs else "")
            out.append(f'<article class="card" id="site-{esc(site["id"])}"><h3>{esc(site["name"])}'
                       f'{status}</h3><dl class="facts">{dl}</dl>{desc}{show}</article>')
        orphans = [s for s in self.subnets if s["site"] not in self.sites]
        if orphans:
            out.append("<h3>Ranges no site holds</h3><p>"
                       + ", ".join(self.subnet_link(s["cidr"]) for s in orphans) + "</p>")
        return "".join(out)

    def _search_text(self, s: dict) -> str:
        site = self.sites.get(s["site"], {})
        bits: list[Any] = [s["cidr"], s["site"], site.get("name"), site.get("location"),
                           s.get("environment"), s.get("purpose"), s.get("notes"),
                           s.get("confidence"), s.get("addressing"), s.get("declared_as"),
                           *(s.get("action_ids") or []),
                           *(f"vlan {v.split(':', 1)[1]}" for v in s.get("vlans") or []),
                           *(p.get("name") for p in s.get("segments") or [])]
        for a in s["addresses"]:
            bits += [a["ip"], *(a.get("names") or [])]
            for sg in a.get("sightings") or []:
                for k, v in sg.items():
                    if k in _SIGHTING_PLUMBING or not isinstance(v, str):
                        continue
                    bits.append(v)
                    if k == "mac" and mac_key(v):
                        bits.append(mac_key(v))
        text = " ".join(str(b) for b in bits if b not in (None, ""))
        return " ".join(sorted(set(text.lower().replace("_", " ").split())))

    def subnets_section(self) -> str:
        rows = []
        for i, s in enumerate(self.subnets):
            vlans = sorted({v.split(":", 1)[1] for v in s.get("vlans") or []},
                           key=lambda v: (len(v), v))
            kids = self.in_children(s["cidr"]) if self.children.get(s["cidr"]) else 0
            if kids:
                found = (f'{kids:,} <span class="muted">in its subnets</span>'
                         + (f'<br><small>{s["address_count"]:,} outside them</small>'
                            if s["address_count"] else ""))
            elif s["usable"] > 1:
                share = min(1.0, s["address_count"] / s["usable"])
                found = (f'{s["address_count"]:,} <span class="muted">of {s["usable"]:,}</span>'
                         f'<div class="bar" aria-hidden="true"><i style="width:{share:.1%}"></i></div>')
            else:
                found = f"{s['address_count']:,}"
            sources = " ".join(f"{e} {self.label(e)}" for e in s.get("evidence") or []).lower()
            rows.append(
                f'<tr data-i="{i}" data-search="{esc(self._search_text(s))}" '
                f'data-sources="{esc(sources)}"><td>{self.subnet_link(s["cidr"])}</td>'
                + _td(self.site_name(s["site"])) + _td(s.get("purpose")) + _td(s.get("environment"))
                + _td(", ".join(vlans)) + f'<td class="num">{found}</td>'
                + f"<td>{_confidence_tag(s.get('confidence'))}</td>" + _td(s.get("newest_evidence"))
                + "<td>" + " ".join(self.action_link(a) for a in s.get("action_ids") or [])
                + "</td></tr>")
        used = [x for x in self.sites if any(s["site"] == x for s in self.subnets)]
        envs = sorted({str(s.get("environment") or "unstated") for s in self.subnets})
        confs = sorted({str(s.get("confidence") or "unstated") for s in self.subnets})

        def chips(kind: str, items: list[tuple[str, str]]) -> str:
            return "".join(f'<button type="button" class="chip" data-f="{esc(kind)}" '
                           f'data-v="{esc(v)}" aria-pressed="false">{esc(text)}</button>'
                           for v, text in items)

        groups = [("Site", "site", [(x, self.site_name(x)) for x in used])]
        if len(envs) > 1:
            groups.append(("Environment", "env", [(e, e) for e in envs]))
        if len(confs) > 1:
            groups.append(("Confidence", "conf", [(c, c) for c in confs]))
        groups.append(("Show only", "flag", [("actions", "has an action"),
                                            ("empty", "no address found"), ("vlan", "has a VLAN")]))
        filters = "".join(f'<div class="filters" role="group" aria-label="{esc(lbl)}">'
                          f'<span class="lbl">{esc(lbl)}</span>{chips(kind, items)}</div>'
                          for lbl, kind, items in groups)
        tools = (
            '<div class="js-only ipam" hidden><div class="toolbar"><div>'
            '<label class="field" for="subnet-filter">Search subnets and addresses</label>'
            '<input type="search" id="subnet-filter" autocomplete="off" spellcheck="false" '
            'placeholder="address, subnet, machine name, MAC, words, or site:, env:, vlan:">'
            '</div><button type="button" class="btn" id="subnet-clear">Clear</button>'
            '<button type="button" class="btn" id="subnet-csv">Download CSV of what is shown</button>'
            '<button type="button" class="btn" id="subnet-link">Copy link to this view</button></div>'
            f'<div id="subnet-chips">{filters}</div>'
            '<div id="subnet-answer" class="lookup-box" role="status" hidden></div>'
            '<p id="subnet-count" class="muted" aria-live="polite"></p></div>')
        lead = ("<p>Every address block in the plan: subnets, the ranges sites hold, and single "
                "addresses. A subnet's own page, under Addresses, says how its addresses are given "
                "out, where its facts come from, and every address in it.</p>")
        return lead + tools + _table(["Subnet", "Site", "Purpose", "Environment", "VLAN",
                                      "Addresses found of usable", "Confidence", "Newest evidence",
                                      "Actions"], rows, table_id="subnet-table", num=frozenset({5}))

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
        macs = sorted({str(sg["mac"]) for sg in a.get("sightings") or [] if sg.get("mac")})
        if macs:
            flags.append("MAC: " + ", ".join(macs))
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

    def _subnet_detail(self, s: dict) -> str:
        site = self.sites.get(s["site"], {})
        kv: list[tuple[str, str]] = [
            ("Subnet", f"<code>{esc(s['cidr'])}</code> · IPv{esc(s.get('ip_version') or '')}"
                       f" · {esc(s.get('scope') or '')}"),
            ("Site", esc(self.site_name(s["site"]))
             + (f" ({esc(site['location'])})" if site.get("location") else "")),
        ]
        if s.get("purpose"):
            kv.append(("Purpose", esc(s["purpose"])))
        if s.get("notes"):
            kv.append(("Notes", esc(s["notes"])))
        if s.get("confidence"):
            meaning = CONFIDENCE.get(str(s["confidence"]))
            kv.append(("Confidence", _confidence_tag(s["confidence"])
                       + (f" {esc(meaning)}" if meaning else "")))
        if s.get("parent"):
            kv.append(("Inside", self.subnet_link(s["parent"])))
        if self.children.get(s["cidr"]):
            kv.append(("Contains", " ".join(self.subnet_link(c) for c in self.children[s["cidr"]])))
        titles = {str(a.get("id")): str(a.get("title") or "") for a in self.actions}
        if s.get("action_ids"):
            kv.append(("Actions", "<br>".join(f"{self.action_link(x)} {esc(titles.get(x, ''))}"
                                              for x in s["action_ids"])))
        kv.append(("How addresses are given out", esc(self.addressing_text(s))))
        if s.get("internet_registry"):
            r = s["internet_registry"]
            kv.append(("Internet routing", esc(_registry_line(r))
                       + (f"<br><small>Looked up {esc(r['looked_up'])}</small>"
                          if r.get("looked_up") else "")))
        dl = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in kv)
        ev = "".join(
            f"<li>{esc(self.label(e))}: {esc(self.sources.get(e, {}).get('as_of_basis') or 'dated')} "
            f"{esc(self.sources.get(e, {}).get('as_of') or '')}"
            + (f" <span class=\"muted\">({esc(age)})</span>"
               if (age := age_text(self.sources.get(e, {}).get("as_of"), self.built_on)) else "")
            + "</li>" for e in s.get("evidence") or [])
        out = (f'<div class="grid2"><dl class="facts">{dl}</dl><div><h4>Where this comes from</h4>'
               f"<ul>{ev}</ul></div></div>")
        if s.get("segments"):
            segs = ["<tr>" + _td(self.site_name(p.get("site") or "")) + _td(p.get("vlan"), num=True)
                    + _td(p.get("name"), code=True) + _td(p.get("switch"))
                    + _td(" · ".join(p.get("meaning") or [])) + "</tr>" for p in s["segments"]]
            out += "<h4>Segments</h4>" + _table(["Site", "VLAN", "Segment", "Switch",
                                                 "What the name says"], segs, num=frozenset({1}))
        n = _net(s["cidr"])
        if n.version == 4 and MAP_PREFIX[0] <= n.prefixlen <= MAP_PREFIX[1] and s["addresses"]:
            seen = sum(1 for a in s["addresses"] if _seen(a))
            named = s["address_count"] - seen
            label = f"{seen:,} of {s['usable']:,} addresses seen in use; {named:,} more only named"
            out += (f'<div class="js-only" hidden><h4>Which addresses are in use</h4>'
                    f'<div class="usemap" role="img" aria-label="{esc(label)}"></div>'
                    f'<p class="legend"><span><i class="u"></i>seen in use ({seen:,})</span>'
                    f'<span><i class="n"></i>only named, by DNS or a document ({named:,})</span>'
                    "<span><i></i>not reported by any source (it may still be in use)</span></p></div>")
        if s["addresses"]:
            rows = []
            for a in s["addresses"]:
                when = a.get("last_observed") or (
                    f"documented {a['last_documented']}" if a.get("last_documented") else "")
                rows.append(f'<tr data-ip="{esc(a["ip"])}" data-seen="{1 if _seen(a) else 0}">'
                            + _td(a["ip"], code=True) + _td(", ".join(a["names"]))
                            + f"<td>{self.labels(a['sources'])}</td>"
                            + _td(", ".join(EVIDENCE_WORDS.get(e, e) for e in a["evidence"]))
                            + _td(when) + f"<td>{self._flags(a)}</td></tr>")
            out += (f"<h4>Every address in this subnet ({s['address_count']:,})</h4>"
                    + _table(["Address", "Names", "Reported by", "Evidence", "Last seen in use",
                              "Notes"], rows))
        else:
            out += ('<p class="muted">No source reported an address here. That is not the same as '
                    "the subnet being empty: see How this was built, under Sources.</p>")
        return out

    def addresses_section(self) -> str:
        by_site: dict[str, list[dict]] = defaultdict(list)
        for s in self.subnets:
            by_site[s["site"]].append(s)
        out = ["<p>Each subnet opens to how its addresses are given out, where its facts come "
               "from, and every address in it, listed under the most specific subnet holding it "
               "with every source that reported it.</p>"]
        for sid, subs in by_site.items():
            out.append(f"<h3>{esc(self.site_name(sid))}</h3>")
            for s in subs:
                purpose = f" {s['purpose']}" if s.get("purpose") else ""
                summary = (f"<code>{esc(s['cidr'])}</code>{esc(purpose)} "
                           f"({esc(_plural(s['address_count'], 'address', 'addresses'))})")
                n = _net(s["cidr"])
                mapped = (f' data-map="{esc(s["cidr"])}"' if n.version == 4 and s["addresses"]
                          and MAP_PREFIX[0] <= n.prefixlen <= MAP_PREFIX[1] else "")
                out.append(f'<details id="{anchor(s["cidr"])}"{mapped}><summary>{summary}</summary>'
                           + self._subnet_detail(s) + "</details>")
        return "".join(out)

    def vlan_rows(self) -> list[tuple]:
        conflicts = {(c["site"], c["vlan"]) for c in self.checks.get("vlan_conflicts") or []}
        rows: list[tuple] = []
        for seg in self.plan.get("segments") or []:
            name = seg["name"]
            if seg.get("meaning"):
                name += " (" + ", ".join(seg["meaning"]) + ")"
            if seg.get("location"):
                where = seg["location"]
                if seg.get("location_meaning"):
                    where += f" ({seg['location_meaning']})"
                name += f"; defined in {where}"
            if seg.get("superseded_by"):
                name += f"; no longer listed by {seg['superseded_by']}"
            notes = []
            if seg.get("mode"):
                notes.append(seg["mode"] + (f" {seg['trunk_vlans']}" if seg.get("trunk_vlans")
                                            else ""))
            if seg.get("vlan_source"):
                src = self.sources.get(seg["vlan_source"], {})
                notes.append(f"VLAN as stated by {self.label(seg['vlan_source'])}"
                             + (f", {src['as_of']}" if src.get("as_of") else ""))
            clash = (seg["site"], seg.get("vlan")) in conflicts and not seg.get("superseded_by")
            rows.append((seg["site"], seg.get("vlan"), seg.get("subnet") or "", name,
                         seg.get("switch") or "", self.label(seg["source"]), "; ".join(notes), clash))
        for s in self.subnets:
            if s.get("vlan") is not None:
                rows.append((s["site"], s["vlan"], s["cidr"], s.get("purpose") or "", "",
                             "plan file", "", (s["site"], s["vlan"]) in conflicts))
        return sorted(rows, key=lambda r: (self.site_name(r[0]), r[1] if r[1] is not None else -1,
                                           r[2]))

    def vlans_section(self, rows: list[tuple]) -> str:
        body = []
        for site, vlan, cidr, name, switch, src, note, clash in rows:
            flag = (" " + _tag("carries several subnets", "status-not-measured",
                               "Within one site a VLAN should carry one subnet") if clash else "")
            body.append(('<tr class="conflict">' if clash else "<tr>") + _td(self.site_name(site))
                        + _td(vlan, num=True)
                        + (f"<td>{self.subnet_link(cidr)}</td>" if cidr else "<td></td>")
                        + _td(name) + _td(switch) + _td(src)
                        + f"<td>{esc(note)}{flag}</td></tr>")
        filt = ('<div class="js-only" hidden><label class="field" for="vlan-filter">Filter the '
                'VLANs and segments</label><input type="search" id="vlan-filter" '
                'autocomplete="off" placeholder="VLAN, segment, switch or subnet"></div>')
        lead = ("<p>Every segment a source reports, with its VLAN, and every VLAN the plan file "
                "states. The same VLAN at two sites is normal, since each site has its own layer 2; "
                "within one site, one VLAN should carry one subnet.</p>")
        out = lead + filt + _table(["Site", "VLAN", "Subnet", "Name or purpose", "Switch",
                                    "Stated by", "Mode and notes"], body, table_id="vlan-table",
                                   num=frozenset({1}))
        codes = self.plan.get("segment_codes") or {}
        if codes:
            crow = ["<tr>" + _td(k, code=True) + _td(v.get("meaning") if isinstance(v, dict) else v)
                    + _td(v.get("environment") if isinstance(v, dict) else "") + "</tr>"
                    for k, v in codes.items()]
            out += ("<h3>What the parts of a segment name mean</h3>"
                    + _table(["Code", "Meaning", "Environment"], crow))
        return out

    def mirrors_section(self) -> str:
        cidrs = {s["cidr"]: s for s in self.subnets}

        def cell(cidr: str | None) -> str:
            if not cidr:
                return '<td><span class="status status-not-measured">none</span></td>'
            s = cidrs[cidr]
            vl = sorted({v.split(":", 1)[1] for v in s.get("vlans") or []}, key=lambda v: (len(v), v))
            return (f"<td>{self.subnet_link(cidr)}<br>{esc(s.get('purpose') or '')}"
                    f'<br><small>{esc(", ".join("VLAN " + v for v in vl) + " · " if vl else "")}'
                    f'{esc(_plural(s["address_count"], "address", "addresses"))}</small></td>')

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

    def by_as(self, public: list[dict]) -> str:
        """Every public address's routing, grouped by the autonomous system announcing it."""
        groups: dict[str, dict[str, Any]] = {}
        for s in public:
            recs = [a["internet_registry"] for a in s["addresses"] if a.get("internet_registry")]
            if not recs and s.get("internet_registry") and _net(s["cidr"]).num_addresses == 1:
                recs = [s["internet_registry"]]
            for r in recs:
                key = str(r.get("asn") or "NA")
                g = groups.setdefault(key, {"r": r, "prefixes": set(), "holders": set(),
                                            "sites": set(), "n": 0})
                g["n"] += 1
                if r.get("announced_prefix"):
                    g["prefixes"].add(str(r["announced_prefix"]))
                if r.get("registrant") or r.get("network_name"):
                    g["holders"].add(str(r.get("registrant") or r.get("network_name")))
                g["sites"].add(self.site_name(s["site"]))
        if not groups:
            return ""
        rows = ["<tr>" + _td("" if k == "NA" else f"AS{k}") + _td(
                    g["r"].get("as_name") or ("announced by no autonomous system" if k == "NA" else ""))
                + _td(", ".join(sorted(g["prefixes"], key=_prefix_order)), code=True)
                + _td("; ".join(sorted(g["holders"])))
                + _td("; ".join(sorted(g["sites"]))) + _td(f"{g['n']:,}", num=True) + "</tr>"
                for k, g in sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0]))]
        return ("<h3>Who routes and holds these addresses</h3><p>For every public address with a "
                "saved internet-registry lookup: the autonomous system announcing it, the prefix "
                "announced, and who the registry says holds the range. For address space a "
                "provider assigns, the registry may name the provider rather than the "
                "organisation using it.</p>"
                + _table(["Announced by", "AS name", "Announced prefix", "Registered to",
                          "Where it is used", "Addresses"], rows, num=frozenset({5})))

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
        return (note + self.by_as(public) + "<h3>Public ranges</h3>"
                + _table(["Range", "Site", "Purpose", "Addresses", "Announced by", "AS name",
                          "Registered to", "Looked up"], rows, num=frozenset({3}))
                + self.chains_section())

    def chains_section(self) -> str:
        out = []
        for c in self.plan.get("exposure_chains") or []:
            hops = "".join(
                "<li>" + esc(h.get("label") or "")
                + (f": any address in the network <code>{esc(h['network'])}</code>"
                   if h.get("network") else f": <code>{esc(h.get('address') or '')}</code>")
                + (f" ({esc(h['name'])})" if h.get("name") else "") + "</li>"
                for h in c.get("hops") or [])
            when = f", {c['as_of']}" if c.get("as_of") else ""
            out.append(f"<h3>{esc(c['name'])}</h3><p>The path a request takes from the internet, "
                       f"as {esc(self.label(c['source']))} describes it{esc(when)}.</p>"
                       f'<ol class="chain">{hops}</ol>')
        return "".join(out)

    def checks_section(self) -> str:
        stale = self.stale_sources()
        cards = [f'<article class="card"><h4><a href="#check-{esc(key)}">'
                 f"{esc(_plural(len(self.checks.get(key) or []), 'item'))}: {esc(title)}</a></h4>"
                 f"<p>{esc(why)}</p></article>" for key, (title, why) in CHECKS.items()]
        cards.append('<article class="card"><h4><a href="#check-stale-sources">'
                     f"{esc(_plural(len(stale), 'source'))} a whole calendar month or more old "
                     "at the build</a></h4>"
                     "<p>A source read from a system describes it on the day it was read. The "
                     "older it is, the more may have changed since.</p></article>")
        cards.append('<article class="card"><h4><a href="#set-aside">'
                     f"{esc(_plural(self.set_aside_total(), 'reading'))} set aside</a></h4>"
                     "<p>Readings that do not belong in the plan, such as a roaming device's "
                     "addresses on other networks, counted by source and reason.</p></article>")
        out = ["<p>What to look at before relying on a row. Each list is found by comparing the "
               "sources with each other and with the plan file, not asserted by hand.</p>"
               f'<div class="cards">{"".join(cards)}</div>']
        segs: dict[tuple[str, Any], list[str]] = defaultdict(list)
        for e in self.plan.get("segments") or []:
            if not e.get("superseded_by"):
                segs[(e["site"], e.get("vlan"))].append(str(e["name"]))
        for key, (title, why) in CHECKS.items():
            items = self.checks.get(key) or []
            out.append(f'<h3 id="check-{esc(key)}">{esc(title)} '
                       f'<span class="muted">({len(items):,})</span></h3><p>{esc(why)}</p>')
            if key == "vlan_conflicts":
                rows = ["<tr>" + _td(self.site_name(i["site"])) + _td(i["vlan"], num=True)
                        + "<td>" + ", ".join(self.subnet_link(c) for c in i["subnets"]) + "</td>"
                        + _td(", ".join(sorted(segs.get((i["site"], i["vlan"]), [])))) + "</tr>"
                        for i in items]
                out.append(_table(["Site", "VLAN", "Subnets", "Segments"], rows, num=frozenset({1})))
            elif key == "unknown_addressing":
                rows = [f"<tr><td>{self.subnet_link(i['subnet'])}</td>" + _td(i["addressing"], code=True)
                        + _td("treated as static") + "</tr>" for i in items]
                out.append(_table(["Subnet", "Addressing", "Read as"], rows))
            elif key in ("no_addresses_found", "documented_only"):
                rows = [f"<tr><td>{self.subnet_link(c)}</td>"
                        + _td(self.site_name(self.by_cidr.get(c, {}).get("site", "")))
                        + _td(self.by_cidr.get(c, {}).get("purpose"))
                        + f"<td>{_confidence_tag(self.by_cidr.get(c, {}).get('confidence'))}</td></tr>"
                        for c in items]
                out.append(_table(["Subnet", "Site", "Purpose", "Confidence"], rows))
            else:
                rows = [f"<tr><td>{self.subnet_link(i['subnet'])}</td>" + _td(i["ip"], code=True)
                        + _td(", ".join(i["names"])) + f"<td>{self.labels(i['sources'])}</td>"
                        + _td(self._check_detail(key, i)) + "</tr>" for i in items]
                out.append(_table(["Subnet", "Address", "Names", "Reported by", "Detail"], rows))
        out.append(f'<h3 id="check-stale-sources">Sources a whole calendar month or more old at the build '
                   f'<span class="muted">({len(stale):,})</span></h3>'
                   "<p>Documents are left out: their date is when they were written.</p>"
                   + _table(["Source", "Date", "Age at build"],
                            ["<tr>" + _td(s["label"]) + _td(s.get("as_of"))
                             + _td(age_text(s.get("as_of"), self.built_on)) + "</tr>" for s in stale]))
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

    def _action_card(self, a: dict) -> str:
        subs = " ".join(self.subnet_link(str(c)) for c in a.get("subnets") or [])
        kind = str(a.get("kind") or "")
        head = " · ".join(x for x in (str(a.get("id") or ""),
                                      ACTION_KINDS.get(kind, (kind,))[0] if kind else "") if x)
        return (f'<article class="card action k-{esc(kind or "none")}" id="action-{esc(a.get("id"))}">'
                f'<p class="muted"><small>{esc(head)}</small></p>'
                f"<h4>{esc(a.get('title') or '')}</h4>"
                + (f"<p>{esc(a['detail'])}</p>" if a.get("detail") else "")
                + (f"<p><b>Who:</b> {esc(a['who'])}</p>" if a.get("who") else "")
                + (f"<p><small>Subnets: {subs}</small></p>" if subs else "") + "</article>")

    def actions_section(self) -> str:
        kinds = [str(a.get("kind") or "") for a in self.actions]
        if not any(kinds):
            return "".join(self._action_card(a) for a in self.actions)
        order = [k for k in ACTION_KINDS if k in kinds] + sorted(
            {k for k in kinds if k and k not in ACTION_KINDS}) + ([""] if "" in kinds else [])
        known = [k for k in order if k in ACTION_KINDS]
        lead = ("<p>What the data cannot settle on its own. "
                + " ".join(f"<b>{esc(ACTION_KINDS[k][0])}</b> {esc(ACTION_KINDS[k][1])}." for k in known)
                + (" The <b>Who</b> on each names the role that holds the answer." if any(
                    a.get("who") for a in self.actions) else "") + "</p>")
        out = [lead]
        for k in order:
            group = [a for a in self.actions if str(a.get("kind") or "") == k]
            title = ACTION_KINDS[k][0] if k in ACTION_KINDS else (k or "Other")
            out.append(f"<h3>{esc(title)} <span class=\"muted\">({len(group):,})</span></h3>"
                       + '<div class="cards">' + "".join(self._action_card(a) for a in group)
                       + "</div>")
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
                        + _td(when) + _td(age_text(s.get("as_of"), self.built_on))
                        + _td("; ".join(extra + list(s.get("notes") or []))) + "</tr>")
        conf = " ".join(f"{_confidence_tag(k)} {esc(v[:1].upper() + v[1:])}."
                        for k, v in CONFIDENCE.items())
        method = (
            "<h3>How this was built</h3>"
            "<p><b>Where the data comes from.</b> Every subnet and address is read from a source "
            "listed above, or from the plan file, which holds what no export states: the sites, "
            "what each subnet is for, and which sources to read. The plan file never lists an "
            "address on its own authority.</p>"
            "<p><b>How an address finds its subnet.</b> Each address is placed in the most "
            "specific subnet holding it. An address outside every subnet is set aside, never "
            "made into a subnet of its own; so is one that describes no network (loopback, "
            "link-local) or exists only inside a machine. A source that roams, such as a "
            "laptop's check-in log, reports every network the device visited, so it can only "
            "place an address inside a subnet the plan already holds. Set aside counts every "
            "reading left out, by source and reason.</p>"
            f"<p><b>What the confidence words mean.</b> {conf}</p>"
            "<p><b>What the dates mean.</b> <i>Last seen in use</i> on an address is the newest "
            "date any source saw it: the machine's own last-seen time where the source records "
            "one, otherwise the source's date. <i>Newest evidence</i> on a subnet is the newest "
            "of those and of the sources declaring the subnet.</p>"
            "<p><b>What this cannot see.</b> The plan holds no DHCP server's configuration, so "
            "the addresses shown are the ones seen in use, not the ranges handed out or "
            "reserved, and a subnet with no address found may still be busy. Machines no "
            "source reaches are not here.</p>"
            "<p><b>The files beside this page.</b> The CSV holds one row per subnet, for a "
            "spreadsheet. The JSON holds everything on this page: sites, subnets with their "
            "addresses, segments, checks and actions, ready for another system to import.</p>")
        return _table(["Source", "Kind", "What it shows", "Date", "Age at build", "Notes"],
                      rows) + method


def _lookup_data(plan: dict, view: _View) -> str:
    subnets: list[dict] = []
    addresses: dict[str, dict[str, Any]] = {}
    macs: dict[str, list[list[Any]]] = defaultdict(list)
    for s in plan.get("subnets") or []:
        net = ipaddress.ip_network(s["cidr"], strict=False)
        subnets.append({"cidr": s["cidr"], "v": net.version, "base": str(int(net.network_address)),
                        "len": net.prefixlen, "anchor": anchor(s["cidr"]),
                        "site": view.site_name(s["site"]) if s["site"] in view.sites else s["site"],
                        "site_id": s["site"], "purpose": s.get("purpose") or "",
                        "env": s.get("environment") or "", "conf": s.get("confidence") or "",
                        "vlans": sorted({v.split(":", 1)[1] for v in s.get("vlans") or []},
                                        key=lambda v: (len(v), v)),
                        "count": s["address_count"], "usable": s["usable"],
                        "newest": s.get("newest_evidence") or "",
                        "actions": list(s.get("action_ids") or [])})
        for a in s["addresses"]:
            ip = ipaddress.ip_address(a["ip"])
            keys = sorted({mac_key(sg.get("mac")) for sg in a.get("sightings") or []} - {""})
            addresses[f"{ip.version}:{int(ip)}"] = {
                "where": a["ip"], "names": a["names"], "s": len(subnets) - 1,
                "sources": [view.label(x) for x in a["sources"]],
                "last": a.get("last_observed") or "", "documented": a.get("last_documented") or "",
                "find": " ".join([a["ip"], *keys, *a["names"]]).lower().replace("_", " ")}
            for key in keys:
                macs[key].append([a["ip"], len(subnets) - 1])
    special = [[v, str(base), length, kind] for v, base, length, kind in SPECIAL_RANGES]
    return json.dumps({"subnets": subnets, "addresses": addresses, "macs": macs,
                       "special": special, "kinds": ADDRESS_KINDS},
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
    body = (f"<style>{_EXTRA_CSS}</style>" + view.stats()
            + '<nav class="ipam-tabs" id="ipam-tabs" role="tablist" aria-label="Sections" hidden></nav>'
            + "\n".join(panels)
            + f'<script type="application/json" id="ipam-lookup">{_lookup_data(plan, view)}'
            + f"</script><script>{_SCRIPT}</script>")
    org = str(plan.get("organisation") or "")
    title = str(plan.get("title") or "IP address plan")
    if org and org not in title:
        title = f"{title}: {org}"
    sha = str(plan.get("plan_sha256") or "")
    h = headline(plan)
    footer = (f"<p>Built {esc(plan.get('built_on') or '')} from the plan file"
              + (f" (SHA-256 <code>{esc(sha[:16])}</code>…)" if sha else "")
              + " and the sources listed under Sources. "
              + esc(f"{_plural(len(view.subnets), 'address block')} ({_plural(h['subnet'], 'subnet')}), "
                    f"{_plural(int(view.counts.get('addresses', 0)), 'address', 'addresses')}"
                    + (f", {_plural(h['segments'], 'segment')}" if h["segments"] else "") + ".")
              + "</p>")
    return htmlpage.page(title, body, theme=theme, lead=str(plan.get("subtitle") or ""),
                         description=title, footer=footer,
                         eyebrow=str(plan.get("part") or "") if part is None else part,
                         byline=str(plan.get("author") or "") if author is None else author)
