"""Turning one run's rows into a consistent observation, and summarising it.

Each collector reports on its own terms. :func:`finalise` makes the run's
rows into one set, in this order:

1. **merge**: rows that describe the same thing (the same bill-of-materials
   reference, see :meth:`~takestock.model.CryptoAsset.bom_ref`) become one;
2. **lifecycle**: migration strategy, support status and the plan marks
   (``replaced_by``, ``retiring_by``) from the target profile's
   ``lifecycle:`` block, then Windows support derived from the bundled
   lifecycle data (see :mod:`takestock.lifecycle`);
3. **readings across rows**: a key served by more than one host, a port-80
   redirect with nothing to stop it being stripped, the HTTP protocol readings
   carried onto the TLS row for the same endpoint, and certificate expiry read
   from a live handshake in preference to a transparency log;
4. **software names** filled from the daemon dictionary;
5. **grading** against the baseline (:mod:`takestock.policy`) and a
   **disposition** from the rules and decisions in effect
   (:mod:`takestock.disposition`);
6. **usage bands** (:mod:`takestock.usage`) and **evidence depth**
   (:mod:`takestock.depth`).

:func:`summarise` then counts what the observation holds and lists its
coverage gaps, with their classifications in parallel lists so they survive a
round trip through JSON.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import fields

from . import agility, binding, config, coverage, depth
from .disposition import (
    ACCEPTANCE_TRACKS,
    DispositionRules,
    accepted_breakout,
    apply_disposition,
    load_dispositions,
)
from .lifecycle import (
    PLAN_MARKS,
    apply_migration_strategy,
    apply_plan_marks,
    apply_support_status,
    derive_windows_support,
    lifecycle_summary,
    unmatched_patterns,
)
from .model import (
    GRADED_VERDICTS,
    NA_VERDICT,
    PQ_BASES,
    PQ_READINGS,
    PQ_VALUES,
    CryptoAsset,
    ungraded_tokens,
    worst,
)
from .plaintext import PLAINTEXT_FLAG, UNVERIFIED_FLAG
from .policy import Policy
from .usage import apply_bands, band_summary

# ── 1. merging rows that describe the same thing ──

_LIST_FIELDS = ("protocol_versions", "key_exchange", "signatures", "symmetric", "hashes",
                "flags", "citations")

#: ``extra`` key on a merged row: how many collected rows it stands for.
MERGED_ROWS_KEY = "merged_rows"
#: ``extra`` key on a merged row: every source that reported it, when more than one did.
MERGED_SOURCES_KEY = "merged_sources"


def _union(lists: Iterable[list]) -> list:
    out: list = []
    for values in lists:
        for v in values:
            if v not in out:
                out.append(v)
    return out


def _merge_group(group: list[CryptoAsset]) -> CryptoAsset:
    """One row from rows sharing a reference: the first row, filled in from the rest."""
    first = group[0]
    if len(group) == 1:
        return first
    for f in fields(CryptoAsset):
        name = f.name
        values = [getattr(a, name) for a in group]
        if name in _LIST_FIELDS:
            setattr(first, name, _union(values))
        elif name == "extra":
            merged: dict = {}
            for extra in values:
                for k, v in (extra or {}).items():
                    merged.setdefault(k, v)
            first.extra = merged
        elif name == "notes":
            first.notes = "; ".join(dict.fromkeys(n for n in values if n))
        elif name == "verdict":
            graded = [v for v in values if v in GRADED_VERDICTS]
            if graded:
                first.verdict = worst(graded)
            elif NA_VERDICT in values:
                first.verdict = NA_VERDICT
        elif getattr(first, name) in ("", None):
            setattr(first, name, next((v for v in values if v not in ("", None)),
                                      getattr(first, name)))
    first.extra[MERGED_ROWS_KEY] = len(group)
    sources = list(dict.fromkeys(a.source for a in group if a.source))
    if len(sources) > 1:
        first.extra[MERGED_SOURCES_KEY] = sources
    return first


def merge_duplicates(assets: list[CryptoAsset]) -> tuple[list[CryptoAsset], int]:
    """Merge rows with the same reference, keeping first-seen order.

    Two rows share a reference when their data state, protocol, host, port
    and name all agree, which is when they describe the same thing. Returns
    the merged rows and how many rows were folded into others.
    """
    groups: dict[str, list[CryptoAsset]] = {}
    for a in assets:
        groups.setdefault(a.bom_ref(), []).append(a)
    merged = [_merge_group(g) for g in groups.values()]
    return merged, len(assets) - len(merged)


# ── 3. readings that need more than one row ──

def _host_key(host: str | None) -> str:
    return str(host or "").strip().lower().rstrip(".")


SHARED_KEY_PREFIX = "shared-key:"


def flag_shared_keys(assets: list[CryptoAsset]) -> dict:
    """Flag every row whose public key (``extra.pubkey_sha256``) also serves another host.

    The flag carries the number of hosts (``shared-key:3``); the row's
    ``extra`` names the other hosts and how many distinct certificates carry
    the key.
    """
    by_key: dict[str, list[CryptoAsset]] = {}
    for a in assets:
        k = a.extra.get("pubkey_sha256")
        if k:
            by_key.setdefault(str(k), []).append(a)
    keys = flagged = 0
    for group in by_key.values():
        hosts = sorted({_host_key(a.host) for a in group if a.host})
        if len(hosts) < 2:
            continue
        keys += 1
        certs = {a.extra.get("cert_sha256") for a in group if a.extra.get("cert_sha256")}
        for a in group:
            flagged += 1
            a.flags = sorted(set(a.flags) | {f"{SHARED_KEY_PREFIX}{len(hosts)}"})
            a.extra["shared_key_hosts"] = [h for h in hosts if h != _host_key(a.host)]
            a.extra["shared_key_certs"] = len(certs) or None
    return {"keys": keys, "assets": flagged}


REDIRECT_FLAG_PREFIX = "http-redirect:"
STRIPPABLE_FLAG = "redirect-strippable"


def flag_strippable_redirects(assets: list[CryptoAsset]) -> dict:
    """Flag an HSTS row whose host redirects port 80 to HTTPS with no effective HSTS policy.

    Without HSTS, someone on the network path can answer the first cleartext
    request themselves and never pass the redirect on.
    """
    redirecting = {_host_key(a.host) for a in assets if a.host
                   and any(f.startswith(REDIRECT_FLAG_PREFIX) for f in a.flags)}
    flagged = 0
    for a in assets:
        if a.source != "hsts" or _host_key(a.host) not in redirecting:
            continue
        a.extra["http_redirect_from_port_80"] = True
        if a.extra.get("hsts_effective") is False:
            a.flags = sorted(set(a.flags) | {STRIPPABLE_FLAG})
            flagged += 1
    return {"assets": flagged}


#: ``extra`` keys (and key prefixes, ending ``_``) the HSTS check records about
#: HTTP protocol versions, carried onto the TLS row for the same endpoint.
HTTP_PROTOCOL_KEYS = ("http_negotiated_protocol", "http3_advertised", "alt_svc_", "dns_https_")


def _is_http_protocol_key(key: str) -> bool:
    return any(key == k or (k.endswith("_") and key.startswith(k)) for k in HTTP_PROTOCOL_KEYS)


def carry_http_protocol_readings(assets: list[CryptoAsset]) -> dict:
    """Copy the HTTP protocol readings from each HSTS row onto the TLS row for the same endpoint."""
    readings = {(_host_key(a.host), str(a.port)): a for a in assets
                if a.source == "hsts" and a.host}
    carried = 0
    for a in assets:
        if a.source != "tls_scan" or not a.host:
            continue
        src = readings.get((_host_key(a.host), str(a.port)))
        if src is None:
            continue
        for key, value in src.extra.items():
            if _is_http_protocol_key(key):
                a.extra[key] = value
        carried += 1
    return {"assets": carried}


EXPIRY_READ_BY_HANDSHAKE_FLAG = "expiry-read-by-handshake"
EXPIRY_FLAGS = frozenset({"expired", "renewal-overdue", "expiry-soon"})


def reconcile_certificate_expiry(assets: list[CryptoAsset]) -> dict:
    """Judge a logged certificate's expiry on what the host serves, where a handshake read it.

    A transparency log records every certificate issued, including ones
    since replaced. Where a live handshake read the certificate a host
    actually serves (``extra.cert_not_after``), the log row's expiry flag is
    withdrawn and the row says which reading the expiry rests on.
    """
    live: dict[str, list[CryptoAsset]] = {}
    for a in assets:
        if a.source != "ct_dns" and a.host and a.extra.get("cert_not_after"):
            live.setdefault(_host_key(a.host), []).append(a)

    annotated = withdrawn = 0
    for a in assets:
        if a.source != "ct_dns" or a.data_state != "certificate":
            continue
        served = live.get(_host_key(a.host))
        if not served:
            continue
        annotated += 1
        dropped = sorted(set(a.flags) & EXPIRY_FLAGS)
        if dropped:
            withdrawn += 1
            a.extra["log_expiry_flag_withdrawn"] = dropped[0]
        a.flags = sorted((set(a.flags) - EXPIRY_FLAGS) | {EXPIRY_READ_BY_HANDSHAKE_FLAG})
        seen = sorted(
            ({"source": r.source, "port": str(r.port or ""),
              "cert_not_after": str(r.extra.get("cert_not_after") or ""),
              "cert_days_remaining": r.extra.get("cert_days_remaining")} for r in served),
            key=lambda d: (d["cert_not_after"], d["source"], d["port"]))
        a.extra["expiry_read_by_handshake"] = seen
        readings = "; ".join(f"{d['source']} on port {d['port'] or '?'} read a served "
                             f"certificate expiring {str(d['cert_not_after'])[:10]}" for d in seen)
        logged = str(a.extra.get("not_after") or "")[:10] or "an unrecorded date"
        note = (f"Expiry is judged on the served certificate, not the log: the log records "
                f"one expiring {logged}, and {readings}")
        a.notes = "; ".join(p for p in (note, a.notes) if p)
    return {"annotated": annotated, "expiry_withdrawn": withdrawn}


# ── the whole pass ──

def finalise(assets: list[CryptoAsset], policy: Policy, dictionary: Mapping[str, Mapping],
             dispositions: DispositionRules | None = None,
             lifecycle: Mapping | None = None) -> tuple[list[CryptoAsset], dict]:
    """Merge, annotate, grade and place every row; return the rows and what each pass did.

    ``dictionary`` maps a process binary to its product
    (:func:`takestock.config.load_dictionary`). ``dispositions`` defaults to
    the bundled generic rules. ``lifecycle`` is the target profile's
    ``lifecycle:`` block, with optional ``migration_strategy`` and
    ``support_status`` mappings and optional ``replaced_by`` and
    ``retiring_by`` pattern lists. Every pattern that matched nothing is
    listed under ``lifecycle_unmatched``.
    """
    rules = dispositions if dispositions is not None else load_dispositions()
    assets, merged = merge_duplicates(list(assets))
    block = dict(lifecycle or {})
    apply_migration_strategy(assets, block.get("migration_strategy") or {})
    apply_support_status(assets, block.get("support_status") or {})
    apply_plan_marks(assets, block)
    unmatched = (unmatched_patterns(assets, block.get("migration_strategy") or {},
                                    "migration_strategy")
                 + unmatched_patterns(assets, block.get("support_status") or {},
                                      "support_status"))
    for key in PLAN_MARKS:
        unmatched += unmatched_patterns(assets, list(block.get(key) or []), key)
    windows = derive_windows_support(assets, config.load_windows_lifecycle())
    passes = {
        "merged_duplicates": merged,
        "lifecycle_unmatched": unmatched,
        "windows_support": windows,
        "shared_keys": flag_shared_keys(assets),
        "strippable_redirects": flag_strippable_redirects(assets),
        "http_readings_carried": carry_http_protocol_readings(assets),
        "certificate_expiry": reconcile_certificate_expiry(assets),
    }
    for a in assets:
        if not a.software and a.software_binary in dictionary:
            a.software = str(dictionary[a.software_binary].get("product") or a.software_binary)
        policy.apply(a)
        apply_disposition(a, rules)
    apply_bands(assets)
    depth.stamp(assets)
    return assets, passes


# ── gaps the grading itself raises ──

_NOT_MEASURED_TEXT = {
    "key-exchange-group": ("key exchange group not reported for {name}: the cipher suite "
                           "names an ephemeral key exchange, and the scan did not say which "
                           "group was used"),
}


def not_measured_gaps(assets: Iterable[CryptoAsset]) -> list[coverage.Gap]:
    """One gap per ``not-measured:<attribute>`` flag the grading raised."""
    out = []
    for a in assets:
        for f in a.flags:
            if not f.startswith("not-measured:"):
                continue
            attribute = f[len("not-measured:"):]
            template = _NOT_MEASURED_TEXT.get(
                attribute, f"{attribute.replace('-', ' ')} not reported for {{name}}")
            out.append(coverage.gap(
                coverage.NOT_MEASURED, template.format(name=a.name),
                impact_kind=coverage.NARROWS_CONFIDENCE,
                impact=("The connection was measured and one part of it was not visible. "
                        "Its grade rests on what was seen, so it is a ceiling: measuring "
                        "the missing part can only lower it."),
                harvest="A closer scan of this one service that reports the missing attribute.",
                nature=coverage.LOW_FIDELITY))
    return out


# ── what counts as a finding ──

def findings(assets: Iterable[CryptoAsset], out_of_cycle: Iterable[str] = ()) -> list[dict]:
    """The rows judged adverse: a weak verdict, or a disposition on an out-of-cycle rung.

    An ``unknown`` verdict is not a finding (nothing could be judged), and
    neither is a coverage gap.
    """
    urgent = frozenset(out_of_cycle)
    out = []
    for a in assets:
        why = []
        if a.verdict == "weak":
            why.append("weak-verdict")
        if a.disposition and a.disposition in urgent:
            why.append(f"disposition-{a.disposition}")
        if why:
            out.append({"name": a.name, "host": a.host, "port": a.port,
                        "protocol": a.protocol, "verdict": a.verdict,
                        "disposition": a.disposition, "why": why})
    return out


# ── the summary ──

def ungraded_summary(assets: Iterable[CryptoAsset]) -> dict:
    """Tokens the baseline has no row for, counted per baseline table."""
    by_table: dict[str, Counter] = {}
    count = 0
    for a in assets:
        for table, token in ungraded_tokens(a.flags):
            by_table.setdefault(table, Counter())[token] += 1
            count += 1
    return {"count": count,
            "by_table": {t: dict(c.most_common()) for t, c in sorted(by_table.items())}}


def plaintext_summary(assets: Iterable[CryptoAsset]) -> dict:
    """Listeners carrying cleartext, and ones whose encryption is unverified, per protocol."""
    cleartext: Counter = Counter()
    unverified: Counter = Counter()
    for a in assets:
        for f in a.flags:
            if f.startswith(PLAINTEXT_FLAG):
                cleartext[f[len(PLAINTEXT_FLAG):]] += 1
            elif f.startswith(UNVERIFIED_FLAG):
                unverified[f[len(UNVERIFIED_FLAG):]] += 1
    return {"cleartext": sum(cleartext.values()), "unverified": sum(unverified.values()),
            "by_protocol": {"cleartext": dict(cleartext.most_common()),
                            "unverified": dict(unverified.most_common())}}


def pq_readiness_summary(assets: list[CryptoAsset]) -> dict:
    """Post-quantum readiness of key establishment and of signatures, by value and by basis."""
    out: dict = {"total_assets": len(assets)}
    for axis, value_of, basis_of in (
            ("kex", lambda a: a.pq_kex, lambda a: a.pq_kex_basis),
            ("sig", lambda a: a.pq_sig, lambda a: a.pq_sig_basis)):
        values = Counter(value_of(a) for a in assets)
        out[axis] = {
            "by_value": {v: values.get(v, 0) for v in PQ_VALUES},
            "read": sum(values[v] for v in PQ_READINGS),
            "gap": values.get("gap", 0),
            "not_applicable": values.get(NA_VERDICT, 0),
            "by_basis": {b: sum(1 for a in assets if basis_of(a) == b) for b in PQ_BASES},
        }
    return out


def shared_keys_summary(assets: Iterable[CryptoAsset]) -> dict:
    """How many keys serve more than one host, and how many rows carry one."""
    rows = [a for a in assets if any(f.startswith(SHARED_KEY_PREFIX) for f in a.flags)]
    keys = {str(a.extra.get("pubkey_sha256") or "") for a in rows} - {""}
    return {"keys": len(keys), "assets": len(rows)}


def disposition_summary(assets: list[CryptoAsset], rules: DispositionRules | None = None) -> dict:
    """Rows per disposition track and per basis, with the acceptances broken out."""
    tracks = Counter(a.disposition or "none" for a in assets)
    basis = Counter(a.disposition_basis or "none" for a in assets)
    out: dict = {"by_track": dict(tracks.most_common()), "by_basis": dict(basis.most_common()),
                 "accepted": accepted_breakout(assets),
                 "acceptance_tracks": sorted(ACCEPTANCE_TRACKS)}
    if rules is not None:
        out["ladder"] = list(rules.rungs)
        out["out_of_cycle"] = sorted(rules.out_of_cycle)
    return out


def gap_fields(gaps: list) -> dict:
    """The gaps as text, with each classification in a list of the same length."""
    return {
        "gaps": [str(g) for g in gaps],
        "gap_kinds": coverage.kinds(gaps),
        "gap_required": [coverage.is_required(g) for g in gaps],
        "gap_impacts": coverage.impacts(gaps),
        "gap_impact_kinds": coverage.impact_kinds(gaps),
        "gap_harvests": coverage.harvests(gaps),
        "gap_natures": coverage.natures(gaps),
    }


def summarise(assets: list[CryptoAsset], gaps: list,
              rules: DispositionRules | None = None) -> dict:
    """The observation's summary: counts, readings across the estate, and its gaps."""
    flags = Counter(f for a in assets for f in a.flags)
    return {
        "total_assets": len(assets),
        "by_verdict": dict(Counter(a.verdict for a in assets)),
        "by_data_state": dict(Counter(a.data_state for a in assets)),
        "by_source": dict(Counter(a.source or "unattributed" for a in assets)),
        "top_flags": flags.most_common(15),
        "weak_assets": [a.name for a in assets if a.verdict == "weak"],
        "ungraded": ungraded_summary(assets),
        "plaintext": plaintext_summary(assets),
        "shared_keys": shared_keys_summary(assets),
        "pq_readiness": pq_readiness_summary(assets),
        "usage_bands": band_summary(assets),
        "lifecycle": lifecycle_summary(assets),
        "evidence_depth": depth.summarise(assets),
        "dispositions": disposition_summary(assets, rules),
        "agility": agility.agility(assets),
        "binding": binding.hardware_software_split(assets),
        **gap_fields(gaps),
    }
