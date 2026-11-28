"""Units of work: what a team would have to do, counted once per piece of work.

An inventory says what is wrong. A plan says what somebody would have to do,
and the two use different arithmetic. Sixty findings read as sixty jobs. If one
configuration change clears all of them they are one job; if each needs its own
visit they are sixty. :func:`plan` keeps those
two readings apart and says which one the evidence supports.

## The unit and its key

``disposition.py`` already decides how work is shared. A rule or decision that
declares ``effort_scope: per-rule`` says every asset it matches shares one unit
of its effort, and stamps its own id on each of them as ``effort_group``. So a
unit of work is:

    the asset's ``effort_group``, when the entry that decided it said the work
    is shared; otherwise the asset itself.

That is the only grouping used, on purpose. This module invents no group the
disposition layer did not confer, because a grouping nobody decided would make
the plan look more achievable than the evidence allows.

## "One decision, or N actions?"

Grouping can understate work as easily as counting overstates it: one decision
can still be many touches. Every row therefore carries an answer to *one
decision, or N actions?*, and it reads ``unverified`` unless the observation
proves otherwise. Exactly one thing proves it: a unit of a single asset, where
the decision and the action are one event. Any other unit gets ``unverified``
and an upper bound, the number of distinct hosts it touches (a unit of 60
assets on 50 hosts is at most 50 touches). Nothing else moves that column.

**The guard makes the failure cheap.** The pessimistic answer is the default
and is always visible, so a reader acting on a grouped row knows the touch
count is unproven. The grouping itself is a person's recorded judgement, which
this module has no standing to refuse.

## ``kinds``: the same question from the other side

A track can also be under-grouped. If many assets were decided by one rule that
sizes each asset separately, they read as that many jobs, and nobody has said
whether one policy change would cover them. ``kinds`` rolls the rows up by the
entry that decided them (its verbatim ``reason``, which is present on every
observation, unlike an id that older observations lack). A kind of many
ungrouped units says so: *counted as N jobs; nobody has decided whether one
change covers them*.

``decision_owed`` turns that into the figure a planner wants: how many units
would come off the plan if each such kind turned out to be one change. It
prints both figures and asserts neither, and it says that one central change is
not no work: governance, funding and change control are not modelled here.

## The order is not a recommendation

Rows sort by remediation track and then by assets cleared per unit. The second
key is leverage, which ranks a large cleanup of a low-value service above a
single finding on the most sensitive system. That is an easiest-win order, not
a risk order. The tool cannot order by risk (blast radius, business
criticality and likelihood are not in the data), so :data:`ORDER` names the sort
key and states that the sequence is not a recommendation, and :data:`AXES`
lists greatest-risk-first as an axis that is not modelled.

## The denominator is the observation

Units are counted over the assets that carry a track, and an asset carries one
only if an instrument reached it. ``coverage`` reports what the plan was
computed over and which instruments produced it, and every row names its own
sources: a small number of units is not evidence of a small problem when whole
classes of equipment were never examined.

## Naming assets is a different altitude

:func:`plan` names a fix and a count and never a host, so a report that must not
name a host can draw it. :func:`unit_assets` returns the identities separately,
keyed exactly as the rows are: one grouping rule, two payloads.

This module counts and arranges. Every track, size, verdict and flag it reads
was decided by ``policy.py`` and ``disposition.py`` before it was called.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from functools import cache

from . import lifecycle
from .disposition import DispositionRules, end_condition, load_dispositions
from .model import VERDICT_ORDER, CryptoAsset, is_informational_flag

#: Tracks that are a decision not to act, so their rows are not work to
#: schedule. ``defer-migration`` is absent on purpose: deferred work is still
#: work that lands in a later window. ``retire-planned`` is absent too: the
#: primitive may be defensible today, but replacing it is work somebody has to
#: schedule, and this view is where that work belongs.
NON_WORK_TRACKS = frozenset({"no-action", "accept-replacement-planned", "accept-no-alternative"})

#: A unit's size in words. The letters stay in the data; a table read by
#: someone who has never seen the ladder should not have to decode them.
SIZE_LABEL = {"S": "small", "M": "medium", "L": "large", "XL": "very large"}

#: A track that no table knows sorts after every known one.
_UNKNOWN_TRACK_ORDER = 99


@dataclass(frozen=True)
class TrackTables:
    """How to show and order tracks: a label, a sort position, and which are urgent.

    Built from a :class:`~takestock.disposition.DispositionRules` by
    :meth:`from_rules`, or by hand when a caller carries tracks the ladder no
    longer holds (for example rungs retired from a ladder that stored
    observations still name). A track a table does not know keeps its slug as
    its label, sorts last, and is not out of cycle.
    """

    label: Mapping[str, str] = field(default_factory=dict)
    order: Mapping[str, int] = field(default_factory=dict)
    out_of_cycle: Collection[str] = frozenset()

    @classmethod
    def from_rules(cls, rules: DispositionRules) -> TrackTables:
        """The tables for the ladder and fixed tracks ``rules`` declares."""
        order = rules.track_order
        return cls(label={t: rules.track_label(t) for t in order}, order=order,
                   out_of_cycle=rules.out_of_cycle)

    def label_of(self, track: str) -> str:
        return self.label.get(track, track)

    def position(self, track: str) -> int:
        return self.order.get(track, _UNKNOWN_TRACK_ORDER)


@cache
def _bundled_tracks() -> TrackTables:
    return TrackTables.from_rules(load_dispositions())


# ── the prioritisation axes, and how far each is modelled ───────────────────
#
# One row per axis a planner would weigh. `state` is `modelled`,
# `partly-modelled` or `not-modelled`, and nothing may read `modelled` on the
# strength of a proxy: the register is rendered beside the table so a reader can
# tell which columns are measurements and which are absences. It forbids
# nothing (a build could still ship an axis without registering it), which is
# why the tests assert the axes named here are all present.
AXES: list[dict[str, str]] = [
    {"axis": "Size of the work", "state": "modelled",
     "source": "`effort` (S, M, L or XL), set by the rule or decision that set the track",
     "note": "An estimate made by the tool or by a person, never a quote."},
    {"axis": "Assets cleared per fix (leverage)", "state": "modelled",
     "source": "`effort_group`, the unit's own membership",
     "note": "The count is exact. What it costs to deliver is a different column."},
    {"axis": "Does one fix close several finding classes?", "state": "modelled",
     "source": "the flag families carried by the unit's assets",
     "note": "Informational flags are left out: they state a fact, not a finding."},
    {"axis": "Lifecycle — can this even be patched?", "state": "modelled",
     "source": "`support_status`, declared in the target profile (`lifecycle.py`)",
     "note": ("A unit holding an end-of-support asset cannot be sized as a patch, and the "
              "view does not present it as one. The status is declared rather than "
              "derived, so a blank means nobody has classified the asset.")},
    {"axis": "Usage volume", "state": "partly-modelled",
     "source": "`extra.estate_connections` per service class, and `usage_band` per asset",
     "note": ("Connections are a class-level figure, so they order fixes against each "
              "other and say nothing about one host. An asset the usage data never "
              "covered carries no figure, and silence is not quietness.")},
    {"axis": "Likelihood of outage, unauthorised access or privacy breach",
     "state": "partly-modelled", "source": "implicit in the track only",
     "note": ("The most urgent track means readily exploitable and the others do not, "
              "which is a ranking and not a likelihood. Nothing computes one.")},
    {"axis": "One decision or N actions?", "state": "partly-modelled",
     "source": "distinct hosts touched by the unit",
     "note": ("Proven only for a single-asset unit. Every other unit reads `unverified` "
              "with an upper bound, because nothing observed says whether a change can be "
              "pushed centrally.")},
    {"axis": "Greatest risk first — ordering by exposure, not leverage",
     "state": "not-modelled", "source": "",
     "note": ("The tool cannot order by risk: blast radius, business criticality and "
              "likelihood are all absent. The table is ordered by track and then by "
              "leverage, and leverage is not risk.")},
    {"axis": "Complexity — how known is the fix, chance of surprises",
     "state": "not-modelled", "source": "",
     "note": "No source. Distinct from size, and not inferable from it."},
    {"axis": "Specialist skill or dependencies", "state": "not-modelled", "source": "",
     "note": "No source. It would need a skills register nobody has supplied."},
    {"axis": "Blast radius if the fix goes wrong", "state": "not-modelled", "source": "",
     "note": ("No source, and independent of complexity: one line in a shared load "
              "balancer can refuse every client that offers an older protocol version.")},
    {"axis": "Reversibility", "state": "not-modelled", "source": "",
     "note": ("No source. A DNS record reverts within its time to live and a firmware "
              "replacement does not, which drives appetite more than effort does.")},
    {"axis": "Already proven elsewhere in the observation", "state": "not-modelled", "source": "",
     "note": ("No source. Some hosts may already run the encrypted variant of a service "
              "others run in clear, but joining the two is not built, and asserting it "
              "unjoined would be a claim about a change nobody has tested.")},
    {"axis": "Owner / whose queue", "state": "not-modelled", "source": "",
     "note": ("No source. This is lead time rather than effort, and it is often the "
              "binding constraint when few people deliver the work.")},
    {"axis": "Change window", "state": "not-modelled", "source": "",
     "note": "No source. A scheduling constraint independent of size."},
]


def _first_sentence(text: str, limit: int = 150) -> str:
    """The opening claim of a ``reason``, for a table cell. The full text stays
    on the asset; this is a label, never a substitute for it."""
    t = " ".join((text or "").split())
    if not t:
        return ""
    head = t.split(". ")[0].rstrip(".")
    return head if len(head) <= limit else head[: limit - 1].rstrip() + "…"


def _identity(a: CryptoAsset) -> str:
    """What counts as one thing to touch. Host first, because two findings on one
    host are one visit; an asset with neither host nor address falls back to its
    own name rather than collapsing into a shared empty bucket."""
    return a.host or a.ip or a.name


def _unit_key(a: CryptoAsset) -> str:
    """Which unit of work a finding belongs to: its ``effort_group`` when the
    deciding entry said the work is shared, the asset itself otherwise. Written
    once so :func:`plan` and :func:`unit_assets` cannot key differently."""
    return a.effort_group or f"asset:{a.bom_ref()}"


def unit_assets(assets: list[CryptoAsset]) -> dict[str, list[str]]:
    """The identities behind each unit of work, keyed as :func:`plan` keys its rows.

    Deliberately not a field on the rows: they are drawn at two altitudes with
    different rules about naming a host, and a separate structure lets a report
    that may not name a host avoid carrying the names at all.
    """
    out: dict[str, set[str]] = {}
    for a in assets:
        if not a.disposition:
            continue
        out.setdefault(_unit_key(a), set()).add(_identity(a))
    return {k: sorted(v) for k, v in out.items()}


def _finding_classes(group: list[CryptoAsset]) -> dict[str, int]:
    out: dict[str, int] = {}
    for a in group:
        for f in a.flags:
            if is_informational_flag(f):
                continue
            fam = f.split(":")[0]
            out[fam] = out.get(fam, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _leverage(group: list[CryptoAsset]) -> dict:
    """How much traffic a fix stands in front of.

    ``extra.estate_connections`` is a class-level figure: connections to a
    service across the whole estate, repeated on every asset in the class. It is
    therefore summed over the distinct service classes the unit covers and never
    over its assets, because adding it per asset would multiply one stream of
    traffic by the number of machines that bind the port.
    """
    by_service: dict[str, int] = {}
    with_a_figure = 0
    for a in group:
        extra = a.extra or {}
        service = str(extra.get("service") or "")
        raw = str(extra.get("estate_connections") or "")
        if not service or not raw:
            continue
        try:
            n = int(raw)
        except ValueError:
            continue
        with_a_figure += 1
        by_service[service] = max(by_service.get(service, 0), n)
    return {
        "connections": sum(by_service.values()),
        "service_classes": len(by_service),
        "assets_with_a_figure": with_a_figure,
        "assets": len(group),
    }


def _usage(group: list[CryptoAsset]) -> dict[str, int]:
    bands: dict[str, int] = {}
    for a in group:
        if a.usage_band:
            bands[a.usage_band] = bands.get(a.usage_band, 0) + 1
    return bands


def _actions(group: list[CryptoAsset], hosts: int) -> dict:
    """The "one decision or N actions?" answer for one unit.

    ``unverified`` unless the observation proves otherwise, and only a unit of
    one asset does. Add no further basis without a source that measures central
    manageability.
    """
    if len(group) == 1:
        return {
            "basis": "single-asset", "one_decision": True, "actions": 1,
            "upper_bound": 1,
            "note": "One asset: the decision and the action are the same thing.",
        }
    return {
        "basis": "unverified", "one_decision": True, "actions": None,
        "upper_bound": hosts,
        "note": (f"One decision. Whether it is one action or as many as {hosts:,} "
                 f"depends on whether something central can push the change, and "
                 f"nothing in this observation proves it either way."),
    }


def _row(key: str, group: list[CryptoAsset], hosts: set[str], tracks: TrackTables) -> dict:
    first = group[0]
    bases = sorted({a.disposition_basis for a in group if a.disposition_basis})
    unpatchable = sum(1 for a in group if lifecycle.is_unpatchable(a))
    worst = min((VERDICT_ORDER.get(a.verdict, 99) for a in group), default=99)
    worst_verdict = next((v for v, i in VERDICT_ORDER.items() if i == worst), "")
    sizes = sorted({a.effort for a in group if a.effort})
    # Read before the row is built because `is_work` depends on it: an
    # acceptance past its review date is work again. A unit's assets were decided
    # by one entry, so the first asset's end condition is the unit's.
    ec = end_condition(first.disposition, first.disposition_until, first.disposition_review)
    return {
        "key": key,
        "shared": bool(first.effort_group),
        "track": first.disposition,
        "track_label": tracks.label_of(first.disposition),
        "act_out_of_cycle": first.disposition in tracks.out_of_cycle,
        "is_work": (first.disposition not in NON_WORK_TRACKS or bool(ec.get("stale"))),
        "kind": first.disposition_reason.strip(),
        "fix": _first_sentence(first.disposition_reason),
        "until": first.disposition_until,
        "review": first.disposition_review,
        "end_condition": ec,
        "size": sizes[0] if len(sizes) == 1 else "",
        "size_label": SIZE_LABEL.get(sizes[0], "") if len(sizes) == 1 else "",
        # A unit holding an end-of-support asset cannot honestly be sized as a
        # patch: no update is coming, so the remedy is isolation or replacement
        # and the size above measures the wrong thing.
        "patch_possible": unpatchable == 0,
        "unpatchable": unpatchable,
        "assets_cleared": len(group),
        "hosts": len(hosts),
        "internet_facing": sum(1 for a in group if a.internet_facing),
        "finding_classes": _finding_classes(group),
        "leverage": _leverage(group),
        "usage": _usage(group),
        # Which population this row speaks for. A row computed from one export
        # covers one class of equipment and nothing else.
        "sources": sorted({a.source for a in group if a.source}),
        "data_states": sorted({a.data_state for a in group if a.data_state}),
        "worst_verdict": worst_verdict,
        "basis": bases[0] if len(bases) == 1 else ("mixed" if bases else ""),
        "deadline": min((a.pqc_deadline for a in group if a.pqc_deadline), default=""),
        "actions": _actions(group, len(hosts)),
    }


def _kinds(rows: list[dict], kind_hosts: dict[str, set[str]],
           kind_assets: dict[str, list[CryptoAsset]], tracks: TrackTables) -> list[dict]:
    """The rows rolled up by the entry that decided them: the under-grouping
    question, which the rows alone cannot show. See the module docstring.

    The leverage figure is re-aggregated from ``kind_assets`` rather than added
    up from the rows, because ``estate_connections`` repeats on every asset in a
    service class and the rows would count one stream of traffic once per unit.
    """
    out: dict[str, dict] = {}
    for r in rows:
        k = out.setdefault(r["kind"], {
            "kind": r["kind"], "fix": r["fix"], "track": r["track"],
            "track_label": r["track_label"], "is_work": r["is_work"],
            "findings": 0, "units": 0, "shared_units": 0, "sizes": {},
            # What the fix is about, in flag families. A reason often opens with
            # who decided it, which says nothing about the work; the families do.
            "finding_classes": {},
            "connections": _leverage(kind_assets.get(r["kind"], []))["connections"],
            "hosts": len(kind_hosts.get(r["kind"], set())),
            "sources": sorted({a.source for a in kind_assets.get(r["kind"], [])
                               if a.source}),
        })
        k["findings"] += r["assets_cleared"]
        k["units"] += 1
        for fam, n in r["finding_classes"].items():
            k["finding_classes"][fam] = k["finding_classes"].get(fam, 0) + n
        if r["shared"]:
            k["shared_units"] += 1
        if r["size"]:
            k["sizes"][r["size"]] = k["sizes"].get(r["size"], 0) + 1
    rows_out = list(out.values())
    for k in rows_out:
        k["finding_classes"] = dict(sorted(k["finding_classes"].items(),
                                           key=lambda kv: -kv[1]))
        if k["units"] > 1 and not k["shared_units"]:
            k["grouping"] = {
                "basis": "unverified",
                "note": (f"Counted as {k['units']:,} separate jobs, because the rule "
                         f"that decided them sizes each asset on its own. No decision "
                         f"says whether one change covers them all — if it does, "
                         f"this is one unit and not {k['units']:,}."),
            }
        elif k["shared_units"]:
            k["grouping"] = {
                "basis": "ruled-shared",
                "note": ("Counted as shared work, because the entry that decided it "
                         "says so. How many touches that is remains unverified."),
            }
        else:
            k["grouping"] = {"basis": "single-unit", "note": ""}
    rows_out.sort(key=lambda k: (tracks.position(k["track"]), -k["units"], -k["findings"]))
    return rows_out


#: The sort key, and the sentence that stops it being read as a plan. Written
#: once so every renderer states the same thing about what the order means.
#: A leverage-first sort is not forbidden; a silent one is.
ORDER = {
    "sorted_by": "the remediation track, then assets cleared per unit",
    "is_a_recommended_sequence": False,
    "principle": ("A risk order would weigh exposure, business criticality and "
                  "likelihood; none is in the data."),
    "note": ("This table is not that order. The track it sorts on encodes urgency, "
             "not exposure, and the second key is leverage, which ranks a large "
             "cleanup of a low-value service above a single finding on the system "
             "holding the most sensitive data. Nothing here computes risk: blast "
             "radius, business criticality and likelihood are all unmodelled, so "
             "this table says it cannot give a risk order rather than leaving a "
             "reader to infer one from it."),
}

#: The caution that travels with any total computed here. A unit count is bounded
#: by what an instrument reached.
DENOMINATOR_NOTE = (
    "These units of work are computed over the assets in this observation that "
    "carry a remediation track. An asset carries one only if an instrument "
    "reached it, so the total is bounded by coverage rather than by the estate. "
    "Read it against the coverage gaps and the declared asset classes, never on "
    "its own.")

#: The two sentences that travel with the conditional figure, written here so no
#: renderer can word it more confidently than the data allows.
DECISION_OWED_NOTE = (
    "It has not been decided whether one change covers each of these kinds of fix. "
    "If one does, they are that many fewer units; if it does not, the larger "
    "figure is the honest one. Nothing in this observation can tell the two "
    "apart, so both are printed and neither is asserted.")
DECISION_OWED_COST = (
    "And one change is not the same as no work. A single central change still "
    "carries the governance, funding, planning and change control that "
    "authorise it, and none of that is modelled here: deciding a kind is central "
    "moves effort out of this count, it does not remove it from the programme.")


def _decision_owed(kinds: list[dict], totals: dict) -> dict:
    """How much of the plan's size is waiting on a decision rather than on work.

    A kind marked ``unverified`` is counted as many jobs and nobody has decided
    that one change covers them. This turns that fact into the number a planner
    wants: the plan if every such kind went the central way. It is a conditional
    and labelled as one; ``totals`` is untouched.
    """
    open_kinds = [k for k in kinds
                  if k.get("is_work") and (k.get("grouping") or {}).get("basis") == "unverified"]
    at_stake = sum(k["units"] - 1 for k in open_kinds)
    return {
        "kinds": len(open_kinds),
        # Both figures, always: one alone would read as a measurement.
        "units_at_stake": at_stake,
        "work_units_now": totals["work_units"],
        "work_units_if_each_is_one_change": totals["work_units"] - at_stake,
        "largest_kind": max((k["units"] for k in open_kinds), default=0),
        "note": DECISION_OWED_NOTE,
        "cost": DECISION_OWED_COST,
    }


#: Source id to what a reader should see in its place: the ``source`` each
#: collector or reader stamps on its rows, which is the string :func:`_coverage`
#: counts. A coverage note should never print a module identifier at a person
#: who has not seen the code. ``tests/test_remediation.py`` fails when a
#: collector or reader declares a source this map has not heard of.
SOURCE_LABEL: dict[str, str] = {
    "azure_resource_graph": "Azure Resource Graph encryption-settings export",
    "caa": "certificate-authority authorisation records in public DNS",
    "commvault": "Commvault backup configuration export",
    "ct_dns": "public certificate transparency logs",
    "dane": "mail server certificate records in public DNS",
    "dns_zones": "DNS zone files exported from the DNS host",
    "dnssec": "DNS signing (DNSSEC) read through validating public resolvers",
    "entra_app_credentials": "Microsoft Entra application credentials",
    "entra_audit": "Microsoft Entra directory change records",
    "entra_auth_methods": "Microsoft Entra sign-in methods in use",
    "entra_privileged_groups": "Microsoft Entra membership of administrative role groups",
    "entra_signins": "Microsoft Entra interactive sign-in records",
    "entra_workload_signins": "Microsoft Entra application and non-interactive sign-in records",
    "estate": "the asset classes the organisation declares",
    "exchange_online": "Exchange Online anti-phishing, DKIM signing and connector settings",
    "exo_client_access": "Exchange Online mailbox access methods that are switched on",
    "exo_outbound_protection": "Exchange Online outbound mail by recipient policy",
    "falcon": "CrowdStrike Falcon endpoint export",
    "falcon_accounts": "CrowdStrike Falcon local accounts",
    "falcon_connections": "CrowdStrike Falcon network connections",
    "falcon_disk_encryption": "CrowdStrike Falcon disk encryption state",
    "falcon_dns": "CrowdStrike Falcon DNS lookups, by the organisation behind each name",
    "falcon_endpoint_events": "CrowdStrike Falcon removable media and credential-store events",
    "falcon_estate_coverage": "CrowdStrike Falcon sensor coverage",
    "falcon_http": "CrowdStrike Falcon web requests read in clear, by destination",
    "falcon_logins": "CrowdStrike Falcon sign-in records",
    "falcon_logon_events": "CrowdStrike Falcon sign-in and group-change events, per machine",
    "falcon_sha1_signed_modules": "CrowdStrike Falcon software signed with SHA-1",
    "falcon_software": "CrowdStrike Falcon installed software",
    "falcon_system_resources": "CrowdStrike Falcon firmware census",
    "falcon_tls_clienthello": "CrowdStrike Falcon outbound handshakes, what the software asks for",
    "falcon_vulnerabilities": "CrowdStrike Falcon open vulnerabilities",
    "falcon_windows_os_security": "CrowdStrike Falcon Windows boot and memory protections",
    "falcon_zta": "CrowdStrike Falcon Zero Trust Assessment",
    "hsts": "web strict-transport-security check",
    "ike_scan": "VPN key-exchange proposal scan",
    "implicit_tls": "mail port encryption check, where encryption is always on",
    "intel_amt": "Intel AMT firmware answer check",
    "internal_scan": "internal service encryption check, authorised separately",
    "m365_bitlocker": "Microsoft 365 BitLocker recovery-key escrow",
    "mail_transport": "Exchange Online per-message transport encryption",
    "netdev": "network and out-of-band equipment configuration",
    "oracle_tde": "Oracle database encryption-at-rest export",
    "plaintext_scan": "unencrypted-port check",
    "rdp_scan": "remote desktop security-layer scan",
    "rvtools": "RVTools virtualisation inventory",
    "sbom": "application software bill of materials",
    "smb_scan": "file-sharing protocol and signing check",
    "smtp_starttls": "mail transport encryption check",
    "software_inventory": "installed cryptographic providers and their versions",
    "software_support": "software census with vendor support dates and exploited defects",
    "spf_senders": "public mail sender-policy records",
    "ssh_audit": "secure-shell configuration scan",
    "tls_scan": "transport encryption scan",
    "vmware": "VMware platform export",
    "vsphere_lists": "vSphere Client list exports of machines, hosts and datastores",
    "winrm_config": "Windows remote-management configuration",
}


def source_label(source: str, labels: Mapping[str, str] | None = None) -> str:
    """A reader-facing name for a source id, falling back to the id itself.

    ``labels`` replaces :data:`SOURCE_LABEL` for a caller with sources of its
    own; build it as ``{**SOURCE_LABEL, "my_source": "..."}`` to extend this one.
    The fallback is the cheap-failure half of the guard: an unmapped source still
    reports its numbers rather than dropping them or raising during a render.
    The coverage test is what stops the id reaching a reader.
    """
    return (SOURCE_LABEL if labels is None else labels).get(source, source)


def _coverage(assets: list[CryptoAsset], tracked: list[CryptoAsset], summary: dict) -> dict:
    """What the plan was computed over, and which instruments produced it."""
    by_source: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for a in tracked:
        if a.source:
            by_source[a.source] = by_source.get(a.source, 0) + 1
        if a.data_state:
            by_state[a.data_state] = by_state.get(a.data_state, 0) + 1
    est = summary.get("estate") or {}
    return {
        "assets_in_observation": len(assets),
        "assets_with_a_track": len(tracked),
        "assets_with_no_track": len(assets) - len(tracked),
        "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
        "by_data_state": dict(sorted(by_state.items(), key=lambda kv: -kv[1])),
        # Straight from the `estate` reader's summary when the profile declares
        # equipment, `None` when it does not. Never a zero, which would read as
        # "no class is dark" rather than "nobody checked".
        "declared_classes": est.get("declared_classes"),
        "dark_classes": est.get("dark_count"),
        "note": DENOMINATOR_NOTE,
    }


def plan(assets: list[CryptoAsset], summary: dict | None = None, *,
         tracks: TrackTables | None = None) -> dict:
    """The remediation view: units of work, the fix kinds behind them, the axes
    that are and are not modelled, and any counting defect that inflated totals.

    Assets with no disposition are skipped rather than bucketed under an
    invented track: a machine that has proposed nothing has proposed nothing.

    ``summary`` is optional and two keys are read from it:
    ``disposition_integrity`` (the observation's own record of a malformed
    shared-effort entry) and ``estate`` (the declared-class counts). An
    observation without them renders those blocks empty, which is correct:
    nothing was checked, so nothing is claimed.

    ``tracks`` says how to label and order tracks. By default it is built from
    the bundled ladder and fixed tracks; pass
    ``TrackTables.from_rules(load_dispositions_for_target(profile))`` to use an
    organisation's own ladder.
    """
    summary = summary or {}
    tracks = tracks if tracks is not None else _bundled_tracks()
    units: dict[str, list[CryptoAsset]] = {}
    unit_hosts: dict[str, set[str]] = {}
    kind_hosts: dict[str, set[str]] = {}
    kind_assets: dict[str, list[CryptoAsset]] = {}
    order: list[str] = []
    for a in assets:
        if not a.disposition:
            continue
        key = _unit_key(a)
        if key not in units:
            units[key] = []
            unit_hosts[key] = set()
            order.append(key)
        units[key].append(a)
        unit_hosts[key].add(_identity(a))
        kind_hosts.setdefault(a.disposition_reason.strip(), set()).add(_identity(a))
        kind_assets.setdefault(a.disposition_reason.strip(), []).append(a)

    rows = [_row(k, units[k], unit_hosts[k], tracks) for k in order]
    rows.sort(key=lambda r: (tracks.position(r["track"]), -r["assets_cleared"], r["fix"]))
    kinds = _kinds(rows, kind_hosts, kind_assets, tracks)

    work_rows = [r for r in rows if r["is_work"]]
    totals = {
        "findings": sum(r["assets_cleared"] for r in rows),
        "units": len(rows),
        "kinds": len(kinds),
        "work_findings": sum(r["assets_cleared"] for r in work_rows),
        "work_units": len(work_rows),
        "shared_units": sum(1 for r in rows if r["shared"]),
        # How many units make a leverage claim nothing has verified: the measure
        # of how much of the plan's optimism is unproven.
        "unverified_units": sum(1 for r in rows if r["actions"]["basis"] == "unverified"),
        "largest_unit": max((r["assets_cleared"] for r in rows), default=0),
        "unpatchable_units": sum(1 for r in rows if r["unpatchable"]),
    }
    return {
        "totals": totals,
        # Named before the numbers, because it governs how they are read.
        "order": ORDER,
        "coverage": _coverage(assets, [a for a in assets if a.disposition], summary),
        "rows": rows,
        "kinds": kinds,
        "decision_owed": _decision_owed(kinds, totals),
        "axes": AXES,
        # A malformed `effort_scope: per-rule` entry degrades to per-asset and
        # silently inflates every total above, so the defect is carried into the
        # view (`disposition.integrity_problems`) rather than left on a console.
        "integrity": list(summary.get("disposition_integrity") or []),
    }
