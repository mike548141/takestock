"""Propose what to do about each graded asset, and roughly how big the job is.

A **disposition** is a track plus a plain-language reason, an effort size
(S, M, L, XL) and, for an acceptance, what ends it. It sits beside the verdict
and never changes it: a weak cipher on an accepted track is still weak.

A track is either a **rung** of the remediation ladder (time-ordered, most
urgent first) or one of the fixed tracks in :data:`WHY_TRACK_LABEL`, which say
why something is not being acted on in the ordinary way. The ladder is data:
``data/dispositions.yaml`` declares a default (critical, then waves 1 to 3),
and an organisation's overlay may declare its own ``ladder`` instead.

Two files feed it:

* ``data/dispositions.yaml`` ships with the tool and holds generic rules only;
* an organisation's **overlay**, ``targets/<stem>.dispositions.yaml`` beside its
  target profile, may add its own ``ladder``, ``rules``, its recorded ``decisions``, any
  ``adoptions`` of a generic rule, and a ``programme`` block of its own dates
  (for example ``pqc_target_year``). The tool supplies no dates of its own.

Order of precedence for one asset: the first matching **decision** (overlay
decisions before tool decisions), else the first matching **rule** (overlay
rules before tool rules), else nothing. A rule's match is ``proposed``; a
decision's is ``decided``. An **adoption** names a generic rule by id together
with the hash of its exact wording (:func:`rule_hash`), and turns that rule's
matches into ``decided`` for as long as the wording is unchanged. If the rule
is later reworded, the adoption no longer applies and
:meth:`DispositionRules.adoption_drift` lists it.

Every entry that carries an ``effort`` must say how it is owed, with
``effort_scope``: ``per-asset`` (each matching asset is its own job) or
``per-rule`` (every matching asset shares one unit of work, grouped by the
entry's ``id``). There is no default, so an effort size is never multiplied by
an asset count unless somebody chose that.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date as _date
from pathlib import Path

from . import config
from .model import CryptoAsset

#: Suffix of the overlay beside a target profile: ``acme.yaml`` -> ``acme.dispositions.yaml``.
OVERLAY_SUFFIX = ".dispositions.yaml"

#: Top-level sections a dispositions file may hold. Anything else is refused,
#: so a misspelt section cannot silently drop a person's decisions.
FILE_SECTIONS = frozenset({"programme", "ladder", "rules", "decisions", "adoptions",
                           "dispensations"})

#: The post-quantum exposure flags (see ``policy.py``). An asset carrying either
#: owes the organisation's post-quantum target year, if one is set.
PQ_FLAGS = frozenset({"quantum-vulnerable-kex", "quantum-vulnerable-signature"})

VALID_EFFORTS = {"S", "M", "L", "XL"}
VALID_EFFORT_SCOPES = {"per-asset", "per-rule"}

BASIS_PROPOSED = "proposed"
BASIS_DECIDED = "decided"
BASIS_NONE = "none"


class UndeclaredEffortScopeError(ValueError):
    """A dispositions file has an entry with ``effort`` but no ``effort_scope``."""


class LadderError(ValueError):
    """A ladder is malformed, or a rule proposes a rung the ladder does not have."""


#: The tracks beside the ladder, in display order, with a reader's name for each.
WHY_TRACK_LABEL = {
    "pqc-migrate": "Post-quantum migration",
    "retire-planned": "Retire — replacement planned",
    "defer-migration": "Defer — migrating or retiring",
    "accept-replacement-planned": "Accept until replaced",
    "accept-no-alternative": "Accept — no encrypted option",
    "no-action": "No action",
}
WHY_TRACKS = frozenset(WHY_TRACK_LABEL)

#: Tracks that accept a finding rather than schedule its removal. Each one
#: should say what ends it (``until``) and when it is next looked at (``review``).
ACCEPTANCE_TRACKS = frozenset({"accept-replacement-planned", "accept-no-alternative", "retire-planned"})


def parse_ladder(entries: object, where: str = "ladder") -> list[dict]:
    """Check a ``ladder:`` list and return it as ``{track, label, out_of_cycle}`` dicts."""
    if not isinstance(entries, list) or not entries:
        raise LadderError(f"{where}: a ladder is a non-empty list of rungs")
    out: list[dict] = []
    seen: set[str] = set()
    for entry in entries:
        track = str((entry or {}).get("track") or "").strip() if isinstance(entry, dict) else ""
        if not track:
            raise LadderError(f"{where}: every rung needs a 'track', got {entry!r}")
        if track in seen or track in WHY_TRACKS:
            raise LadderError(f"{where}: rung {track!r} is declared twice or names a fixed track")
        seen.add(track)
        out.append({"track": track, "label": str(entry.get("label") or track),
                    "out_of_cycle": bool(entry.get("out_of_cycle", False))})
    return out


def load_ladder(path: Path | None = None) -> list[dict]:
    """The ladder declared in the tool's dispositions file (or the file at ``path``)."""
    doc = config.load_yaml_strict(path if path is not None else config.dispositions_path())
    return parse_ladder(doc.get("ladder"), "dispositions ladder")

# What an artefact can say about when an acceptance ends.
END_UNTIL = "until"
END_OPEN_ENDED = "open-ended"
END_NOT_APPLICABLE = "not-applicable"

END_UNTIL_TEMPLATE = "Accepted until {until}."
END_UNTIL_NOTE = ("This ends when the named condition is met, and somebody has to "
                  "check whether it has been.")
END_OPEN_ENDED_TEXT = "Accepted with no end condition recorded."
END_OPEN_ENDED_NOTE = ("Nothing records what would end this, so it stands until "
                       "somebody revisits it.")

# The review date of an acceptance: a separate question from what ends it.
# Past its review date an acceptance lapses and the finding counts in full.
REVIEW_NOT_APPLICABLE = "not-applicable"
REVIEW_NONE = "none"
REVIEW_SET = "set"
REVIEW_LAPSED = "lapsed"

REVIEW_SET_TEMPLATE = "To be reviewed by {review}."
REVIEW_NONE_TEXT = "No review date is recorded, so nothing brings this decision back for a second look."
REVIEW_LAPSED_TEMPLATE = ("The review date of {review} has passed, so this acceptance has "
                          "lapsed and the finding counts in full until it is renewed.")

_REVIEW_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REVIEW_MONTH = re.compile(r"^\d{4}-\d{2}$")

#: Keys a ``match:`` block may use. An unknown key is an error, never a silent miss.
MATCH_KEYS = {
    "verdict", "data_state", "protocol", "source", "internet_facing",
    "flags_any", "flags_all", "flags_none", "flags_prefix_any", "flags_prefix_none",
    "host_pattern", "extra_true", "extra_any", "primitive_any", "third_party",
}


def _norm_host(v: object) -> str:
    return str(v or "").strip().lower().rstrip(".")


def operated_elsewhere(target: dict) -> tuple[frozenset[str], frozenset[str]]:
    """``(hosts, domains)`` the target profile declares an outside provider runs.

    Hosts come from ``scan_targets.saas_443`` and ``scan_targets.smtp_25``;
    domains from each ``third_party`` entry's ``domains``. A host nobody has
    declared is treated as the organisation's own.
    """
    st = (target or {}).get("scan_targets") or {}
    hosts: set[str] = set()
    for key in ("saas_443", "smtp_25"):
        for entry in st.get(key) or []:
            h = _norm_host(entry.get("host") if isinstance(entry, dict) else entry)
            if h:
                hosts.add(h)
    domains: set[str] = set()
    for entry in (target or {}).get("third_party") or []:
        if not isinstance(entry, dict):
            continue
        for d in entry.get("domains") or []:
            if _norm_host(d):
                domains.add(_norm_host(d))
    return frozenset(hosts), frozenset(domains)


@dataclass
class DispositionRules:
    """The ladder, rules, decisions and adoptions in effect for one organisation."""

    programme: dict = field(default_factory=dict)
    ladder: list[dict] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    adoptions: list[dict] = field(default_factory=list)
    third_party_hosts: frozenset[str] = frozenset()
    third_party_domains: frozenset[str] = frozenset()

    @property
    def rungs(self) -> tuple[str, ...]:
        """The ladder's tracks, most urgent first."""
        return tuple(r["track"] for r in self.ladder)

    @property
    def valid_tracks(self) -> frozenset[str]:
        """Every track a rule or decision may propose: the rungs and the fixed tracks."""
        return frozenset(self.rungs) | WHY_TRACKS

    @property
    def out_of_cycle(self) -> frozenset[str]:
        """Rungs whose work does not wait for a planning cycle."""
        return frozenset(r["track"] for r in self.ladder if r.get("out_of_cycle"))

    def track_label(self, track: str) -> str:
        """A reader's name for ``track``; its slug when it has none."""
        for r in self.ladder:
            if r["track"] == track:
                return str(r["label"])
        return WHY_TRACK_LABEL.get(track, track)

    @property
    def track_order(self) -> dict[str, int]:
        """Display order: the rungs, then the fixed tracks. Nothing branches on it."""
        return {t: i for i, t in enumerate([*self.rungs, *WHY_TRACK_LABEL])}

    def is_third_party(self, host: str) -> bool:
        """Whether the target profile declares ``host`` as run by an outside provider."""
        h = _norm_host(host)
        if not h:
            return False
        if h in self.third_party_hosts:
            return True
        return any(h == d or h.endswith("." + d) for d in self.third_party_domains)

    @property
    def adopted_rule_ids(self) -> set[str]:
        """Every rule id some adoption names (whether or not its wording still matches)."""
        out: set[str] = set()
        for r in self.adoptions:
            out.update(str(x) for x in _as_list(r.get("rules") or []))
        return out

    @property
    def adopted_rule_hashes(self) -> dict[str, set[str]]:
        """Rule id to every wording hash an adoption recorded for it."""
        out: dict[str, set[str]] = {}
        for r in self.adoptions:
            hashes = r.get("rule_hashes") or {}
            for rid in _as_list(r.get("rules") or []):
                if rid in hashes:
                    out.setdefault(str(rid), set()).add(str(hashes[rid]))
        return out

    def is_adopted(self, rule: dict) -> bool:
        """True when an adoption names this rule and recorded the hash of its current wording."""
        return rule_hash(rule) in self.adopted_rule_hashes.get(str(rule.get("id") or ""), set())

    def adoption_drift(self) -> list[dict]:
        """Adopted rules whose current wording is not what was adopted."""
        named = self.adopted_rule_ids
        hashes = self.adopted_rule_hashes
        out: list[dict] = []
        for rule in self.rules:
            rid = str(rule.get("id") or "")
            if rid not in named or self.is_adopted(rule):
                continue
            out.append({"id": rid, "hash": rule_hash(rule),
                        "state": "reworded" if rid in hashes else "no-hash",
                        "adopted_hashes": sorted(hashes.get(rid, set()))})
        return out


def _read(path: Path) -> dict:
    doc = config.load_yaml_strict(path) or {}
    unknown = sorted(set(doc) - FILE_SECTIONS)
    if unknown:
        raise ValueError(
            f"{path}: unknown section(s) {unknown}; a dispositions file holds only "
            f"{sorted(FILE_SECTIONS)}")
    return doc


def load_dispositions(path: Path | None = None, overlay: Path | None = None) -> DispositionRules:
    """Load the tool's generic rules, with an organisation's overlay in front of them.

    The overlay's ``ladder``, when it declares one, replaces the tool's.
    Raises :class:`UndeclaredEffortScopeError` if any entry sizes its effort
    without saying whether it is owed per asset or per rule, and
    :class:`LadderError` if any entry proposes a track the ladder lacks.
    """
    tool_path = path if path is not None else config.dispositions_path()
    tool = _read(tool_path)
    over = _read(overlay) if overlay is not None else {}
    _refuse_undeclared_effort_scope(tool, tool_path)
    if overlay is not None:
        _refuse_undeclared_effort_scope(over, overlay)
    if over.get("ladder") is not None:
        ladder = parse_ladder(over["ladder"], f"{overlay}: ladder")
    else:
        ladder = parse_ladder(tool.get("ladder"), f"{tool_path}: ladder")
    dr = DispositionRules(
        programme=over.get("programme") or {},
        ladder=ladder,
        rules=(over.get("rules") or []) + (tool.get("rules") or []),
        decisions=(over.get("decisions") or []) + (tool.get("decisions") or []),
        adoptions=(over.get("adoptions") or []) + (tool.get("adoptions") or []),
    )
    off_ladder = sorted({str(e.get("id") or e.get("when") or e.get("disposition"))
                         for e in dr.rules + dr.decisions
                         if e.get("disposition") not in dr.valid_tracks})
    if off_ladder:
        raise LadderError(
            f"entries propose a track the ladder does not have: {off_ladder}. A ladder "
            f"must contain every rung a loaded rule or decision proposes")
    return dr


def _refuse_undeclared_effort_scope(doc: dict, where: Path) -> None:
    undeclared: list[str] = []
    for section in ("rules", "decisions"):
        for entry in doc.get(section) or []:
            if not isinstance(entry, dict) or "effort" not in entry:
                continue
            if entry.get("effort_scope") is None:
                label = entry.get("id") or entry.get("when") or entry
                undeclared.append(f"{section[:-1]} {label}")
    if not undeclared:
        return
    n = len(undeclared)
    raise UndeclaredEffortScopeError(
        f"{where}: {n} entr{'y' if n == 1 else 'ies'} carry 'effort:' with no "
        f"'effort_scope:': {'; '.join(undeclared)}. Declare 'per-asset' (each "
        f"matching asset is its own job) or 'per-rule' (every matching asset "
        f"shares one unit of this effort).")


def overlay_path_for_target(target: dict) -> Path | None:
    """The dispositions overlay beside a loaded target profile, or None if there is none."""
    tpath = target.get("_path")
    if not tpath:
        return None
    p = Path(tpath)
    if not p.suffix:
        return None
    cand = p.with_name(p.name[: -len(p.suffix)] + OVERLAY_SUFFIX)
    return cand if cand.exists() else None


def load_dispositions_for_target(target: dict, path: Path | None = None) -> DispositionRules:
    """:func:`load_dispositions` with the target's overlay and its outside-provider declarations."""
    dr = load_dispositions(path=path, overlay=overlay_path_for_target(target))
    dr.third_party_hosts, dr.third_party_domains = operated_elsewhere(target)
    return dr


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _primitive_tokens(a: CryptoAsset) -> set[str]:
    # Every primitive token on the asset, lower-cased; a TLS suite name is also
    # split into its parts so a rule can name "sha1" and reach "..._SHA".
    out: set[str] = set()
    for axis in (a.key_exchange, a.signatures, a.symmetric, a.hashes):
        for token in axis or []:
            t = str(token).strip().lower()
            if not t:
                continue
            out.add(t)
            if t.startswith("tls_"):
                out.update(p for p in t.split("_") if p)
    return out


# Spellings under which a primitive appears in collector output.
_PRIMITIVE_ALIASES = {"sha1": {"sha1", "sha", "hmac-sha1"}}


def _carries_primitive(a: CryptoAsset, wanted: list) -> bool:
    have = _primitive_tokens(a)
    for token in wanted:
        t = str(token).strip().lower()
        if have & _PRIMITIVE_ALIASES.get(t, {t}):
            return True
    return False


def matches(match: dict, a: CryptoAsset, dr: DispositionRules | None = None) -> bool:
    """Whether every key in a ``match:`` block holds for ``a``.

    ``third_party`` needs ``dr`` loaded for a target; without it every host
    counts as the organisation's own.
    """
    for key, val in (match or {}).items():
        if key == "verdict":
            if a.verdict not in _as_list(val):
                return False
        elif key == "data_state":
            if a.data_state not in _as_list(val):
                return False
        elif key == "protocol":
            if a.protocol not in _as_list(val):
                return False
        elif key == "source":
            if a.source not in _as_list(val):
                return False
        elif key == "internet_facing":
            if a.internet_facing != val:
                return False
        elif key == "flags_any":
            if not (set(a.flags) & set(_as_list(val))):
                return False
        elif key == "flags_all":
            if not set(_as_list(val)) <= set(a.flags):
                return False
        elif key == "flags_none":
            if set(a.flags) & set(_as_list(val)):
                return False
        elif key == "flags_prefix_any":
            if not any(f.startswith(p) for f in a.flags for p in _as_list(val)):
                return False
        elif key == "flags_prefix_none":
            if any(f.startswith(p) for f in a.flags for p in _as_list(val)):
                return False
        elif key == "primitive_any":
            if not _carries_primitive(a, _as_list(val)):
                return False
        elif key == "host_pattern":
            if not re.search(val, a.host or ""):
                return False
        elif key == "extra_any":
            if not isinstance(val, dict):
                raise ValueError(
                    "dispositions: 'extra_any' takes a mapping of field to allowed "
                    f"value(s), got {type(val).__name__}")
            for field_name, allowed in val.items():
                have = a.extra.get(field_name)
                if have is None:
                    return False
                wanted = {str(x).strip().lower() for x in _as_list(allowed)}
                if str(have).strip().lower() not in wanted:
                    return False
        elif key == "third_party":
            if not isinstance(val, bool):
                raise ValueError(f"dispositions: 'third_party' takes true or false, got {val!r}")
            declared = dr.is_third_party(a.host) if dr is not None else False
            if declared != val:
                return False
        elif key == "extra_true":
            if not bool(a.extra.get(val)):
                return False
        else:
            raise ValueError(f"dispositions: unknown match key {key!r}")
    return True


def _first_match(entries: list[dict], a: CryptoAsset,
                 dr: DispositionRules | None = None) -> dict | None:
    for entry in entries:
        if matches(entry.get("match", {}), a, dr):
            return entry
    return None


def _effort_group(entry: dict) -> str:
    if entry.get("effort_scope") != "per-rule":
        return ""
    return str(entry.get("id") or "")


def _until(entry: dict) -> str:
    return str(entry.get("until") or "").strip()


def _review(entry: dict) -> str:
    return str(entry.get("review") or "").strip()


def _review_ceiling(review: str) -> str:
    # A month-only review date has not passed until the month is over. "-31"
    # is a comparison sentinel for "end of the month", never a real date.
    if _REVIEW_MONTH.match(review):
        return review + "-31"
    return review


def review_state(track: str, review: str, today: str = "") -> str:
    """One of the ``REVIEW_*`` states for an acceptance's review date on ``today`` (ISO day)."""
    if track not in ACCEPTANCE_TRACKS:
        return REVIEW_NOT_APPLICABLE
    review = (review or "").strip()
    if not review:
        return REVIEW_NONE
    now = (today or "").strip() or _date.today().isoformat()
    return REVIEW_LAPSED if _review_ceiling(review) < now else REVIEW_SET


def end_condition(track: str, until: str, review: str = "", today: str = "") -> dict:
    """What a reader is told about when a disposition ends, and when it is reviewed."""
    until = (until or "").strip()
    review = (review or "").strip()
    rstate = review_state(track, review, today)
    if rstate == REVIEW_LAPSED:
        rtext = REVIEW_LAPSED_TEMPLATE.format(review=review)
    elif rstate == REVIEW_SET:
        rtext = REVIEW_SET_TEMPLATE.format(review=review)
    elif rstate == REVIEW_NONE:
        rtext = REVIEW_NONE_TEXT
    else:
        rtext = ""
    extra = {"review": review, "review_state": rstate, "review_text": rtext,
             "stale": rstate == REVIEW_LAPSED}
    if until:
        return {"state": END_UNTIL, "text": END_UNTIL_TEMPLATE.format(until=until),
                "note": END_UNTIL_NOTE, **extra}
    if track in ACCEPTANCE_TRACKS:
        return {"state": END_OPEN_ENDED, "text": END_OPEN_ENDED_TEXT,
                "note": END_OPEN_ENDED_NOTE, **extra}
    return {"state": END_NOT_APPLICABLE, "text": "", "note": "", **extra}


def asset_end_condition(a: CryptoAsset, today: str = "") -> dict:
    """:func:`end_condition` for an asset that has been through :func:`apply_disposition`."""
    return end_condition(a.disposition, a.disposition_until, a.disposition_review, today)


def is_stale_acceptance(a: CryptoAsset, today: str = "") -> bool:
    """True when ``a`` sits on an acceptance whose review date has passed."""
    return review_state(a.disposition, a.disposition_review, today) == REVIEW_LAPSED


def accepted_breakout(assets: list[CryptoAsset], today: str = "") -> dict:
    """Counts of accepted assets, split by review state. Lapsed ones are counted apart."""
    out = {"assets": 0, "findings": 0, "with_review": 0,
           "no_review_date": 0, "lapsed": 0, "lapsed_findings": 0}
    for a in assets:
        state = review_state(a.disposition, a.disposition_review, today)
        if state == REVIEW_NOT_APPLICABLE:
            continue
        if state == REVIEW_LAPSED:
            out["lapsed"] += 1
            if a.verdict == "weak":
                out["lapsed_findings"] += 1
            continue
        out["assets"] += 1
        if a.verdict == "weak":
            out["findings"] += 1
        if state == REVIEW_SET:
            out["with_review"] += 1
        else:
            out["no_review_date"] += 1
    return out


def _default_pqc_deadline(a: CryptoAsset, programme: dict) -> str:
    if PQ_FLAGS & set(a.flags):
        year = programme.get("pqc_target_year")
        return str(year) if year else ""
    return ""


def _apply_entry(a: CryptoAsset, entry: dict, basis: str, default_deadline: str) -> None:
    a.disposition = entry["disposition"]
    a.disposition_basis = basis
    a.disposition_reason = entry["reason"]
    a.disposition_until = _until(entry)
    a.disposition_review = _review(entry)
    a.effort = str(entry.get("effort", ""))
    a.effort_group = _effort_group(entry)
    a.pqc_deadline = str(entry["pqc_deadline"]) if "pqc_deadline" in entry else default_deadline


def apply_disposition(a: CryptoAsset, dr: DispositionRules) -> CryptoAsset:
    """Set ``a``'s disposition fields from the first matching decision, else rule."""
    default_deadline = _default_pqc_deadline(a, dr.programme)
    decision = _first_match(dr.decisions, a, dr)
    if decision is not None:
        _apply_entry(a, decision, BASIS_DECIDED, default_deadline)
        return a
    rule = _first_match(dr.rules, a, dr)
    if rule is not None:
        _apply_entry(a, rule, BASIS_DECIDED if dr.is_adopted(rule) else BASIS_PROPOSED,
                     default_deadline)
        return a
    a.disposition = ""
    a.disposition_basis = BASIS_NONE
    a.disposition_reason = ""
    a.disposition_until = ""
    a.disposition_review = ""
    a.effort = ""
    a.effort_group = ""
    a.pqc_deadline = default_deadline
    return a


def apply_all(assets: list[CryptoAsset], dr: DispositionRules) -> list[CryptoAsset]:
    """:func:`apply_disposition` over every asset, in place."""
    for a in assets:
        apply_disposition(a, dr)
    return assets


# Whether the decisions behind a rendered report are the ones its observation
# was taken under (see render_basis).
BASIS_AS_OBSERVED = "as-observed"
BASIS_CHANGED = "changed"
BASIS_NOT_RECORDED = "not-recorded"
BASIS_NOT_REAPPLIED = "not-re-applied"

# A key whose absence means a stated value, filled in before hashing so that
# writing the value out does not change the hash.
_RULE_HASH_ABSENT_MEANT = {"effort_scope": "per-asset"}


def _hash_normal(v):
    if isinstance(v, str):
        return " ".join(v.split())
    if isinstance(v, dict):
        return {str(k): _hash_normal(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_hash_normal(x) for x in v]
    return v


def rule_hash(rule: dict) -> str:
    """A short hash of a rule's wording, ignoring its id and changes in whitespace."""
    body = {k: v for k, v in rule.items() if k != "id"}
    for key, meant in _RULE_HASH_ABSENT_MEANT.items():
        body.setdefault(key, meant)
    payload = json.dumps(_hash_normal(body), sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def set_digest(dr: DispositionRules) -> str:
    """A short hash of everything that decides a disposition, to record with an observation."""
    body: dict = {"programme": dr.programme, "ladder": dr.ladder, "rules": dr.rules,
                  "decisions": dr.decisions, "adoptions": dr.adoptions}
    if dr.third_party_hosts or dr.third_party_domains:
        body["third_party"] = {"hosts": sorted(dr.third_party_hosts),
                               "domains": sorted(dr.third_party_domains)}
    payload = json.dumps(body, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def render_basis(observed: str, rendered: str, rendered_at: str, observed_at: str = "") -> dict:
    """Compare the disposition set an observation recorded with the one a report used.

    ``observed`` and ``rendered`` are :func:`set_digest` values; ``rendered``
    is empty when the target profile could not be read at render time.
    """
    when = f" on {observed_at}" if observed_at else ""
    if not rendered:
        state = BASIS_NOT_REAPPLIED
        headline = "These unit counts could not be brought up to date."
        note = ("The target profile this observation names could not be read, so its "
                "disposition decisions were not re-applied. Every track and unit count "
                f"below is as it stood when the observation ran{when}.")
    elif not observed:
        state = BASIS_NOT_RECORDED
        headline = "Which decisions these unit counts came from cannot be compared."
        note = (f"Tracks and unit counts below reflect the dispositions as at {rendered_at} "
                f"({rendered}). The observation{when} did not record which set it ran "
                "under, so the two cannot be compared.")
    elif observed == rendered:
        state, headline, note = BASIS_AS_OBSERVED, "", ""
    else:
        state = BASIS_CHANGED
        headline = "The dispositions behind these unit counts are not the observation's own."
        note = (f"The dispositions changed after this observation was taken{when}. Tracks "
                f"and unit counts below reflect them as at {rendered_at} ({rendered}), not "
                f"the set the observation ran under ({observed}). What was measured is "
                "unchanged; what it is judged against is not.")
    return {"state": state, "observed": observed, "rendered": rendered,
            "rendered_at": rendered_at, "headline": headline, "note": note}


def validate_rule(rule: dict, tracks: frozenset[str] | None = None) -> list[str]:
    """Problems with one rule or decision entry; empty when it is well formed.

    ``tracks`` is the set a disposition may name (``DispositionRules.valid_tracks``);
    by default, the tool's ladder and the fixed tracks.
    """
    if tracks is None:
        tracks = frozenset(r["track"] for r in load_ladder()) | WHY_TRACKS
    problems = []
    if not str(rule.get("reason", "")).strip():
        problems.append("missing or empty 'reason'")
    track = rule.get("disposition")
    if track not in tracks:
        problems.append(f"disposition {track!r} not in {sorted(tracks)}")
    if rule.get("effort") not in VALID_EFFORTS:
        problems.append(f"effort {rule.get('effort')!r} not in {sorted(VALID_EFFORTS)}")
    scope = rule.get("effort_scope")
    if scope is None:
        problems.append("missing 'effort_scope': declare 'per-asset' (each matching asset "
                        "is its own job) or 'per-rule' (every matching asset shares one "
                        "unit of this effort)")
    elif scope not in VALID_EFFORT_SCOPES:
        problems.append(f"effort_scope {scope!r} not in {sorted(VALID_EFFORT_SCOPES)}")
    elif scope == "per-rule" and not str(rule.get("id") or "").strip():
        problems.append("effort_scope: per-rule needs an 'id' to group by")
    if "until" in rule and not _until(rule):
        problems.append("'until' is present but empty: name the condition that ends this, "
                        "or drop the key")
    if _until(rule) and track == "no-action":
        problems.append("'until' on 'no-action': nothing is being accepted, so nothing ends")
    if "review" in rule and not _review(rule):
        problems.append("'review' is present but empty: give a date (YYYY-MM-DD, or YYYY-MM "
                        "for a month), or drop the key")
    elif _review(rule):
        rev = _review(rule)
        if not (_REVIEW_DAY.match(rev) or _REVIEW_MONTH.match(rev)):
            problems.append(f"'review' {rev!r} is not a date: write YYYY-MM-DD or YYYY-MM. "
                            "A review date that cannot be compared can never lapse")
        elif track not in ACCEPTANCE_TRACKS:
            problems.append(f"'review' on {track!r}: a review date belongs to an acceptance "
                            f"({sorted(ACCEPTANCE_TRACKS)})")
    for key, val in (rule.get("match", {}) or {}).items():
        if key not in MATCH_KEYS:
            problems.append(f"unknown match key {key!r}")
        elif key == "extra_any" and not isinstance(val, dict):
            problems.append("'extra_any' takes a mapping of field to allowed value(s), "
                            f"got {type(val).__name__}")
        elif key == "third_party" and not isinstance(val, bool):
            problems.append(f"'third_party' takes true or false, got {val!r}")
    return problems


def deciding_entry(a: CryptoAsset, dr: DispositionRules) -> tuple[str, dict] | None:
    """``("decision", entry)`` or ``("rule", entry)`` for whatever decides ``a``, or None."""
    decision = _first_match(dr.decisions, a, dr)
    if decision is not None:
        return ("decision", decision)
    rule = _first_match(dr.rules, a, dr)
    if rule is not None:
        return ("rule", rule)
    return None


def integrity_problems(dr: DispositionRules, assets: list[CryptoAsset] | None = None) -> list[dict]:
    """Entries that declare ``per-rule`` but have no ``id`` to group by.

    Their assets fall back to one unit of work each. With ``assets`` given,
    each problem says how many assets it affects and by how much the unit
    count is inflated.
    """
    malformed: list[tuple[str, dict]] = []
    for kind, entries in (("decision", dr.decisions), ("rule", dr.rules)):
        for entry in entries:
            if entry.get("effort_scope") == "per-rule" and not str(entry.get("id") or "").strip():
                malformed.append((kind, entry))
    if not malformed:
        return []

    affected: dict[int, int] = {}
    if assets is not None:
        wanted = {id(e) for _, e in malformed}
        for a in assets:
            decided = deciding_entry(a, dr)
            if decided is not None and id(decided[1]) in wanted:
                affected[id(decided[1])] = affected.get(id(decided[1]), 0) + 1

    problems: list[dict] = []
    for kind, entry in malformed:
        n = affected.get(id(entry)) if assets is not None else None
        where = f"a {kind} recorded {entry.get('when') or '(undated)'}"
        problems.append({
            "problem": "per-rule-without-id",
            "entry": where,
            "kind": kind,
            "detail": ("declares `effort_scope: per-rule` but carries no `id`, so the assets "
                       "it covers could not be grouped and are counted as one unit of work each"),
            "affected": n,
            "inflated_units_by": (n - 1) if n else None,
        })
    return problems
