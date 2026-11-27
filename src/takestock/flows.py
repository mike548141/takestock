"""Information flows joined to the cryptography that carries them.

An information-sharing register says **what leaves the organisation, and to
whom**. An observation says **how strong the channels are**. Neither is a
business finding alone: "this TLS floor is weak" names no consequence, and
"we share records with 40 outside organisations" names no exposure. Joined,
they say "the old cipher on the supplier link underlies 7 recorded flows
that carry customer records to 3 partners", which is a sentence a
decision-maker can act on.

This module does the join and nothing else: it reads the register, splits its
multi-valued channel field, applies a **declared channel map**, and rolls the
result up per flow, per channel, per asset and in total.

**The join key** is one thing, and everything else is carried along it::

    register channel token  --(declared map)-->  {host, port} or {protocol}

Party, direction, classification and compliance flag ride the join. They make
a joined finding mean something, but they are never matched on, because an
observation does not know a party from a purpose.

**The map is judgement, not measurement.** Saying that the channel called
"Partner portal" is the host ``portal.example.test`` is an architectural
inference somebody made and wrote down. Nothing here upgrades it to evidence.
It lives in a reviewable file beside the target profile
(``<stem>.flows.yaml``), and the payload echoes its provenance, so a changed
source with unchanged output is visible as a defect.

**The four kinds.** Every channel token is classified into exactly one, so the
four counts add up to the register's own row count and a reader can check the
arithmetic:

``measured``
    every declared leg joins to a row in this observation. It may still carry
    named blind spots: a measured channel is not a fully measured one.
``measured-partial``
    what was measured does not stand for the whole channel, and the map says
    which part it misses: a control riding on the transport (such as the
    cipher on an archive, or how its keys are handed over) or a leg no
    instrument can see.
``unjoined``
    the register names nothing a scanner could be pointed at. This is a data
    request. It is printed, never dropped, because these are often the
    channels the register itself calls secure, and silence reads as
    endorsement.
``not-cryptographic``
    telephone, paper, post: outside a cryptographic assessment, and shown so
    the classes still add up.

**A leg nothing here can measure.** Every collector measures a *listener*: a
service that accepts a connection on a host and port an instrument can be
pointed at. A handheld device that only dials out accepts nothing, so no
instrument sees that hop however long the scan list grows. A leg may therefore
declare ``measurable: false``. It names no host, port or protocol (a selector
would claim something in the observation could match it), it must name
``would_measure`` (the export or supplier statement that would settle it), and
it raises its own gap carrying that route out.

**Two guards, and what each costs.**

* A channel token in the register with no row in the map **raises**. This
  forbids the act: the alternative, reading the token as ``unjoined``, is
  silent and plausible, and a coverage figure that quietly dropped would
  already have circulated. The run stops until somebody edits the map.
* A declared leg that matches no row does **not** raise. This makes the
  failure cheap: a scan can be skipped or a name can move, so the leg is
  recorded as unjoined and raised as a gap, and the run finishes.

The map's own contradictions raise as well, because they need no observation
to see and are always authoring errors.

**Classification.** A register's classification column is ranked against
:data:`CLASSIFICATION_ORDER`, the New Zealand Protective Security Requirements
scheme (a public government standard). A map can replace it with its own
scale (``classification:`` in the map, see ``docs/TARGET-PROFILE.md``). A value outside
the scale is reported, never silently ranked. A trailing ``???`` is a marker
some registers use for an unknown or doubtful value; it becomes the separate field
``classification_certain`` and is never a lost suffix, and an absent value is
also recorded as not certain.

**Everything emitted is JSON-serialisable** (``str``, ``int``, ``bool``,
``list``, ``dict``). Dates are strings, read as strings.

**What this module will not say.** That an unjoined channel is insecure (it is
unmeasured: the register asserts security and nothing here holds evidence
either way); that a measured channel is safe end to end (the declared legs are
the legs somebody declared, and ``blind_spots`` names the rest); or a party
count summed across channels (parties are counted as distinct sets, because an
organisation reached two ways is one organisation).
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import config, coverage
from .model import CryptoAsset, worst

#: The ``source`` the flows plug-in's summary and gaps go under.
SOURCE = "flows"

#: The suffix of the channel map, an overlay beside the target profile.
MAP_SUFFIX = config.FLOWS_MAP_SUFFIX

#: Where the register is read from when the map names no path.
DEFAULT_REGISTER_PATH = "inbox/information-flows.json"

#: A page or script that assigns the register's rows to a constant named
#: ``RAW``. The assignment is matched and the rest handed to a real JSON
#: decoder: values hold commas, brackets and quotes, so scanning for the end
#: of the array by hand gets them wrong.
RAW_MARKER = re.compile(r"const\s+RAW\s*=\s*")

#: A marker some registers write after a classification that is unknown or doubtful.
UNCERTAINTY_MARKER = "???"

#: Separates the channels in a register row that rides more than one.
CHANNEL_SEPARATOR = ";"

KIND_MEASURED = "measured"
KIND_MEASURED_PARTIAL = "measured-partial"
KIND_UNJOINED = "unjoined"
KIND_NOT_CRYPTOGRAPHIC = "not-cryptographic"
#: The kinds, best-evidenced first.
KINDS = (KIND_MEASURED, KIND_MEASURED_PARTIAL, KIND_UNJOINED, KIND_NOT_CRYPTOGRAPHIC)

#: A heading and a one-line gloss for each kind, so every renderer words the
#: same class the same way. ``unjoined`` must never read as a verdict:
#: "insecure" and "no encryption" are claims nothing here supports, and
#: "impossible" is wrong too, because what such a channel lacks is an
#: endpoint to point an instrument at, which is a data request.
KIND_LABEL: dict[str, tuple[str, str]] = {
    KIND_MEASURED: (
        "Measured",
        "every leg the channel map declares joined to something this "
        "observation graded; a measured channel may still carry named blind "
        "spots of its own"),
    KIND_MEASURED_PARTIAL: (
        "Partly measured",
        "what was measured does not stand for the whole channel, and the map "
        "names the part it misses: a control on top of the transport, such "
        "as the cipher on an archive or how its keys are handed over, or a "
        "hop no instrument here can see, such as a handheld device that "
        "only dials out"),
    KIND_UNJOINED: (
        "Not tested — no endpoint supplied",
        "the register names no host, port or address a scanner could be "
        "pointed at, so there is no evidence for or against the security it "
        "claims. The instruments exist; what they need is an address list. "
        "This is a data request, not a finding"),
    KIND_NOT_CRYPTOGRAPHIC: (
        "No cryptography",
        "telephone, paper or post: outside a cryptographic assessment, and "
        "shown rather than dropped so the classes still add up"),
}

#: How much a kind tells you, best first. A flow riding several channels takes
#: the best-joined of them: knowing one leg beats knowing none. ``unjoined``
#: outranks ``not-cryptographic`` because an unmeasured encrypted channel is a
#: question that could still be answered, and a telephone call never will be.
KIND_RANK = {k: i for i, k in enumerate(KINDS)}

#: The order a reader should meet the channels in, which is not ``KIND_RANK``
#: reversed. The axis is how much is still unanswered: a channel nobody can
#: measure heads the list, and a telephone call, which no export changes, is
#: last.
KIND_CONCERN = (KIND_UNJOINED, KIND_MEASURED_PARTIAL, KIND_MEASURED, KIND_NOT_CRYPTOGRAPHIC)
CONCERN_RANK = {k: i for i, k in enumerate(KIND_CONCERN)}

#: The New Zealand Protective Security Requirements classification scheme,
#: lowest first: the business-impact levels, then the national-security
#: levels above them. A published government scheme, so it can ship as
#: default data; a map's ``classification: scale:`` replaces it.
CLASSIFICATION_ORDER = {
    "UNCLASSIFIED": 0,
    "IN-CONFIDENCE": 1,
    "SENSITIVE": 2,
    "RESTRICTED": 3,
    "CONFIDENTIAL": 4,
    "SECRET": 5,
    "TOP SECRET": 6,
}

#: The classification from which a flow is counted as sensitive.
SENSITIVITY_FLOOR = "IN-CONFIDENCE"

# The register columns read by name. Every other column is carried through
# untouched in ``Flow.extra``, so an export's own words for its parties and
# groupings never have to be written into this module.
FIELD_ID = "flow_id"
FIELD_DIRECTION = "direction"
FIELD_PARTY = "external_party"
FIELD_CHANNEL = "channel"
FIELD_CLASSIFICATION = "classification"
FIELD_COMPLIANCE = "compliance_flag"
KNOWN_FIELDS = (FIELD_ID, FIELD_DIRECTION, FIELD_PARTY, FIELD_CHANNEL,
                FIELD_CLASSIFICATION, FIELD_COMPLIANCE)

#: What kind of thing a named blind spot is. They are three different
#: unanswered questions and a reader acts on each differently: ``leg`` is
#: another hop nobody measured; ``control`` is something riding on a measured
#: transport, whose verdict says nothing about it; ``routing`` is not knowing
#: which of several paths is taken at all. Only ``control`` makes a channel
#: ``measured-partial``.
SCOPES = ("leg", "control", "routing")

#: The ``extra`` key the plug-in writes onto the rows a flow rides.
EXTRA_KEY = "flows"


class RegisterError(ValueError):
    """The register could not be read as a register.

    Raised by the parsers only. :func:`read_register` turns it into a reason,
    and :func:`build` into a coverage gap: a missing or malformed export is a
    fact about the inputs, not a bug.
    """


class FlowMapError(ValueError):
    """The channel map contradicts itself or does not cover the register.

    Guard class: forbids the act. Both failures are errors in a file a person
    wrote, and either would otherwise surface as a coverage figure that reads
    correct and is not.
    """


# ── the model ─────────────────────────────────────────────────────────────

def scale_rank(scale: Mapping[str, int] | None = None) -> Mapping[str, int]:
    """``scale``, or the default scheme when it is None."""
    return CLASSIFICATION_ORDER if scale is None else scale


@dataclass(frozen=True)
class Flow:
    """One register row, normalised.

    ``channels`` is the multi-valued channel field split and stripped: a flow
    that names three channels rides all three, and counting the raw string
    would lose every such flow.
    """

    flow_id: str
    direction: str
    party: str
    channels: tuple[str, ...]
    classification: str
    classification_certain: bool
    compliance_flag: str
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def sensitivity(self) -> int | None:
        """The classification's rank in the default scheme, or None when absent or unknown."""
        return CLASSIFICATION_ORDER.get(self.classification)

    def at_or_above(self, floor: str = SENSITIVITY_FLOOR,
                    scale: Mapping[str, int] | None = None) -> bool:
        """Whether the flow is classified at ``floor`` or higher on ``scale``."""
        ranks = scale_rank(scale)
        rank = ranks.get(self.classification)
        return rank is not None and rank >= ranks[floor]


@dataclass(frozen=True)
class Leg:
    """One hop of a channel: a selector an instrument can be pointed at, or a
    named hop nothing here can reach.

    ``host``, ``port`` and ``protocols`` are ANDed when given. A leg with a
    host and no port matches every port measured on that host.

    A leg with ``measurable=False`` is the second shape. It carries no
    selector at all, matches nothing by construction, and carries
    ``would_measure``: the export or statement that would settle it. ``gap`` is
    the optional data-request id that would close the leg.
    """

    label: str
    host: str = ""
    port: str = ""
    protocols: tuple[str, ...] = ()
    measurable: bool = True
    would_measure: str = ""
    gap: str = ""

    def matches(self, asset: CryptoAsset) -> bool:
        """Whether ``asset`` is a row of this leg. An unmeasurable leg matches nothing, ever."""
        if not self.measurable:
            return False
        if self.host and (asset.host or "").lower() != self.host.lower():
            return False
        if self.port and str(asset.port or "") != self.port:
            return False
        if self.protocols and (asset.protocol or "").lower() not in self.protocols:
            return False
        return True

    def as_dict(self) -> dict:
        """The leg as the payload holds it. Only non-default fields appear."""
        out: dict = {"leg": self.label}
        if self.host:
            out["host"] = self.host
        if self.port:
            out["port"] = self.port
        if self.protocols:
            out["protocols"] = list(self.protocols)
        if not self.measurable:
            out["measurable"] = False
            out["would_measure"] = self.would_measure
        if self.gap:
            out["gap"] = self.gap
        return out


@dataclass(frozen=True)
class BlindSpot:
    """Something the map's author knows is not measured, named so it can be chased.

    ``scope`` is one of :data:`SCOPES`.
    """

    what: str
    gap: str
    scope: str = "leg"

    def as_dict(self) -> dict:
        return {"what": self.what, "gap": self.gap, "scope": self.scope}


@dataclass(frozen=True)
class Request:
    """A data request the map names, and who could answer it.

    ``owner`` is who holds the answer and ``asked`` the date somebody asked.
    They are two fields because "nobody has asked" and "asked three weeks ago
    and no answer" are different findings with different next steps.
    """

    id: str
    title: str = ""
    owner: str = ""
    asked: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "owner": self.owner,
                "asked": self.asked, "note": self.note}

    def attribution(self) -> str:
        """One sentence saying who owes the answer, worded so that an unasked
        request cannot be mistaken for an unanswered one."""
        if not self.owner:
            return ("No owner is recorded for this request, so nobody has yet been "
                    "named who could answer it")
        if self.asked:
            return (f"Asked on {self.asked} and no answer is held yet. Asked of: "
                    f"{self.owner}")
        return f"Not yet requested. Who holds the answer: {self.owner}"


@dataclass(frozen=True)
class Channel:
    """One declared channel token: its kind, legs, blind spots and data request."""

    token: str
    kind: str
    legs: tuple[Leg, ...] = ()
    blind_spots: tuple[BlindSpot, ...] = ()
    gap: str = ""
    note: str = ""

    @property
    def unmeasurable_legs(self) -> tuple[Leg, ...]:
        """The declared hops no instrument here can reach."""
        return tuple(leg for leg in self.legs if not leg.measurable)

    @property
    def data_requests(self) -> list[str]:
        """The request ids this channel owes: from its blind spots, its legs and itself."""
        ids = [b.gap for b in self.blind_spots if b.gap]
        ids += [leg.gap for leg in self.legs if leg.gap]
        if self.gap:
            ids.append(self.gap)
        return sorted(set(ids))


# ── reading the register ──────────────────────────────────────────────────

def _split_channels(value: object) -> tuple[str, ...]:
    tokens = [t.strip() for t in str(value or "").split(CHANNEL_SEPARATOR)]
    return tuple(t for t in tokens if t)


def _classification(value: object) -> tuple[str, bool]:
    """``("SENSITIVE", False)`` from ``"SENSITIVE???"``; ``("", False)`` from nothing.

    An absent value is not certain: recording it as certain would let a row
    nobody assessed sit beside one somebody did.
    """
    text = str(value or "").strip()
    if not text:
        return "", False
    if text.endswith(UNCERTAINTY_MARKER):
        return text[: -len(UNCERTAINTY_MARKER)].strip(), False
    return text, True


def _flow(row: dict, ordinal: int) -> Flow:
    level, certain = _classification(row.get(FIELD_CLASSIFICATION))
    extra = {str(k): "" if v is None else str(v)
             for k, v in row.items() if k not in KNOWN_FIELDS}
    return Flow(
        flow_id=str(row.get(FIELD_ID) or ordinal),
        direction=str(row.get(FIELD_DIRECTION) or "").strip(),
        party=str(row.get(FIELD_PARTY) or "").strip(),
        channels=_split_channels(row.get(FIELD_CHANNEL)),
        classification=level,
        classification_certain=certain,
        compliance_flag=str(row.get(FIELD_COMPLIANCE) or "").strip(),
        extra=extra,
    )


def _flows_from(rows: list) -> list[Flow]:
    return [_flow(row, i) for i, row in enumerate(rows, 1) if isinstance(row, dict)]


def parse_register(text: str) -> list[Flow]:
    """The flows in a register held as text.

    Two shapes are read: a page or script that assigns a JSON array of rows to
    a constant named ``RAW`` (``const RAW = [...]``), and a file that is
    itself a JSON array of rows, or an object whose ``flows`` key holds one.
    The parser keeps looking past a ``RAW`` match that does not decode, because
    the marker can appear in a comment or in prose before the real assignment.
    """
    for match in RAW_MARKER.finditer(text):
        try:
            value, _ = json.JSONDecoder().raw_decode(text, match.end())
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return _flows_from(value)
    if text.lstrip()[:1] in ("[", "{"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict):
            value = value.get("flows")
        if isinstance(value, list):
            return _flows_from(value)
    raise RegisterError(
        "no decodable register found: this does not look like a register export "
        "(expected a CSV file, a JSON array of rows, or a `const RAW = [...]` assignment)")


def parse_register_csv(text: str) -> list[Flow]:
    """The flows in a CSV register: one row per flow, the columns named as the
    ``FIELD_*`` constants say, any further column carried through."""
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise RegisterError("the CSV has no header row, so this does not look like a "
                            "register export")
    rows = []
    for raw in reader:
        row = {k: (v or "") for k, v in raw.items() if k is not None and isinstance(v, str)}
        if any(v.strip() for v in row.values()):
            rows.append(row)
    return _flows_from(rows)


def read_register(path: Path) -> tuple[list[Flow], str]:
    """``(flows, "")``, or ``([], reason)``: never an exception, never a silent empty.

    A ``.csv`` file is read as CSV; anything else as :func:`parse_register`
    reads it. The caller turns a reason into a coverage gap.
    """
    if not path.exists():
        return [], "file not present"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], str(exc)
    try:
        flows = parse_register_csv(text) if path.suffix.lower() == ".csv" \
            else parse_register(text)
    except RegisterError as exc:
        return [], str(exc)
    if not flows:
        return [], "the export decoded but declared no flows"
    return flows, ""


# ── the declared channel map ──────────────────────────────────────────────

def _oneline(text: object) -> str:
    """A folded YAML scalar as one line, so no newline lands mid-sentence in a gap."""
    return " ".join(str(text or "").split())


def _legs(token: str, raw: object) -> tuple[Leg, ...]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise FlowMapError(f"channel {token!r}: `legs:` must be a list")
    out: list[Leg] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise FlowMapError(f"channel {token!r}: each leg must be a mapping")
        protocols = entry.get("protocol") or entry.get("protocols") or []
        if isinstance(protocols, str):
            protocols = [protocols]
        leg = Leg(
            label=str(entry.get("leg") or "leg"),
            host=str(entry.get("host") or "").strip(),
            port=str(entry.get("port") or "").strip(),
            protocols=tuple(str(p).strip().lower() for p in protocols if str(p).strip()),
            # Absent means measurable.
            measurable=bool(entry.get("measurable", True)),
            would_measure=_oneline(entry.get("would_measure")),
            gap=str(entry.get("gap") or "").strip(),
        )
        where = f"channel {token!r}, leg {leg.label!r}"
        if leg.measurable:
            if not leg.host and not leg.protocols:
                raise FlowMapError(
                    f"{where}: a leg must name a host or a protocol, or it selects "
                    "the whole observation")
            if leg.would_measure:
                raise FlowMapError(
                    f"{where}: `would_measure:` says what would settle a leg no "
                    "instrument here can reach, so it contradicts a leg that names a "
                    "host or a protocol. Drop it, or declare the leg `measurable: false`")
        else:
            if leg.host or leg.port or leg.protocols:
                raise FlowMapError(
                    f"{where}: a leg declared `measurable: false` must name no host, "
                    "port or protocol: a selector claims something in this observation "
                    "could match it, and the declaration says nothing can")
            if not leg.would_measure:
                raise FlowMapError(
                    f"{where}: a leg declared `measurable: false` must name "
                    "`would_measure:`, the export or supplier statement that would "
                    "settle it. An unmeasurable hop with no route out is a shrug, "
                    "not a finding")
        out.append(leg)
    return tuple(out)


def _blind_spots(token: str, raw: object) -> tuple[BlindSpot, ...]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise FlowMapError(f"channel {token!r}: `unmeasured:` must be a list")
    out: list[BlindSpot] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise FlowMapError(f"channel {token!r}: each unmeasured entry must be a mapping")
        what = str(entry.get("what") or "").strip()
        gap = str(entry.get("gap") or "").strip()
        if not what or not gap:
            raise FlowMapError(
                f"channel {token!r}: an unmeasured entry needs both `what` (what is not "
                "measured) and `gap` (the data-request id that would close it); an "
                "unnamed blind spot cannot be chased")
        scope = str(entry.get("scope") or "leg").strip()
        if scope not in SCOPES:
            raise FlowMapError(
                f"channel {token!r}: unmeasured `scope` must be one of {', '.join(SCOPES)} "
                "('leg' is another hop, 'control' is something riding on the transport, "
                f"'routing' is not knowing which path is taken), not {scope!r}")
        out.append(BlindSpot(what=what, gap=gap, scope=scope))
    return tuple(out)


def build_channel_map(doc: Mapping) -> dict[str, Channel]:
    """Validate a ``channels:`` block into :class:`Channel` objects.

    Every contradiction found here is internal to the declaration, which is why
    it raises :class:`FlowMapError` rather than becoming a gap.
    """
    channels: dict[str, Channel] = {}
    for token, spec in (doc.get("channels") or {}).items():
        token = str(token)
        if not isinstance(spec, dict):
            raise FlowMapError(
                f"channel {token!r}: expected a mapping, got {type(spec).__name__}")
        kind = str(spec.get("kind") or "").strip()
        if kind not in KINDS:
            raise FlowMapError(
                f"channel {token!r}: kind {kind!r} is not one of {', '.join(KINDS)}")
        legs = _legs(token, spec.get("legs"))
        blind = _blind_spots(token, spec.get("unmeasured"))
        gap = str(spec.get("gap") or "").strip()
        has_unmeasurable = any(not leg.measurable for leg in legs)

        if kind in (KIND_MEASURED, KIND_MEASURED_PARTIAL) and not any(
                leg.measurable for leg in legs):
            raise FlowMapError(
                f"channel {token!r} is declared {kind!r} but names no leg to measure: "
                "say `unjoined` and give it a data-request id instead")
        if kind == KIND_MEASURED and has_unmeasurable:
            raise FlowMapError(
                f"channel {token!r} is declared {KIND_MEASURED!r} and declares a leg "
                "with `measurable: false`. A channel with a hop no instrument can "
                "reach is not measured on every leg: declare it "
                f"{KIND_MEASURED_PARTIAL!r}")
        if kind == KIND_MEASURED_PARTIAL and not (
                any(b.scope == "control" for b in blind) or has_unmeasurable):
            raise FlowMapError(
                f"channel {token!r} is declared {KIND_MEASURED_PARTIAL!r}, which means "
                "the measured legs do not stand for the whole channel, and the map must "
                "say which part they miss. Name a control on top of the transport under "
                "`unmeasured:` with `scope: control`, or declare a leg "
                f"`measurable: false` with `would_measure:`, or declare the channel "
                f"{KIND_MEASURED!r}")
        if kind == KIND_UNJOINED:
            if any(leg.measurable for leg in legs):
                raise FlowMapError(
                    f"channel {token!r} is declared {KIND_UNJOINED!r} but names legs: a "
                    "channel with something to point a scanner at is not unjoined")
            if legs:
                raise FlowMapError(
                    f"channel {token!r} is declared {KIND_UNJOINED!r} and names a leg with "
                    "`measurable: false`. An unmeasurable leg hangs off a measured "
                    "transport; an unjoined channel has no measured transport, so record "
                    "the hop under `unmeasured:` with its `gap:` instead")
            if not gap:
                raise FlowMapError(
                    f"channel {token!r} is {KIND_UNJOINED!r} and must carry a `gap:` "
                    "data-request id, or the coverage it costs is recorded nowhere")
        if kind == KIND_NOT_CRYPTOGRAPHIC and (legs or gap or blind):
            raise FlowMapError(
                f"channel {token!r} is {KIND_NOT_CRYPTOGRAPHIC!r}: there is no "
                "cryptography to measure, so a leg, a gap or an unmeasured control on it "
                "is a contradiction")
        channels[token] = Channel(token=token, kind=kind, legs=legs, blind_spots=blind,
                                  gap=gap, note=str(spec.get("note") or "").strip())
    return channels


def build_requests(doc: Mapping) -> dict[str, Request]:
    """Validate a ``data_requests:`` block into :class:`Request` objects.

    The block is optional (an id with no declaration reads as unowned, loudly),
    but an entry that says nothing raises: a request with no title or no owner
    cannot be chased and is indistinguishable in a report from no row at all.
    """
    out: dict[str, Request] = {}
    for rid, spec in (doc.get("data_requests") or {}).items():
        rid = str(rid)
        if not isinstance(spec, dict):
            raise FlowMapError(
                f"data request {rid!r}: expected a mapping, got {type(spec).__name__}")
        title = str(spec.get("title") or "").strip()
        owner = str(spec.get("owner") or "").strip()
        if not title:
            raise FlowMapError(
                f"data request {rid!r}: needs a `title:`, the short name of what is being "
                "asked for, in words a reader of the report will understand without the id")
        if not owner:
            raise FlowMapError(
                f"data request {rid!r}: needs an `owner:`, who holds the answer. A request "
                "nobody owns cannot be chased")
        out[rid] = Request(id=rid, title=_oneline(title), owner=_oneline(owner),
                           asked=str(spec.get("asked") or "").strip(),
                           note=_oneline(spec.get("note")))
    return out


def build_scale(doc: Mapping) -> tuple[dict[str, int] | None, str]:
    """The ``(scale, floor)`` a map's ``classification:`` block declares.

    ``(None, SENSITIVITY_FLOOR)`` when the map declares none, so the default
    scheme applies. The block holds ``scale:`` (a list of the register's own
    classification values, lowest first) and optionally ``floor:`` (the value
    from which a flow counts as sensitive; default: the second value, or the
    only one).
    """
    raw = doc.get("classification")
    if raw is None:
        return None, SENSITIVITY_FLOOR
    if not isinstance(raw, dict) or set(raw) - {"scale", "floor"}:
        raise FlowMapError("`classification:` takes only `scale:` and `floor:`")
    values = raw.get("scale")
    if (not isinstance(values, list) or not values
            or any(not isinstance(v, str) or not v.strip() for v in values)):
        raise FlowMapError("`classification: scale:` must be a list of the register's "
                           "classification values, lowest first")
    names = [v.strip() for v in values]
    if len(set(names)) != len(names):
        raise FlowMapError("`classification: scale:` names a value twice")
    floor = str(raw.get("floor") or "").strip() or names[min(1, len(names) - 1)]
    if floor not in names:
        raise FlowMapError(f"`classification: floor:` {floor!r} is not in the scale")
    return {n: i for i, n in enumerate(names)}, floor


def map_path_for_target(target: Mapping) -> Path | None:
    """``targets/acme.yaml`` gives ``targets/acme.flows.yaml``, or None when absent.

    A convention rather than a setting, so a profile cannot point at another
    organisation's map through a stale path.
    """
    tpath = target.get("_path")
    if not tpath:
        return None
    p = Path(str(tpath))
    if not p.suffix:
        return None
    cand = p.with_name(p.name[: -len(p.suffix)] + MAP_SUFFIX)
    return cand if cand.exists() else None


def load_map(path: Path) -> dict:
    """Read the map strictly: a repeated ``channels:`` key would silently discard
    half of what a person wrote (:func:`takestock.config.load_yaml_strict`)."""
    return config.load_yaml_strict(path) or {}


def register_path_for_target(target: Mapping) -> str:
    """The register path a target's map declares, or :data:`DEFAULT_REGISTER_PATH`.

    Reads the map's ``register.path`` and nothing else, so a caller that needs
    only the register (not the join) finds the same file :func:`build` does.
    """
    path = map_path_for_target(target)
    if path is None:
        return DEFAULT_REGISTER_PATH
    declared = (load_map(path).get("register") or {}).get("path")
    return str(declared or DEFAULT_REGISTER_PATH)


# ── the join ──────────────────────────────────────────────────────────────

def _asset_key(asset: CryptoAsset) -> str:
    return asset.name


def join(flows: Sequence[Flow], channels: Mapping[str, Channel],
         assets: Iterable[CryptoAsset], register: Mapping | None = None,
         floor: str = SENSITIVITY_FLOOR,
         requests: Mapping[str, Request] | None = None,
         scale: Mapping[str, int] | None = None) -> dict:
    """The whole payload: per flow, per channel token, per asset and in total.

    Raises :class:`FlowMapError` when the register names a channel the map
    does not (see the module docstring for why that stops the run).
    """
    asset_list = list(assets)
    ranks = scale_rank(scale)
    if floor not in ranks:
        raise FlowMapError(f"the sensitivity floor {floor!r} is not in the classification scale")

    unmapped = sorted({t for f in flows for t in f.channels if t not in channels})
    if unmapped:
        raise FlowMapError(
            "the register names channel(s) the channel map does not cover: "
            + ", ".join(repr(t) for t in unmapped)
            + ". Add a row for each to the target's `.flows.yaml`, with a `kind:` of "
            "measured, measured-partial, unjoined or not-cryptographic. Treating an "
            "unknown channel as unjoined would drop coverage with nothing saying so.")

    # Resolve each channel's legs against this observation, once.
    channel_assets: dict[str, list[CryptoAsset]] = {}
    channel_legs: dict[str, list[dict]] = {}
    for token, chan in channels.items():
        matched: dict[str, CryptoAsset] = {}
        legs_out: list[dict] = []
        for leg in chan.legs:
            hits = [a for a in asset_list if leg.matches(a)]
            for a in hits:
                matched[_asset_key(a)] = a
            entry = leg.as_dict()
            entry["assets"] = len(hits)
            entry["joined"] = bool(hits)
            entry["verdict"] = worst([a.verdict for a in hits]) if hits else ""
            legs_out.append(entry)
        channel_assets[token] = list(matched.values())
        channel_legs[token] = legs_out

    def sensitive(f: Flow) -> bool:
        return f.at_or_above(floor, ranks)

    flow_rows: list[dict] = []
    for f in flows:
        kinds = [channels[t].kind for t in f.channels]
        best = min(kinds, key=lambda k: KIND_RANK[k]) if kinds else KIND_UNJOINED
        names = sorted({_asset_key(a) for t in f.channels for a in channel_assets[t]})
        verdicts = [a.verdict for t in f.channels for a in channel_assets[t]]
        flow_requests = sorted({g for t in f.channels for g in channels[t].data_requests})
        flow_rows.append({
            "flow_id": f.flow_id,
            "direction": f.direction,
            "party": f.party,
            "channels": list(f.channels),
            "channel_kinds": kinds,
            "kind": best,
            "classification": f.classification,
            "classification_certain": f.classification_certain,
            "sensitive": sensitive(f),
            "compliance_flag": f.compliance_flag,
            "assets": names,
            "worst_verdict": worst(verdicts) if verdicts else "",
            "data_requests": flow_requests,
            # The register's other columns, untouched: who is on the far end,
            # what travels, who owns it. This module has no words of its own
            # for any of them.
            "extra": dict(f.extra),
        })

    channel_rows: list[dict] = []
    for token, chan in channels.items():
        riders = [f for f in flows if token in f.channels]
        chan_assets = channel_assets[token]
        channel_rows.append({
            "channel": token,
            "kind": chan.kind,
            "flows": len(riders),
            "parties": len({f.party for f in riders if f.party}),
            "sensitive_flows": sum(1 for f in riders if sensitive(f)),
            "uncertain_flows": sum(1 for f in riders if not f.classification_certain),
            "inbound": sum(1 for f in riders if f.direction.lower() == "inbound"),
            "outbound": sum(1 for f in riders if f.direction.lower() == "outbound"),
            "legs": channel_legs[token],
            "legs_unjoined": [leg["leg"] for leg in channel_legs[token] if not leg["joined"]],
            # A subset of `legs_unjoined`: an unmeasurable leg is genuinely
            # absent from the observation, and what this list adds is why: no
            # rerun closes it, so nobody should schedule one.
            "legs_unmeasurable": [leg.label for leg in chan.unmeasurable_legs],
            "blind_spots": [b.as_dict() for b in chan.blind_spots],
            "gap": chan.gap,
            "data_requests": chan.data_requests,
            "assets": sorted(_asset_key(a) for a in chan_assets),
            "worst_verdict": worst([a.verdict for a in chan_assets]) if chan_assets else "",
            "note": chan.note,
            "flow_ids": [f.flow_id for f in riders],
        })
    # Least evidence first, then the most sensitive traffic.
    channel_rows.sort(key=lambda r: (CONCERN_RANK[r["kind"]], -r["sensitive_flows"],
                                     -r["flows"], r["channel"]))

    by_class: dict[str, int] = {k: 0 for k in KINDS}
    parties_by_class: dict[str, set[str]] = {k: set() for k in KINDS}
    sensitive_by_class: dict[str, int] = {k: 0 for k in KINDS}
    for row in flow_rows:
        by_class[row["kind"]] += 1
        if row["party"]:
            parties_by_class[row["kind"]].add(row["party"])
        if row["sensitive"]:
            sensitive_by_class[row["kind"]] += 1

    crosstab: dict[str, dict[str, int]] = {}
    for row in flow_rows:
        bucket = crosstab.setdefault(row["compliance_flag"] or "(unrecorded)",
                                     {k: 0 for k in KINDS})
        bucket[row["kind"]] += 1

    unrecognised = sorted({f.classification for f in flows
                           if f.classification and f.classification not in ranks})
    request_ids = sorted({g for c in channels.values() for g in c.data_requests})
    declared = requests or {}

    # The reverse index, so a row in an inventory can say what rides it.
    by_asset: dict[str, dict] = {}
    for row in channel_rows:
        for name in row["assets"]:
            entry = by_asset.setdefault(name, {
                "channels": [], "flows": 0, "parties": 0, "sensitive_flows": 0,
                "data_requests": [], "flow_ids": []})
            entry["channels"].append(row["channel"])
            entry["flow_ids"] += row["flow_ids"]
    for entry in by_asset.values():
        ids = set(entry.pop("flow_ids"))
        riders = [f for f in flows if f.flow_id in ids]
        entry["flows"] = len(riders)
        # Distinct parties across the asset's channels, never the sum of the
        # per-channel counts.
        entry["parties"] = len({f.party for f in riders if f.party})
        entry["sensitive_flows"] = sum(1 for f in riders if sensitive(f))
        entry["data_requests"] = sorted(
            {g for c in entry["channels"] for g in channels[c].data_requests})
        entry["channels"] = sorted(entry["channels"])

    payload = {
        "basis": "declared-mapping",
        "register": dict(register or {}),
        "sensitivity_floor": floor,
        "flows": flow_rows,
        "channels": channel_rows,
        "by_asset": by_asset,
        # Every named request, keyed by id so a renderer resolves an id it
        # meets on a channel row without a second pass. An id with no
        # declaration is simply absent.
        "requests": {rid: declared[rid].as_dict() for rid in request_ids if rid in declared},
        "totals": {
            "flows": len(flows),
            "by_class": by_class,
            "joined": by_class[KIND_MEASURED] + by_class[KIND_MEASURED_PARTIAL],
            "parties": len({f.party for f in flows if f.party}),
            "parties_by_class": {k: len(v) for k, v in parties_by_class.items()},
            "parties_joined": len(parties_by_class[KIND_MEASURED]
                                  | parties_by_class[KIND_MEASURED_PARTIAL]),
            "sensitive_flows": sum(1 for f in flows if sensitive(f)),
            "sensitive_by_class": sensitive_by_class,
            "uncertain_flows": sum(1 for f in flows if not f.classification_certain),
            "inbound": sum(1 for f in flows if f.direction.lower() == "inbound"),
            "outbound": sum(1 for f in flows if f.direction.lower() == "outbound"),
            "channels": len(channels),
            "unrecognised_classifications": unrecognised,
            "data_requests": request_ids,
        },
        "compliance_by_class": crosstab,
    }
    if scale is not None:
        payload["classification_scale"] = sorted(scale, key=lambda k: scale[k])
    return payload


def empty_payload() -> dict:
    """What a workspace with no channel map yields: the shape of a real payload,
    so every reader is written once."""
    return {
        "basis": "declared-mapping",
        "register": {},
        "sensitivity_floor": SENSITIVITY_FLOOR,
        "flows": [],
        "channels": [],
        "by_asset": {},
        "requests": {},
        "totals": {
            "flows": 0,
            "by_class": {k: 0 for k in KINDS},
            "joined": 0,
            "parties": 0,
            "parties_by_class": {k: 0 for k in KINDS},
            "parties_joined": 0,
            "sensitive_flows": 0,
            "sensitive_by_class": {k: 0 for k in KINDS},
            "uncertain_flows": 0,
            "inbound": 0,
            "outbound": 0,
            "channels": 0,
            "unrecognised_classifications": [],
            "data_requests": [],
        },
        "compliance_by_class": {},
    }


# ── the entry point ───────────────────────────────────────────────────────

def _unmeasurable_leg_gap(row: Mapping, leg: Mapping, requests: Mapping[str, Request],
                          floor: str) -> coverage.Gap:
    request = str(leg.get("gap") or "")
    req = requests.get(request) or Request(id=request)
    owner = f" {req.attribution()}." if request else ""
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"channel {row['channel']!r}, leg {leg['leg']!r}: a declared hop that no instrument "
        "here can measure. Every instrument measures a listener, a service that accepts a "
        "connection, and this hop has none to point an instrument at, so no further scanning "
        f"closes it. {row['flows']} recorded flow(s), {row['sensitive_flows']} of them at "
        f"{floor} or above, ride this channel." + owner,
        impact=(f"The verdict shown for {row['channel']!r} describes the legs that were "
                "measured and says nothing about this one. If this hop is weaker than they "
                "are, a reader who takes the channel's verdict as the channel's protection "
                "is reading a stronger claim than the evidence supports."),
        impact_kind=coverage.CHANGES_CONCLUSION,
        harvest=str(leg.get("would_measure") or ""),
        nature=coverage.NO_DATA)


def _unjoined_leg_gap(row: Mapping, leg: str) -> coverage.Gap:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"channel {row['channel']!r}, leg {leg!r}: the channel map declares it, and this "
        "observation holds no row matching it, so the "
        f"{row['flows']} flow(s) riding that channel are joined on the remaining legs only",
        impact=("The channel's verdict describes the legs that were joined and says nothing "
                "about this one. If this hop is weaker than they are, the verdict is wrong "
                "rather than narrow."),
        impact_kind=coverage.CHANGES_CONCLUSION,
        harvest=("Run again once a row matches the declared leg, or correct the leg's host "
                 "or protocol in the channel map."),
        nature=coverage.NO_DATA)


def _request_gap(request: str, payload: Mapping, requests: Mapping[str, Request],
                 floor: str) -> coverage.Gap:
    blocked = [r for r in payload["channels"] if request in r["data_requests"]]
    flows_blocked = sum(r["flows"] for r in blocked)
    sensitive = sum(r["sensitive_flows"] for r in blocked)
    names = ", ".join(sorted(r["channel"] for r in blocked))
    unnamed = [r["channel"] for r in blocked if r["gap"] == request]
    # A blind spot names something beside the declared legs; an unmeasurable
    # leg is a declared leg with nothing to point an instrument at. Both can
    # own a request, and the sentence needs a subject whichever does.
    spots = sorted(
        {b["what"] for r in blocked for b in r["blind_spots"] if b["gap"] == request}
        | {f"the {leg['leg']} leg" for r in blocked for leg in r["legs"]
           if not leg.get("measurable", True) and leg.get("gap") == request})
    if unnamed:
        what = f"the register names no endpoint a scanner could be pointed at for {names}"
    elif not spots:
        what = f"{names} is measured on its declared legs"
    else:
        what = (f"{names} is measured on the legs an instrument can reach, but "
                + "; ".join(spots) + " is not")
    req = requests.get(request) or Request(id=request)
    title = f" ({req.title})" if req.title else ""
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"data request {request}{title}: {what}. {flows_blocked} recorded flow(s), "
        f"{sensitive} of them at {floor} or above, travel this way with no evidence either "
        f"for or against the security the register claims for them. {req.attribution()}",
        impact=("The flows riding these channels have no evidence either for or against the "
                "security the register claims for them. A reader who takes that claim as "
                "verified is taking it on the register's word."),
        impact_kind=coverage.CHANGES_CONCLUSION,
        harvest="The named data request, from the party the gap already attributes it to.",
        nature=coverage.NO_DATA)


def build(target: Mapping, repo: Path | None, assets: Iterable[CryptoAsset], *,
          map_path: Path | None = None) -> tuple[dict, list[coverage.Gap]]:
    """The payload and its coverage gaps, for a loaded target profile.

    ``repo`` is the workspace the register path is resolved against (None: the
    workspace in effect). ``map_path`` names the channel map; without it the
    map is the profile's ``<stem>.flows.yaml`` overlay.

    Degrades rather than crashes, and each step is different:

    * no map: the organisation records no flows. The empty payload and no gap,
      because a workspace with nothing declared is not missing an export;
    * a map and no export: a real gap, and the payload says so rather than
      reporting zero flows as if that were the answer;
    * a map that contradicts itself: raises :class:`FlowMapError`.
    """
    gaps: list[coverage.Gap] = []
    path = map_path if map_path is not None else map_path_for_target(target)
    if path is None:
        return empty_payload(), gaps

    doc = load_map(path)
    channels = build_channel_map(doc)
    requests = build_requests(doc)
    scale, floor = build_scale(doc)
    # Declared values are emitted as strings: a date object in a payload
    # breaks JSON serialisation at the last step of a run.
    register = {k: ("" if v is None else str(v))
                for k, v in dict(doc.get("register") or {}).items()}
    # `source` is echoed in display form (underscores as spaces): a file name
    # of mixed case, digits and underscores trips entropy-based secret
    # scanners wherever it lands in a JSON summary. The change is
    # deterministic, so a re-issued register still changes the echo.
    if isinstance(register.get("source"), str):
        register["source"] = register["source"].replace("_", " ")

    declared = str(register.get("path") or DEFAULT_REGISTER_PATH)
    flows, unreadable = read_register(config.inbox_path(declared, repo))
    if not flows:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            f"{declared} (the information-sharing register export): which information "
            "flows ride which measured channel, to which outside organisations, at what "
            "classification. Without it every finding keeps its cryptographic severity and "
            "loses its business impact" + (f"; {unreadable}" if unreadable else ""),
            impact=("Findings keep their cryptographic severity and lose their business "
                    "weight: a weak cipher on a channel carrying nothing ranks alongside one "
                    "carrying sensitive records to an outside organisation. A reader cannot "
                    "order remediation by what each finding would expose."),
            impact_kind=coverage.CHANGES_CONCLUSION,
            harvest="The information-sharing register export at the declared path.",
            nature=coverage.NO_DATA))
        payload = empty_payload()
        payload["register"] = register
        return payload, gaps

    payload = join(flows, channels, assets, register=register, requests=requests,
                   floor=floor, scale=scale)

    # A declared leg this observation holds no row for is loud but not fatal.
    # The two reasons read alike and are filed differently: a measurable leg
    # with no row is could-not-test (a probe was skipped or a name moved, and
    # the next run may close it); an unmeasurable leg is not-collected (no run
    # ever will, because somebody has to hand over an artefact).
    for row in payload["channels"]:
        unmeasurable = set(row["legs_unmeasurable"])
        for leg in row["legs_unjoined"]:
            if leg not in unmeasurable:
                gaps.append(_unjoined_leg_gap(row, leg))
        for leg in row["legs"]:
            if not leg.get("measurable", True):
                gaps.append(_unmeasurable_leg_gap(row, leg, requests, floor))

    # Each named data request once, with what it would unblock.
    for request in payload["totals"]["data_requests"]:
        gaps.append(_request_gap(request, payload, requests, floor))
    return payload, gaps


# ── back onto the inventory ───────────────────────────────────────────────

def carries_sentence(entry: Mapping, floor: str = SENSITIVITY_FLOOR) -> str:
    """What one asset carries, in one line.

    A string, not a structure: ``extra`` is shown as a flat list, and a
    mapping there prints as ``[object Object]``. The structured form stays in
    the payload (``by_asset``).
    """
    flows_n = int(entry.get("flows") or 0)
    if not flows_n:
        return ""
    parties = int(entry.get("parties") or 0)
    sensitive = int(entry.get("sensitive_flows") or 0)
    channels = list(entry.get("channels") or [])
    org = "organisation" if parties == 1 else "organisations"
    out = (f"{flows_n} recorded information flow{'' if flows_n == 1 else 's'} "
           f"to {parties} {org}")
    if sensitive:
        out += f", {sensitive} at {floor} or above"
    if channels:
        out += " — channel: " + "; ".join(channels)
    return out


def annotate(assets: Iterable[CryptoAsset], payload: Mapping) -> int:
    """Write ``extra["flows"]`` onto every row the register's flows ride.

    Idempotent: the key is rewritten from the payload every time, and removed
    from a row nothing rides. Returns how many rows were annotated.
    """
    by_asset = dict(payload.get("by_asset") or {})
    floor = str(payload.get("sensitivity_floor") or SENSITIVITY_FLOOR)
    n = 0
    for a in assets:
        entry = by_asset.get(_asset_key(a))
        sentence = carries_sentence(entry, floor) if entry else ""
        if sentence:
            a.extra[EXTRA_KEY] = sentence
            n += 1
        else:
            a.extra.pop(EXTRA_KEY, None)
    return n


def row_annotations(assets: Iterable[CryptoAsset], payload: Mapping) -> dict[str, dict]:
    """``{bom_ref: {"flows": sentence}}`` for every row the payload's flows ride.

    What an annotation plug-in hands back (:class:`takestock.plugins.StepResult`).
    The rows are not changed.
    """
    by_asset = dict(payload.get("by_asset") or {})
    floor = str(payload.get("sensitivity_floor") or SENSITIVITY_FLOOR)
    out: dict[str, dict] = {}
    for a in assets:
        entry = by_asset.get(_asset_key(a))
        sentence = carries_sentence(entry, floor) if entry else ""
        if sentence:
            out[a.bom_ref()] = {EXTRA_KEY: sentence}
    return out
