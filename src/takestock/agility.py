"""When an algorithm has to change, what has to happen for each asset.

This is cryptographic agility as a set of **positions**, not a score. Each
position names what a change would act on, and an asset is placed in one only
where something measured decides it:

=================  ==========================================  ==================================
Position           What a change acts on                       Placed by
=================  ==========================================  ==================================
``replacement``    the component itself: it cannot reach a     a ``capability-ceiling:<max>`` flag
                   newer algorithm at all                      (a documented maximum for the
                                                               version in service)
``library``        a cryptographic provider installed in       a ``version-spread:<n>`` flag (the
                   several versions at once                    number of versions in service)
``reissuance``     a credential re-issued on a running cycle   the certificate's validity window
``provider``       another organisation's service              a ``third-party`` row, a
                                                               vendor-operated role, or the
                                                               ``key-custody:platform-managed`` flag
``unevidenced``    unknown                                     nothing measured places it
=================  ==========================================  ==================================

Two things are deliberately absent. There is no per-asset rating, so an
unplaced row can never look like a reassuring mark. And nothing sums across
positions, because each counts a different kind of thing (machines, versions,
certificates, organisations); every group states its own unit.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from .model import CryptoAsset

REPLACEMENT = "replacement"
LIBRARY = "library"
REISSUANCE = "reissuance"
PROVIDER = "provider"
UNEVIDENCED = "unevidenced"

POSITION_ORDER = (REPLACEMENT, LIBRARY, REISSUANCE, PROVIDER)

CEILING_FLAG = "capability-ceiling:"
SPREAD_FLAG = "version-spread:"
PLATFORM_KEY_FLAG = "key-custody:platform-managed"
#: Flag on a third-party row whose post-quantum roadmap is not on record.
ROADMAP_UNRECORDED_FLAG = "pq-roadmap-unrecorded"

#: The phrase a role sentence carries for an endpoint an outside provider runs.
VENDOR_OPERATED_MARKER = "vendor-operated"

# Coverage rows describe the tool's reach, not something whose algorithm can change.
EXCLUDED_STATES = frozenset({"estate"})

CAVEAT = (
    "These are positions, not scores. Each names what a change to the algorithm "
    "would have to act on (a component, a software version, an issuance cycle, "
    "or another organisation's service), and each is placed only where something "
    "measured decides it. Nothing here rates how hard any change would be, and the "
    "counts are not comparable with one another because each counts a different "
    "kind of thing."
)

#: What no instrument here can see, and why. Reported with every result.
BLIND: tuple[dict[str, str], ...] = (
    {"what": "Algorithm names and cipher-suite lists hard-coded in application code",
     "why": "Nothing here reads source or binaries. A software bill of materials names "
            "the components an application is built with, not the algorithm choices "
            "made inside them"},
    {"what": "Certificate pinning in client software",
     "why": "A pinned certificate is invisible until the certificate changes and the "
            "client stops working. Scanning a server cannot show what its clients trust"},
    {"what": "Trust stores embedded in appliances, devices and firmware",
     "why": "The authorities a device accepts decide whether a new issuer can be "
            "introduced at all, and they are read only from inside the device"},
    {"what": "Whether an issuer, an issuing client or a relying party would accept a "
             "different algorithm",
     "why": "The issuance reading measures how often a credential is replaced, not "
            "whether a different algorithm could be requested and would be accepted"},
    {"what": "Internally issued certificates",
     "why": "Certificate readings come from public issuance logs and from scanned "
            "endpoints. Certificates issued privately for internal services, devices "
            "and users appear in neither"},
    {"what": "Whether an algorithm list in a deployed product can actually be edited",
     "why": "Knowing which cipher suites an endpoint accepts is not evidence that anyone "
            "can change them. That is a property of the product's configuration "
            "surface, which nothing here reads"},
)


def _flag_value(flags: Iterable[str], prefix: str) -> str:
    for f in flags:
        if f.startswith(prefix):
            return f[len(prefix):]
    return ""


def _lifetime_days(not_before: str, not_after: str) -> int | None:
    if not (not_before and not_after):
        return None
    try:
        start = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        end = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return None
    days = (end - start).days
    return days if days > 0 else None


def position_of(data_state: str, protocol: str, role: str,
                flags: tuple[str, ...], cert_lifetime_days: int | None) -> str:
    """The agility position the measured facts place, or :data:`UNEVIDENCED`.

    Takes plain values rather than an asset so that no per-asset badge can be
    built from it.
    """
    if any(f.startswith(CEILING_FLAG) for f in flags):
        return REPLACEMENT
    if any(f.startswith(SPREAD_FLAG) for f in flags):
        return LIBRARY
    if data_state == "third-party":
        return PROVIDER
    if VENDOR_OPERATED_MARKER in (role or "").casefold():
        return PROVIDER
    if PLATFORM_KEY_FLAG in flags:
        return PROVIDER
    if cert_lifetime_days:
        return REISSUANCE
    return UNEVIDENCED


def certificate_window(asset: CryptoAsset) -> int | None:
    """A certificate's validity window in days, from ``extra`` (``not_before``/``not_after``,
    or ``cert_not_before``/``cert_not_after``); None when not recorded."""
    e = asset.extra or {}
    return (_lifetime_days(str(e.get("not_before") or ""), str(e.get("not_after") or ""))
            or _lifetime_days(str(e.get("cert_not_before") or ""),
                              str(e.get("cert_not_after") or "")))


def _issuer_of(asset: CryptoAsset) -> str:
    e = asset.extra or {}
    issuer = str(e.get("issuer") or e.get("cert_issuer") or "").strip()
    for part in issuer.split("/"):
        if part.startswith("organizationName="):
            return part[len("organizationName="):].strip()
    return issuer


def _group(label: str, unit: str, count: int, detail: str) -> dict:
    return {"label": label, "unit": unit, "count": count, "detail": detail}


def _replacement_groups(rows: list[CryptoAsset]) -> list[dict]:
    out = []
    for a in sorted(rows, key=lambda x: -(x.hosts_count or 0)):
        ceiling = _flag_value(a.flags, CEILING_FLAG)
        out.append(_group(
            f"{a.software} {a.version}".strip(),
            "machines running this version", a.hosts_count or 0,
            f"cannot negotiate above {ceiling}, so no configuration change reaches a "
            f"newer algorithm: the component is replaced first"
            if ceiling else "a recorded capability ceiling"))
    return out


def _library_groups(rows: list[CryptoAsset]) -> list[dict]:
    out = []
    for a in sorted(rows, key=lambda x: -int(_flag_value(x.flags, SPREAD_FLAG) or 0)):
        versions = int(_flag_value(a.flags, SPREAD_FLAG) or 0)
        out.append(_group(
            a.software or "product not recorded",
            "distinct versions in service at once", versions,
            f"across {a.hosts_count} machines; an algorithm change delivered as a library "
            f"upgrade has to land on every one of these versions"
            if a.hosts_count else "an algorithm change delivered as a library upgrade has "
                                  "to land on every one of these versions"))
    return out


_LOG_POPULATION = "Certificates published in public issuance logs"
_SERVED_POPULATION = "Certificates served by endpoints the scan reached"


def _reissuance_groups(rows: list[CryptoAsset]) -> list[dict]:
    populations: dict[str, list[tuple[int, str]]] = {_LOG_POPULATION: [], _SERVED_POPULATION: []}
    for a in rows:
        window = certificate_window(a)
        if not window:
            continue
        key = _LOG_POPULATION if a.data_state == "certificate" else _SERVED_POPULATION
        populations[key].append((window, _issuer_of(a) or "issuer not recorded"))
    out = []
    for label, entries in populations.items():
        if not entries:
            continue
        windows = sorted({w for w, _ in entries})
        issuers = sorted({i for _, i in entries})
        span = (f"a {windows[0]}-day validity window" if len(windows) == 1
                else f"validity windows of {windows[0]}–{windows[-1]} days")
        out.append(_group(
            label, "certificates", len(entries),
            f"{span}, so each is re-issued at least every {windows[-1]} days. "
            f"Issuers recorded: {', '.join(issuers)}"))
    return out


def _provider_groups(rows: list[CryptoAsset]) -> list[dict]:
    orgs, endpoints, keys = [], [], []
    for a in rows:
        if a.data_state == "third-party":
            orgs.append(a)
        elif VENDOR_OPERATED_MARKER in (a.role or "").casefold():
            endpoints.append(a)
        else:
            keys.append(a)
    out = []
    if orgs:
        unrecorded = sum(1 for a in orgs
                         if any(f.startswith(ROADMAP_UNRECORDED_FLAG) for f in a.flags))
        out.append(_group(
            "Outside organisations relied on", "organisations", len(orgs),
            f"{unrecorded} with no cryptographic roadmap on record. Leaving the change "
            f"to a provider is a position, not a gap, but it is sound only where the "
            f"provider's own roadmap is known"))
    if endpoints:
        out.append(_group(
            "Endpoints recorded as vendor-operated", "endpoints", len(endpoints),
            "the algorithm changes when the operator changes it. A weak floor here is a "
            "procurement requirement, not a setting the organisation can alter"))
    if keys:
        out.append(_group(
            "Stored data whose key the platform holds and rotates", "storage resources",
            len(keys),
            "re-keying under a new algorithm is the platform operator's act, on the "
            "platform operator's schedule"))
    return out


_GROUPERS = {
    REPLACEMENT: _replacement_groups,
    LIBRARY: _library_groups,
    REISSUANCE: _reissuance_groups,
    PROVIDER: _provider_groups,
}

#: For each position: the act it names, the evidence that places it, and what that evidence cannot say.
POSITION_TEXT: dict[str, dict[str, str]] = {
    REPLACEMENT: {
        "act": "The component is replaced before the algorithm can change",
        "evidence": "A capability ceiling: a documented maximum recorded for the "
                    "version in service",
        "limit": "It says the ceiling exists, not how much work removing it is",
    },
    LIBRARY: {
        "act": "A software upgrade, repeated across every version of the provider in service",
        "evidence": "The number of distinct versions of one cryptographic provider running "
                    "at the same time, counted from the host software inventory",
        "limit": "The number of versions is a fact; how hard any one of them is to move "
                 "is not measured here",
    },
    REISSUANCE: {
        "act": "The credential is re-issued on a cycle that is already running",
        "evidence": "The certificate's own validity window, in days, which sets the "
                    "longest possible interval between issuances",
        "limit": "This measures the cycle, not the choices. Nothing here says the issuer "
                 "offers a newer algorithm, that the issuing client can request it, or "
                 "that relying parties would accept it. The two populations may overlap "
                 "(a scanned endpoint can serve a certificate a public log also holds) and "
                 "are not added together. Both cover externally reachable services only",
    },
    PROVIDER: {
        "act": "Another organisation changes it, on its own schedule",
        "evidence": "The row is about an outside organisation, an endpoint recorded as "
                    "vendor-operated, or a key held and rotated by a platform the "
                    "organisation does not run",
        "limit": "This records who acts, not what they will do or when; that is what a "
                 "provider's own roadmap would say",
    },
}


def agility(assets: Iterable[CryptoAsset]) -> dict:
    """The agility positions across ``assets``, with the unplaced count first; {} if no rows."""
    assets = list(assets)
    rows = [a for a in assets if a.data_state not in EXCLUDED_STATES]
    excluded = [a for a in assets if a.data_state in EXCLUDED_STATES]
    if not rows:
        return {}

    placed: dict[str, list[CryptoAsset]] = {p: [] for p in POSITION_ORDER}
    unevidenced: list[CryptoAsset] = []
    for a in rows:
        p = position_of(a.data_state, a.protocol, a.role or "", tuple(a.flags), certificate_window(a))
        if p == UNEVIDENCED:
            unevidenced.append(a)
        else:
            placed[p].append(a)

    by_state: dict[str, int] = {}
    for a in unevidenced:
        by_state[a.data_state] = by_state.get(a.data_state, 0) + 1

    positions = []
    for p in POSITION_ORDER:
        if not placed[p]:
            continue
        text = POSITION_TEXT[p]
        positions.append({"position": p, "act": text["act"], "evidence": text["evidence"],
                          "limit": text["limit"], "groups": _GROUPERS[p](placed[p])})

    return {
        "caveat": CAVEAT,
        "unevidenced": {
            "count": len(unevidenced),
            "of": len(rows),
            "share": round(len(unevidenced) / len(rows), 3),
            "by_state": dict(sorted(by_state.items(), key=lambda kv: -kv[1])),
            "meaning": "Nothing measured says what a change to the algorithm would act on. "
                       "This is not a judgement that these are hard to change; it is the "
                       "absence of any reading",
        },
        "positions": positions,
        "excluded": {
            "count": len(excluded),
            "reason": "Coverage rows: the tool reporting whether an instrument exists for a "
                      "declared class of the estate. They are not things whose algorithm can "
                      "change, so they are not counted as unevidenced",
        },
        "blind": [dict(b) for b in BLIND],
    }
