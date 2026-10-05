"""Reuse a recent certificate-transparency answer instead of asking again.

Certificate-transparency search services limit how often they may be asked,
and a domain with many certificates takes many pages. A run may therefore
reuse a domain's answer from an earlier observation, under three conditions:
the observation is recent (``CT_CACHE_DAYS``), it finished (a completion
marker parses: ``bom.cdx.json``, or a file a caller registered with
:func:`register_completion_marker`), and its read of that domain reached the
end of the results (its page record says ``exhausted``). A reused answer is always reported as such,
with its age, so a reader knows a certificate issued since then is missing.

The raw files this module reads are written by the ``ct_dns`` collector:
``raw/ct-<domain>.json`` (the issuances) and ``raw/ct-<domain>.pages.json``
(how the read went).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import obsarchive

#: How old (in days) an answer may be and still be reused.
CT_CACHE_DAYS = 2

#: The oldest answer an observation may carry and still be committed as measured.
CT_COMMIT_MAX_AGE_DAYS = CT_CACHE_DAYS

#: Prefix of the raw files holding certificate-transparency answers.
RAW_PREFIX = "ct-"

#: The file whose presence (as parseable JSON) marks a finished observation.
COMPLETION_MARKER = "bom.cdx.json"

_registered_markers: list[str] = []

_OBS_NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2})(\d{2})Z$")


def register_completion_marker(*names: str) -> None:
    """Accept further file names as the mark of a finished observation.

    For a tool that runs takestock's collectors inside its own observations
    and writes its finished-run file under another name: once registered, an
    observation holding any one of the markers as parseable JSON counts as
    finished. Registering the same name twice has no further effect.
    """
    for name in names:
        if not name or "/" in name or name in (".", ".."):
            raise ValueError(f"a completion marker is a plain file name, not {name!r}")
        if name != COMPLETION_MARKER and name not in _registered_markers:
            _registered_markers.append(name)


def completion_markers() -> tuple[str, ...]:
    """Every completion marker in effect: the built-in one, then registered ones."""
    return (COMPLETION_MARKER, *_registered_markers)


def raw_name(domain: str) -> str:
    """File name of the raw issuances for ``domain``."""
    return f"{RAW_PREFIX}{domain}.json"


def pages_name(domain: str) -> str:
    """File name of the page record for ``domain``."""
    return f"{RAW_PREFIX}{domain}.pages.json"


@dataclass(frozen=True)
class Cached:
    """A reusable answer: the issuances, and where and when they were read."""

    payload: list
    observed: str
    observation: str
    age_days: int
    domain: str = ""


def _observation_time(name: str) -> datetime | None:
    m = _OBS_NAME.match(name)
    if not m:
        return None
    day, hh, mm = m.groups()
    try:
        return datetime.strptime(f"{day} {hh}:{mm}", "%Y-%m-%d %H:%M").replace(tzinfo=UTC)
    except ValueError:
        return None


def _is_complete(observation: Path) -> bool:
    for name in completion_markers():
        try:
            json.loads((observation / name).read_text())
        except (OSError, ValueError):
            continue
        return True
    return False


def _read_to_the_end(observation: Path, domain: str) -> bool:
    try:
        note = json.loads((observation / "raw" / pages_name(domain)).read_text())
    except (OSError, ValueError):
        return False
    return isinstance(note, dict) and note.get("exhausted") is True


def find(domain: str, observations: Path, max_age_days: int = CT_CACHE_DAYS,
         ref_time: datetime | None = None) -> Cached | None:
    """The newest reusable answer for ``domain`` under ``observations``, or None."""
    now = ref_time or datetime.now(UTC)
    cutoff = now - timedelta(days=max_age_days)
    if not observations.is_dir():
        return None
    candidates = []
    for child in obsarchive.observations(observations):
        when = _observation_time(child.name)
        if when is not None and when >= cutoff:
            candidates.append((when, child))
    for when, child in sorted(candidates, reverse=True):
        if not _is_complete(child):
            continue
        path = child / "raw" / raw_name(domain)
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(payload, list):
            continue
        if not _read_to_the_end(child, domain):
            continue
        return Cached(payload=payload, observed=when.date().isoformat(),
                      observation=child.name, age_days=(now - when).days,
                      domain=domain)
    return None


def reuse_gap(reused: list[Cached]) -> str:
    """The coverage-gap sentence for answers that were reused rather than re-read."""
    oldest = max(c.age_days for c in reused)
    n = len(reused)
    return (f"Certificate Transparency not re-queried for {n} domain(s) "
            f"(reused an answer up to {oldest}d old) — a certificate issued "
            "since then would not appear in this observation")


def summarise(reused: list[Cached], domains: list[str], window_days: int,
              refresh: bool) -> dict:
    """A record of what was reused, for the observation's summary."""
    hits = sorted(reused, key=lambda c: c.domain)
    return {
        "window_days": window_days,
        "refresh": refresh,
        "domains": len(domains),
        "hits": len(hits),
        "misses": len(domains) - len(hits),
        "oldest_age_days": max((c.age_days for c in hits), default=0),
        "commit_max_age_days": CT_COMMIT_MAX_AGE_DAYS,
        "reused": [{"domain": c.domain, "observation": c.observation,
                    "observed": c.observed, "age_days": c.age_days} for c in hits],
    }


def commit_refusal(reused: list[Cached],
                   max_age_days: int = CT_COMMIT_MAX_AGE_DAYS) -> str:
    """Why a run carrying stale reused answers should not be recorded as measured; "" if it may."""
    stale = [c for c in reused if c.age_days > max_age_days]
    if not stale:
        return ""
    worst = max(stale, key=lambda c: c.age_days)
    return (f"{len(stale)} Certificate Transparency answer(s) older than the "
            f"{max_age_days}-day commit window (oldest {worst.age_days}d, "
            f"{worst.domain} from {worst.observation}). Re-run with --refresh "
            "to record a measured observation.")


def rate_limit_detail(resp: dict) -> str:
    """The HTTP status and rate-limit headers of a response, for a message; "" if none."""
    bits = []
    if resp.get("status"):
        bits.append(f"HTTP {resp['status']}")
    bits += [f"{k}={v}" for k, v in sorted(resp.get("headers", {}).items())]
    return f" ({'; '.join(bits)})" if bits else ""
