"""Reuse an earlier observation's active-probe rows instead of probing again.

``takestock observe <target> --carry-scan <observation>`` runs the passive and
ingest collectors afresh and, in place of the active probes, takes the rows an
earlier ``--scan`` observation of the same target measured. Each carried row
is unchanged: it keeps its own ``collected_at``, ``source``, notes and grade
inputs, so a reader sees when it was measured and by which collector. The raw
transcripts beside those rows come across too. An organisation that probes
its hosts on a schedule, and takes observations more often than that, can so
keep its probe evidence in every observation without probing again.

What is carried
---------------

A row is carried when only an active probe could have written it:

* every row whose ``source`` is an active collector's (``tls_scan``,
  ``ike_scan``, ``plaintext_scan`` and the rest, from
  :data:`takestock.collectors.REGISTRY`), except the ``ssh_audit`` rows read
  from supplied ssh-audit files, which the ingest collector reads afresh;
* the ``spf_senders`` rows written by the STARTTLS probe of the relays a
  sender policy names. The policy itself is DNS and is expanded afresh; the
  carried relay rows are handed to the collector in place of the probe.

The gaps those probes raise come with them: ``ike_scan``'s and ``hsts``'s
are worked out again from the carried rows, and the relays that did not
answer are read back from the earlier ``summary.json``. Every top-level file
in the earlier ``raw/`` is copied, except the certificate-transparency
answers (``ct-*``), which belong to the passive ``ct_dns`` collector and have
their own reuse rules (:mod:`takestock.ctcache`). A file this run wrote is
never overwritten. Plug-ins keep their raw files in sub-folders, which are
not copied.

Refusals
--------

Each is raised as :class:`CarryRefused` before anything is written to the new
observation or sent anywhere:

* the earlier observation cannot be found or read, or has not finished;
* it is older than the age limit (:data:`CARRY_MAX_AGE_DAYS` days unless the
  caller sets another), or dated after the new one;
* it was taken of another target, or of another organisation;
* it was not a ``--scan`` observation (so it holds no probe rows), which
  includes an observation that was itself a carry, or was derived from
  another (:mod:`takestock.rerun`): a carry always reaches back to the run
  that measured;
* an active collector, or ``spf_senders``, failed in it, so its rows are not
  a complete measurement.

The one live contact
--------------------

A ``plaintext_scan`` row graded ``cleartext-served`` on a port that speaks
HTTP is not carried on trust: it is re-checked with the one plain-HTTP request
:func:`takestock.collectors.plaintext_scan.verify_cleartext_http` sends. The
row keeps its ``collected_at``; the request's date is recorded in
``extra.cleartext_verified_on``. That request is a probe, so
:func:`takestock.observe.observe` refuses the carry before anything is sent
unless the target profile carries the same complete ``authorisation:`` record
``--scan`` needs.

The record
----------

``summary.json`` gains a ``carried_scan`` block (:func:`record`) saying which
observation the rows came from, the dates they were measured, the age in
days, the age limit, the collectors carried, the number of rows by source,
the raw files copied, and each re-check with its outcome before and after.
The block is present only on a carried observation.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import collectors, coverage, ctcache, obsarchive
from .model import CryptoAsset, load_assets

#: How old (in days) an earlier observation may be and still be carried.
CARRY_MAX_AGE_DAYS = 31

#: The ``summary.json`` key holding the carry record.
SUMMARY_KEY = "carried_scan"

_ISO = "%Y-%m-%dT%H:%M:%SZ"
_STAMP = "%Y-%m-%dT%H%MZ"


class CarryRefused(Exception):
    """The carry will not happen. ``code`` is a short machine name; the message says why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def active_collectors() -> list[str]:
    """The registered active collectors, in registration order."""
    return collectors.names("active")


def active_sources() -> frozenset[str]:
    """The ``source`` an active collector writes on its rows: its module's name."""
    return frozenset(collectors.REGISTRY[n].module for n in active_collectors())


def is_probe_row(a: CryptoAsset) -> bool:
    """True for a row only an active probe could have written."""
    from .collectors import spf_senders, ssh_audit
    if a.source == ssh_audit.SOURCE:
        return not str(a.source_name).startswith(ssh_audit.INBOX_SOURCE_PREFIX)
    if a.source == spf_senders.SOURCE_KEY:
        return a.source_name == spf_senders.SOURCE_PROBE
    return a.source in active_sources()


@dataclass
class Held:
    """What a checked earlier observation offers to carry."""

    path: Path
    stamp: str
    collected_at: str
    age_days: int
    max_age_days: int
    rows: list[CryptoAsset]
    carried: list[str] = field(default_factory=list)
    not_run: dict[str, str] = field(default_factory=dict)
    spf_gap_texts: list[str] = field(default_factory=list)
    raw_files: list[Path] = field(default_factory=list)

    @property
    def spf_rows(self) -> list[CryptoAsset]:
        """The relay-probe rows, handed to ``spf_senders`` in place of its probe."""
        from .collectors import spf_senders
        return [a for a in self.rows if a.source == spf_senders.SOURCE_KEY]

    @property
    def probe_rows(self) -> list[CryptoAsset]:
        """Every other carried row."""
        from .collectors import spf_senders
        return [a for a in self.rows if a.source != spf_senders.SOURCE_KEY]

    def gaps(self, target: dict) -> list[coverage.Gap]:
        """The coverage gaps ``ike_scan`` and ``hsts`` raise, worked out from the carried rows."""
        from .collectors import hsts, ike_scan
        return (list(ike_scan.coverage_gaps([a for a in self.rows if a.source == ike_scan.SOURCE]))
                + list(hsts.coverage_gaps(target, [a for a in self.rows
                                                   if a.source == hsts.SOURCE])))

    def spf_gaps(self) -> list[coverage.Gap]:
        """The relay-probe gaps: relays that did not answer, and certificates not read."""
        from .collectors import spf_senders
        return spf_senders.carried_gaps(self.spf_rows, self.spf_gap_texts)

    def dates(self) -> list[str]:
        """The distinct dates the carried rows were measured on."""
        return sorted({a.collected_at for a in self.rows if a.collected_at})

    def by_source(self) -> dict[str, int]:
        """Carried rows by ``source``."""
        return dict(sorted(Counter(a.source for a in self.rows).items()))


def resolve(ref: str | Path, observations: Path) -> Path:
    """The earlier observation ``ref`` names: a directory, or a stamp under ``observations``.

    An archived observation (:mod:`takestock.obsarchive`) is unpacked, raw
    transcripts included. A symbolic link such as ``latest`` resolves to the
    run it points at, so the record names a run, never a pointer that moves.
    """
    p = Path(str(ref)).expanduser()
    if p.is_dir():
        return p.resolve()
    for root, stamp in ((p.parent, p.name), (observations, str(ref))):
        if (root / stamp).is_dir():
            return (root / stamp).resolve()
        if not obsarchive.is_stamp(stamp):
            continue
        try:
            entry = obsarchive.entry_for(obsarchive.read_manifest(root), stamp)
            if entry is not None:
                return obsarchive.unpacked(root, stamp, upto=1).resolve()
        except (OSError, ValueError, KeyError) as exc:
            raise CarryRefused("carry-unreadable",
                               f"{stamp} is archived but could not be unpacked: {exc}") from exc
    raise CarryRefused("carry-not-found",
                       f"no observation {str(ref)!r}: neither a directory nor an observation "
                       "stamp held, as a folder or archived, under the workspace's observations/")


def _read_json(path: Path) -> object:
    return json.loads(path.read_text())


def _taken(block: dict, fallback: str) -> datetime | None:
    for value, fmt in ((block.get("collected_at"), _ISO), (block.get("stamp") or fallback, _STAMP)):
        try:
            return datetime.strptime(str(value or ""), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def load(ref: str | Path, target: dict, observations: Path, now: datetime,
         max_age_days: int = CARRY_MAX_AGE_DAYS, organisation: str = "") -> Held:
    """Check the earlier observation and return what it carries, or raise :class:`CarryRefused`.

    ``organisation`` is the name this run records for ``target``. Reads only:
    nothing is written, except that an archived observation is unpacked into
    the archive's own unpacking folder.
    """
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or max_age_days < 0:
        raise CarryRefused("carry-bad-age", f"the age limit must be a whole number of days, "
                                            f"0 or more, not {max_age_days!r}")
    obs = resolve(ref, observations)
    if not any(_parses(obs / name) for name in ctcache.completion_markers()):
        raise CarryRefused("carry-unfinished",
                           f"{obs.name} has not finished: none of "
                           f"{', '.join(ctcache.completion_markers())} is there and readable")
    try:
        summary = _read_json(obs / "summary.json")
        rows = load_assets(_read_json(obs / "assets.json"))  # type: ignore[arg-type]
        if not isinstance(summary, dict):
            raise ValueError("summary.json is not an object")
    except (OSError, ValueError, TypeError) as exc:
        raise CarryRefused("carry-unreadable",
                           f"{obs.name} is not a readable observation (summary.json and "
                           f"assets.json are both needed): {exc}") from exc
    block = summary.get("observation") or {}
    stamp = str(block.get("stamp") or obs.name)

    taken = _taken(block, obs.name)
    if taken is None:
        raise CarryRefused("carry-unreadable",
                           f"{stamp} records no usable time, so its age cannot be judged")
    age = now - taken
    if age < timedelta(0):
        raise CarryRefused("carry-from-the-future",
                           f"{stamp} is dated after this observation ({now.strftime(_ISO)}), "
                           "so its rows cannot stand for an earlier measurement")
    if age > timedelta(days=max_age_days):
        raise CarryRefused("carry-too-old",
                           f"{stamp} is {age.days} days old, past the {max_age_days}-day limit. "
                           "Probe again with --scan, or raise the limit deliberately "
                           "with --carry-max-age")

    held_org, held_target = str(block.get("organisation") or ""), Path(str(block.get("target")
                                                                           or "")).stem
    this_target = Path(str(target.get("_path") or "")).stem
    if held_org != organisation or held_target != this_target:
        raise CarryRefused("carry-other-target",
                           f"{stamp} was taken of target {held_target!r} ({held_org!r}); this "
                           f"run is {this_target!r} ({organisation!r}). Another target's probe "
                           "rows would be presented as this one's")

    if block.get("scan") is not True:
        why = ("it was itself a carry" if summary.get(SUMMARY_KEY)
               else "it was derived from an earlier observation" if summary.get("rerun")
               else "it was taken without --scan")
        raise CarryRefused("carry-not-scanned",
                           f"{stamp} holds no probe measurement to carry: {why}. Carry from "
                           "the observation that ran the probes")

    probes = set(active_collectors()) | {"spf_senders"}
    failed = sorted(set(block.get("failed_collectors") or []) & probes)
    if failed:
        raise CarryRefused("carry-degraded",
                           f"{stamp} recorded a failure in {', '.join(failed)}, so those rows "
                           "are not a complete measurement to carry. Probe again with --scan")

    ran = set(block.get("collectors_run") or [])
    skipped = dict(block.get("collectors_skipped") or {})
    carried = [n for n in active_collectors() if n in ran]
    not_run = {n: str(skipped.get(n) or "") for n in active_collectors() if n not in ran}

    raw = obs / "raw"
    files = sorted(p for p in raw.iterdir()
                   if p.is_file() and not p.name.startswith(ctcache.RAW_PREFIX)
                   ) if raw.is_dir() else []
    return Held(path=obs, stamp=stamp, collected_at=taken.strftime(_ISO), age_days=age.days,
                max_age_days=max_age_days, rows=[a for a in rows if is_probe_row(a)],
                carried=carried, not_run=not_run,
                spf_gap_texts=[str(g) for g in summary.get("gaps") or []], raw_files=files)


def _parses(path: Path) -> bool:
    try:
        _read_json(path)
    except (OSError, ValueError):
        return False
    return True


# ── the cleartext re-check ──

#: Re-checks one row: (row, raw directory, reference time) -> the updated copy.
Verifier = Callable[[CryptoAsset, Path, datetime | None], CryptoAsset]


def recheck_rows(rows: Iterable[CryptoAsset]) -> list[CryptoAsset]:
    """The carried rows the re-check sends a request for.

    ``plaintext_scan`` rows graded ``cleartext-served`` on a port that speaks
    HTTP (:func:`takestock.collectors.plaintext_scan.needs_cleartext_check`).
    """
    from .collectors import plaintext_scan
    return [a for a in rows if a.source == plaintext_scan.SOURCE
            and plaintext_scan.needs_cleartext_check(a)]


def recheck(rows: list[CryptoAsset], raw: Path, ref_time: datetime | None,
            verify: Verifier | None = None) -> tuple[list[CryptoAsset], list[dict]]:
    """Re-check the rows :func:`recheck_rows` picks; return every row and one record per request.

    The caller has already checked the authorisation record: this sends.
    """
    from .collectors import plaintext_scan
    send = verify or plaintext_scan.verify_cleartext_http
    targets = {id(a) for a in recheck_rows(rows)}
    out: list[CryptoAsset] = []
    records: list[dict] = []
    for a in rows:
        if id(a) not in targets:
            out.append(a)
            continue
        after = send(a, raw, ref_time)
        done = after.extra or {}
        records.append({"host": a.host, "port": a.port,
                        "before": (a.extra or {}).get("plaintext_outcome", ""),
                        "after": done.get("plaintext_outcome", ""),
                        "collected_at": after.collected_at,
                        "verified_on": done.get("cleartext_verified_on", ""),
                        "status": done.get("cleartext_verify_status", "")})
        out.append(after)
    return out, records


def copy_raw(held: Held, raw: Path) -> int:
    """Copy the earlier raw transcripts into ``raw``, never over a file already there."""
    n = 0
    for src in held.raw_files:
        dst = raw / src.name
        if dst.exists():
            continue
        shutil.copy2(src, dst)
        n += 1
    return n


def record(held: Held, raw_copied: int, rechecked: list[dict]) -> dict:
    """The ``carried_scan`` block for ``summary.json``."""
    return {"from_observation": held.stamp, "from_collected_at": held.collected_at,
            "measured": held.dates(), "age_days": held.age_days,
            "max_age_days": held.max_age_days, "collectors": list(held.carried),
            "rows": len(held.rows), "by_source": held.by_source(),
            "raw_files": raw_copied, "rechecked": rechecked}
