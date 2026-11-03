"""CrowdStrike Falcon: Windows boot, memory-isolation and device-memory protections, by control.

Windows has a set of protections below the operating system: Secure Boot,
virtualisation-based security and what runs inside it, and the fences that
stop a plugged-in device reading memory. This reader counts, for each
protection, how many readings report it on, off or not available, and, where
a second export reads the same protection, how often the two agree.

**The input** (``input:``) is a CSV with one row per Windows machine (or per
machine and network adapter) and one column per protection, each holding a
state such as ``Enabled``. No public list of the Falcon console's headings
for these columns was found, so every heading defaults to the field's own
name below and is named with ``settings: columns:`` (a heading, or a list
tried in order). A control whose column is not in the export gets no row and
is listed on the scope row.

===========================  ====================================================
field (and default heading)  the protection, in Microsoft's terms
===========================  ====================================================
``machine``                  the machine's name (default heading ``hostname``)
``mac``                      its network adapter, read only to leave it out of the
                             unread columns (default heading ``mac_address``)
``secure_boot_enabled``      Secure Boot is on: the firmware loads only signed boot
                             software
``secure_boot_requested``    Secure Boot has been requested (a separate setting)
``vbs``                      virtualisation-based security: a hypervisor-isolated
                             region the operating system cannot reach into
``credential_guard``         Credential Guard: credentials kept in that region
``system_guard``             System Guard: protects the integrity of start-up
``kernel_dma_protection``    Kernel DMA Protection: external devices cannot read
                             memory directly
``iommu``                    the IOMMU, the hardware that limits which memory a device
                             can reach
``uefi_memory_protection``   firmware memory marked so it cannot be both written and
                             run
``secure_mor_requested``     the Memory Overwrite Request: the firmware is asked to
                             overwrite memory at restart
===========================  ====================================================

**The states.** A cell equal, ignoring case, to a word in ``settings: on:``
(default ``enabled``) is on, in ``off:`` (default ``disabled``) off, and in
``unavailable:`` (default ``not available``, ``unavailable``) on hardware
that cannot provide it. A blank cell is counted as ``(blank)``.

**A column whose meaning is not established.** ``settings: unidentified:``
lists further headings to count without naming what they measure. Each gets a
row flagged ``platform-control-not-identified`` and one coverage gap, so a
figure from it is not quoted as a known control.

**A second reading.** ``settings: compare:`` names another export that
reads the same protections per machine, and the reader counts, on the
machines both cover, how often the two agree. Its keys:

* ``file``: a JSON file holding a list of records. A record may hold its
  fields itself, or as JSON text under ``@rawstring``, the field where
  LogScale keeps an event's original text.
* ``host_field``: the record's field holding the machine name (required).
* ``signals_field``: the field holding the signals as a mapping (default:
  the record itself).
* ``pairs``: which signal reads each control, as ``{field: signal}``; an
  ``unidentified`` column is named by its heading. A control with no pair is
  not compared.
* ``yes`` and ``no``: the signal values meaning on and off (default ``yes``,
  ``true`` and ``no``, ``false``).

Machines are matched by name ignoring case; where a machine has several
records, the last is read. Only readings that are on or off on both sides
are compared.

**A platform export.** ``settings: platforms:`` names a CSV of every
sensored machine and its operating system (``file``; ``host_column``,
default ``hostname``; ``os_column``, default ``os_version``). The scope row
then says what the machines this export does not cover run, so a missing
Windows machine shows as a shortfall rather than being assumed away.

**Rows.** One per control, ``Windows platform protection — <heading>``,
``n/a``: a population, flagged ``platform-control-readings:<n>``, and
``platform-control-off-everywhere`` when no reading is on and some are off,
or ``platform-control-reading-contested`` when the second reading disagrees on
more readings than it agrees. One scope row, ``Windows platform protection
scope`` (``n/a``, ``scope-windows-only``). Every figure counts readings, not
machines, since a machine can have more than one row.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_windows_os_security"

READINGS_FLAG = "platform-control-readings:"
OFF_EVERYWHERE_FLAG = "platform-control-off-everywhere"
UNIDENTIFIED_FLAG = "platform-control-not-identified"
CONTESTED_FLAG = "platform-control-reading-contested"
SCOPE_FLAG = "scope-windows-only"

register_informational_prefixes(READINGS_FLAG, UNIDENTIFIED_FLAG, CONTESTED_FLAG, SCOPE_FLAG)

#: Each control's field and what it protects, in the order rows are written.
CONTROLS: tuple[tuple[str, str], ...] = (
    ("secure_boot_enabled",
     "whether the firmware loads only boot software carrying a trusted signature"),
    ("secure_boot_requested",
     "whether Secure Boot has been requested, a setting separate from whether it is on"),
    ("vbs",
     "whether the machine runs virtualisation-based security, a region isolated by the "
     "hypervisor that the operating system itself cannot reach into"),
    ("credential_guard",
     "whether credentials are kept inside that isolated region while the machine runs"),
    ("system_guard",
     "whether the integrity of the machine's start-up is protected"),
    ("kernel_dma_protection",
     "whether a device plugged into the machine is stopped from reading its memory directly"),
    ("iommu",
     "whether IOMMU protection, the hardware that limits which memory a device can reach, "
     "is reported on"),
    ("uefi_memory_protection",
     "whether firmware memory is marked so that it cannot be both written and run"),
    ("secure_mor_requested",
     "whether the firmware is asked to overwrite memory at restart, so that what it held "
     "cannot be read afterwards"),
)

#: Each field and its default heading, which is the field's own name.
HEADINGS: dict[str, str] = {"machine": "hostname", "mac": "mac_address",
                            **{field: field for field, _ in CONTROLS}}

ON, OFF, UNAVAILABLE = ("enabled",), ("disabled",), ("not available", "unavailable")
YES, NO = ("yes", "true"), ("no", "false")


class SecondReading:
    """The ``compare`` setting: another export's signals per machine."""

    def __init__(self, ctx: Context) -> None:
        conf = _fp.nested(ctx, "compare")
        self.pairs: dict[str, str] = {str(k): str(v)
                                      for k, v in dict(conf.get("pairs") or {}).items()}
        self.yes = _fp.words(conf.get("yes"), YES)
        self.no = _fp.words(conf.get("no"), NO)
        self.signals: dict[str, Mapping[str, Any]] = {}
        path = _fp.file_setting(ctx, conf)
        host_field = str(conf.get("host_field") or "")
        if path is None or not host_field or not path.exists():
            return
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            return
        if not isinstance(records, list):
            return
        signals_field = str(conf.get("signals_field") or "")
        for rec in records:
            if not isinstance(rec, dict):
                continue
            raw = rec.get("@rawstring")
            try:
                event = json.loads(raw) if isinstance(raw, str) else rec
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            host = str(event.get(host_field) or "").strip().upper()
            items = event.get(signals_field) if signals_field else event
            if host and isinstance(items, dict):
                self.signals[host] = items

    def state(self, host: str, signal: str) -> str:
        """``on``, ``off`` or ``""`` for one machine's signal."""
        value = str((self.signals.get(host) or {}).get(signal) or "").strip().lower()
        return "on" if value in self.yes else "off" if value in self.no else ""


def platform_spread(ctx: Context, present: set[str]) -> tuple[dict[str, int], int]:
    """The platform export's machines missing from this export, by operating system, and how
    many machines the platform export lists."""
    conf = _fp.nested(ctx, "platforms")
    rows, _, _ = _fp.load(_fp.file_setting(ctx, conf))
    if not rows:
        return {}, 0
    hosts = _fp.heading_list(conf.get("host_column"), ("hostname",))
    os_cols = _fp.heading_list(conf.get("os_column"), ("os_version",))
    seen: dict[str, str] = {}
    for r in rows:
        host = _fp.first(r, hosts).upper()
        if host:
            seen.setdefault(host, _fp.first(r, os_cols) or "unknown")
    absent: dict[str, int] = {}
    for host, os_name in seen.items():
        if host not in present:
            absent[os_name] = absent.get(os_name, 0) + 1
    return absent, len(seen)


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of Windows platform protections was read"
        + (f" ({why})" if why else "")
        + ": Secure Boot, virtualisation-based security, Credential Guard and the "
        "device-memory protections, counted across the Windows machines",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Without it these protections rest on whatever other reading of them exists, "
                "if any, and a misread column cannot be caught by comparing two readings."),
        harvest=("Export the Windows machines' platform protections as CSV, name it with "
                 "input:, and name its headings with settings: columns:."),
        nature=coverage.NO_DATA)


def _unidentified_gap(heading: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_MEASURED,
        f"which protection the column {heading!r} of the Windows platform protection export "
        "reports is not established, so its readings are counted and not placed against any "
        "named control",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("A figure from this column cannot be acted on, or quoted as the state of a "
                "named protection, until what it measures is known."),
        harvest=("A definition of the column from the product's documentation or support, or "
                 "a reading taken from a machine whose configuration is set deliberately."),
        nature=coverage.LOW_FIDELITY)


def read(path: Path, ctx: Context) -> tuple[list[CryptoAsset], list]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    rows, header, unreadable = _fp.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    s = ctx.settings or {}
    headings = _fp.columns(ctx, HEADINGS)
    on, off = _fp.words(s.get("on"), ON), _fp.words(s.get("off"), OFF)
    unavailable = _fp.words(s.get("unavailable"), UNAVAILABLE)
    unidentified = [str(h) for h in (s.get("unidentified") or [])]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon Windows platform protection export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}

    machines = {_fp.first(r, headings["machine"]).upper() for r in rows} - {""}
    second = SecondReading(ctx)
    absent, platform_machines = platform_spread(ctx, machines)

    # (row label, the field's headings, what it protects, whether its meaning is established)
    controls: list[tuple[str, tuple[str, ...], str, bool, str]] = []
    missing: list[str] = []
    for field, subject in CONTROLS:
        hs = headings[field]
        present = [h for h in hs if _fp.has_column(header, (h,))]
        if present:
            controls.append((present[0], hs, subject, True, field))
        else:
            missing.append(hs[0])
    for h in unidentified:
        if _fp.has_column(header, (h,)):
            controls.append((h, (h,), "", False, h))
        else:
            missing.append(h)
    read_headings = {h for _, hs, _, _, _ in controls for h in hs} | set(
        headings["machine"]) | set(headings["mac"])
    unread = [h for h in header if not _fp.has_column(read_headings, (h,))]

    out: list[CryptoAsset] = []
    gaps: list = []
    for label, hs, subject, named, key in controls:
        census: dict[str, int] = {}
        for r in rows:
            value = (_fp.first(r, hs) or "(blank)").lower()
            census[value] = census.get(value, 0) + 1
        enabled = sum(n for v, n in census.items() if v in on)
        disabled = sum(n for v, n in census.items() if v in off)
        not_available = sum(n for v, n in census.items() if v in unavailable)
        readings = sum(census.values())

        agree = disagree = 0
        signal = second.pairs.get(key)
        if signal and second.signals:
            for r in rows:
                host = _fp.first(r, headings["machine"]).upper()
                other = second.state(host, signal)
                value = _fp.first(r, hs).lower()
                mine = "on" if value in on else "off" if value in off else ""
                if other and mine:
                    if mine == other:
                        agree += 1
                    else:
                        disagree += 1
        compared = agree + disagree

        flags = [f"{READINGS_FLAG}{readings}"]
        if not named:
            flags.append(UNIDENTIFIED_FLAG)
        elif disabled and not enabled:
            flags.append(OFF_EVERYWHERE_FLAG)
        if compared and disagree > agree:
            flags.append(CONTESTED_FLAG)

        parts = [f"{enabled:,} of {readings:,} readings report this protection on, "
                 f"{disabled:,} off"
                 + (f", and {not_available:,} on hardware that cannot provide it"
                    if not_available else "") + "."]
        parts.append(f"It reports {subject}." if named else
                     "Which protection this column reports is not established, so it is "
                     "counted and placed against no named control.")
        if compared:
            parts.append(f"A second reading covers {compared:,} of these readings and agrees "
                         f"on {agree:,}" + (f", disagreeing on {disagree:,}." if disagree
                                            else ", with no disagreement."))
        elif signal:
            parts.append("No second reading was available, so this rests on one export.")
        out.append(CryptoAsset(
            name=f"Windows platform protection — {label}", data_state="platform-integrity",
            protocol="", role=roles.platform_protection_population(subject, readings),
            verdict="n/a", flags=flags, hosts_count=len(machines), notes=" ".join(parts),
            extra={"column": label, "readings": str(readings), "enabled": str(enabled),
                   "disabled": str(disabled), "not_available": str(not_available),
                   "second_instrument_agrees": str(agree),
                   "second_instrument_differs": str(disagree)},
            **base))
        if not named:
            gaps.append(_unidentified_gap(label))

    if absent:
        windows_absent = sum(n for o, n in absent.items() if o.lower().startswith("windows"))
        spread = ", ".join(f"{o}: {n:,}" for o, n in sorted(absent.items(), key=lambda kv: -kv[1]))
        if windows_absent:
            population = (f"{_fp.plural(windows_absent, 'Windows machine')} in the platform "
                          "export are not in this one, so it is not a complete Windows view and "
                          f"its figures are short by that many. The machines it lacks run: "
                          f"{spread}.")
        else:
            population = (f"None of the {_fp.plural(sum(absent.values()), 'machine')} in the "
                          f"platform export that this one lacks runs Windows ({spread}), so this "
                          f"export "
                          f"covers every Windows machine among the {platform_machines:,} the "
                          "platform export lists.")
    else:
        population = ("No platform export was read, so whether this covers every Windows "
                      "machine is not checked.")
    out.append(CryptoAsset(
        name="Windows platform protection scope", data_state="platform-integrity", protocol="",
        role=roles.platform_protection_scope(), verdict="n/a", flags=[SCOPE_FLAG],
        hosts_count=len(machines),
        notes=(f"{len(rows):,} readings covering {_fp.plural(len(machines), 'machine')}; a "
               "machine with more than one network adapter can be read more than once, so "
               f"every figure counts readings. {population}"
               + (f" {len(unread):,} column(s) in the file are not read: {', '.join(unread)}."
                  if unread else "")
               + (f" Not in the file, so not read: {', '.join(missing)}." if missing else "")
               + " A machine without a sensor has no reading."),
        extra={"rows": str(len(rows)), "distinct_hosts": str(len(machines)),
               "sibling_export_hosts": str(platform_machines),
               "absent_from_this_export": str(sum(absent.values())),
               "columns_unread": str(len(unread))},
        **base))
    return out, gaps


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows and gaps, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    assets, gaps = read(ctx.input, ctx)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon Windows platform protections",
                gap_prefix=False)
