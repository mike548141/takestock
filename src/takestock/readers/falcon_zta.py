"""CrowdStrike Falcon: the Zero Trust Assessment's platform-integrity answers, one row per machine.

**The input** (``input:``) is an export of the sensor's
``ZeroTrustHostAssessment`` events from LogScale (Falcon Next-Gen SIEM):
JSON (an array of rows, one object, or one object per line) or CSV.
``docs/COLLECTORS.md`` gives the query. Each row is read in one of three
shapes:

* the raw event as a JSON string under ``@rawstring``, with the sensor ID
  ``aid`` and the event time ``@timestamp`` (milliseconds) beside it;
* the event itself, with its ``assessments`` and ``scores`` objects;
* the event flattened, as ``assessments.<item>`` and ``scores.<name>``.

The event carries the machine (``hostname``, ``os_version``,
``product_name``, ``product_type_desc``, ``event_platform``), the three
assessment ``scores``, and ``assessments``: one ``yes`` or ``no`` per
assessment item. The machine's latest event (by ``@timestamp``) is kept;
a row with no readable event or sensor ID is counted in a gap, never
dropped in silence.

**One row per machine**, ``Platform integrity — <machine>``, with every
assessment item in ``extra`` under ``zta.``, so a view of endpoint
management reads the same row. The grade reads only the items of
:data:`CONTROLS`, which together say whether the machine verifies what it
boots, enforces code signatures while running, protects the key material
held in memory, and guards that memory against direct memory access:

* ``weak`` when any of them answers ``no`` (each flagged by name);
* ``acceptable`` when every one the machine carries answers ``yes``, never
  ``strong``, since these are switches, not graded cryptographic primitives;
* ``unknown`` when an answer is neither ``yes`` nor ``no``
  (``unreadable-assessment:<item>``), or when the machine carries none of
  them (``not-assessed:platform-integrity``): answers to other items say
  nothing about these.

An item a machine does not carry is never a ``no``: it is flagged
``not-assessed:<item>`` and kept out of the grade. ``firmware_is_uefi``
answering ``no`` adds ``secure-boot-impossible-legacy-bios``: Secure Boot
is a UEFI feature, so on that machine the remedy is new firmware or
hardware, not a setting. ``settings: controls: {<item>: <flag>}`` replaces
the graded set.

**Machine type.** ``product_type_desc`` is the assessment's type for the
machine. ``settings: host_types:`` names further exports that type each
sensor's machine, read as the ``falcon`` reader reads them (``aid`` and
``ProductType`` by default; ``settings: columns: {host_types: {...}}``
names others). Where every one gives a sensor the same type, ignoring case,
and it differs from the assessment's, theirs is kept; the assessment's
stays in ``extra.host_type_reported`` beside the basis.

**Coverage gaps.** No export read; rows that could not be read; and
machines carrying none of the graded items, by platform.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi
from .falcon import HOST_TYPE_HEADINGS, host_types, resolve_type

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_zta"

NOT_ASSESSED = "not-assessed:"
UNREADABLE = "unreadable-assessment:"
NOT_ASSESSED_AT_ALL = f"{NOT_ASSESSED}platform-integrity"
LEGACY_BIOS_FLAG = "secure-boot-impossible-legacy-bios"
EXTRA_PREFIX = "zta."
register_informational_prefixes(NOT_ASSESSED, UNREADABLE)

BASIS_ASSESSMENT = "zero-trust assessment"
BASIS_INVENTORY = "sensor inventory, joined on sensor id"

#: Verifying what the machine boots.
BOOT_CHAIN = {
    "secure_boot_enabled": "no-secure-boot",
    "firmware_is_uefi": "legacy-bios-firmware",
    "uefi_memory_protection": "no-uefi-memory-protection",
    "hsti_available": "no-hardware-security-testing",
    "smm_protections": "no-firmware-memory-protection",
}
#: Enforcing code signatures while the machine runs. ``test_signing_disabled``
#: answering ``no`` means code signed with a test certificate is loaded.
CODE_SIGNATURE = {
    "hvci_enabled": "no-kernel-code-integrity",
    "hvci_strict_mode": "no-strict-kernel-code-integrity",
    "kmci_enabled": "no-kernel-mode-code-integrity",
    "test_signing_disabled": "test-signing-enabled",
    "secure_kernel_running": "no-secure-kernel",
}
#: Protecting key material held in memory (cached sign-in secrets are keys).
KEY_MATERIAL = {
    "credential_guard_running": "no-credential-guard",
    "vsm_available": "no-virtualisation-based-security",
    "secure_mor_available": "no-secure-memory-overwrite",
}
#: Guarding that memory against direct memory access by devices.
DMA_PROTECTION = {
    "dma_guard_enabled": "no-dma-guard",
    "iommu_available": "no-iommu",
    "iommu_in_use": "iommu-not-in-use",
    "mbec_available": "no-mode-based-execution-control",
}
#: The assessment items the grade reads, each with the flag its ``no`` raises.
CONTROLS: dict[str, str] = {**BOOT_CHAIN, **CODE_SIGNATURE, **KEY_MATERIAL, **DMA_PROTECTION}

#: The further machine-type exports' fields and default headings (as the ``falcon`` reader's).
HEADINGS: dict[str, dict[str, Any]] = {"host_types": dict(HOST_TYPE_HEADINGS)}


def _yes_no(value: object) -> str | None:
    """``yes`` or ``no``, or None for anything else (never folded into ``no``)."""
    text = str(value).strip().lower()
    return text if text in ("yes", "no") else None


def load(path: Path) -> tuple[list[Any], str]:
    """The export's rows (any JSON value; the caller checks each), or ([], why)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        return [], str(exc)
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, list):
        return doc, ""
    if isinstance(doc, dict):
        return [doc], ""
    out: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append(None)
    if any(isinstance(r, dict) for r in out):
        return out, ""
    table = _csv_rows(text)
    if table:
        return table, ""
    return [], ("the file is not a JSON array, one JSON object per line, or a CSV with an "
                "@rawstring or assessments.<item> column")


def _csv_rows(text: str) -> list[Any]:
    """The rows of a CSV export carrying the event (``@rawstring``) or its flattened items."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        heads = [h.strip() for h in (reader.fieldnames or [])]
        if "@rawstring" not in heads and not any(h.startswith("assessments.") for h in heads):
            return []
        return [{(k or "").strip(): v for k, v in r.items() if k} for r in reader]
    except csv.Error:
        return []


def _unflatten(row: Mapping[str, Any], prefix: str) -> dict[str, Any]:
    return {k[len(prefix):]: v for k, v in row.items()
            if isinstance(k, str) and k.startswith(prefix)}


def event_of(row: object) -> dict[str, Any] | None:
    """The assessment event a row carries, in any of the three shapes, or None."""
    if not isinstance(row, dict):
        return None
    raw = row.get("@rawstring")
    if raw is not None:
        if not isinstance(raw, str):
            return None
        try:
            event = json.loads(raw)
        except ValueError:
            return None
        return event if isinstance(event, dict) else None
    if isinstance(row.get("assessments"), dict):
        return dict(row)
    flat = _unflatten(row, "assessments.")
    if flat:
        event = {k: v for k, v in row.items() if "." not in str(k)}
        event["assessments"] = flat
        event["scores"] = _unflatten(row, "scores.")
        return event
    return None


def _when(row: Mapping[str, Any], event: Mapping[str, Any]) -> float:
    for v in (row.get("@timestamp"), event.get("timestamp")):
        try:
            return float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return float("-inf")


def latest(rows: list[Any]) -> tuple[dict[str, dict[str, Any]], int]:
    """Each sensor's latest event, and how many rows could not be read."""
    held: dict[str, tuple[float, dict[str, Any]]] = {}
    unreadable = 0
    for row in rows:
        event = event_of(row)
        if event is None:
            unreadable += 1
            continue
        aid = str((row.get("aid") if isinstance(row, dict) else "") or event.get("aid")
                  or "").strip()
        if not aid:
            unreadable += 1
            continue
        when = _when(row, event)
        if aid not in held or when > held[aid][0]:
            held[aid] = (when, event)
    return {aid: ev for aid, (_, ev) in held.items()}, unreadable


def posture(items: Mapping[str, Any], controls: Mapping[str, str] | None = None,
            ) -> tuple[str, set[str], dict[str, int]]:
    """``(verdict, flags, counts)`` for one machine's assessment items."""
    lens = controls if controls is not None else CONTROLS
    flags: set[str] = set()
    failing = passing = unreadable = absent = 0
    for item, flag in lens.items():
        if item not in items:
            absent += 1
            continue
        answer = _yes_no(items[item])
        if answer == "no":
            failing += 1
            flags.add(flag)
        elif answer == "yes":
            passing += 1
        else:
            unreadable += 1
            flags.add(f"{UNREADABLE}{item}")
    if failing + passing + unreadable == 0:
        flags.add(NOT_ASSESSED_AT_ALL)
        verdict = "unknown"
    else:
        flags.update(f"{NOT_ASSESSED}{item}" for item in lens if item not in items)
        verdict = "weak" if failing else ("unknown" if unreadable else "acceptable")
    if _yes_no(items.get("firmware_is_uefi")) == "no":
        flags.add(LEGACY_BIOS_FLAG)
    return verdict, flags, {"failing": failing, "passing": passing,
                            "unreadable": unreadable, "absent": absent}


def _notes(counts: Mapping[str, int], flags: set[str], items: int, graded: int) -> str:
    if NOT_ASSESSED_AT_ALL in flags:
        parts = [f"Not assessed: none of the {graded} platform-integrity items this reader "
                 f"grades is among this machine's {items} assessment item(s), so its posture "
                 "is unmeasured, not good"]
    else:
        lead = "Controls off: " if counts["failing"] else ""
        parts = [f"{lead}{counts['passing']} of {counts['passing'] + counts['failing']} "
                 "platform-integrity controls assessed on this machine are on"]
        if counts["absent"]:
            parts.append(f"{counts['absent']} not assessed here")
        if counts["unreadable"]:
            parts.append(f"{counts['unreadable']} answered something other than yes or no")
    if LEGACY_BIOS_FLAG in flags:
        parts.append("legacy BIOS firmware, so Secure Boot cannot be turned on here: the "
                     "remedy is new firmware or hardware, not a setting")
    parts.append(f"all {items} assessment item(s) are kept for the endpoint-management view")
    return "; ".join(parts) + "."


def _no_export_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon Zero Trust Assessment export was read"
        + (f" ({why})" if why else "")
        + ": whether each machine verifies what it boots, enforces code signatures and "
        "protects the key material in its memory, and an independent count of the machines "
        "with the sensor",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it the report can say what is installed on each machine but not "
                "whether its built-in protections (secure boot, code signing, credential "
                "protection) are on, and it loses a second count of the machines with the "
                "sensor."),
        harvest=("Run the Zero Trust Assessment query in docs/COLLECTORS.md (falcon_zta), export "
                 "the results as JSON and name the file with input:."),
        nature=coverage.NO_DATA)


def _unreadable_gap(unreadable: int, total: int) -> coverage.Gap:
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"{unreadable:,} of {total:,} row(s) in the Zero Trust Assessment export could not be "
        "read: a row is expected to carry the event (as JSON under @rawstring, or as its own "
        "fields) and a sensor ID. They are counted rather than skipped, since a dropped row "
        "would read as a machine that does not exist",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Some machines in the export could not be read, so every share of machines "
                "here is over slightly fewer machines than the export holds."),
        harvest="Export the events again; a cut-off file is one possible cause.",
        nature=coverage.NO_DATA)


def _unassessed_gap(unassessed: list[dict[str, Any]], assessed: list[dict[str, Any]],
                    total: int, graded: int) -> coverage.Gap:
    platforms = Counter(str(h["platform"] or "unknown") for h in unassessed)
    where = ", ".join(f"{n:,} {p}" for p, n in sorted(platforms.items()))
    sizes = sorted({h["items"] for h in unassessed})
    size = f"{sizes[0]:,}" if len(sizes) == 1 else f"{sizes[0]:,}-{sizes[-1]:,}"
    best = max((h["items"] for h in assessed), default=0)
    return coverage.gap(
        coverage.EXTENT_UNKNOWN,
        f"the Zero Trust Assessment carries none of the {graded} platform-integrity items "
        f"graded here for {len(unassessed):,} of {total:,} machine(s) ({where}). Each carries "
        f"{size} assessment item(s), where the {len(assessed):,} machine(s) graded carry up to "
        f"{best:,}. None of the graded boot-chain, code-signing, credential-protection or "
        "direct-memory-access items is answered for them, so each is unknown and flagged "
        f"{NOT_ASSESSED_AT_ALL}, not passed. This is a limit of what the assessment covers, "
        "not a finding about the machines",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("For these machines the assessment answers none of the items graded here, so "
                "any share of protected machines is over the smaller set, and whether these "
                "machines verify their boot, enforce code signing or protect key material "
                "cannot be answered from the items graded here; settings: controls: can add "
                "this platform's own items, listed with the graded ones, since it replaces the "
                "whole set."),
        harvest=("A platform-integrity assessment for these machines from the vendor, or a "
                 "different instrument for the operating system they run."),
        nature=coverage.NO_DATA)


def read(path: Path | None, *, type_paths: list[Path] | None = None,
         headings: Mapping[str, Mapping[str, Any]] | None = None,
         controls: Mapping[str, str] | None = None,
         ) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows and gaps for one assessment export."""
    if path is None:
        return [], [_no_export_gap("")]
    if not path.exists():
        return [], [_no_export_gap(f"{path.name} was named and not found")]
    rows, why = load(path)
    if not rows:
        return [], [_no_export_gap(why or "the file holds no rows")]
    lens = dict(controls) if controls is not None else dict(CONTROLS)
    heads = (headings or HEADINGS)["host_types"]
    others = host_types(type_paths or [], heads)
    when = file_mtime_date(path) or ""
    source_name = _fi.source_name("Zero Trust Assessment", when)

    machines, unreadable = latest(rows)
    unassessed: list[dict[str, Any]] = []
    assessed: list[dict[str, Any]] = []
    out: list[CryptoAsset] = []
    for aid, event in sorted(machines.items()):
        raw_items = event.get("assessments")
        items: dict[str, Any] = raw_items if isinstance(raw_items, dict) else {}
        hostname = str(event.get("hostname") or "").strip()
        os_version = str(event.get("os_version") or "").strip()
        product = str(event.get("product_name") or "").strip()
        reported = str(event.get("product_type_desc") or "").strip()
        kept = resolve_type(aid, reported, others)
        platform = str(event.get("event_platform") or "").strip()
        scores = event.get("scores") if isinstance(event.get("scores"), dict) else {}
        verdict, flags, counts = posture(items, lens)
        (unassessed if NOT_ASSESSED_AT_ALL in flags else assessed).append(
            {"platform": platform, "items": len(items)})
        extra: dict[str, Any] = {
            "aid": aid, "os_version": os_version, "product_name": product,
            "host_type": kept, "host_type_reported": reported,
            "host_type_basis": BASIS_INVENTORY if kept != reported else BASIS_ASSESSMENT,
            "event_platform": platform, "scores": scores, "zta_items": len(items),
            "zta_crypto_items_assessed": counts["passing"] + counts["failing"]
                                         + counts["unreadable"],
        }
        extra.update({f"{EXTRA_PREFIX}{k}": v for k, v in items.items()})
        out.append(CryptoAsset(
            name=f"Platform integrity — {hostname or aid}",
            role=roles.platform_integrity(hostname, roles.machine_kind(os_version, kept)),
            data_state="platform-integrity", protocol="", host=hostname, software=product,
            version=os_version, source=NAME, source_class="private", source_name=source_name,
            collected_at=when, verdict=verdict, flags=sorted(flags),
            notes=_notes(counts, flags, len(items), len(lens)), extra=extra))

    gaps: list[coverage.Gap] = []
    if unreadable:
        gaps.append(_unreadable_gap(unreadable, len(rows)))
    if unassessed:
        gaps.append(_unassessed_gap(unassessed, assessed, len(machines), len(lens)))
    return out, gaps


def step(ctx: Context) -> StepResult:
    """The plug-in's step: one row per machine assessed, or a gap saying no export was read."""
    controls = (ctx.settings or {}).get("controls")
    lens = ({str(k): str(v) for k, v in controls.items()}
            if isinstance(controls, Mapping) and controls else None)
    assets, gaps = read(ctx.input, type_paths=_entra.paths(ctx, "host_types"),
                        headings=_fi.headings(ctx, HEADINGS), controls=lens)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon Zero Trust Assessment (platform integrity per machine)",
                gap_prefix=False)
