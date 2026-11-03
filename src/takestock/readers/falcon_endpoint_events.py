"""CrowdStrike Falcon: removable storage and USB devices the sensor saw, and two counts held as a gap.

Two CSV exports, each written by a LogScale (Falcon Next-Gen SIEM) query
that groups the sensor's events and counts them; ``docs/COLLECTORS.md``
gives the queries.

* ``input:``: USB devices connected (``DcUsbDeviceConnected``) and
  removable storage volumes mounted (``RemovableMediaVolumeMounted``),
  grouped by event, machine and device maker and product.
* ``settings: sensor_events:``: sensor tampering events
  (``SensorTampering``) and the process holding Windows sign-in credentials
  opened from an unsigned module (``LsassHandleFromUnsignedModule``),
  grouped by event and machine.

Every other endpoint row describes how a machine is configured. These rows
say what happened on it.

* ``Removable storage mounted``: mounts, on how many machines, and how many
  rows name the device. Evidence of use, never of a device control: the
  events cannot show whether the device was allowed, blocked elsewhere,
  encrypted or authorised. NZISM v3.9 13.3.6.C.02 is cited for what such a
  control must do.
* ``USB devices connected``: USB device connections of whatever kind the
  event records, not only storage, with the makers counted.

**The tampering and credential-store counts are not rows.** Either event
type is what interference or credential theft would produce, and either may
also have an ordinary cause; the export carries nothing that tells them
apart (not the module, the access asked for, or whether the platform raised
a detection).
A count alone would read as an incident or as an all-clear and be neither,
so the counts go into one gap saying what is unknown until the events are
triaged against the platform's detections. Every row is ``n/a``.

A machine is counted by its name ignoring case, or by its sensor ID where a
row has no name. Counts are events, not uses: the export does not say how
many events one connection raises.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_identity as _fi
from . import _falcon_traffic as _ft
from ._falcon_traffic import COUNT_HEADING

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_endpoint_events"

TAMPER = "SensorTampering"
LSASS = "LsassHandleFromUnsignedModule"
USB = "DcUsbDeviceConnected"
MOUNT = "RemovableMediaVolumeMounted"

#: NZISM v3.9 13.3.6.C.02 (MUST, all classifications): "Agencies MUST prevent unauthorised
#: media from connecting to a system via the use of: device access control software; seals;
#: physical means; or other methods approved by the Accreditation Authority."
NZISM_MEDIA = "NZISM v3.9 13.3.6.C.02"

#: Each export's fields and the headings they are read from unless ``settings: columns:`` names others.
HEADINGS: dict[str, dict[str, Any]] = {
    "devices": {"event": "#event_simpleName", "machine": "ComputerName", "sensor_id": "aid",
                "manufacturer": "DeviceManufacturer", "product": "DeviceProduct",
                "count": COUNT_HEADING},
    "sensor_events": {"event": "#event_simpleName", "machine": "ComputerName",
                      "sensor_id": "aid", "count": COUNT_HEADING},
}


def _no_sensor_events_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of sensor tampering events or unsigned access to the "
        "credential process was read" + (f" ({why})" if why else "")
        + ": how often, and on how many machines",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Without it nothing says whether anything on the machines interferes with the "
                "sensor or opens the process that holds sign-in credentials the way credential "
                "theft does."),
        harvest=("Run the sensor event query in docs/COLLECTORS.md (falcon_endpoint_events) and "
                 "name the CSV with settings: sensor_events:."),
        nature=coverage.NO_DATA)


def _held_gap(tamper: tuple[int, int] | None, lsass: tuple[int, int] | None) -> coverage.Gap:
    parts = []
    if tamper:
        parts.append(f"{_ft.plural(tamper[0], 'sensor tampering event')} on "
                     f"{_ft.plural(tamper[1], 'machine')}")
    if lsass:
        parts.append(f"{_ft.plural(lsass[0], 'event')} on {_ft.plural(lsass[1], 'machine')} "
                     "where the process holding sign-in credentials was opened from a module "
                     "without a valid signature")
    return coverage.gap(
        coverage.NOT_MEASURED,
        "the sensor event export holds " + " and ".join(parts)
        + ". What these counts mean is not known: either event type is what interference or "
          "credential theft would produce, and either may also have an ordinary cause, which "
          "the export cannot tell apart. Until the events are triaged against the platform's "
          "own detections, neither count is reported as a reading",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("The report says nothing about whether anything interferes with the sensor or "
                "reaches for stored sign-in credentials. The events exist; a count quoted "
                "without triage would read as an incident or as an all-clear, and be neither."),
        harvest=("Triage the events against the platform's detections. Nothing else in the "
                 "report waits on it."),
        nature=coverage.LOW_FIDELITY)


def _no_devices_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of USB devices and removable storage was read"
        + (f" ({why})" if why else "")
        + ": whether removable storage is used at all, and on how many machines",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Without it nothing says whether removable storage is in use, so what may be "
                "copied off a machine has no evidence either way."),
        harvest=("Run the device query in docs/COLLECTORS.md (falcon_endpoint_events) and name "
                 "the CSV with input:."),
        nature=coverage.NO_DATA)


def sensor_event_gaps(path: Path | None, h: Mapping[str, Any]) -> list[coverage.Gap]:
    """The one gap for the tampering and credential-store counts (none when neither event is there)."""
    rows, why = _fi.rows(path)
    if not rows:
        return [_no_sensor_events_gap(why or ("the file named holds no rows" if path else ""))]

    def tally(event: str) -> tuple[int, int] | None:
        hit = [r for r in rows if _fi.value(r, h["event"]) == event]
        if not hit:
            return None
        machines = {_fi.machine(r, h) for r in hit} - {""}
        return sum(_fi.events(_fi.value(r, h["count"])) for r in hit), len(machines)

    tamper, lsass = tally(TAMPER), tally(LSASS)
    return [_held_gap(tamper, lsass)] if (tamper or lsass) else []


def device_rows(path: Path | None, h: Mapping[str, Any]) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The removable storage and USB rows, or a gap when the export holds none."""
    rows, why = _fi.rows(path)
    if not rows or path is None:
        return [], [_no_devices_gap(why or ("the file named holds no rows" if path else ""))]
    when = file_mtime_date(path) or ""
    base: dict[str, Any] = {"data_state": "discovery", "protocol": "endpoint-event",
                            "source": NAME,
            "source_class": "private", "source_name": _fi.source_name("device event", when),
            "collected_at": when, "verdict": "n/a"}
    mounts = [r for r in rows if _fi.value(r, h["event"]) == MOUNT]
    usb = [r for r in rows if _fi.value(r, h["event"]) == USB]
    mount_hosts = {_fi.machine(r, h) for r in mounts} - {""}
    usb_hosts = {_fi.machine(r, h) for r in usb} - {""}
    mount_events = sum(_fi.events(_fi.value(r, h["count"])) for r in mounts)
    usb_events = sum(_fi.events(_fi.value(r, h["count"])) for r in usb)
    makers = {_fi.value(r, h["manufacturer"]) for r in usb} - {""}
    named = sum(1 for r in mounts
                if _fi.value(r, h["manufacturer"]) or _fi.value(r, h["product"]))
    out = [
        CryptoAsset(
            name="Removable storage mounted", role=roles.removable_storage(len(mount_hosts)),
            flags=[f"removable-storage-mounted:{len(mount_hosts)}"],
            hosts_count=len(mount_hosts),
            notes=(f"Removable storage was mounted {mount_events:,} times on "
                   f"{len(mount_hosts):,} machines. "
                   + (f"{named:,} of {len(mounts):,} rows name the device. " if mounts else "")
                   + f"{NZISM_MEDIA} says agencies must prevent unauthorised media from "
                     "connecting, by device access control software or another approved "
                     "means. These events show storage was connected; they cannot show whether "
                     "the device was authorised, whether a device control allowed it, what was "
                     "copied, or whether the media was encrypted. They are evidence of use, not "
                     "of the control either way. " + _fi.NO_TIMES_NOTE),
            extra={"events": str(mount_events), "hosts": str(len(mount_hosts)),
                   "rows": str(len(mounts)), "rows_naming_device": str(named),
                   "standard": NZISM_MEDIA},
            **base),
        CryptoAsset(
            name="USB devices connected", role=roles.usb_devices(len(usb_hosts)),
            flags=[f"usb-devices-connected:{len(usb_hosts)}"], hosts_count=len(usb_hosts),
            notes=(f"{usb_events:,} USB connection events on {len(usb_hosts):,} machines, from "
                   f"{len(makers):,} named makers. These are connections of whatever kind of "
                   "USB device the event records, not only storage, so this is the reach of "
                   "the USB channel, not a count of storage; storage is the row above. "
                   + _fi.NO_TIMES_NOTE),
            extra={"events": str(usb_events), "hosts": str(len(usb_hosts)),
                   "manufacturers": str(len(makers))},
            **base),
    ]
    return out, []


def read(devices: Path | None, sensor_events: Path | None = None, *,
         headings: Mapping[str, Mapping[str, Any]] | None = None,
         ) -> tuple[list[CryptoAsset], list[coverage.Gap]]:
    """The rows and gaps for both exports: the sensor event gap first, then the device rows."""
    heads = headings or HEADINGS
    gaps = sensor_event_gaps(sensor_events, heads["sensor_events"])
    rows, g = device_rows(devices, heads["devices"])
    return rows, gaps + g


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the device rows, and the gaps for what was not read or not reported."""
    assets, gaps = read(ctx.input, _entra.newest(ctx, "sensor_events"),
                        headings=_fi.headings(ctx, HEADINGS))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gaps.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon removable storage, USB devices and sensor events",
                gap_prefix=False)
