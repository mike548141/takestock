"""The CrowdStrike Falcon device and sensor event reader in takestock's readers library.

Each export is composed in its test under the reader's default headings (the
sensor's field names, and ``_count``), with made-up machine names and device
makers. Nothing here was captured from a real export.
"""

from __future__ import annotations

import os
from pathlib import Path

from entra_helpers import by_name, ctx, write

from takestock import coverage
from takestock.readers import falcon_endpoint_events as reader
from takestock.readers import library

DEVICES = ("#event_simpleName", "aid", "ComputerName", "DeviceManufacturer", "DeviceProduct",
           "_count")
SENSOR = ("#event_simpleName", "aid", "ComputerName", "_count")


def _export(path: Path, columns: tuple[str, ...], rows: list[dict]) -> Path:
    path = write(path, columns, rows)
    os.utime(path, (1_900_000_000, 1_900_000_000))  # 2030-03-17
    return path


def _d(event: str, machine: str, maker: str = "", product: str = "", n: int = 1) -> dict:
    return {"#event_simpleName": event, "aid": f"aid-{machine}", "ComputerName": machine,
            "DeviceManufacturer": maker, "DeviceProduct": product, "_count": str(n)}


def _e(event: str, machine: str, n: int) -> dict:
    return {"#event_simpleName": event, "aid": f"aid-{machine}", "ComputerName": machine,
            "_count": str(n)}


def _run(tmp_path: Path, devices: list[dict] | None, sensor: list[dict] | None):
    settings = ({"sensor_events": str(_export(tmp_path / "s.csv", SENSOR, sensor))}
                if sensor is not None else {})
    path = _export(tmp_path / "d.csv", DEVICES, devices) if devices is not None else None
    return reader.step(ctx(reader.PLUGIN, path, settings))


def test_the_reader_is_in_the_library():
    assert library()["falcon_endpoint_events"] is reader.PLUGIN
    assert reader.PLUGIN.kind == "general" and reader.PLUGIN.input == ""


def test_nothing_named_gives_two_gaps_sensor_events_first():
    out = reader.step(ctx(reader.PLUGIN, None))
    assert out.records == []
    assert [coverage.kind_of(g) for g in out.gaps] == [coverage.NOT_COLLECTED] * 2
    assert "tampering" in str(out.gaps[0]) and "USB" in str(out.gaps[1])


def test_device_rows(tmp_path):
    out = _run(tmp_path, [
        _d("RemovableMediaVolumeMounted", "alpha", n=2),
        _d("RemovableMediaVolumeMounted", "Bravo", "Example Storage Co", n=1),
        _d("DcUsbDeviceConnected", "alpha", "Example Input Co", "Keyboard", 5),
        _d("DcUsbDeviceConnected", "charlie", "Example Storage Co", "Stick", 3),
        _d("DcUsbDeviceConnected", "bravo", "", "", 1),
    ], [_e("SensorTampering", "alpha", 1)])
    rows = by_name(out.records)
    mounted = rows["Removable storage mounted"]
    assert mounted.verdict == "n/a" and mounted.data_state == "discovery"
    assert mounted.protocol == "endpoint-event"
    assert mounted.flags == ["removable-storage-mounted:2"]
    assert mounted.extra == {"events": "3", "hosts": "2", "rows": "2", "rows_naming_device": "1",
                             "standard": "NZISM v3.9 13.3.6.C.02"}
    usb = rows["USB devices connected"]
    assert usb.flags == ["usb-devices-connected:3"]
    assert usb.extra == {"events": "9", "hosts": "3", "manufacturers": "2"}
    assert usb.collected_at == "2030-03-17"


def test_sensor_event_counts_are_a_gap_never_rows(tmp_path):
    out = _run(tmp_path, [_d("DcUsbDeviceConnected", "alpha", "Example Input Co", n=1)], [
        _e("SensorTampering", "alpha", 4), _e("SensorTampering", "bravo", 1),
        _e("LsassHandleFromUnsignedModule", "charlie", 7)])
    assert [r.name for r in out.records] == ["Removable storage mounted",
                                             "USB devices connected"]
    assert len(out.gaps) == 1
    g = out.gaps[0]
    assert coverage.kind_of(g) == coverage.NOT_MEASURED
    assert coverage.nature_of(g) == coverage.LOW_FIDELITY
    assert "5 sensor tampering events on 2 machines" in str(g)
    assert "7 events on 1 machine where" in str(g)


def test_a_sensor_export_without_either_event_raises_nothing(tmp_path):
    out = _run(tmp_path, [_d("DcUsbDeviceConnected", "alpha", n=1)],
               [_e("SomeOtherEvent", "alpha", 2)])
    assert out.gaps == []
