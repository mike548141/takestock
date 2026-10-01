"""How much a cleartext service is used, as a band rather than a bare number.

``usage_count`` (connections seen to one host's listener) is banded against
other assets with the same finding (the same ``plaintext:`` flag), so a band
compares like with like:

* ``high``: at or above the median of the assets in its class that have a count;
* ``low``: below that median, or a recorded count of zero;
* ``unknown``: no count was recorded.

There is no ``none`` band: a connection log lists connections that happened,
so "never used" and "not recorded" cannot be told apart. ``unknown`` sorts
above ``low`` because a silent asset may be the busiest one.

The band orders findings within a disposition track and is never an input to
the track: an unused open port is as reachable as a busy one.
"""

from __future__ import annotations

from collections.abc import Iterable

from .model import CryptoAsset

UNKNOWN = "unknown"
LOW = "low"
HIGH = "high"

#: Sort key: high first, then unknown, then low, then unbanded.
BAND_RANK = {HIGH: 0, UNKNOWN: 1, LOW: 2, "": 3}

_CLASS_PREFIX = "plaintext:"


def _finding_class(asset: CryptoAsset) -> str:
    for f in asset.flags:
        if f.startswith(_CLASS_PREFIX):
            return f
    return ""


def apply_bands(assets: Iterable[CryptoAsset]) -> list[CryptoAsset]:
    """Set ``usage_band`` on every asset; assets without a ``plaintext:`` flag get ''."""
    assets = list(assets)
    populations: dict[str, list[int]] = {}
    for a in assets:
        cls = _finding_class(a)
        if cls and a.usage_count:
            populations.setdefault(cls, []).append(a.usage_count)
    medians = {cls: sorted(v)[len(v) // 2] for cls, v in populations.items()}

    for a in assets:
        cls = _finding_class(a)
        if not cls:
            a.usage_band = ""
        elif a.usage_count is None:
            a.usage_band = UNKNOWN
        elif a.usage_count <= 0:
            a.usage_band = LOW
        else:
            a.usage_band = HIGH if a.usage_count >= medians.get(cls, 0) else LOW
    return assets


def band_summary(assets: Iterable[CryptoAsset]) -> dict:
    """Counts per band, and the share of banded assets that had a measured count."""
    banded = [a for a in assets if a.usage_band]
    counts = {b: sum(1 for a in banded if a.usage_band == b) for b in (HIGH, LOW, UNKNOWN)}
    total = len(banded)
    measured = total - counts[UNKNOWN]
    return {
        "by_band": counts,
        "total_banded": total,
        "measured": measured,
        "measured_share": round(measured / total, 3) if total else 0.0,
    }
