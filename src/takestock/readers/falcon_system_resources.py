"""CrowdStrike Falcon: which BIOS or UEFI firmware versions the sensored machines run.

Firmware is the first code a machine runs, and where Secure Boot's chain of
trust starts. This reader counts the machines on each firmware version and
finds machines left behind while identical hardware beside them has been
updated.

**The input** (``input:``) is a CSV with one row per machine (or per machine
and network adapter). The default headings are the field names of the
Falcon sensor's host record as the CrowdStrike API returns it (Elastic's
CrowdStrike integration shows them in a sample record; ``docs/COLLECTORS.md``
gives the source). An export from the Falcon console carries headings of its
own; name them with ``settings: columns:`` (a heading, or a list tried in
order):

=====================  =====================  ==============================
field                  default heading        what it holds
=====================  =====================  ==============================
``machine``            ``hostname``           the machine's name
``os``                 ``os_version``         its operating system
``bios_manufacturer``  ``bios_manufacturer``  who made the firmware
``bios_version``       ``bios_version``       the firmware version
=====================  =====================  ==============================

**One row per manufacturer and version**, named ``Firmware <manufacturer>
<version>``, ``n/a``, flagged ``firmware-census:<n>``: a population, never a
row per machine. Machines are counted by name, ignoring case.

**"Behind" means behind this estate's own newest, on the same hardware.**
takestock holds no list of each manufacturer's current firmware, so a version
is never called out of date against the vendor. Versions are grouped into
hardware *families* by their leading token (``Q91`` in ``Q91 Ver. 3.41``);
two families are parallel product lines and are never compared. Within a
family an order is claimed only when every version has the same shape once
its digit runs are set aside; the versions are then compared number by
number. A version older than the newest the estate itself runs in its family
is flagged ``firmware-behind-estate-peers:<n>``, ``n`` being how many newer
versions the estate runs there: the newer firmware is known to install on
that hardware. A family whose versions have different shapes is flagged
``firmware-spread-unordered`` and nothing in it is ranked.

All three flags are informational: when a rollout begins, every machine not
yet updated gains the *behind* flag, and that is not the estate getting
worse.

**A scope row**, ``Firmware census scope`` (``n/a``,
``scope-no-firmware-currency-baseline``), counts rows, machines, versions
and makers, the machines behind their peers, and rows with no firmware
fields.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_system_resources"

CENSUS_FLAG = "firmware-census:"
BEHIND_FLAG = "firmware-behind-estate-peers:"
UNORDERED_FLAG = "firmware-spread-unordered"
SCOPE_FLAG = "scope-no-firmware-currency-baseline"

register_informational_prefixes(CENSUS_FLAG, BEHIND_FLAG, UNORDERED_FLAG, SCOPE_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "machine": "hostname",
    "os": "os_version",
    "bios_manufacturer": "bios_manufacturer",
    "bios_version": "bios_version",
}

NO_MAKER = "(manufacturer not reported)"
NO_VERSION = "(version not reported)"


def family_of(version: str) -> str:
    """The hardware family of a firmware version: its leading token (``Q91 Ver. 3.41`` gives ``Q91``)."""
    m = re.match(r"[^\s.]+", version.strip())
    return m.group(0) if m else version.strip()


def shape(version: str) -> str:
    """A version with its digit runs set aside: two versions are ordered only when their shapes match."""
    return re.sub(r"\d+", "#", version)


def order_key(version: str) -> tuple:
    """Digit runs compare as numbers, everything else as text."""
    return tuple(int(c) if c.isdigit() else c for c in re.split(r"(\d+)", version))


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of machines' firmware was read"
        + (f" ({why})" if why else "")
        + ": which BIOS or UEFI firmware versions the sensored machines run",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Firmware is the first code a machine runs and where Secure Boot's chain of "
                "trust starts. Without this export nothing says which versions are in "
                "service, so machines left behind while identical hardware is updated cannot "
                "be seen."),
        harvest=("Export the sensored machines' firmware details as CSV and name it with "
                 "input:; name its headings with settings: columns: if they are not the "
                 "API's field names."),
        nature=coverage.NO_DATA)


def read(path: Path, headings: Mapping[str, Sequence[str]]) -> tuple[list[CryptoAsset], list]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    rows, _, unreadable = _fp.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon firmware export, "
                   + (f"file dated {when}" if when else "file date unavailable"))

    pairs: dict[tuple[str, str], set[str]] = {}
    pair_os: dict[tuple[str, str], dict[str, int]] = {}
    machines: set[str] = set()
    unversioned = 0
    for r in rows:
        machine = _fp.first(r, headings["machine"]).upper()
        if not machine:
            continue
        machines.add(machine)
        maker = _fp.first(r, headings["bios_manufacturer"])
        version = _fp.first(r, headings["bios_version"])
        if not maker and not version:
            unversioned += 1
            continue
        key = (maker or NO_MAKER, version or NO_VERSION)
        pairs.setdefault(key, set()).add(machine)
        os_name = _fp.first(r, headings["os"]) or "unknown"
        mix = pair_os.setdefault(key, {})
        mix[os_name] = mix.get(os_name, 0) + 1

    families: dict[tuple[str, str], list[str]] = {}
    for maker, version in pairs:
        families.setdefault((maker, family_of(version)), []).append(version)
    newest: dict[tuple[str, str], str] = {}
    unordered: set[tuple[str, str]] = set()
    for fam, versions in families.items():
        if len(versions) < 2:
            continue
        if len({shape(v) for v in versions}) == 1:
            newest[fam] = max(versions, key=order_key)
        else:
            unordered.add(fam)

    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}
    out: list[CryptoAsset] = []
    behind_versions = behind_machines = 0
    for (maker, version), held in sorted(pairs.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        n = len(held)
        fam = (maker, family_of(version))
        siblings = families[fam]
        fam_machines = sum(len(pairs[(maker, v)]) for v in siblings)
        flags = [f"{CENSUS_FLAG}{n}"]
        note = (f"{_fp.plural(n, 'machine')} report this firmware"
                + (f", {n / fam_machines:.0%} of the {fam_machines:,} in its hardware family"
                   if len(siblings) > 1 else "")
                + ". A population, not a finding: nothing here says whether it is the "
                  "manufacturer's current release.")
        if fam in newest and version != newest[fam]:
            newer = [v for v in siblings if order_key(v) > order_key(version)]
            flags.append(f"{BEHIND_FLAG}{len(newer)}")
            behind_versions += 1
            behind_machines += n
            top = newest[fam]
            note += (f" It is older than the newest version this estate runs on the same "
                     f"hardware family ({top}, on {_fp.plural(len(pairs[(maker, top)]), 'machine')}"
                     f"), by {_fp.plural(len(newer), 'version')} seen here, so a newer version "
                     "is known to install on this hardware. That is drift within the estate, "
                     "not a judgement against the manufacturer's releases.")
        elif fam in unordered:
            flags.append(UNORDERED_FLAG)
            note += (" The versions in this hardware family are not all numbered the same "
                     "way, so none of them is ranked against the others.")
        mix = pair_os[(maker, version)]
        out.append(CryptoAsset(
            name=f"Firmware {maker} {version}", data_state="discovery", protocol="firmware",
            role=roles.firmware_version_population(n), software=f"{maker} {version}",
            verdict="n/a", flags=flags, hosts_count=n, notes=note,
            extra={"manufacturer": maker, "version": version, "family": family_of(version),
                   "hosts": str(n), "family_hosts": str(fam_machines),
                   "os_mix": ", ".join(f"{k}: {v}" for k, v in
                                       sorted(mix.items(), key=lambda kv: -kv[1]))},
            **base))

    makers = sorted({m for m, _ in pairs})
    out.append(CryptoAsset(
        name="Firmware census scope", data_state="discovery", protocol="firmware",
        role=roles.firmware_census_scope(), verdict="n/a", flags=[SCOPE_FLAG],
        hosts_count=len(machines),
        notes=(f"{len(rows):,} rows covering {_fp.plural(len(machines), 'machine')}; a machine "
               "with more than one network adapter can have a row for each. "
               f"{len(pairs):,} manufacturer and version pairs from "
               f"{_fp.plural(len(makers), 'firmware maker')}"
               + (f"; {unversioned:,} row(s) carried no firmware fields" if unversioned else "")
               + f". {_fp.plural(behind_machines, 'machine')} on "
                 f"{_fp.plural(behind_versions, 'version')} run firmware older than the newest "
                 "the estate itself runs on the same hardware. The export is the machines' "
                 "state when it was taken. Whether any version is its manufacturer's current "
                 "release is not answered here: takestock holds no firmware release list, so "
                 "'behind' means behind the estate's own machines, never behind the vendor. "
                 "A machine without a sensor has no row."),
        extra={"rows": str(len(rows)), "distinct_hosts": str(len(machines)),
               "pairs": str(len(pairs)), "manufacturers": str(len(makers)),
               "behind_estate_pairs": str(behind_versions),
               "behind_estate_hosts": str(behind_machines)},
        **base))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    assets, gaps = read(ctx.input, _fp.columns(ctx, HEADINGS))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon firmware versions",
                gap_prefix=False)
