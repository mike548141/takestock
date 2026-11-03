"""CrowdStrike Falcon: the cryptographic software installed on each machine, by release line.

The probes measure what a service negotiates. This reader measures what it
negotiates *with*: the TLS libraries, runtimes and other cryptographic
software installed on the machines a Falcon sensor runs on. Two questions
need the installed version rather than a probe:

* **A capability ceiling.** A release line that cannot negotiate a protocol
  cannot be configured into it; only an upgrade reaches it.
* **How quickly the estate could change an algorithm.** One measurable
  proxy is how many versions of the same library are in service at once.

**The input** (``input:``) is a CSV with one row per machine and installed
application. ``docs/COLLECTORS.md`` gives a LogScale query over the sensor's
``InstalledApplication`` events that writes it. The fields read, and their
default headings (``settings: columns:`` names another heading, or a list
tried in order):

===============  =================  =========================================
field            default heading    what it holds
===============  =================  =========================================
``agent_id``     ``aid``            the sensor's ID, used when a row names no machine
``machine``      ``ComputerName``   the machine's name
``product``      ``AppName``        the application's name
``version``      ``AppVersion``     its version
``last_used``    ``last_used``      optional: when it last ran
===============  =================  =========================================

**Matching.** Each application's name is matched against a register of
cryptographic software: takestock's ``crypto-software.csv`` unless
``settings: register:`` names a CSV with the same columns. The first entry
whose ``match`` expression matches the start of the name, ignoring case,
names the product; an application no entry matches is not reported.

**One row per product and release line**, named ``<product> <line>``, never
one per machine. The line is the version's first component, or its first two
when the first is ``1`` (so ``1.0`` and ``1.1`` are separate lines, and
``7.12.4`` is line ``7``), after any packaging epoch (``1:``) and
distribution release suffix (``-4.fc99``) are set aside. A row is graded only
where the register has an entry for that product with exactly that
``branch``, a ``max_tls`` and a ``citation``:

* ``max_tls`` below ``settings: weak_below:`` (default: the lowest TLS
  version the baseline grades better than weak): ``weak``, flagged
  ``capability-ceiling:<max_tls>``;
* below TLS 1.3 but not below ``weak_below``: ``unknown``, with the same
  flag;
* TLS 1.3: ``acceptable``, since the library does not stop a modern
  protocol (a service's configuration still may);
* no such entry: ``unknown``, flagged ``ungraded:crypto-software:<product>
  <line>``.

A product found at two or more versions gets ``<product> version spread``
(``n/a``, flagged ``version-spread:<n>``). Each row's ``extra.installed_on``
lists the machines it counts.

**The secure-shell server, per exact package version.** Each version of a
package named in ``settings: ssh_server_packages:`` (default
``openssh-server``) gets its own row, ``OpenSSH server <version>``, naming
its machines, with the full version string kept: a distribution's release
suffix carries the fixes it has backported, so the upstream number alone can
understate how patched a package is. Flagged ``sshd-version-census:<n>``.
An installed package is not a measurement of what any server negotiates.

**A scope row**, ``Cryptographic software scope``, flagged
``scope-register-limited``: the register is the limit of what is reported.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import config, coverage, roles
from ..collectors.software_inventory import TLS_ORDER, tls_floor, tls_rank
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_software"

CEILING_FLAG = "capability-ceiling:"
SPREAD_FLAG = "version-spread:"
SSHD_FLAG = "sshd-version-census:"
SCOPE_FLAG = "scope-register-limited"

register_informational_prefixes(SPREAD_FLAG, SSHD_FLAG, SCOPE_FLAG)

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "agent_id": "aid",
    "machine": "ComputerName",
    "product": "AppName",
    "version": "AppVersion",
    "last_used": "last_used",
}

#: The secure-shell server's package name, unless ``settings: ssh_server_packages:`` names others.
SSH_SERVER_PACKAGES = ("openssh-server",)

#: The extra key listing the machines a row counts, the shape the configuration register reads.
INSTALLED_ON = "installed_on"

_NEWEST_TLS = TLS_ORDER[-1]
_EPOCH = re.compile(r"^\d+:")
_RELEASE = re.compile(r"-.*$")


def upstream_version(raw: str) -> str:
    """The upstream version inside a package version: ``2:5.31p1-19.fc99`` gives ``5.31p1``."""
    return _RELEASE.sub("", _EPOCH.sub("", str(raw or "").strip()))


def branch_of(version: str) -> str:
    """The release line a version belongs to: ``1.4.17`` gives ``1.4``, ``7.12.4`` gives ``7``.

    Two components when the first is ``1`` (OpenSSL's 1.0 and 1.1, for
    example, are separate lines), otherwise one.
    """
    parts = [p for p in re.split(r"[.\-p]", upstream_version(version)) if p]
    if not parts:
        return ""
    if parts[0] == "1" and len(parts) > 1:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def load_register(path: Path | None) -> list[dict[str, str]]:
    """The register named by ``settings: register:``, else takestock's ``crypto-software.csv``."""
    if path is None:
        return config.load_crypto_software()
    with path.open(newline="", encoding="utf-8-sig") as fh:
        return [{k: str(v or "").strip() for k, v in r.items() if k} for r in csv.DictReader(fh)]


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon export of installed applications was read"
        + (f" ({why})" if why else "")
        + ": which products supply the estate's cryptography, at which versions, and which "
        "machines carry a version that cannot negotiate a current protocol at all",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it a weak protocol result has no product attached, so the fix cannot "
                "be planned as the upgrade of a named library, and how many versions of each "
                "library are in service is unknown."),
        harvest=("Run the LogScale query in docs/COLLECTORS.md (falcon_software) and name its "
                 "CSV with input:."),
        nature=coverage.NO_DATA)


def _grade(entry: Mapping[str, str] | None, product: str, line: str, hosts: int,
           weak_below: str) -> tuple[str, list[str], str]:
    """Verdict, flags and note for one product and release line."""
    if entry is None:
        return ("unknown", [f"ungraded:crypto-software:{product} {line}"],
                f"{_fp.plural(hosts, 'machine')} carry {product} {line}. The register records "
                "that this product provides cryptography, and has no capability on record for "
                "this release line, so the row is counted and not graded.")
    max_tls = entry["max_tls"]
    detail = entry.get("note", "").strip().rstrip(".")
    source = f"Source: {entry['citation']}."
    if tls_rank(max_tls) < tls_rank(_NEWEST_TLS):
        weak = tls_rank(max_tls) < tls_rank(weak_below)
        return ("weak" if weak else "unknown", [f"{CEILING_FLAG}{max_tls}"],
                f"{_fp.plural(hosts, 'machine')} carry {product} {line}, which cannot "
                f"negotiate anything above {max_tls}. " + (f"{detail}. " if detail else "")
                + "No configuration change reaches past that; only an upgrade does. "
                + ("" if weak else f"The ceiling is not below {weak_below}, so it is recorded "
                   "and not graded weak. ") + source)
    return ("acceptable", [],
            f"{_fp.plural(hosts, 'machine')} carry {product} {line}, which can negotiate up to "
            f"{max_tls}: the library does not stop a current protocol, though a service's "
            f"configuration still may. {source}")


def read(path: Path, register: list[dict[str, str]], headings: Mapping[str, Sequence[str]],
         weak_below: str, ssh_packages: Sequence[str]) -> tuple[list[CryptoAsset], list]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    rows, header, unreadable = _fp.load(path)
    if not rows:
        return [], [_missing_gap(f"the file could not be read: {unreadable}" if unreadable
                                 else "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = ("CrowdStrike Falcon installed-application export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    usage_column = _fp.has_column(header, headings["last_used"])
    ssh = {p.lower() for p in ssh_packages}

    found: dict[str, dict[str, dict[str, Any]]] = {}
    entries: dict[str, Mapping[str, str]] = {}
    machines: set[str] = set()
    sshd: dict[str, set[str]] = {}
    sshd_package: dict[str, str] = {}
    for r in rows:
        machine = _fp.first(r, headings["machine"]) or _fp.first(r, headings["agent_id"])
        if machine:
            machines.add(machine)
        name = _fp.first(r, headings["product"])
        if not name:
            continue
        version = _fp.first(r, headings["version"])
        if name.lower() in ssh and machine and version:
            sshd.setdefault(version, set()).add(machine)
            sshd_package.setdefault(version, name.lower())
        entry = next((e for e in register
                      if e.get("match") and re.match(e["match"], name, re.IGNORECASE)), None)
        if entry is None:
            continue
        product = entry["product"]
        entries.setdefault(product, entry)
        slot = found.setdefault(product, {}).setdefault(
            branch_of(version), {"machines": set(), "versions": set(), "unused": 0, "seen": 0})
        if machine:
            slot["machines"].add(machine)
        if version:
            slot["versions"].add(version)
        if usage_column:
            slot["seen"] += 1
            if not _fp.first(r, headings["last_used"]):
                slot["unused"] += 1

    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}
    out: list[CryptoAsset] = []
    for product, lines in sorted(found.items()):
        provides = entries[product].get("provides", "")
        state = "in-transit" if provides == "tls" else "key-material"
        all_versions = {v for s in lines.values() for v in s["versions"]}
        all_machines = {m for s in lines.values() for m in s["machines"]}
        for line, slot in sorted(lines.items()):
            n = len(slot["machines"])
            entry = next((e for e in register
                          if e.get("product") == product and e.get("branch") == line
                          and e.get("max_tls") and e.get("citation")), None)
            verdict, flags, note = _grade(entry, product, line, n, weak_below)
            versions = sorted(slot["versions"])
            extra: dict[str, Any] = {"branch": line, "versions": " ".join(versions),
                                     "version_count": str(len(versions)), "provides": provides,
                                     INSTALLED_ON: sorted(slot["machines"])}
            if slot["seen"]:
                extra["installs_never_used"] = str(slot["unused"])
                extra["installs_with_usage_data"] = str(slot["seen"])
            out.append(CryptoAsset(
                name=f"{product} {line}", data_state=state, protocol=provides or "software",
                role=roles.crypto_library_line(product, n), software=product, version=line,
                verdict=verdict, flags=flags, hosts_count=n, notes=note, extra=extra, **base))
        if len(all_versions) > 1:
            out.append(CryptoAsset(
                name=f"{product} version spread", data_state=state,
                protocol=provides or "software", role=roles.crypto_library_spread(product),
                software=product, verdict="n/a", flags=[f"{SPREAD_FLAG}{len(all_versions)}"],
                hosts_count=len(all_machines),
                notes=(f"{_fp.plural(len(all_machines), 'machine')} carry "
                       f"{len(all_versions):,} different versions of {product}, in "
                       f"{_fp.plural(len(lines), 'release line')}. The more versions in "
                       "service, the more separate upgrades a change of algorithm needs. This "
                       "is a measure of how quickly the estate could move, not a weakness in "
                       "any machine."),
                extra={"versions": " ".join(sorted(all_versions)),
                       "version_count": str(len(all_versions)),
                       "branch_count": str(len(lines))},
                **base))

    all_sshd = {m for ms in sshd.values() for m in ms}
    for version, held in sorted(sshd.items()):
        upstream = upstream_version(version)
        release = version.split("-", 1)[1] if "-" in version else ""
        n = len(held)
        out.append(CryptoAsset(
            name=f"OpenSSH server {version}", data_state="in-transit", protocol="ssh",
            role=roles.ssh_server_package(n), software="OpenSSH server", version=version,
            verdict="unknown",
            flags=[f"{SSHD_FLAG}{n}", f"ungraded:crypto-software:OpenSSH {branch_of(version)}"],
            hosts_count=n,
            notes=(f"{_fp.plural(n, 'machine')} carry the secure-shell server package at "
                   f"exactly {version}. "
                   + (f"The suffix -{release} is the distribution's own build, which can carry "
                      f"fixes backported from later releases, so a claim about a vulnerability "
                      f"needs this full version and not the upstream {upstream} alone. "
                      if release else "")
                   + "An installed package says nothing about what a server negotiates, or "
                     "whether one is running; an SSH probe measures that."),
            extra={"package": sshd_package[version],
                   "package_version": version, "upstream_version": upstream,
                   "package_release": release, "branch": branch_of(version),
                   "hosts": " ".join(sorted(held)), INSTALLED_ON: sorted(held),
                   "sshd_hosts_total": str(len(all_sshd))},
            **base))

    out.append(CryptoAsset(
        name="Cryptographic software scope", data_state="in-transit", protocol="software",
        role=roles.crypto_library_scope_row(), verdict="n/a", flags=[SCOPE_FLAG],
        hosts_count=len(machines),
        notes=(f"Read from {len(rows):,} installed-application rows on "
               f"{_fp.plural(len(machines), 'machine')}, matched against a register of "
               f"{len(register):,} entries for cryptographic software. Software the register "
               "does not list is not reported here: the register is the limit, not the estate. "
               "Only a release line whose capability the register records, with its source, "
               "is graded; the rest are counted."),
        extra={"install_records": str(len(rows)), "hosts": str(len(machines)),
               "register_entries": str(len(register)), "products_found": str(len(found))},
        **base))
    return out, []


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    settings = ctx.settings or {}
    register_path = _entra.newest(ctx, "register")
    try:
        register = load_register(register_path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return StepResult(gaps=[_missing_gap(f"the register named could not be read: {exc}")])
    baseline = ctx.baseline or getattr(ctx.policy, "b", None) or {}
    weak_below = str(settings.get("weak_below") or tls_floor(baseline))
    packages = _fp.words(settings.get("ssh_server_packages"), SSH_SERVER_PACKAGES)
    assets, gaps = read(ctx.input, register, _fp.columns(ctx, HEADINGS), weak_below, packages)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon installed cryptographic software",
                gap_prefix=False)
