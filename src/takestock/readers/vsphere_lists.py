"""vSphere Client list exports: the virtual machines, hosts and datastores a vCenter lists.

Each inventory list in the vSphere Client has an **Export** action that saves
the columns on screen as a CSV file (UTF-8, with a byte-order mark). The file
is named after the list: ``vmsForDatacenter_Name`` for virtual machines,
``hostsForVCenter_Name`` for hosts and ``datastoresForVCenter_Name`` for
datastores. With more than one vCenter, the person exporting adds a label
after the list name so the files can sit in one folder, for example
``vmsForDatacenter_Name SiteA.csv``.

**The input** is a folder of such exports. Every file whose name starts with
one of the three list names is read; other files are ignored. The label
after the list name is the row's **site**. It is taken from the file and
never from a machine's name, because a machine replicated from another
vCenter keeps the name it had there.

**A row is not always a machine.** VMware Site Recovery Manager registers a
placeholder at the recovery site for each machine it protects: powered off,
with the protected machine's name, and with ``Managed By`` naming Site
Recovery Manager. Counting placeholders would count each protected machine
twice, so they are left out of every count but the scope row's. The list has
no templates.

**Rows** (all ``n/a`` except a host certificate, which is ``unknown``):

* per site, **VM encryption**: how many machines vCenter reports with VM
  Encryption on and off. Encryption off is recorded as a fact
  (``vm-encryption-off:<n>``), not graded: whether a machine's files are
  encrypted at rest can also be decided by the storage beneath it, which this
  export does not show. Machines that are encrypted are graded by the
  cipher vSphere uses (:data:`CIPHER`). A value that is neither on nor off is
  flagged ``ungraded:vm-encryption:<value>``;
* per site, **virtual TPM**: machines without one (``vtpm-absent:<n>``);
* per site with Windows machines, **virtualisation-based security**: Windows
  machines whose settings enable it (``vbs-enabled:<n>``);
* per configured **guest operating system**, across sites, with the vendor's
  support status on the export date where a lifecycle line matches the name
  exactly (``guest-os-census:<n>``);
* per host, its **certificate expiry** (``expired`` or ``expiry-soon`` as at
  the export date); the list gives no key, signature or issuer, so each is
  flagged ``not-assessed:certificate-key-and-signature``;
* per **ESXi version**, with its support status (``esxi-version-census:<n>``);
* per site, the **datastores** and what backs them (``datastore-census:<n>``);
* one **scope** row (``scope-vsphere-lists``).

**Support status** comes from a software lifecycle table in the format of
takestock's ``data/software-lifecycle.yaml``, looked up by the configured
guest type (kind ``os``) or ``VMware ESXi <version>`` (kind ``hypervisor``),
exact matches only, on the export's date. The bundled table is used unless
the declaration's ``settings`` names another with ``lifecycle:``.

**Datastores.** A block device's NAA identifier (``naa.6…`` or ``naa.5…``)
carries its maker's IEEE organisationally unique identifier (OUI). A
datastore whose device carries a storage-array maker's prefix
(:data:`ARRAY_MAKERS`), or which is a virtual-volume container, is counted
on an array; one with any other prefix is counted as on disks inside a host;
one with no prefix as not placed. Datastores on disks inside hosts are a
coverage gap: the export does not say whether those disks are encrypted.

**Dates.** The exports carry no date, so every row is dated by the oldest
file's modification date, and certificate expiry is counted from that date,
never from today, so a later run gives the same answer.

**Cannot see.** The key provider configured in vCenter; which datastore
holds which machine's disks; whether any storage encrypts; anything inside a
guest (the operating system is as configured, not as running); and a host
certificate's key, algorithm and issuer.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from datetime import date, datetime
from pathlib import Path

import yaml

from .. import config, coverage, lifecycle, roles
from ..model import CryptoAsset, cert_expiry_flag, register_informational_prefixes, worst
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "vsphere_lists"

#: The file name each list's export starts with.
VM_LIST = "vmsForDatacenter_Name"
HOST_LIST = "hostsForVCenter_Name"
DATASTORE_LIST = "datastoresForVCenter_Name"
LISTS = (VM_LIST, HOST_LIST, DATASTORE_LIST)

#: The cipher vSphere uses for VM Encryption and vSAN encryption, as the
#: baseline names it. Neither offers a choice. Broadcom's vSphere 8.0
#: documentation: "the DEK encrypts the VMDK using the XTS-AES-256 (512-bit
#: key size) algorithm" (*How vSphere Virtual Machine Encryption Protects Your
#: Environment*), and "The ESXi host encrypts disk data using the industry
#: standard AES-256 XTS mode" (vSAN, *How vSAN Data-At-Rest Encryption Works*).
CIPHER = "aes256_xts"

#: Where Broadcom documents that a virtual TPM needs a key provider ("You must
#: create a key provider before you can add a vTPM").
VTPM_SOURCE = ("https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/"
               "vsphere-security/securing-virtual-machines-with-virtual-trusted-"
               "platform-module/enable-vtpm-for-an-existing-virtual-machine.html")

VM_CENSUS_FLAG = "vsphere-vm-census:"
VM_ENCRYPTION_OFF_FLAG = "vm-encryption-off:"
VTPM_ABSENT_FLAG = "vtpm-absent:"
VBS_ENABLED_FLAG = "vbs-enabled:"
DATASTORE_FLAG = "datastore-census:"
GUEST_OS_FLAG = "guest-os-census:"
ESXI_FLAG = "esxi-version-census:"
SCOPE_FLAG = "scope-vsphere-lists"
CERT_NOT_ASSESSED_FLAG = "not-assessed:certificate-key-and-signature"

register_informational_prefixes(
    VM_CENSUS_FLAG, "vm-encryption-off", VTPM_ABSENT_FLAG, VBS_ENABLED_FLAG, DATASTORE_FLAG,
    GUEST_OS_FLAG, ESXI_FLAG, SCOPE_FLAG)

ENCRYPTED = frozenset({"yes", "true", "encrypted"})
NOT_ENCRYPTED = frozenset({"no", "false", "not encrypted", "none"})

#: ``Managed By`` on a Site Recovery Manager placeholder names the extension.
PLACEHOLDER_MANAGER = "site recovery manager"

#: Site Recovery Manager (extension ``com.vmware.vcDr``) keeps a custom
#: attribute on each machine it protects; a list export can show it as a
#: column, and a value in it marks the machine protected.
PROTECTED_ATTRIBUTE = "com.vmware.vcdr:::protected"

#: How the host list writes a certificate's expiry: ``Mar 4, 2031 10:15 AM``.
CERT_DATE_FORMAT = "%b %d, %Y %I:%M %p"

#: Storage-array makers' OUIs, as the IEEE registry holds them (read through
#: the Wireshark project's ``manuf`` file), each a prefix the maker's arrays
#: put in the NAA identifiers of the volumes they present. Where the registry
#: now names a holder other than the array's familiar maker, both are given.
ARRAY_MAKERS: dict[str, str] = {
    "0002ac": "3PAR data",
    "000d31": "Compellent Technologies, Inc.",
    "000097": "Dell EMC",
    "8ccf09": "Dell EMC",
    "006016": "Dell EMC (CLARiiON)",
    "24a937": "Everpure, Inc. (Pure Storage)",
    "0060e8": "Hitachi Computer Products (America), Inc.",
    "005076": "IBM Corp",
    "742b0f": "Infinidat Ltd.",
    "00a098": "NetApp",
    "6c9ce9": "Nimble Storage",
}

#: Other makers whose OUIs commonly appear in the NAA identifiers of disks and
#: solid-state drives inside servers, from the same registry.
DEVICE_MAKERS: dict[str, str] = {
    "0024e8": "Dell Inc.",
    "000cca": "HGST a Western Digital Company",
    "5cd2e4": "Intel Corporate",
    "ace42e": "SK hynix",
    "002538": "Samsung Electronics Co., Ltd.",
    "000c50": "Seagate Technology",
    "000039": "Toshiba Corporation",
    "0014ee": "Western Digital Technologies, Inc.",
}

_NAA = re.compile(r"naa\.[56]([0-9a-f]{6})")
_SIZE = re.compile(r"([\d.,]+)\s*([KMGTP]B)", re.IGNORECASE)
_GB_PER = {"KB": 1 / 1024 ** 2, "MB": 1 / 1024, "GB": 1.0, "TB": 1024.0, "PB": 1024.0 ** 2}

Rows = list[dict[str, str]]


# ── reading ──

def heading(name: object) -> str:
    """A column heading folded for lookup: whitespace runs (some headings hold a line
    break) become one space, and case is ignored."""
    return " ".join(str(name or "").split()).casefold()


def read_list(path: Path) -> Rows:
    """The rows of one list export, keyed by folded heading (the first of two equal headings wins)."""
    with path.open(encoding="utf-8-sig", newline="") as fh:
        out = []
        for raw in csv.DictReader(fh):
            row: dict[str, str] = {}
            for k, v in raw.items():
                if k is None:
                    continue
                row.setdefault(heading(k), str(v or "").strip())
            out.append(row)
        return out


def field(row: dict[str, str], name: str) -> str:
    return row.get(heading(name), "")


def _field_containing(row: dict[str, str], word: str) -> str:
    return next((v for k, v in row.items() if word in k), "")


def list_files(folder: Path | None, list_name: str) -> list[Path]:
    """The exports of one list in ``folder``, in name order."""
    if folder is None or not folder.is_dir():
        return []
    return sorted(p for p in folder.glob(f"{list_name}*.csv") if p.is_file())


def vm_lists_present(folder: Path | None) -> bool:
    """Whether ``folder`` holds at least one virtual-machine list export."""
    return bool(list_files(folder, VM_LIST))


def lists_folder(ctx: Context) -> Path | None:
    """The folder of list exports another reader's ``settings`` names under ``vsphere_lists``."""
    rel = (ctx.settings or {}).get("vsphere_lists")
    return ctx.inbox_path(str(rel)) if rel else None


def site_of(path: Path, list_name: str) -> str:
    """The label after the list name in the file name."""
    return path.stem[len(list_name):].strip(" _-") or "(unnamed)"


def _placeholder(row: dict[str, str]) -> bool:
    return PLACEHOLDER_MANAGER in field(row, "Managed By").casefold()


def _on(row: dict[str, str]) -> bool:
    return field(row, "State").casefold() == "powered on"


def _windows(os_name: str) -> bool:
    return "windows" in os_name.casefold()


def _cert_date(text: str) -> date | None:
    try:
        return datetime.strptime(" ".join(text.split()), CERT_DATE_FORMAT).date()
    except ValueError:
        return None


def maker_prefix(device: str) -> str:
    """The OUI inside a device's NAA identifier, or "" when it has none."""
    m = _NAA.match(device.strip().casefold())
    return m.group(1) if m else ""


def capacity_gb(text: str) -> float:
    """A capacity as the list writes it (``1.5 TB``, ``800 GB``), in GB; 0 when unreadable."""
    m = _SIZE.match(text.strip())
    if not m:
        return 0.0
    return float(m.group(1).replace(",", "")) * _GB_PER[m.group(2).upper()]


# ── support status ──

def support(table: dict, kind: str, product: str, on: str) -> dict:
    """The vendor's support band for ``product`` on ``on``, from ``table``, or why there is none."""
    if not table or not on:
        return {"band": "", "line": "", "why": "no lifecycle table or no export date"}
    hits = lifecycle.match_lines(table, kind, product, "")
    if not hits:
        return {"band": "", "line": "", "why": "no lifecycle line matches this name exactly"}
    if len(hits) > 1:
        return {"band": "", "line": "", "why": "more than one lifecycle line matches this name"}
    line = hits[0]
    s = lifecycle.line_support(line, date.fromisoformat(on))
    sources = table.get("sources") or {}
    urls = sorted({str((sources.get(v.get("source")) or {}).get("url") or "")
                   for v in line.get("variants") or []} - {""})
    return {"band": s["band"], "condition": s["condition"], "until": s["holds_until"],
            "line": str(line["id"]), "why": s["reason"], "urls": " ".join(urls)}


def support_sentence(sup: dict, on: str) -> str:
    if not sup.get("band") or sup["band"] == lifecycle.UNKNOWN_SUPPORT:
        return f"No vendor support status is given: {sup.get('why') or 'not determined'}. "
    cond = f" ({sup['condition']})" if sup.get("condition") else ""
    until = f" until {sup['until']}" if sup.get("until") else ""
    return (f"Vendor support on the export date, {on}: {sup['band']}{cond}{until}, from the "
            f"vendor's published lifecycle ({sup.get('urls') or sup['line']}). ")


def _lifecycle_table(ctx: Context) -> tuple[dict, coverage.Gap | None]:
    named = (ctx.settings or {}).get("lifecycle")
    if not named:
        return config.load_software_lifecycle() or {}, None
    path = ctx.inbox_path(str(named))
    try:
        return config.load_yaml_strict(path), None
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {}, coverage.gap(
            coverage.NOT_COLLECTED,
            f"the lifecycle table named in the vsphere_lists settings could not be read: "
            f"{path.name} ({exc})",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="No guest operating system or ESXi version is given a support status.",
            harvest="Correct the lifecycle: setting, or remove it to use the bundled table.",
            nature=coverage.NO_DATA)


# ── the step ──

def read(ctx: Context) -> StepResult:
    """The plug-in's step: rows for every list export in the input folder.

    With no input, or a folder holding none of the three lists, nothing is
    written: the list exports are one way of answering the virtual estate's
    questions, and the ``vmware`` reader's gap covers their absence.
    """
    folder = ctx.input
    files = {name: list_files(folder, name) for name in LISTS}
    if not any(files.values()):
        return StepResult()
    gaps: list[coverage.Gap] = []
    lists: dict[str, list[tuple[str, Path, Rows]]] = {name: [] for name in LISTS}
    unreadable = []
    for name, paths in files.items():
        for p in paths:
            try:
                lists[name].append((site_of(p, name), p, read_list(p)))
            except (OSError, UnicodeDecodeError, csv.Error) as exc:
                unreadable.append(f"{p.name} ({exc})")
    if unreadable:
        gaps.append(coverage.gap(
            coverage.NOT_COLLECTED,
            "vSphere Client list exports that could not be read: " + "; ".join(unreadable),
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("These rows cover only the exports that could be read, so every count "
                    "below may be short of the whole virtual estate."),
            harvest="Export the list again from the vSphere Client and replace the file.",
            nature=coverage.NO_DATA))

    paths = [p for entries in lists.values() for _s, p, _r in entries]
    dates = sorted({d for d in (file_mtime_date(p) for p in paths) if d})
    stamp = dates[0] if dates else ""
    dates_text = " and ".join(dates) if dates else "an unstated date"
    source_name = f"vSphere Client list exports, files dated {dates_text}"
    table, table_gap = _lifecycle_table(ctx)
    if table_gap is not None:
        gaps.append(table_gap)

    machines: dict[str, Rows] = {}
    tally: dict[str, dict[str, int]] = {}
    for site, _p, rows in lists[VM_LIST]:
        t = tally.setdefault(site, {"rows": 0, "placeholders": 0, "machines": 0, "on": 0,
                                    "protected": 0})
        for r in rows:
            if not field(r, "Name"):
                continue
            t["rows"] += 1
            if _field_containing(r, PROTECTED_ATTRIBUTE):
                t["protected"] += 1
            if _placeholder(r):
                t["placeholders"] += 1
                continue
            t["machines"] += 1
            t["on"] += _on(r)
            machines.setdefault(site, []).append(r)

    out: list[CryptoAsset] = []
    for site, members in machines.items():
        out += _site_rows(site, members, source_name, stamp, ctx)
    out += _guest_os_rows(machines, source_name, stamp, dates_text, table)
    out += _host_rows(lists[HOST_LIST], source_name, stamp, dates_text, table)
    out += _datastore_rows(lists[DATASTORE_LIST], source_name, stamp, gaps)
    out.append(_scope_row(lists, tally, source_name, stamp, dates_text))
    return StepResult(records=out, gaps=gaps)


def _asset(**kw) -> CryptoAsset:
    return CryptoAsset(source=NAME, source_class="private", **kw)


def _site_rows(site: str, members: Rows, source_name: str, stamp: str,
               ctx: Context) -> list[CryptoAsset]:
    n = len(members)
    on = sum(_on(r) for r in members)
    states = Counter(field(r, "Encryption").casefold() for r in members)
    n_on = sum(c for v, c in states.items() if v in ENCRYPTED)
    n_off = sum(c for v, c in states.items() if v in NOT_ENCRYPTED)
    other = {v or "(blank)": c for v, c in states.items() if v not in ENCRYPTED | NOT_ENCRYPTED}
    where = f"the {site} vCenter"
    rows: list[CryptoAsset] = []

    flags = {f"{VM_CENSUS_FLAG}{n}"}
    if n_off:
        flags.add(f"{VM_ENCRYPTION_OFF_FLAG}{n_off}")
    flags |= {f"ungraded:vm-encryption:{v}" for v in other}
    verdicts: list[str] = []
    symmetric: list[str] = []
    if n_on:
        grade = ctx.policy.grade("symmetric", CIPHER)
        if grade == "unknown":
            flags.add(f"ungraded:symmetric:{CIPHER}")
        else:
            symmetric.append(CIPHER)
            verdicts.append(grade)
    others = ("; " + ", ".join(f"{c} report {v!r}" for v, c in sorted(other.items()))
              if other else "")
    none_on = ("No machine here is encrypted by vSphere. Encrypting a machine needs a key "
               "provider configured in vCenter, and this list gives each machine's state, "
               "not that setting: it is consistent with there being no key provider, but "
               "does not show it. ") if n_off == n else ""
    rows.append(_asset(
        name=f"VM encryption, {site} vCenter", role=roles.vm_encryption_population(n),
        data_state="at-rest", protocol="vm-encryption", software="VMware vSphere VM Encryption",
        source_name=source_name, collected_at=stamp, symmetric=symmetric,
        verdict=worst(verdicts) if verdicts else "n/a", flags=sorted(flags), hosts_count=n,
        notes=(f"vCenter's virtual-machine list for {where} shows {n} machines (Site Recovery "
               f"Manager placeholders left out; {on} powered on): {n_off} with VM encryption "
               f"off and {n_on} with it on{others}. " + none_on
               + "VM encryption is vSphere's own encryption of each machine's files, so a "
               "disk file copied off the datastore cannot be read without its key. It is "
               "separate from any encryption the storage beneath performs, which this list "
               "does not show."),
        extra={"site": site, "vms": str(n), "encryption_on": str(n_on),
               "encryption_off": str(n_off),
               "encryption_other": ", ".join(f"{v}={c}" for v, c in sorted(other.items()))}))

    no_tpm = [r for r in members if field(r, "TPM").casefold() != "true"]
    no_tpm_windows = sum(1 for r in no_tpm if _windows(field(r, "Guest OS")))
    tpm_flags = {f"{VM_CENSUS_FLAG}{n}"} | ({f"{VTPM_ABSENT_FLAG}{len(no_tpm)}"} if no_tpm else set())
    rows.append(_asset(
        name=f"Virtual TPM, {site} vCenter", role=roles.virtual_tpm_population(n),
        data_state="platform-integrity", protocol="firmware", source_name=source_name,
        collected_at=stamp, verdict="n/a", flags=sorted(tpm_flags), hosts_count=n,
        notes=(f"{len(no_tpm)} of the {n} machines in {where} have no virtual TPM, "
               f"{no_tpm_windows} of them configured as Windows. vSphere can add a virtual "
               f"TPM only once a key provider is configured ({VTPM_SOURCE}), the same "
               "precondition VM encryption has. A machine without a TPM cannot keep its "
               "disk-encryption key, or a measured record of how it started, in one: "
               "BitLocker there needs a password or a startup key at each start instead of "
               "the TPM an unattended server would use, and nothing can attest to how it "
               "started. Nothing inside the guests is read here."),
        extra={"site": site, "vms": str(n), "no_vtpm": str(len(no_tpm)),
               "no_vtpm_windows": str(no_tpm_windows), "vtpm_precondition_source": VTPM_SOURCE}))

    windows = [r for r in members if _windows(field(r, "Guest OS"))]
    if windows:
        vbs = [r for r in windows if field(r, "VBS").casefold() == "true"]
        vbs_on = sum(_on(r) for r in vbs)
        vbs_elsewhere = sum(1 for r in members if not _windows(field(r, "Guest OS"))
                            and field(r, "VBS").casefold() == "true")
        vbs_flags = {f"{VM_CENSUS_FLAG}{len(windows)}"} | (
            {f"{VBS_ENABLED_FLAG}{len(vbs)}"} if vbs else set())
        also = (f" {vbs_elsewhere} machine(s) not configured as Windows have it enabled too."
                if vbs_elsewhere else "")
        rows.append(_asset(
            name=f"Virtualisation-based security setting, {site} vCenter",
            role=roles.virtualisation_security_population(len(windows)),
            data_state="platform-integrity", protocol="firmware", source_name=source_name,
            collected_at=stamp, verdict="n/a", flags=sorted(vbs_flags), hosts_count=len(windows),
            notes=(f"{len(vbs)} of the {len(windows)} machines in {where} configured as Windows "
                   f"have virtualisation-based security enabled in their settings, {vbs_on} of "
                   f"them powered on.{also} The setting gives the guest the hardware "
                   "virtualisation, memory protection, EFI firmware and secure boot that "
                   "Windows Credential Guard and memory integrity need. Whether Windows uses "
                   "them is read inside the machine, not from this setting."),
            extra={"site": site, "windows_vms": str(len(windows)), "vbs_enabled": str(len(vbs)),
                   "vbs_enabled_powered_on": str(vbs_on)}))
    return rows


def _guest_os_rows(machines: dict[str, Rows], source_name: str, stamp: str, dates_text: str,
                   table: dict) -> list[CryptoAsset]:
    total = sum(len(m) for m in machines.values())
    by_os: dict[str, list[tuple[str, dict[str, str]]]] = {}
    for site, entries in machines.items():
        for r in entries:
            by_os.setdefault(field(r, "Guest OS") or "(not recorded)", []).append((site, r))
    rows = []
    for os_name, members in sorted(by_os.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        n = len(members)
        on = sum(_on(r) for _s, r in members)
        sites = Counter(s for s, _r in members)
        sup = support(table, "os", os_name, stamp)
        rows.append(_asset(
            name=f"vSphere guest OS {os_name}", role=roles.virtual_guest_os_population(n),
            data_state="platform-integrity", protocol="firmware", source_name=source_name,
            collected_at=stamp, verdict="n/a", flags=[f"{GUEST_OS_FLAG}{n}"], hosts_count=n,
            notes=(f"{n} of the {total} machines in the list exports dated {dates_text} are "
                   f"configured as {os_name}, {on} of them powered on ("
                   + ", ".join(f"{s}: {c}" for s, c in sorted(sites.items())) + "). This is "
                   "the guest type set in each machine's settings, which is not updated when "
                   "the guest is upgraded, so a machine may run another release. "
                   + support_sentence(sup, stamp)).rstrip(),
            extra={"guest_os": os_name, "vms": str(n), "powered_on": str(on),
                   "sites": ", ".join(f"{s}={c}" for s, c in sorted(sites.items())),
                   "vendor_support_band": sup.get("band") or "",
                   "lifecycle_line": sup.get("line") or "",
                   "vendor_support_until": sup.get("until") or ""}))
    return rows


def _host_rows(hosts: list[tuple[str, Path, Rows]], source_name: str, stamp: str,
               dates_text: str, table: dict) -> list[CryptoAsset]:
    rows: list[CryptoAsset] = []
    versions: dict[str, list[tuple[str, str]]] = {}
    as_of = date.fromisoformat(stamp) if stamp else None
    for site, _p, entries in hosts:
        for r in entries:
            host = field(r, "Name")
            if not host:
                continue
            version = field(r, "Version") or "(not reported)"
            versions.setdefault(version, []).append((site, host))
            written = field(r, "Certificate Valid To")
            valid_to = _cert_date(written)
            flags = [CERT_NOT_ASSESSED_FLAG]
            days = ""
            if valid_to is None:
                when = f"The certificate expiry in the list, {written or '(blank)'!r}, could not be read. "
            elif as_of is None:
                when = (f"The certificate is valid until {valid_to.isoformat()}; the export has "
                        "no date to measure that from. ")
            else:
                remaining = (valid_to - as_of).days
                expiry = cert_expiry_flag(remaining)
                flags = ([expiry] if expiry else []) + [CERT_NOT_ASSESSED_FLAG]
                when = (f"The certificate is valid until {valid_to.isoformat()}, {remaining} "
                        "days after the export date. ")
                days = str(remaining)
            rows.append(_asset(
                name=f"ESXi host certificate {host}", role=roles.hypervisor_host_certificate(),
                data_state="certificate", protocol="tls", host=host,
                software=f"VMware ESXi {version}", version=version, source_name=source_name,
                collected_at=stamp, verdict="unknown", flags=sorted(flags),
                notes=(when + "The host list gives only the expiry, not the key type or size, "
                       "the signature algorithm, the issuer or the issue date, so the "
                       "certificate's strength is not assessed."),
                extra={"site": site, "cluster": field(r, "Cluster"),
                       "cert_not_after": valid_to.isoformat() if valid_to else written,
                       "cert_days_remaining_at_export": days}))
    total = sum(len(v) for v in versions.values())
    for version, members in sorted(versions.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        n = len(members)
        product = f"VMware ESXi {version}"
        sup = support(table, "hypervisor", product, stamp)
        rows.append(_asset(
            name=product, role=roles.hypervisor_host_population(n),
            data_state="platform-integrity", protocol="firmware", software=product,
            version=version, source_name=source_name, collected_at=stamp, verdict="n/a",
            flags=[f"{ESXI_FLAG}{n}"], hosts_count=n,
            notes=(f"{n} of the {total} hosts in the host lists dated {dates_text} run ESXi "
                   f"{version}. The list gives the version, not the build. "
                   + support_sentence(sup, stamp)).rstrip(),
            extra={"esx_version": version, "hosts": " ".join(sorted(h for _s, h in members)),
                   "sites": ", ".join(sorted({s for s, _h in members})),
                   "vendor_support_band": sup.get("band") or "",
                   "lifecycle_line": sup.get("line") or ""}))
    return rows


def _datastore_rows(stores: list[tuple[str, Path, Rows]], source_name: str, stamp: str,
                    gaps: list[coverage.Gap]) -> list[CryptoAsset]:
    rows = []
    in_hosts: list[tuple[str, int, int]] = []
    for site, _p, entries in stores:
        named = [r for r in entries if field(r, "Name")]
        if not named:
            continue
        n = len(named)
        types = Counter(field(r, "Type") or "(blank)" for r in named)
        vsan = sum(c for t, c in types.items() if "vsan" in t.casefold())
        on_array: Rows = []
        elsewhere: Rows = []
        unplaced: Rows = []
        makers: Counter[str] = Counter()
        for r in named:
            prefix = maker_prefix(field(r, "Device"))
            if field(r, "Type").casefold() == "vvol":
                on_array.append(r)
                makers["a virtual-volume container on a storage array"] += 1
            elif prefix in ARRAY_MAKERS:
                on_array.append(r)
                makers[ARRAY_MAKERS[prefix]] += 1
            elif prefix:
                elsewhere.append(r)
                makers[DEVICE_MAKERS.get(prefix, f"maker prefix {prefix}")] += 1
            else:
                unplaced.append(r)
                makers["a device identifier with no maker prefix"] += 1
        single = sum(1 for r in elsewhere if field(r, "Access").casefold() == "single host")
        size = round(sum(capacity_gb(field(r, "Capacity")) for r in elsewhere))
        if elsewhere:
            in_hosts.append((site, len(elsewhere), size))
        rows.append(_asset(
            name=f"Datastores, {site} vCenter", role=roles.datastore_population(n),
            data_state="at-rest", protocol="datastore", source_name=source_name,
            collected_at=stamp, verdict="n/a", flags=[f"{DATASTORE_FLAG}{n}"], hosts_count=n,
            notes=(f"The {site} vCenter lists {n} datastores: "
                   + ", ".join(f"{c} {t}" for t, c in sorted(types.items()))
                   + f", {vsan} of them vSAN. By the maker named in each device identifier: "
                   + ", ".join(f"{c} on {m}" for m, c in sorted(makers.items(),
                                                              key=lambda kv: -kv[1]))
                   + f". {len(on_array)} are on a storage array and {len(elsewhere)} on disks "
                   f"from other makers, taken to be disks inside the hosts ({single} attached "
                   f"to a single host, about {size:,} GB)"
                   + (f"; {len(unplaced)} could not be placed" if unplaced else "")
                   + ". The list has no encryption column, so whether any device encrypts is "
                   "not known from it, and it does not say which datastore holds which "
                   "machine's disks."),
            extra={"site": site, "datastores": str(n), "vsan": str(vsan),
                   "on_array": str(len(on_array)), "off_array": str(len(elsewhere)),
                   "off_array_capacity_gb": str(size), "unplaced": str(len(unplaced)),
                   "types": ", ".join(f"{t}={c}" for t, c in sorted(types.items()))}))
    if in_hosts:
        total = sum(n for _s, n, _c in in_hosts)
        each = "; ".join(f"{s}: {n}, about {c / 1024:.1f} TB" for s, n, c in in_hosts)
        gaps.append(coverage.gap(
            coverage.NOT_MEASURED,
            f"{total} datastores are on disks inside hosts rather than on a storage array "
            f"({each}); the vCenter list does not say whether those disks are encrypted",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("An array's encryption does not reach disks inside a host, so for "
                    "whatever is stored on them (the list does not say which machines' disks "
                    "are) whether it is encrypted at rest is not known either way."),
            harvest=("A reading of those disks' encryption, from the hosts or their storage "
                     "controllers, answers it."),
            nature=coverage.LOW_FIDELITY))
    return rows


def _scope_row(lists: dict[str, list[tuple[str, Path, Rows]]], tally: dict[str, dict[str, int]],
               source_name: str, stamp: str, dates_text: str) -> CryptoAsset:
    machines = sum(t["machines"] for t in tally.values())
    vm_rows = sum(t["rows"] for t in tally.values())
    on = sum(t["on"] for t in tally.values())
    placeholders = sum(t["placeholders"] for t in tally.values())
    hosts = sum(sum(1 for r in rs if field(r, "Name")) for _s, _p, rs in lists[HOST_LIST])
    stores = sum(sum(1 for r in rs if field(r, "Name")) for _s, _p, rs in lists[DATASTORE_LIST])
    files = sorted(p.name for entries in lists.values() for _s, p, _r in entries)
    per_site = "; ".join(
        f"{s}: {t['rows']} rows less {t['placeholders']} placeholder(s) is {t['machines']} "
        f"machines, {t['on']} powered on"
        + (f", {t['protected']} rows marked protected by Site Recovery Manager"
           if t["protected"] else "")
        for s, t in sorted(tally.items()))
    return _asset(
        name="vSphere list exports scope", role=roles.vsphere_lists_scope(),
        data_state="platform-integrity", protocol="firmware", source_name=source_name,
        collected_at=stamp, verdict="n/a", flags=[SCOPE_FLAG], hosts_count=machines,
        notes=(f"{len(files)} vSphere Client list export(s), dated {dates_text}. The "
               f"virtual-machine lists hold {vm_rows} rows; {placeholders} are Site Recovery "
               f"Manager placeholders, which stand in for a machine that runs at another "
               f"site, leaving {machines} machines, {on} of them powered on. By site: "
               f"{per_site or 'no virtual-machine list'}. The host lists hold {hosts} hosts "
               f"and the datastore lists {stores} datastores. A row's site is the export it "
               "is in, never a machine's name, and templates are not listed. Not in these "
               "exports: the key provider setting, which datastore holds which machine's "
               "disks, anything measured inside a guest (the operating system is as "
               "configured), and a host certificate's key, algorithm and issuer."),
        extra={"files": ", ".join(files), "vm_rows": str(vm_rows),
               "placeholders": str(placeholders), "machines": str(machines),
               "powered_on": str(on), "hosts": str(hosts), "datastores": str(stores),
               "export_dates": dates_text})


#: The declaration. It names no default input; give the folder of exports with
#: ``input:``.
PLUGIN = Plugin(
    name=NAME, kind="general", step=read,
    title="vSphere Client list exports: virtual machines, hosts and datastores",
    gap_prefix=False)
