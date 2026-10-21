"""VMware vSphere VM Encryption and vSAN encryption: whether virtual machines and vSAN clusters encrypt.

vSphere offers two encryption controls for data at rest:

* **VM Encryption**, set per virtual machine through its storage policy,
  encrypts that machine's virtual disks, configuration file and core dumps;
* **vSAN data-at-rest encryption**, set per cluster, encrypts everything on
  the cluster's vSAN datastore, whatever each machine's own setting.

Both need a **key provider** configured in vCenter: a standard key provider
(an external key server reached over KMIP), a trusted key provider (vSphere
Trust Authority) or the vSphere Native Key Provider. Both use one fixed
cipher, XTS-AES-256 (:data:`vsphere_lists.CIPHER`, with its source), so a
row that records encryption on and names no cipher is still graded.

**The input** is a CSV a vSphere administrator writes with PowerCLI, one row
per virtual machine or vSAN cluster; ``docs/COLLECTORS.md`` gives the
columns and an example script. Headings are matched without regard to case,
spaces or hyphens, and common synonyms are read (:data:`COLUMNS`).

**Grading.** A row whose ``scope`` is ``vsan``, ``vsan-cluster`` or
``cluster`` is a vSAN cluster; any other is a virtual machine.

* Encryption off (``no``, ``false``, ``disabled`` and the like), or nothing
  recorded at all: a vSAN cluster is ``weak`` and flagged ``encryption-off``.
  A virtual machine is flagged ``vm-encryption-off`` and not graded, because
  its files may still be encrypted by the storage beneath it.
* Encryption on, or a key provider or cipher recorded with no setting: the
  cipher's grade from the baseline. A cipher the baseline does not grade is
  flagged ``ungraded:symmetric:<name>`` and left ``unknown``.
* A setting that is neither on nor off: ``weak``, flagged
  ``encryption-status:<value>``.

Key custody is a flag, never a verdict: ``key-custody:native-key-provider``,
``key-custody:trust-authority``, ``key-custody:external-kms``, or the key
provider's name when its type is not recorded.

**With the vSphere Client's list exports instead.** The virtual-machine list
the vSphere Client exports carries each machine's encryption state, which
the ``vsphere_lists`` reader reads. When this reader's ``settings`` name
that reader's folder under ``vsphere_lists`` and it holds a virtual-machine
list, a missing export here is not a gap.

**Cannot see.** Encryption done by the storage array or the disks beneath a
datastore; whether vMotion or memory is encrypted; the key provider's own
protection of its keys; and any machine or cluster not in the export.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes, worst
from ..plugins import Context, Plugin, StepResult
from ..policy import Policy
from ..util import file_mtime_date
from . import _table
from .vsphere_lists import CIPHER, lists_folder, vm_lists_present

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "vmware"

ENCRYPTED = frozenset({"yes", "true", "1", "enabled", "on"})
NOT_ENCRYPTED = frozenset({"no", "false", "0", "disabled", "off", "none"})
VSAN_SCOPES = frozenset({"vsan", "vsan-cluster", "cluster"})

#: The ways the export may spell the one cipher, read as :data:`CIPHER`.
CIPHER_NAMES = frozenset({"aes-256-xts", "aes256-xts", "xts-aes-256", "aes-xts-256"})

#: Each field and the column names it may arrive under, in order of preference.
COLUMNS: dict[str, tuple[str, ...]] = {
    "scope": ("scope", "type"),
    "name": ("name", "vm_name", "vm", "cluster", "cluster_name"),
    "encrypted": ("encrypted", "encryption", "encryption_enabled"),
    "key_provider": ("key_provider", "kms", "kms_name", "key_provider_name"),
    "key_provider_type": ("key_provider_type", "provider_type", "kms_type"),
    "cipher": ("cipher", "algorithm"),
}

register_informational_prefixes("vm-encryption-off")


def _field(row: dict[str, str], key: str) -> str:
    return _table.value(row, *COLUMNS[key])


def cipher_token(written: str) -> str:
    """The baseline ``symmetric`` name for a cipher as the export writes it.

    Blank is the one cipher vSphere uses. Any other unrecognised value is
    passed on lower-cased, so the baseline does not grade it and it is
    flagged rather than assumed.
    """
    text = written.strip().lower()
    if not text or text in CIPHER_NAMES:
        return CIPHER
    return text


def custody(provider_type: str, provider_name: str) -> str:
    """The ``key-custody:`` flag for a key provider, or "" when none is recorded."""
    t = provider_type.strip().lower()
    if "native" in t or "nkp" in t:
        return "key-custody:native-key-provider"
    if "trust" in t:
        return "key-custody:trust-authority"
    if any(w in t for w in ("standard", "kms", "kmip", "external")):
        return "key-custody:external-kms"
    if provider_name.strip():
        return "key-custody:" + provider_name.strip().lower().replace(" ", "-")
    return ""


def row_for(row: dict[str, str], source_name: str, collected_at: str,
            policy: Policy) -> CryptoAsset:
    """One virtual machine's or vSAN cluster's row."""
    name = _field(row, "name")
    state = _field(row, "encrypted").lower()
    provider = _field(row, "key_provider")
    provider_type = _field(row, "key_provider_type")
    cipher = _field(row, "cipher")
    vsan = (_field(row, "scope").lower() or "vm") in VSAN_SCOPES
    software = "VMware vSAN" if vsan else "VMware vSphere VM Encryption"
    ident = name or ("vsan-cluster" if vsan else "vm")

    flags: set[str] = set()
    tokens: list[str] = []
    verdicts: list[str] = []
    if state in NOT_ENCRYPTED or not (state or provider or cipher):
        if vsan:
            flags.add("encryption-off")
            verdicts.append("weak")
        else:
            flags.add("vm-encryption-off")
    elif state in ENCRYPTED or not state:
        token = cipher_token(cipher)
        grade = policy.grade("symmetric", token)
        if grade == "unknown":
            flags.add(f"ungraded:symmetric:{token}")
        else:
            tokens.append(token)
            verdicts.append(grade)
            if grade == "weak":
                flags.add(f"weak-algorithm:{cipher}")
    else:
        flags.add(f"encryption-status:{state}")
        verdicts.append("weak")
    held = custody(provider_type, provider)
    if held:
        flags.add(held)

    off = bool(flags & {"encryption-off", "vm-encryption-off"})
    what = "vSAN encryption" if vsan else "VM encryption"
    keys = (f" Key provider {provider or 'not recorded'}"
            + (f" ({provider_type})." if provider_type else ".")) if provider or provider_type else ""
    if off:
        notes = f"{what} is off.{keys}"
    elif any(f.startswith("encryption-status:") for f in flags):
        notes = f"{what} is recorded as {state!r}, which is neither on nor off.{keys}"
    else:
        notes = (f"{what} is on.{keys} Cipher "
                 + (f"{cipher}." if cipher else "not recorded; vSphere uses XTS-AES-256."))
    return CryptoAsset(
        name=f"{software} {ident}", role=roles.virtual_storage_encryption(ident, vsan),
        data_state="at-rest", protocol="vsan-encryption" if vsan else "vm-encryption",
        host=name, software=software, source=NAME, source_class="private",
        source_name=source_name, collected_at=collected_at, symmetric=sorted(set(tokens)),
        verdict=worst(verdicts) if verdicts else ("n/a" if off else "unknown"),
        flags=sorted(flags), notes=notes,
        extra={"scope": "vsan-cluster" if vsan else "vm", "key_provider": provider,
               "key_provider_type": provider_type, "cipher": cipher})


def read(ctx: Context) -> StepResult:
    """The plug-in's step: one row per machine or cluster, or the gap saying none was read."""
    rows: list[dict[str, str]] = []
    why = "no input was given"
    path: Path | None = ctx.input
    if path is not None:
        try:
            rows = _table.read(path)
            why = f"{path.name} holds no rows"
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            why = f"{path.name} could not be read as CSV ({exc})"
    if not rows or path is None:
        if vm_lists_present(lists_folder(ctx)):
            return StepResult()
        return StepResult(gaps=[_none_read(why)])
    # The export carries no date of its own, so the file's date stands for
    # when it was made.
    when = file_mtime_date(path)
    source_name = ("VMware vSphere encryption export (PowerCLI), "
                   + (f"file dated {when}" if when else "file date unavailable"))
    return StepResult(records=[row_for(r, source_name, when or "", ctx.policy) for r in rows])


def _none_read(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no VMware VM Encryption or vSAN encryption export was read: {why}",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Whether the virtual machines' disks are encrypted where they are stored is "
                "not known, for every machine and cluster. Encryption measured elsewhere "
                "does not answer it, and the absence of an answer is not evidence that they "
                "are unencrypted."),
        harvest=("A vSphere administrator runs the PowerCLI script in docs/COLLECTORS.md "
                 "(`vmware`) and names the CSV as the reader's input, or exports the vSphere "
                 "Client's virtual-machine list for the vsphere_lists reader."),
        nature=coverage.NO_DATA)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(
    name=NAME, kind="general", step=read,
    title="VMware vSphere VM Encryption and vSAN encryption export", gap_prefix=False)
