"""Windows drive encryption and recovery-key escrow, from Microsoft Intune and Entra exports.

An encrypted drive is only half of an at-rest control. The other half is
whether a copy of its recovery key is held somewhere the organisation can
reach. A drive whose key exists only inside the machine is unreadable to a
thief and, after a failed mainboard or a locked-out start-up, unreadable to
its owner too. This reader answers both halves for each Windows device, and
says how the device registers it reads count the estate.

**The input** (``input:``, or ``settings: escrow:``) is a CSV with one row per
Intune-managed Windows device, joining Intune's device record to the BitLocker recovery keys held in
Microsoft Entra ID. ``docs/COLLECTORS.md`` gives a Microsoft Graph PowerShell
script that writes it. The columns read are ``DeviceName``, ``IsEncrypted``,
``EscrowRecordFound``, ``EscrowRecordCount``, ``NewestEscrowDateUtc``,
``RiskState``, ``SerialNumber``, ``Manufacturer``, ``Model``, ``OSVersion``,
``ComplianceState`` and ``ManagementAgent``. A user principal name or display
name in the file is never read into a row: a device's encryption does not need
a named person beside it.

**Further exports, each optional, named in** ``settings:``:

* ``encryption_report``: the Intune encryption report, exported as CSV from
  the admin centre (columns ``Device name``, ``OS version``,
  ``TpmSpecificationVersion``, ``Encryption readiness``, ``Encryption status``,
  ``Profile state summary`` and ``BitLocker State``). It adds the Trusted
  Platform Module (TPM) version, readiness, the profile state and whether the
  operating-system volume's encryption method matches policy. A device may
  appear on more than one row; the rows are folded into one record per device
  name, keeping every value seen, so a device with one profile in error is
  read as in error.
* ``managed_devices``: an export of Intune's device list (``Device name``,
  ``OS`` and, if present, ``SkuFamily``). It gives the enrolled population by
  operating system, and each device's operating system and edition.
* ``directory_devices``: an export of Microsoft Entra ID's device objects
  (``operatingSystem``, ``isManaged``, ``isCompliant``, ``trustType``). Only
  counts are taken from it; no row is written from it.
* ``escrow_missing``: a copy of the main export filtered to the devices with
  no key held in Microsoft Entra ID. It is checked against the main export,
  never trusted in its place.
* ``cross_check``: a drive-encryption export from another product, compared
  device by device (see *A second opinion* below).

Each setting naming a file, ``cross_check``'s ``file`` included, may be a
path, a list of paths or a pattern; the last match in name order is read.

**How a device is graded**, from ``IsEncrypted`` and ``EscrowRecordFound``:

* encrypted, key held in Microsoft Entra ID: ``strong``.
* encrypted, no key held in Microsoft Entra ID: ``weak``, flagged
  ``key-escrow-missing``. The cipher is not the finding, and the row's note
  says so first. The grade is ``weak`` because the control can fail without an
  attacker: Microsoft's *BitLocker recovery overview* (learn.microsoft.com)
  lists, among the events that put a device into BitLocker recovery,
  clearing the TPM, a TPM self-test failure, a new motherboard with a new TPM,
  and moving the drive into another computer. Without a recovery copy, the
  data may then not be recoverable, and nothing alerts anyone when that
  becomes true.

  Only Microsoft Entra ID is read. The same page says a recovery password may
  also be saved in Active Directory Domain Services (AD DS), in a text file or
  on paper, and that a data recovery agent certificate can unlock a drive;
  none of those is read here, so ``key-escrow-missing`` means no copy in
  Microsoft Entra ID, not that no copy exists anywhere.
* not encrypted: ``weak``, flagged ``drive-unencrypted``, or
  ``drive-unencrypted-or-unknown`` when the row's ``RiskState`` label itself
  says the state might only be unknown. Both readings are adverse, and the
  reader does not choose between them.
* either column holding a value other than true or false: ``unknown``, with an
  ``ungraded:`` flag naming the column. A device in the encryption report only
  is graded from its ``Encryption status`` in the same way: ``Encrypted`` is
  encrypted, ``Not encrypted`` is not, and any other value is ``unknown``
  with an ``ungraded:device-encryption:<value>`` flag.

``RiskState`` is read only to corroborate the two columns. Where its label
implies something the columns contradict, the row is flagged
``risk-state-disagrees:<label>``; the grade still follows the columns.

A device in the encryption report whose operating-system volume is encrypted
by a method other than the one policy sets is flagged
``fde-cipher-policy-drift`` and capped at ``acceptable``: the drive is
encrypted and its key is held, but the algorithm in force is not the one
chosen. Microsoft's page *View report details for encryption status of devices
managed with Microsoft Intune* (learn.microsoft.com) lists, among the Windows
status details, "The encryption method of the OS volume doesn't match the
BitLocker policy." The reader matches any ``BitLocker State`` value that names
the OS volume's encryption method and says it differs from, or does not
match, the policy.

**Where two sources disagree about one device**, the row is graded
``unknown`` and flagged ``encryption-source-conflict:<source>``, never
averaged. The encryption report's ``Encryption status`` ("whether the OS
drive is encrypted", on the same Microsoft page) is compared with
``IsEncrypted`` only where every row of the report for that device holds
``Encrypted`` or ``Not encrypted``; any other value is flagged
``encryption-report-status-unread:<value>`` and compared with nothing. A
device appearing only in the report is graded from its status alone, with
key custody left unjudged.

**A second opinion.** ``settings: cross_check:`` names a drive-encryption
export from another product, so a device is compared across vendors as well
as within Microsoft's. Its keys:

* ``file``: the export.
* ``name``: a short word for the source, used in the conflict flag and in the
  scope row's ``<name>_hosts`` and ``<name>_only_hosts`` counts (default
  ``cross_check``).
* ``label``: the source's name in sentences (default: ``name``).
* ``row_key``: the ``extra`` key that carries the source's status on each
  device row (default ``<name>_drive_encryption``).
* ``host_column``: the heading, or list of headings tried in order, holding
  the device name (default ``Device name``, ``DeviceName``, ``Computer``,
  ``Computer name``).
* ``status_column``: the heading holding the encryption status (default
  ``Encryption status``).
* ``encrypted``: the status value, or list of values, meaning encrypted,
  compared ignoring case (default ``Encrypted``).

Device names are matched ignoring case. The other source's devices that this
reader has no row for are counted on the scope row and not graded here; a
reader of that source can use :func:`escrowed_devices` to avoid counting the
devices this reader covers twice.

**Rows.** One per device, named ``Disk encryption and key custody <device>``
with the device name upper-cased; one scope row, ``Endpoint at-rest
population reconciliation`` (``n/a``), stating each register's count and the
disagreements; one ``Endpoint key-storage hardware`` row (``n/a``) from the
encryption report's TPM versions; and, when the device list holds devices
that are not Windows, one ``Managed non-Windows device encryption`` row graded
``unknown``, because such a device's own report that it is encrypted cannot
be checked here.

**The escrow date.** ``NewestEscrowDateUtc`` may be ISO 8601 or a slash date
in the exporting machine's locale. A slash date is ambiguous until a value in
the column settles it: a first field above 12 proves day first, a second
field above 12 proves month first. A column proving neither, or both, is left
unparsed, and the raw text is kept on the row. The date says a key was backed
up then (``createdDateTime`` on Microsoft Graph's *bitlockerRecoveryKey
resource type* is "the date and time when the key was originally backed up to
Microsoft Entra ID"); it cannot say the drive still uses that key.

**Serials.** A device's serial is carried from the main export. A virtual
machine's serial of the form ``VMware-<16 hex digits>-<16 hex digits>`` is
written in space-separated byte pairs, which is easier to read and to match
by eye; any other serial is carried unchanged.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "m365_bitlocker"

KEY_ESCROW_MISSING = "key-escrow-missing"
POLICY_DRIFT_FLAG = "fde-cipher-policy-drift"
CONFLICT_FLAG = "encryption-source-conflict:"
REPORT_SOURCE = "intune-encryption-report"
NO_ESCROW_ROW = "no-escrow-record-row"
NO_REPORT_ROW = "no-encryption-report-row"
SCOPE_FLAG = "scope-population-reconciled"
HARDWARE_FLAG = "key-storage-hardware-recorded"

# What a row says about the reader's own view (which register has a row for a
# device, the scope and hardware rows' own state), never about the device's
# protection.
register_informational_prefixes(NO_ESCROW_ROW, NO_REPORT_ROW, SCOPE_FLAG, HARDWARE_FLAG)

#: ``RiskState`` labels, written with letters and digits only, lower case,
#: and what each implies about (encrypted, key held). Used to corroborate the
#: two columns, never to grade.
RISK_LABELS: dict[str, tuple[bool | None, bool | None]] = {
    "encryptedescrowconfirmed": (True, True),
    "encryptednoescrowrecord": (True, False),
    "notencryptedorunknown": (False, None),
}

#: The TPM version a device should report.
TPM_WANTED = "2.0"

#: ``cross_check`` defaults.
CROSS_CHECK_NAME = "cross_check"
HOST_COLUMNS = ("Device name", "DeviceName", "Computer", "Computer name")
STATUS_COLUMN = "Encryption status"


# ── reading ────────────────────────────────────────────────────────────────

def load(path: Path | None) -> tuple[list[dict], str]:
    """A CSV's rows, or (``[]``, why) when it cannot be read; (``[]``, "") when absent."""
    if path is None or not path.exists():
        return [], ""
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh)), ""
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], str(exc)


def value(row: dict | None, *names: str) -> str:
    """The first of ``names`` holding a value; ``--`` counts as empty."""
    if not row:
        return ""
    for n in names:
        v = _entra.col(row, n)
        if v and v != "--":
            return v
    return ""


def device_key(name: str) -> str:
    """The name devices are matched on: trimmed and upper-cased."""
    return name.strip().upper()


def truth(raw: str) -> bool | None:
    """``True``/``False`` (or yes/no, 1/0); ``None`` for any other value."""
    v = raw.strip().lower()
    if v in ("true", "yes", "1"):
        return True
    if v in ("false", "no", "0"):
        return False
    return None


def _count(raw: str) -> int:
    try:
        return int(raw.strip() or 0)
    except ValueError:
        return 0


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def escrowed_devices(path: Path) -> set[str]:
    """The device names (upper-cased) a main export answers for.

    For another reader of the same devices, so that a device's at-rest state
    is not reported twice.
    """
    rows, _ = load(path)
    return {device_key(value(r, "DeviceName")) for r in rows if value(r, "DeviceName")}


# ── the escrow date ────────────────────────────────────────────────────────

_SLASH_DATE = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})")
_ISO_DATE = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})")


def date_order(values: list[str]) -> str:
    """``day-first``, ``month-first``, or "" when the column does not settle it."""
    day_first = month_first = False
    for v in values:
        m = _SLASH_DATE.match(v or "")
        if not m:
            continue
        if int(m.group(1)) > 12:
            day_first = True
        if int(m.group(2)) > 12:
            month_first = True
    if day_first == month_first:
        return ""
    return "day-first" if day_first else "month-first"


def to_iso(raw: str, order: str) -> str:
    """One date as ``YYYY-MM-DD``, or "" when it cannot be read with ``order``."""
    if not raw:
        return ""
    m = _ISO_DATE.match(raw)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = _SLASH_DATE.match(raw)
    if not m or not order:
        return ""
    a, b = int(m.group(1)), int(m.group(2))
    day, month = (a, b) if order == "day-first" else (b, a)
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return ""
    return f"{m.group(3)}-{month:02d}-{day:02d}"


_VM_SERIAL = re.compile(r"^VMware-([0-9a-fA-F]{16})-([0-9a-fA-F]{16})$")


def serial_display(serial: str) -> str:
    """A ``VMware-<16 hex>-<16 hex>`` serial in byte pairs; any other value unchanged."""
    m = _VM_SERIAL.match(serial)
    if not m:
        return serial
    halves = [" ".join(h[i:i + 2] for i in range(0, 16, 2)) for h in m.groups()]
    return f"VMware-{halves[0]}-{halves[1]}"


# ── the further exports ────────────────────────────────────────────────────

def fold_report(rows: list[dict]) -> dict[str, dict[str, Any]]:
    """The encryption report, one record per device name, every value seen kept."""
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        name = value(r, "Device name")
        if not name:
            continue
        rec = out.setdefault(device_key(name), {
            "rows": 0, "tpm": "", "readiness": set(), "status": set(),
            "bitlocker_state": set(), "profile_state": set()})
        rec["rows"] += 1
        rec["tpm"] = rec["tpm"] or value(r, "TpmSpecificationVersion")
        for field, heading in (("readiness", "Encryption readiness"),
                               ("status", "Encryption status"),
                               ("bitlocker_state", "BitLocker State"),
                               ("profile_state", "Profile state summary")):
            v = value(r, heading)
            if v:
                rec[field].add(v)
    return out


def method_differs_from_policy(state: str) -> bool:
    """Whether a ``BitLocker State`` value says the OS volume's method is not policy's."""
    s = state.lower()
    return ("encryption method" in s and "os volume" in s and "polic" in s
            and ("different" in s or "match" in s))


#: The encryption report's ``Encryption status`` values, and what each means.
REPORT_STATUS = {"encrypted": True, "not encrypted": False}


def unread_statuses(statuses: set[str]) -> set[str]:
    """The ``Encryption status`` values the reader does not recognise."""
    return {s for s in statuses if s.strip().lower() not in REPORT_STATUS}


def report_encrypted(statuses: set[str]) -> bool | None:
    """One device's report rows: encrypted only if every row says so; None if any is unread.

    A device with one row encrypted and another not is read as not encrypted,
    the worse of the two.
    """
    if not statuses or unread_statuses(statuses):
        return None
    return all(REPORT_STATUS[s.strip().lower()] for s in statuses)


def directory_counts(rows: list[dict]) -> dict[str, int]:
    """Counts from the directory's device objects. No identity is kept."""
    return {
        "registrations": len(rows),
        "windows": sum(1 for r in rows if value(r, "operatingSystem").lower() == "windows"),
        "managed": sum(1 for r in rows if truth(value(r, "isManaged")) is True),
        "compliant": sum(1 for r in rows if truth(value(r, "isCompliant")) is True),
        # Microsoft Graph's device resource: trustType "Workplace" indicates
        # bring-your-own personal devices.
        "workplace": sum(1 for r in rows if value(r, "trustType").lower() == "workplace"),
    }


def _as_list(raw: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if not raw:
        return default
    return (str(raw),) if isinstance(raw, str) else tuple(str(v) for v in raw)


def _newest_named(ctx: Context, raw: Any) -> Path | None:
    """A path, a list of paths or a pattern, resolved as the other settings are: the last match."""
    found: list[Path] = []
    for v in ([raw] if isinstance(raw, str) else list(raw)):
        path = ctx.inbox_path(str(v))
        if any(ch in path.name for ch in "*?["):
            found += sorted(path.parent.glob(path.name)) if path.parent.is_dir() else []
        else:
            found.append(path)
    return found[-1] if found else None


class CrossCheck:
    """The ``cross_check`` setting: another product's drive-encryption status per device."""

    def __init__(self, ctx: Context) -> None:
        conf = (ctx.settings or {}).get("cross_check") or {}
        if isinstance(conf, str):
            conf = {"file": conf}
        self.named = bool(conf.get("file"))
        self.name = str(conf.get("name") or CROSS_CHECK_NAME)
        self.label = str(conf.get("label") or self.name)
        self.row_key = str(conf.get("row_key") or f"{self.name}_drive_encryption")
        self.encrypted = {v.lower() for v in _as_list(conf.get("encrypted"), ("Encrypted",))}
        self.status: dict[str, str] = {}
        self.error = ""
        self.path: Path | None = None
        if not self.named:
            return
        self.path = _newest_named(ctx, conf["file"])
        rows, self.error = load(self.path)
        if self.path is None:
            self.error = "no file matches the name given"
        elif not rows and not self.error and not self.path.exists():
            self.error = "the file named does not exist"
        hosts = _as_list(conf.get("host_column"), HOST_COLUMNS)
        status = str(conf.get("status_column") or STATUS_COLUMN)
        for r in rows:
            host, state = value(r, *hosts), value(r, status)
            if host and state:
                self.status[device_key(host)] = state

    def is_encrypted(self, state: str) -> bool:
        return state.strip().lower() in self.encrypted


# ── grading ────────────────────────────────────────────────────────────────

def grade(encrypted: bool | None, escrowed: bool | None,
          risk: str) -> tuple[str, list[str], str]:
    """Verdict, flags and the note's first sentence, from the two columns."""
    if encrypted is None:
        return ("unknown", [f"ungraded:device-encryption:{risk or 'blank'}"],
                "Whether this device's drive is encrypted could not be read: the export's "
                "encryption column holds a value the reader does not recognise.")
    if encrypted is False:
        either = "unknown" in risk
        note = "This device's drive is not encrypted: anyone holding the disk can read it."
        if either:
            note += (" The export's own label for this state covers both a drive that is "
                     "not encrypted and one whose state could not be read; both are adverse, "
                     "and the reader does not choose between them.")
        return ("weak", ["drive-unencrypted-or-unknown" if either else "drive-unencrypted"],
                note)
    if escrowed is None:
        return ("unknown", [f"ungraded:key-escrow:{risk or 'blank'}"],
                "This device's drive is encrypted. Whether a copy of its recovery key is "
                "held could not be read from the export, so custody is left unjudged.")
    if escrowed is False:
        return ("weak", [KEY_ESCROW_MISSING],
                "This device's drive is encrypted; the encryption is not the finding. No "
                "copy of its recovery key is held in Microsoft Entra ID, so if the device "
                "goes into BitLocker recovery (after a TPM is cleared or a motherboard "
                "replaced, for example), its data may not be recoverable unless a copy is "
                "kept somewhere this reader does not read.")
    return ("strong", [],
            "This device's drive is encrypted and a copy of its recovery key is held in "
            "Microsoft Entra ID: the disk stays unreadable if stolen, and recoverable if "
            "the device fails.")


def _risk(raw: str) -> str:
    return re.sub(r"[^a-z0-9]", "", raw.lower())


def _gap_no_escrow(unreadable: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "BitLocker recovery-key escrow per device: no export joining Intune's devices to the "
        "recovery keys held in Microsoft Entra ID was read, so which drives are encrypted "
        "and whether their keys can be recovered is not known from this source"
        + (f"; the file named could not be read ({unreadable})" if unreadable else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("An encrypted drive with no recovery copy may not be recoverable once it "
                "goes into BitLocker recovery, which clearing the TPM or replacing the "
                "motherboard can cause, so 'the drives are encrypted' cannot be reported as "
                "good news until key custody is known."),
        harvest=("Run the PowerShell script in docs/COLLECTORS.md (m365_bitlocker) and name "
                 "its CSV with input:."),
        nature=coverage.NO_DATA)


def _gap_report(unreadable: str) -> str:
    if unreadable:
        return coverage.gap(
            coverage.COULD_NOT_TEST,
            "the Intune encryption report named could not be read "
            f"({unreadable}): TPM version, encryption readiness, profile state and whether "
            "the OS volume's encryption method matches policy are missing from every device",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact=("Whether drives are encrypted and their keys held stands on the main "
                    "export; the hardware holding each key and the method in force are "
                    "not known."),
            harvest="Export the Intune encryption report again as CSV.",
            nature=coverage.LOW_FIDELITY)
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "the Intune encryption report: TPM version, encryption readiness, profile state and "
        "whether the OS volume's encryption method matches policy. Key custody is known from "
        "the main export; the hardware holding each key is not",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Whether each device's key is held is known; whether a TPM protects it on "
                "the device, and whether the encryption method is the one policy sets, is "
                "not."),
        harvest=("Export the encryption report from the Intune admin centre as CSV and name "
                 "it with settings: encryption_report:."),
        nature=coverage.LOW_FIDELITY)


def _gap_cross_check(label: str, why: str) -> str:
    return coverage.gap(
        coverage.COULD_NOT_TEST,
        f"the second drive-encryption source named ({label}) could not be read ({why}), so "
        "no device was compared with it",
        required=False,
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact=("Each device's state rests on Microsoft's sources alone; a disagreement "
                "with the other product would not show."),
        harvest="Export the other product's drive-encryption status again.",
        nature=coverage.NO_DATA)


# ── the reader ─────────────────────────────────────────────────────────────

def read(ctx: Context, path: Path) -> tuple[list[CryptoAsset], list[str]]:
    """Every row and gap for one main export and the settings' further exports."""
    escrow_rows, escrow_error = load(path)
    if not escrow_rows:
        return [], [_gap_no_escrow(escrow_error or ("the file holds no rows"
                                                    if path.exists() else ""))]

    report_path = _entra.newest(ctx, "encryption_report")
    report_rows, report_error = load(report_path)
    inventory_path = _entra.newest(ctx, "managed_devices")
    inventory_rows, _ = load(inventory_path)
    directory_path = _entra.newest(ctx, "directory_devices")
    directory_rows, _ = load(directory_path)
    missing_path = _entra.newest(ctx, "escrow_missing")
    missing_rows, _ = load(missing_path)
    other = CrossCheck(ctx)

    report = fold_report(report_rows)
    inventory = {device_key(value(r, "Device name")): r for r in inventory_rows
                 if value(r, "Device name")}
    escrow: dict[str, dict] = {}
    for r in escrow_rows:
        if value(r, "DeviceName"):
            escrow[device_key(value(r, "DeviceName"))] = r
    devices = sorted(set(escrow) | set(report))

    when = file_mtime_date(path) or ""
    source_name = ("Microsoft Intune and Entra BitLocker key escrow export, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    order = date_order([value(r, "NewestEscrowDateUtc") for r in escrow_rows])

    n = dict.fromkeys(("encrypted", "held", "not_held", "not_encrypted", "ungraded", "drift",
                       "conflicts", "no_escrow_row", "no_report_row", "tpm_wanted",
                       "tpm_other", "risk_disagrees", "serials"), 0)
    dates: list[str] = []
    models: dict[str, int] = {}
    assets: list[CryptoAsset] = []

    for device in devices:
        er, rr = escrow.get(device), report.get(device)
        risk_raw = value(er, "RiskState")
        risk = _risk(risk_raw)
        if er is not None:
            enc = truth(value(er, "IsEncrypted"))
            esc = truth(value(er, "EscrowRecordFound"))
        else:
            statuses = (rr or {}).get("status", set())
            enc = report_encrypted(statuses)
            esc = None
            n["no_escrow_row"] += 1
            if enc is None:
                risk = ",".join(sorted(unread_statuses(statuses))) or risk

        verdict, flags, note = grade(enc, esc, risk)
        extra: dict[str, str] = {}
        serial = serial_display(value(er, "SerialNumber"))
        if serial:
            n["serials"] += 1
        if enc is None:
            n["ungraded"] += 1
        elif enc is False:
            n["not_encrypted"] += 1
        else:
            n["encrypted"] += 1
            if esc is True:
                n["held"] += 1
            elif esc is False:
                n["not_held"] += 1

        if er is not None:
            copies = _count(value(er, "EscrowRecordCount"))
            newest_raw = value(er, "NewestEscrowDateUtc")
            newest = to_iso(newest_raw, order)
            if newest:
                dates.append(newest)
            model = value(er, "Model") or "unknown"
            models[model] = models.get(model, 0) + 1
            extra.update({"risk_state": risk_raw, "escrow_records": str(copies),
                          "manufacturer": value(er, "Manufacturer"), "model": model,
                          "os_version": value(er, "OSVersion"),
                          "compliance_state": value(er, "ComplianceState"),
                          "management_agent": value(er, "ManagementAgent")})
            if newest:
                extra["newest_escrow_date"] = newest
            elif newest_raw:
                extra["newest_escrow_date_unparsed"] = newest_raw
            if esc is True:
                on = f"on {newest}" if newest else "on a date the reader could not read"
                held = f", {copies} copies held" if copies > 1 else ""
                note += (f" The newest copy was backed up {on}{held}; that a key was backed "
                         "up then does not show the drive still uses it.")
            want_enc, want_esc = RISK_LABELS.get(risk, (None, None))
            if risk and ((want_enc is not None and want_enc != enc)
                         or (want_esc is not None and want_esc != esc)):
                flags.append(f"risk-state-disagrees:{risk_raw or 'blank'}")
                n["risk_disagrees"] += 1
        else:
            flags.append(NO_ESCROW_ROW)
            note += (" The device is in the encryption report but not in the escrow export, "
                     "so nothing is known about its recovery key, which is not the same as "
                     "knowing it has none.")

        iv = inventory.get(device)
        if iv is not None:
            if value(iv, "OS"):
                extra["os"] = value(iv, "OS")
            if value(iv, "SkuFamily"):
                extra["sku_family"] = value(iv, "SkuFamily")

        if rr is not None:
            tpm = str(rr["tpm"])
            extra["tpm_specification"] = tpm or "not reported"
            if tpm == TPM_WANTED:
                n["tpm_wanted"] += 1
            elif tpm:
                n["tpm_other"] += 1
                flags.append(f"tpm-below-2:{tpm}")
            else:
                flags.append("tpm-not-reported")
            readiness = sorted(rr["readiness"])
            profile = sorted(rr["profile_state"])
            bl_state = sorted(rr["bitlocker_state"])
            if readiness:
                extra["encryption_readiness"] = ", ".join(readiness)
            if profile:
                extra["encryption_profile_state"] = ", ".join(profile)
            if bl_state:
                extra["bitlocker_state"] = ", ".join(bl_state)
            extra["encryption_report_rows"] = str(rr["rows"])
            if any(r.lower() != "ready" for r in readiness):
                flags.append(f"encryption-not-ready:{', '.join(readiness)}")
            flags.extend(f"encryption-profile-state:{s}" for s in profile
                         if s.lower() != "compliant")
            if any(method_differs_from_policy(s) for s in bl_state):
                n["drift"] += 1
                flags.append(POLICY_DRIFT_FLAG)
                if verdict == "strong":
                    verdict = "acceptable"
                note += (" The encryption method on the operating-system volume is not the "
                         "one policy sets: the drive is encrypted and its key held, but the "
                         "algorithm in force is not the one chosen.")
            report_enc = report_encrypted(rr["status"])
            unread = unread_statuses(rr["status"])
            if unread and er is not None:
                flags.append(f"encryption-report-status-unread:{','.join(sorted(unread))}")
            if enc is not None and report_enc is not None and report_enc != enc:
                n["conflicts"] += 1
                flags.append(CONFLICT_FLAG + REPORT_SOURCE)
                verdict = "unknown"
                note += (" The Intune encryption report and the escrow export disagree about "
                         "whether this drive is encrypted; while they do, neither is "
                         "evidence, so the row is graded unknown.")
        else:
            n["no_report_row"] += 1
            flags.append(NO_REPORT_ROW)

        state = other.status.get(device, "")
        if state:
            extra[other.row_key] = state
            if enc is not None and other.is_encrypted(state) != enc:
                n["conflicts"] += 1
                flags.append(CONFLICT_FLAG + other.name)
                verdict = "unknown"
                note += (f" {other.label} reports this device's drives as {state!r}, which "
                         "the escrow export contradicts; the row is graded unknown until "
                         "one is shown wrong.")

        assets.append(CryptoAsset(
            name=f"Disk encryption and key custody {device}", data_state="at-rest",
            protocol="fde", role=roles.key_custody(device), host=device, serial=serial,
            source=NAME, source_class="private", source_name=source_name, collected_at=when,
            verdict=verdict, flags=flags, notes=note, extra=extra))

    assets.append(_scope_row(devices, escrow, report, len(report_rows), inventory_rows,
                             inventory_path is not None, directory_rows,
                             directory_path is not None, missing_rows,
                             missing_path is not None, other, n, dates, models, order,
                             source_name, when))

    if report:
        known = n["tpm_wanted"] + n["tpm_other"]
        hw_flags = [HARDWARE_FLAG] + ([f"tpm-below-2:{n['tpm_other']}"]
                                      if n["tpm_other"] else [])
        assets.append(CryptoAsset(
            name="Endpoint key-storage hardware", data_state="at-rest", protocol="fde",
            role=roles.key_storage_hardware(), source=NAME, source_class="private",
            source_name=source_name, collected_at=when, verdict="n/a", flags=hw_flags,
            hosts_count=known,
            notes=(f"{n['tpm_wanted']} of {known} devices with a TPM version in the "
                   f"encryption report have version {TPM_WANTED}. The TPM holds each "
                   "drive's key so it cannot be copied off the device. This is recorded, "
                   "not graded: capable hardware is a precondition, not a finding."),
            extra={"tpm_2_0": str(n["tpm_wanted"]), "tpm_other": str(n["tpm_other"])}))

    by_os = _by_os(inventory_rows)
    others = {k: v for k, v in by_os.items() if "windows" not in k.lower()}
    if others:
        count = sum(others.values())
        listing = ", ".join(f"{k}: {v}" for k, v in sorted(others.items()))
        assets.append(CryptoAsset(
            name="Managed non-Windows device encryption", data_state="at-rest",
            protocol="fde", role=roles.unassessed_device_encryption(), source=NAME,
            source_class="private", source_name=source_name, collected_at=when,
            verdict="unknown", flags=["not-assessed:non-windows-at-rest"], hosts_count=count,
            notes=(f"{count} enrolled device(s) are not Windows ({listing}). The reader "
                   "does not grade them: whatever such a device reports about its own "
                   "storage is a single value with no algorithm and no key custody behind "
                   "it that this reader can check. They are listed so the population is "
                   "visible, not as evidence that they are protected."),
            extra={f"os_{_slug(k)}": str(v) for k, v in others.items()}))

    gaps: list[str] = []
    if report_error or not report_rows:
        gaps.append(_gap_report(report_error))
    if other.named and other.error:
        gaps.append(_gap_cross_check(other.label, other.error))
    return assets, gaps


def _by_os(rows: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        os_name = value(r, "OS") or "unknown"
        out[os_name] = out.get(os_name, 0) + 1
    return out


def _scope_row(devices: list[str], escrow: dict[str, dict], report: dict[str, dict],
               report_rows: int, inventory_rows: list[dict], inventory_named: bool,
               directory_rows: list[dict], directory_named: bool, missing_rows: list[dict],
               missing_named: bool, other: CrossCheck, n: dict[str, int], dates: list[str],
               models: dict[str, int], order: str, source_name: str,
               when: str) -> CryptoAsset:
    """The row stating what each register counts, and where they disagree."""
    flags = [SCOPE_FLAG]
    sentences = [
        f"{len(devices)} Windows device(s) have a row: {n['held']} encrypted with a recovery "
        f"key held in Microsoft Entra ID, {n['not_held']} encrypted with none held there, "
        f"{n['not_encrypted']} not encrypted or unreadable, {n['ungraded']} ungraded. "
        "Copies kept in Active Directory Domain Services, in a file, on paper or by a data "
        "recovery agent are not read."]
    extra = {
        "devices": str(len(devices)), "escrow_confirmed": str(n["held"]),
        "escrow_missing": str(n["not_held"]), "not_encrypted": str(n["not_encrypted"]),
        "ungraded": str(n["ungraded"]), "cipher_policy_drift": str(n["drift"]),
        "source_conflicts": str(n["conflicts"]),
        "risk_label_disagreements": str(n["risk_disagrees"]),
        "no_escrow_row": str(n["no_escrow_row"]),
        "no_encryption_report_row": str(n["no_report_row"]),
        "devices_with_serial": str(n["serials"]),
        "encryption_report_rows": str(report_rows),
        "encryption_report_devices": str(len(report)),
        "escrow_report_devices": str(len(escrow)),
        "escrow_date_convention": order or "undetermined",
        "oldest_escrow_record": min(dates) if dates else "",
        "newest_escrow_record": max(dates) if dates else "",
        **{f"model_{_slug(k)}": str(v) for k, v in models.items()},
    }

    if missing_named:
        listed = {device_key(value(r, "DeviceName")) for r in missing_rows
                  if value(r, "DeviceName")}
        strays = listed - set(escrow)
        held_none = {d for d, r in escrow.items()
                     if truth(value(r, "IsEncrypted")) is True
                     and truth(value(r, "EscrowRecordFound")) is False}
        if strays:
            flags.append(f"escrow-missing-list-stray:{len(strays)}")
            sentences.append(
                f"The separate no-key list does not reconcile: {len(strays)} of its "
                f"{len(listed)} device(s) are not in the main export, so the two files "
                "disagree about which devices are exposed.")
        elif listed != held_none:
            flags.append("escrow-missing-list-differs")
            sentences.append(
                f"The separate no-key list names {len(listed)} device(s) where the main "
                f"export's columns identify {len(held_none)}; the grades follow the columns.")
        else:
            sentences.append("The separate no-key list names exactly the devices the main "
                             "export's columns identify.")
    if n["conflicts"]:
        flags.append(f"encryption-sources-disagree:{n['conflicts']}")

    registers = []
    if directory_named:
        d = directory_counts(directory_rows)
        extra.update({"entra_registrations": str(d["registrations"]),
                      "entra_windows": str(d["windows"]), "entra_managed": str(d["managed"]),
                      "entra_workplace_registered": str(d["workplace"])})
        registers.append(
            f"{d['registrations']} device object(s) in Microsoft Entra ID, the widest count "
            f"and one with no encryption column ({d['workplace']} registered as personal "
            "devices)")
    if inventory_named:
        names = {device_key(value(r, "Device name")) for r in inventory_rows
                 if value(r, "Device name")}
        extra["intune_managed_devices"] = str(len(names))
        by_os = ", ".join(f"{k}: {v}" for k, v in sorted(_by_os(inventory_rows).items()))
        registers.append(f"{len(names)} device(s) enrolled in Intune ({by_os})")
    registers.append(
        f"{report_rows} row(s) in the encryption report covering {len(report)} device(s), "
        "so a count of its rows is not a count of devices")
    registers.append(
        f"{len(escrow)} device(s) in the escrow export, the only one that says whether a "
        "key is held in Microsoft Entra ID")
    sentences.append("The registers count different populations, and none stands in for "
                     "another: " + "; ".join(registers) + ".")

    if other.named:
        both = len(set(other.status) & set(devices))
        only = len(set(other.status) - set(devices))
        extra[f"{other.name}_hosts"] = str(len(other.status))
        extra[f"{other.name}_only_hosts"] = str(only)
        sentences.append(
            f"{other.label}'s drive-encryption export covers {len(other.status)} device(s): "
            f"{both} also have a row here, and the {only} that do not are counted here and "
            "not graded; a reader of that source can use escrowed_devices() to avoid "
            "counting them twice.")
    sentences.append(f"Where two sources disagree about a device the row is graded unknown: "
                     f"{n['conflicts']} did.")
    sentences.append(
        f"{n['serials']} of the {len(devices)} row(s) carry a hardware serial, from the "
        f"escrow export; the {n['no_escrow_row']} device(s) placed from the encryption "
        "report alone carry none, because that report has no serial column.")
    sentences.append("No export here can show that a backed-up key is still the key a drive "
                     "uses, only the date it was backed up.")

    return CryptoAsset(
        name="Endpoint at-rest population reconciliation", data_state="at-rest",
        protocol="fde", role=roles.endpoint_at_rest_population(), source=NAME,
        source_class="private", source_name=source_name, collected_at=when, verdict="n/a",
        flags=flags, hosts_count=len(devices), notes=" ".join(sentences), extra=extra)


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the rows, or a gap naming what was not read."""
    path = _entra.primary(ctx, "escrow")
    if path is None:
        return StepResult(gaps=[_gap_no_escrow("")])
    assets, gaps = read(ctx, path)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Windows drive encryption and recovery-key escrow (Intune, Entra)",
                gap_prefix=False)
