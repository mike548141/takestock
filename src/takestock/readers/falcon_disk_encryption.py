"""CrowdStrike Falcon: whether each sensored machine's drives are encrypted.

**The input** (``input:``) is a CSV with one row per machine (or per machine
and network adapter) giving its drive encryption state, such as the Falcon
console's drive encryption view exported as CSV. No public description of
that export's headings was found, so the default headings are plain names of
takestock's own; name an export's own with ``settings: columns:`` (a
heading, or a list tried in order):

* ``machine`` (``hostname``): the machine's name;
* ``platform`` (``platform``): its operating system family;
* ``status`` (``encryption_status``): the export's word for its state;
* ``encrypted_count`` (``encrypted_drives_count``) and ``unencrypted_count``
  (``unencrypted_drives_count``): how many of its volumes are and are not
  encrypted;
* ``encrypted_drives`` and ``unencrypted_drives`` (the same names): which
  volumes, as text (optional).

A cell holding ``--`` is read as blank.

**How a machine is graded.** The status is compared whole, ignoring case,
with the words in ``settings: encrypted:`` (default ``encrypted``) and
``settings: unencrypted:`` (default ``unencrypted``); a status is never
matched by a word inside it, so ``Unencrypted`` is not read as encrypted.

* status encrypted and no unencrypted volume: ``strong``;
* status unencrypted, or unencrypted volumes and no encrypted one: ``weak``,
  ``drive-unencrypted``;
* both encrypted and unencrypted volumes: ``weak``,
  ``drive-partially-encrypted:<n>`` (``n`` volumes not encrypted), since a
  machine whose system volume is encrypted and whose data volume is not
  still leaves data readable;
* anything else: ``unknown``, ``ungraded:drive-encryption:<status>``.

**Recovery keys.** Whether a drive is encrypted says nothing about where a
copy of its recovery key is held. ``settings: escrow:`` names the main export
the ``m365_bitlocker`` reader reads (Intune-managed Windows devices joined to
the BitLocker recovery keys held in Microsoft Entra ID). A machine that
export names is left to that reader, which answers both halves, so its
at-rest state is not reported twice; it is counted on the scope row. Every
machine kept here is then flagged ``key-custody-unknown``: no key-custody
export covers it, so whether a copy of its key is held is unknown, not
absent. Without ``escrow:``, or when that export names no device, a gap says
the recovery-key half is unanswered.

**Rows.** One per machine row, ``Drive encryption <machine>`` (at rest,
``fde``); and a scope row, ``Drive encryption scope`` (``n/a``,
``scope-platform-limited``, and ``scope-yielded-to-key-custody:<n>`` when
rows were left to the key-custody reader), giving the rows, the distinct
machines (counted by name, ignoring case), the platforms in the export and
the grades. Its ``extra.machines`` and ``hosts_count`` hold the export's row
count, rows with no machine name included; ``extra.distinct_hosts`` holds
the machines. A machine with several rows (several network adapters, or
rebuilt under the same name) keeps each row; no rule says which would win.
A machine absent from the export has no answer here, which is not the same
as an unencrypted one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra, m365_bitlocker
from . import _falcon_identity as _fi
from . import _falcon_platform as _fp

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "falcon_disk_encryption"

UNENCRYPTED_FLAG = "drive-unencrypted"
PARTIAL_FLAG = "drive-partially-encrypted:"
UNGRADED_FLAG = "ungraded:drive-encryption:"
CUSTODY_FLAG = "key-custody-unknown"
SCOPE_FLAG = "scope-platform-limited"
YIELDED_FLAG = "scope-yielded-to-key-custody:"

register_informational_prefixes(CUSTODY_FLAG, SCOPE_FLAG, YIELDED_FLAG)

#: Each field and its default heading, unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "machine": "hostname",
    "platform": "platform",
    "status": "encryption_status",
    "encrypted_count": "encrypted_drives_count",
    "unencrypted_count": "unencrypted_drives_count",
    "encrypted_drives": "encrypted_drives",
    "unencrypted_drives": "unencrypted_drives",
}

ENCRYPTED: tuple[str, ...] = ("encrypted",)
UNENCRYPTED: tuple[str, ...] = ("unencrypted",)

ESCROW_UNANSWERED = (
    "This export says whether drives are encrypted and nothing about where their "
    "recovery keys are held. An encrypted drive whose key has no copy outside the "
    "machine can be lost to its owner as well as to a thief, so encrypted is not "
    "the same as recoverable; a key-custody export answers that half")


def _missing_gap(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no CrowdStrike Falcon drive encryption export was read"
        + (f" ({why})" if why else "")
        + ": whether the sensored machines' drives are encrypted at rest (name it with "
          "`input:`)",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it nothing here says whether a lost or stolen machine's drive "
                "can be read by whoever holds it."),
        harvest=("Export the console's drive encryption view as CSV and name it with "
                 "input:; name its headings with settings: columns:."),
        nature=coverage.NO_DATA)


def _escrow_gap() -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "recovery-key custody for the machines in the `falcon_disk_encryption` export: "
        "which drives are encrypted is known, and where a copy of each recovery key is "
        "held is not (name a key-custody export with `settings: escrow:`)",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("An encrypted drive whose recovery key was never saved anywhere else cannot "
                "be unlocked by its owner after a hardware fault either, so a machine "
                "graded strong here may still be a data-loss risk. Do not read encrypted "
                "as recoverable until this is answered."),
        harvest=("Name the m365_bitlocker reader's main export (Intune-managed devices "
                 "joined to the recovery keys held in Microsoft Entra ID) with settings: "
                 "escrow:."),
        nature=coverage.LOW_FIDELITY)


def _words(raw: Any, default: Sequence[str]) -> tuple[str, ...]:
    if raw is None:
        return tuple(default)
    values = [raw] if isinstance(raw, str) else list(raw)
    return tuple(str(v).strip().lower() for v in values if str(v).strip())


def escrowed(ctx: Context) -> set[str]:
    """The device names (upper-cased) the ``escrow`` export answers for; empty when none."""
    path = _entra.newest(ctx, "escrow")
    if path is None or not path.exists():
        return set()
    return m365_bitlocker.escrowed_devices(path)


def read(path: Path, heads: Mapping[str, Any], escrow: set[str],
         encrypted_words: Sequence[str] = ENCRYPTED,
         unencrypted_words: Sequence[str] = UNENCRYPTED) -> tuple[list[CryptoAsset], list]:
    """The rows for one export, or no rows and a gap when it cannot be read or is empty."""
    rows, why = _fi.rows(path)
    if not rows:
        return [], [_missing_gap(why or "the file holds no rows")]
    when = file_mtime_date(path) or ""
    source_name = _fi.source_name("drive encryption", when)
    base: dict[str, Any] = {"source": NAME, "source_class": "private",
                            "source_name": source_name, "collected_at": when}

    out: list[CryptoAsset] = []
    platforms: dict[str, int] = {}
    machines: set[str] = set()
    encrypted = unencrypted = ungraded = yielded = 0
    for r in rows:
        machine = _fi.value(r, heads["machine"])
        if not machine:
            continue
        key = machine.strip().upper()
        machines.add(key)
        # Platforms are counted over every named row, the yielded ones
        # included: the scope row says what the export covers.
        platform = _fi.value(r, heads["platform"]) or "unknown"
        platforms[platform] = platforms.get(platform, 0) + 1
        if key in escrow:
            yielded += 1
            continue
        status = _fi.value(r, heads["status"])
        enc_n = _fi.number(_fi.value(r, heads["encrypted_count"]))
        unenc_n = _fi.number(_fi.value(r, heads["unencrypted_count"]))
        enc_list = _fi.value(r, heads["encrypted_drives"])
        unenc_list = _fi.value(r, heads["unencrypted_drives"])
        word = status.strip().lower()
        flags: list[str] = []
        if word in encrypted_words and unenc_n == 0:
            verdict = "strong"
            encrypted += 1
            note = (f"Every drive on this machine is encrypted ({enc_n} volume(s)"
                    f"{': ' + enc_list if enc_list else ''}).")
        elif word in unencrypted_words or (unenc_n and not enc_n):
            verdict = "weak"
            unencrypted += 1
            flags.append(UNENCRYPTED_FLAG)
            note = (f"No drive on this machine is encrypted ({unenc_n} volume(s)"
                    f"{': ' + unenc_list if unenc_list else ''}), so whoever holds the disk "
                    "can read it.")
        elif unenc_n and enc_n:
            verdict = "weak"
            unencrypted += 1
            flags.append(f"{PARTIAL_FLAG}{unenc_n}")
            note = (f"Partly encrypted: {enc_n} volume(s) encrypted"
                    f"{' (' + enc_list + ')' if enc_list else ''} and {unenc_n} not"
                    f"{' (' + unenc_list + ')' if unenc_list else ''}. The status column "
                    "alone would not show this.")
        else:
            verdict = "unknown"
            ungraded += 1
            flags.append(f"{UNGRADED_FLAG}{status or 'blank'}")
            note = (f"The export gives the drive encryption status {status or '(blank)'!r}, "
                    "which this reader does not recognise, so the machine is graded unknown "
                    "rather than guessed.")
        if escrow:
            flags.append(CUSTODY_FLAG)
            note += (" No key-custody export covers this machine, so whether a copy of its "
                     "recovery key is held anywhere is unknown, not absent.")
        out.append(CryptoAsset(
            name=f"Drive encryption {machine}", data_state="at-rest", protocol="fde",
            role=roles.drive_encryption(machine), host=machine, verdict=verdict,
            flags=flags, notes=note,
            extra={"platform": platform, "status": status, "encrypted_drives": str(enc_n),
                   "unencrypted_drives": str(unenc_n)},
            **base))

    kept = len(out)
    scope_flags = [SCOPE_FLAG]
    if yielded:
        scope_flags.append(f"{YIELDED_FLAG}{yielded}")
    if escrow:
        custody = (f"{_fi_rows(yielded)} ({len(machines & escrow):,} distinct machines) are "
                   "not listed here: the key-custody export names them, so its reader "
                   "reports their encryption and recovery keys together, once. The "
                   f"{kept:,} machine row(s) kept here are the ones no key-custody export "
                   "covers, each flagged key-custody-unknown.")
    else:
        custody = ESCROW_UNANSWERED + "."
    mix = ", ".join(f"{k}: {v}" for k, v in sorted(platforms.items()))
    out.append(CryptoAsset(
        name="Drive encryption scope", data_state="at-rest", protocol="fde",
        role=roles.drive_encryption_scope(), verdict="n/a", flags=scope_flags,
        hosts_count=len(rows),
        notes=(f"{len(rows):,} rows in the export, naming "
               f"{len(machines):,} distinct machines; a machine with several network "
               f"adapters, or rebuilt under the same name, can have more than one row "
               f"({mix}). The export covers only the machines and platforms it lists; a "
               "machine it does not list has no answer here, which is not the same as an "
               "unencrypted one. " + custody),
        extra={"machines": str(len(rows)), "distinct_hosts": str(len(machines)),
               "encrypted": str(encrypted), "unencrypted": str(unencrypted),
               "ungraded": str(ungraded), "yielded_to_key_custody": str(yielded),
               **{f"platform_{k.lower()}": str(v) for k, v in platforms.items()}},
        **base))
    gaps = [] if escrow else [_escrow_gap()]
    return out, gaps


def _fi_rows(n: int) -> str:
    return f"{n:,} of those rows" if n != 1 else "1 of those rows"


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    s = ctx.settings or {}
    heads = {f: list(h) for f, h in _fp.columns(ctx, HEADINGS).items()}
    assets, gaps = read(ctx.input, heads, escrowed(ctx),
                        _words(s.get("encrypted"), ENCRYPTED),
                        _words(s.get("unencrypted"), UNENCRYPTED))
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step still
#: runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="CrowdStrike Falcon drive encryption",
                gap_prefix=False)
