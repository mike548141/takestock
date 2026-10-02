"""An example takestock plug-in: disk encryption state from an invented export.

Example Widgets Ltd (a fictional manufacturer) runs a disk encryption tool
that exports one CSV row per volume:

    Machine,Disk,Status,Cipher,Unlock,Key escrow
    laptop-01.example.test,C:,Protected,XTS 256,Chip+PIN,Yes

takestock has no reader for that tool, so this package supplies one. It is
written to be copied: replace the column names, the status words and the
cipher labels with your own tool's, and keep the shape.

What a plug-in does, and what it leaves to takestock:

* it reads its export and returns one **record** per volume, using the field
  names of the ``endpoint-encryption`` kind (``device``, ``volume``,
  ``state``, ``method`` and so on; see takestock's ``docs/PLUGINS.md``);
* takestock checks every record against that kind's schema, turns the valid
  ones into rows, grades them against its baseline, and records any invalid
  record or missing input as a coverage gap.

So the plug-in translates and never grades. It names no verdict and no flag,
and a cipher label it does not know is passed through as written, so
takestock flags it as ungraded instead of the plug-in guessing.

This package shows each part of the contract once:

* the declaration, :data:`PLUGIN`;
* reading the input takestock resolved (``ctx.input``);
* a data file of its own, ``cipher-names.csv``, read through
  ``ctx.data_file`` (takestock never reads it as its own reference data);
* keeping a copy of what it read in its ``raw/`` directory (``ctx.raw_dir``);
* a coverage gap for rows it could not use;
* a summary contribution, from the step and from the graded rows.

Install it with ``pip install -e examples/plugin-disk-encryption`` (its entry
point registers it), or name the module in the target profile. Either way the
profile declares it:

    plugins:
      - name: example-disk-encryption
        input: inbox/disk-encryption.csv
"""

from __future__ import annotations

import csv
import shutil
from pathlib import Path

from takestock import coverage
from takestock.model import CryptoAsset
from takestock.plugins import Context, Plugin, StepResult

#: The export's status words, mapped to the kind's ``state`` values.
STATUS = {
    "protected": "encrypted",
    "unprotected": "not-encrypted",
    "paused": "suspended",
    "working": "in-progress",
}

#: The export's unlock methods, mapped to the kind's ``key_protectors`` words.
UNLOCK = {
    "chip": "tpm",
    "chip+pin": "tpm+pin",
    "passphrase": "password",
}

ESCROW = {"yes": True, "no": False}


def _cipher_names(path: Path) -> dict[str, str]:
    """The tool's cipher labels mapped to the cipher names takestock's baseline grades."""
    with path.open(newline="", encoding="utf-8") as f:
        return {row["label"].strip().lower(): row["method"].strip() for row in csv.DictReader(f)}


def read(ctx: Context) -> StepResult:
    """Read the export ``ctx.input`` and return one record per volume."""
    assert ctx.input is not None  # takestock does not call the step when the input is missing
    shutil.copyfile(ctx.input, ctx.raw_dir / ctx.input.name)
    ciphers = _cipher_names(ctx.data_file("cipher-names.csv"))

    records: list[dict] = []
    skipped = 0
    with ctx.input.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            machine = (row.get("Machine") or "").strip()
            disk = (row.get("Disk") or "").strip()
            if not machine or not disk:
                skipped += 1
                continue
            status = (row.get("Status") or "").strip().lower()
            cipher = (row.get("Cipher") or "").strip()
            unlock = (row.get("Unlock") or "").strip().lower()
            record: dict = {
                "device": machine,
                "volume": disk,
                # An unknown word is passed through: takestock's schema refuses it
                # and reports the record, rather than this plug-in guessing.
                "state": STATUS.get(status, status),
            }
            if cipher:
                record["method"] = ciphers.get(cipher.lower(), cipher)
            if unlock:
                record["key_protectors"] = [UNLOCK.get(unlock, unlock)]
            escrow = (row.get("Key escrow") or "").strip().lower()
            if escrow in ESCROW:
                record["recovery_key_escrowed"] = ESCROW[escrow]
            records.append(record)

    gaps = []
    if skipped:
        gaps.append(coverage.gap(
            coverage.EXTENT_UNKNOWN,
            f"{skipped} row(s) in {ctx.input.name} name no machine or no disk, so they are not read",
            impact_kind=coverage.NARROWS_CONFIDENCE,
            impact="Those volumes are missing from the counts; every other row stands.",
            harvest="A re-export with the Machine and Disk columns filled on every row.",
            nature=coverage.NO_DATA))
    machines = {r["device"].lower() for r in records}
    return StepResult(records=records, gaps=gaps,
                      summary={"machines": len(machines), "volumes": len(records)})


def summarise(ctx: Context, rows: list[CryptoAsset]) -> dict:
    """After grading: how many volumes are weak, and how many are not yet graded."""
    return {
        "weak_volumes": sum(1 for r in rows if r.verdict == "weak"),
        "ungraded_volumes": sum(1 for r in rows if r.verdict == "unknown"),
    }


PLUGIN = Plugin(
    name="example-disk-encryption",
    kind="endpoint-encryption",
    step=read,
    input="inbox/disk-encryption.csv",
    title="Disk encryption export (example tool)",
    data_files=("cipher-names.csv",),
    summarise=summarise,
)
