"""Commvault backup encryption: the cipher and key custody of each storage policy copy.

A backup is a second copy of the data it protects, and is often kept longer
than the original, on media that is not under the same control as the server
the data came from. So whether backups are encrypted matters as much as
whether the original is.

In Commvault, software encryption is set on each **copy** of a **storage
policy** (or plan): in the copy's properties, an **Encrypt Data** check box
with a **Cipher** list and a **Key Length** list (Commvault documentation,
*Configuring Software Encryption on a Primary Copy*, and the same for a
secondary copy). The ciphers offered are
listed in *Supported Algorithms for Software Encryption*: AES (Rijndael) with
a 128- or 256-bit key, Blowfish (128, 256), Twofish (128, 256), Serpent (128,
256), GOST (256) and 3-DES (192). The same page gives AES's mode as CBC.

**The input** is a CSV with one row per storage policy copy, recorded from
the console by the backup administrator. Commvault publishes no single
report whose columns are documented to carry the cipher and key length of
every copy, so the columns are this reader's own, named after the console's
fields (``docs/COLLECTORS.md``, ``commvault``). Headings may differ in case
and in how words are joined, and common synonyms are read (:data:`COLUMNS`).

**Grading.** A copy whose encryption is off, or recorded as neither on nor
off, is ``weak`` (``encryption-off``, ``encryption-status:<value>``). A row
with no encryption setting and no cipher is read as off: nothing shows the
copy is protected. Otherwise the cipher is graded from the baseline's
``symmetric`` table: AES with a 256-bit key as ``aes256_cbc``, AES with any
other key length as ``aes_cbc``, and the other ciphers by name
(:data:`CIPHERS`). A cipher graded ``weak`` is also flagged
``weak-algorithm:<cipher>``. A cipher the baseline does not grade is flagged
``ungraded:symmetric:<name>`` and leaves the verdict ``unknown``: it is not
guessed at. Encryption recorded as on with no cipher gives the same flag with
no name.

**Key custody** is recorded as a fact and never changes the verdict:
``key-custody:commserve-db`` for keys kept in the CommServe database (where
Commvault keeps them by default), ``key-custody:media-password`` for keys
also written to the backup media under a media password, and the value
recorded otherwise, such as an external key manager's name.

**Cannot see.** Hardware encryption done by a tape drive; encryption of data
on its way to the backup (in transit); whether the copies are immutable; and
any policy or copy missing from the export.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, worst
from ..plugins import Context, Plugin, StepResult
from ..policy import Policy
from ..util import file_mtime_date
from . import _table

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "commvault"

#: Values of the encryption setting read as off, and as on (compared in lower case).
OFF = frozenset({"no", "false", "0", "disabled", "off", "none", "not encrypted"})
ON = frozenset({"yes", "true", "1", "enabled", "on"})

#: Cipher names as Commvault and administrators write them (lower case), and
#: the baseline ``symmetric`` entry each is graded by. AES is sized from the
#: key length in :func:`cipher_token`.
CIPHERS: dict[str, str] = {
    "aes": "aes", "rijndael": "aes",
    "blowfish": "blowfish",
    "twofish": "twofish",
    "serpent": "serpent",
    "gost": "gost",
    "3des": "3des", "3-des": "3des", "des3": "3des", "tripledes": "3des",
    "triple des": "3des", "triple-des": "3des",
}

#: Each field and the column names it may arrive under, in order of preference.
COLUMNS: dict[str, tuple[str, ...]] = {
    "storage_policy": ("storage_policy", "plan", "plan_name", "storage_policy_name", "policy"),
    "copy_name": ("copy", "copy_name", "storage_policy_copy"),
    "storage_pool": ("storage_pool", "pool", "storage_pool_name"),
    "enabled": ("encryption_enabled", "encryption", "enabled", "software_encryption"),
    "cipher": ("cipher", "encryption_algorithm", "algorithm", "encryption_type"),
    "key_length": ("key_length", "keylength", "key_size"),
    "key_management": ("key_management", "key_location", "key_storage", "kms", "kms_name"),
}


def _field(row: dict[str, str], key: str) -> str:
    return _table.value(row, *COLUMNS[key])


def cipher_token(cipher: str, key_length: str) -> str:
    """The baseline ``symmetric`` entry for a cipher name and key length.

    A name not in :data:`CIPHERS` comes back in lower case, unchanged, so the
    baseline does not grade it and the row says so.
    """
    name = cipher.strip().lower()
    known = CIPHERS.get(name, "")
    if known == "aes":
        return "aes256_cbc" if key_length.strip() == "256" else "aes_cbc"
    return known or name


def grade(enabled: str, cipher: str, key_length: str,
          policy: Policy) -> tuple[str, list[str], set[str]]:
    """(verdict, symmetric tokens, flags) for one copy's encryption setting.

    ``enabled`` is the setting as recorded, in lower case.
    """
    flags: set[str] = set()
    tokens: list[str] = []
    verdicts: list[str] = []
    if enabled in OFF or not (enabled or cipher):
        flags.add("encryption-off")
        verdicts.append("weak")
    elif enabled in ON or not enabled:
        # Recorded as on, or a cipher recorded with no setting beside it: an
        # export that names a cipher describes encryption in use.
        token = cipher_token(cipher, key_length)
        verdict = policy.grade("symmetric", token)
        if verdict == "unknown":
            flags.add(f"ungraded:symmetric:{token}")
        else:
            tokens.append(token)
            verdicts.append(verdict)
            if verdict == "weak":
                flags.add(f"weak-algorithm:{cipher}")
    else:
        flags.add(f"encryption-status:{enabled}")
        verdicts.append("weak")
    return (worst(verdicts) if verdicts else "unknown"), tokens, flags


def custody(key_management: str) -> str:
    """The ``key-custody:`` flag for where a copy's keys are held, or "" when not recorded."""
    held = key_management.strip().lower()
    if "commserve" in held or "database" in held:
        return "key-custody:commserve-db"
    if "media" in held:
        return "key-custody:media-password"
    return f"key-custody:{held.replace(' ', '-')}" if held else ""


def row_for(row: dict[str, str], source_name: str, collected_at: str,
            policy: Policy) -> CryptoAsset:
    """One storage policy copy's row."""
    storage_policy = _field(row, "storage_policy")
    copy = _field(row, "copy_name")
    pool = _field(row, "storage_pool")
    enabled = _field(row, "enabled").lower()
    cipher = _field(row, "cipher")
    key_length = _field(row, "key_length")
    key_management = _field(row, "key_management")
    ident = storage_policy or pool or "commvault-policy"
    verdict, tokens, flags = grade(enabled, cipher, key_length, policy)
    held = custody(key_management)
    if held:
        flags.add(held)
    if "encryption-off" in flags:
        state = "Backup encryption is off."
    elif any(f.startswith("encryption-status:") for f in flags):
        state = f"Backup encryption is recorded as {enabled!r}, which is neither on nor off."
    else:
        state = "Backup encryption is on."
    notes = (f"{state} Cipher {cipher or 'not recorded'}, key length "
             f"{key_length or 'not recorded'}, keys held by "
             f"{key_management or 'a party not recorded'}.")
    return CryptoAsset(
        name=f"Commvault backup encryption {ident}" + (f" ({copy})" if copy else ""),
        role=roles.backup_encryption(ident), data_state="at-rest",
        protocol="commvault-backup", software="Commvault", source=NAME,
        source_class="private", source_name=source_name, collected_at=collected_at,
        symmetric=sorted(set(tokens)), verdict=verdict, flags=sorted(flags), notes=notes,
        extra={"storage_policy": storage_policy, "storage_pool": pool, "copy_name": copy,
               "cipher": cipher, "key_length": key_length, "key_management": key_management})


def read(ctx: Context) -> StepResult:
    """The plug-in's step: one row per storage policy copy, or the gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_none_read("no input was given")])
    path: Path = ctx.input
    try:
        rows = _table.read(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return StepResult(gaps=[_none_read(f"{path.name} could not be read as CSV ({exc})")])
    if not rows:
        return StepResult(gaps=[_none_read(f"{path.name} holds no rows")])
    # The settings carry no date of their own, so the file's date stands for
    # when they were recorded.
    when = file_mtime_date(path)
    source_name = ("Commvault storage policy encryption settings, "
                   + (f"file dated {when}" if when else "file date unavailable"))
    return StepResult(records=[row_for(r, source_name, when or "", ctx.policy) for r in rows])


def _none_read(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no Commvault backup encryption export was read: {why}",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Backups hold a second copy of the data they protect, and nothing here says "
                "whether that copy is encrypted. Stored data is only as protected as its "
                "least protected copy, so this can reverse a reassuring answer about data "
                "at rest."),
        harvest=("The backup administrator records each storage policy copy's encryption "
                 "settings as CSV, in the columns docs/COLLECTORS.md lists (`commvault`), "
                 "and names the file as the reader's input."),
        nature=coverage.NO_DATA)


#: The declaration. It names no default input: with none given in the
#: profile, the step still runs and records what is missing in its own gap.
PLUGIN = Plugin(
    name=NAME, kind="backup-encryption", step=read,
    title="Commvault storage policy encryption settings", gap_prefix=False)
