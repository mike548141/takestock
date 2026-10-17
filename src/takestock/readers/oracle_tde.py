"""Oracle Transparent Data Encryption: whether each database's stored data is encrypted.

**Transparent Data Encryption** (TDE) is Oracle Database's encryption of data
at rest. It encrypts tablespaces (the storage units a database's data files
make up) or single columns, using keys that are themselves encrypted by a
master key held in a **keystore** (Oracle's documentation also calls it a
wallet). While the keystore is closed or missing, the database can neither
read nor write its encrypted data; while it is open, data is encrypted as it is
written and decrypted as it is read.

**The input** is a CSV export a database administrator makes, one row per
database (or per pluggable database, in a multitenant container database),
from Oracle's dynamic performance views (Oracle Database Reference):

* ``V$ENCRYPTION_WALLET``: the keystore's ``STATUS`` (``OPEN``, ``CLOSED``,
  ``NOT_AVAILABLE``, ``OPEN_NO_MASTER_KEY``, ``OPEN_UNKNOWN_MASTER_KEY_STATUS``,
  ``UNDEFINED``), ``WALLET_TYPE``, ``WALLET_ORDER`` and ``WRL_PARAMETER`` (where
  the keystore is: a directory, or a key manager's address; never a key);
* ``V$ENCRYPTED_TABLESPACES``: one row per encrypted tablespace, with its
  ``ENCRYPTIONALG`` (``AES128``, ``AES192``, ``AES256``, ``3DES168``);
* ``DBA_TABLESPACES``: every tablespace, so a partial roll-out shows;
* ``V$DATABASE`` and ``V$INSTANCE``: the database's names and its server.

``docs/COLLECTORS.md`` gives a query that writes these columns. The headings
may differ in case and in how words are joined, and common synonyms are read
(:data:`COLUMNS`). The reader reads only the columns; it runs nothing.

**Grading.** A database is ``weak`` when nothing protects its data: no
keystore (``tde-not-enabled``), a closed one (``wallet-closed``), another
status that is not open (``wallet-status:<status>``), or an open keystore and
no encrypted tablespace (``tde-not-enabled`` and ``no-encrypted-tablespaces``).
Otherwise each algorithm is graded from the baseline's ``symmetric`` table
(:data:`ALGORITHMS`). ``ENCRYPTIONALG`` names a cipher and key length but not
its mode, and Oracle's documented tablespace modes differ by release (cipher
feedback, CFB, before 23ai; XTS by default in later releases), so every AES length is
graded as the baseline's unsized ``aes_cbc`` row, AES without authentication,
and never raised to a sized at-rest grade the view cannot confirm. ``3DES168``
is graded ``weak`` and flagged ``weak-algorithm:3DES168``. Any other name is
``unknown`` and flagged ``unrecognised-algorithm:<name>``, not guessed at.

**Other flags.** ``partial-encryption:<n>-of-<m>-tablespaces`` when fewer
tablespaces are encrypted than exist, and ``key-custody:<where>`` from the
keystore type: ``file-local`` for a keystore kept as a file (a software
keystore), ``hsm`` for a hardware security module or Oracle Key Vault, and the
type itself otherwise. Custody is recorded as a fact and never changes the
verdict, which is about the cipher.

**Cannot see.** Column encryption, which these views do not report; whether
the keystore's password or auto-login file is itself protected; backups,
exports and redo shipped elsewhere; and anything about a database not in the
export.
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
NAME = "oracle_tde"

#: Keystore statuses Oracle documents as open.
#: ``OPEN_UNKNOWN_MASTER_KEY_STATUS`` is an open keystore whose master key the
#: database could not check, which Oracle documents for a database that is
#: mounted but not yet open; it is read as open, not as a failure.
OPEN_STATUSES = frozenset({"OPEN", "OPEN_NO_MASTER_KEY", "OPEN_UNKNOWN_MASTER_KEY_STATUS"})

#: ``ENCRYPTIONALG`` values and the baseline ``symmetric`` entry each is graded by.
ALGORITHMS: dict[str, str] = {
    "AES128": "aes_cbc",
    "AES192": "aes_cbc",
    "AES256": "aes_cbc",
    "3DES168": "3des",
}

#: Each field and the column names it may arrive under, in order of preference.
COLUMNS: dict[str, tuple[str, ...]] = {
    "db_name": ("db_name", "name", "database", "db"),
    "db_unique_name": ("db_unique_name", "unique_name", "db_unique"),
    "pdb_name": ("pdb_name", "con_name", "container", "pdb"),
    "host": ("host", "host_name", "hostname", "computername", "server", "db_host"),
    "wallet_type": ("wallet_type", "keystore_type"),
    "wallet_status": ("wallet_status", "status", "keystore_status", "ks_status"),
    "wallet_order": ("wallet_order",),
    "wrl_parameter": ("wrl_parameter", "wallet_location", "key_location", "keystore_location"),
    "algorithm": ("tablespace_encryption_alg", "encryptionalg", "encryption_algorithm", "alg",
                  "algorithm"),
    "encrypted": ("encrypted_tablespace_count", "encrypted_tablespaces", "encrypted_ts_count",
                  "encrypted_count"),
    "tablespaces": ("tablespace_count", "total_tablespaces", "ts_count", "total_ts"),
}


def _count(text: str) -> int | None:
    try:
        return int(text)
    except ValueError:
        return None


def _field(row: dict[str, str], key: str) -> str:
    return _table.value(row, *COLUMNS[key])


def grade(status: str, algorithms: str, encrypted: int | None, tablespaces: int | None,
          policy: Policy) -> tuple[str, list[str], set[str]]:
    """(verdict, symmetric tokens, flags) for one database's keystore and tablespaces.

    ``algorithms`` may join several ``ENCRYPTIONALG`` values with ``/``.
    """
    flags: set[str] = set()
    tokens: list[str] = []
    verdicts: list[str] = []
    any_encrypted = encrypted > 0 if encrypted is not None else bool(algorithms)
    if status in ("", "NOT_AVAILABLE"):
        flags.add("tde-not-enabled")
        verdicts.append("weak")
    elif status == "CLOSED":
        flags.add("wallet-closed")
        verdicts.append("weak")
    elif status not in OPEN_STATUSES:
        flags.add(f"wallet-status:{status.lower()}")
        verdicts.append("weak")
    elif not any_encrypted:
        flags |= {"tde-not-enabled", "no-encrypted-tablespaces"}
        verdicts.append("weak")
    else:
        for alg in sorted({a.strip().upper() for a in algorithms.split("/") if a.strip()}):
            token = ALGORITHMS.get(alg)
            if token is None:
                flags.add(f"unrecognised-algorithm:{alg}")
                verdicts.append("unknown")
                continue
            tokens.append(token)
            verdicts.append(policy.grade("symmetric", token))
            if token == "3des":
                flags.add(f"weak-algorithm:{alg}")
        if encrypted is not None and tablespaces is not None and encrypted < tablespaces:
            flags.add(f"partial-encryption:{encrypted}-of-{tablespaces}-tablespaces")
    return (worst(verdicts) if verdicts else "unknown"), sorted(set(tokens)), flags


def custody(wallet_type: str) -> str:
    """The ``key-custody:`` flag for a keystore type, or "" when none is recorded."""
    if not wallet_type:
        return ""
    if wallet_type == "FILE":
        return "key-custody:file-local"
    if wallet_type in ("HSM", "OKV"):
        return "key-custody:hsm"
    return f"key-custody:{wallet_type.lower()}"


def _shown(n: int | None) -> str:
    return "?" if n is None else str(n)


def row_for(row: dict[str, str], source_name: str, collected_at: str,
            policy: Policy) -> CryptoAsset:
    """One database's row."""
    db = _field(row, "db_name")
    unique = _field(row, "db_unique_name")
    pdb = _field(row, "pdb_name")
    host = _field(row, "host")
    wallet_type = _field(row, "wallet_type").upper()
    status = _field(row, "wallet_status").upper()
    order = _field(row, "wallet_order")
    location = _field(row, "wrl_parameter")
    algorithms = _field(row, "algorithm")
    encrypted = _count(_field(row, "encrypted"))
    tablespaces = _count(_field(row, "tablespaces"))
    ident = unique or db or host or "oracle-db"
    verdict, tokens, flags = grade(status, algorithms, encrypted, tablespaces, policy)
    held = custody(wallet_type)
    if held:
        flags.add(held)
    unprotected = bool(flags & {"tde-not-enabled", "wallet-closed"})
    notes = (("Not protected by Transparent Data Encryption. " if unprotected else "")
             + f"Keystore type {wallet_type or 'not recorded'}, status "
             f"{status or 'not recorded'}, order {order or 'not recorded'}. Tablespace "
             f"algorithm {algorithms or 'none recorded'}; {_shown(encrypted)} of "
             f"{_shown(tablespaces)} tablespaces encrypted.")
    return CryptoAsset(
        name=f"Oracle TDE {ident}" + (f" ({pdb})" if pdb else ""),
        role=roles.database_encryption(ident), data_state="at-rest", protocol="tde",
        host=host, software="Oracle Database", source=NAME, source_class="private",
        source_name=source_name, collected_at=collected_at, symmetric=tokens,
        verdict=verdict, flags=sorted(flags), notes=notes,
        extra={"db_name": db, "db_unique_name": unique, "pdb_name": pdb,
               "wallet_type": wallet_type, "wallet_status": status, "wallet_order": order,
               "wrl_parameter": location, "tablespace_encryption_alg": algorithms,
               "encrypted_tablespace_count": encrypted, "tablespace_count": tablespaces})


def read(ctx: Context) -> StepResult:
    """The plug-in's step: one row per database in the export, or the gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_none_read("no input was given")])
    path: Path = ctx.input
    try:
        rows = _table.read(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return StepResult(gaps=[_none_read(f"{path.name} could not be read as CSV ({exc})")])
    if not rows:
        return StepResult(gaps=[_none_read(f"{path.name} holds no rows")])
    # The export carries no date of its own, so the file's date stands for
    # when the query was run.
    when = file_mtime_date(path)
    source_name = ("Oracle TDE export (V$ENCRYPTION_WALLET, V$ENCRYPTED_TABLESPACES), "
                   + (f"file dated {when}" if when else "file date unavailable"))
    return StepResult(records=[row_for(r, source_name, when or "", ctx.policy) for r in rows])


def _none_read(why: str) -> coverage.Gap:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        f"no Oracle Transparent Data Encryption export was read: {why}",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Whether each Oracle database's stored data is encrypted, with which "
                "algorithm, and whether its keystore is open are not known. Encryption "
                "measured on servers' disks does not answer this, and the absence of an "
                "answer is not evidence that the databases are unencrypted."),
        harvest=("A database administrator runs the query in docs/COLLECTORS.md "
                 "(`oracle_tde`) on each database, saves the result as CSV and names the "
                 "file as the reader's input."),
        nature=coverage.NO_DATA)


#: The declaration. It names no default input: with none given in the
#: profile, the step still runs and records what is missing in its own gap.
PLUGIN = Plugin(
    name=NAME, kind="database-encryption", step=read,
    title="Oracle Transparent Data Encryption keystore and tablespace export",
    gap_prefix=False)
