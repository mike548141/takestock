"""Azure Resource Graph: stored-data encryption, storage TLS floors and exposure settings.

**The input** is a CSV of Azure Resource Graph query results, one row per
resource, downloaded from Resource Graph Explorer in the Azure portal.
``docs/COLLECTORS.md`` gives a query that writes it. The reader places five
resource types: storage accounts, managed disks, disk snapshots, Recovery
Services vaults (where Azure Backup keeps its copies) and key vaults. It
reads these fields, under the column headings in :data:`HEADINGS` by default
(the column names the query in ``docs/COLLECTORS.md`` projects, mostly
Microsoft's property names):

==========================  =============================================
field                       what it holds
==========================  =============================================
``name``, ``type``          the resource's name and type
``subscription``            the subscription's ID
``tls_floor``               a storage account's ``minimumTlsVersion``
``https_only``              a storage account's ``supportsHttpsTrafficOnly``
``public_network``          the resource's ``publicNetworkAccess``
``anonymous_blob``          a storage account's ``allowBlobPublicAccess``
``key_source``              a storage account's ``encryption.keySource``
``disk_encryption``         a disk's or snapshot's ``encryption.type``
``disk_encryption_set``     a disk's or snapshot's ``encryption.diskEncryptionSetId``
``rbac``                    a key vault's ``enableRbacAuthorization``
==========================  =============================================

An export written with other headings is read by naming them:
``settings: {columns: {tls_floor: <heading>, ...}}``. Headings match ignoring
case, spaces and hyphens. A cell that is blank, or holds the text ``null``,
is read as not set. (Microsoft's page on remediating anonymous read access
says a storage account's anonymous access property that is not set "appears
as blank (or null)" in Resource Graph results; the reader reads every column
that way.)

``settings: {subscriptions: <file>}`` names a second export listing the
subscriptions (``name``, ``subscriptionId``). With it, rows carry the
subscription's name, and the scope row says whether every listed
subscription contributed a row. It may be a path or a pattern; for a pattern
the last file in name order is read.

**A storage account gives two rows**, because the export answers two
questions about it. At rest: whose key encrypts the stored data
(``keySource``). In transit: the oldest TLS version its endpoints accept.
The second row has ``protocol: tls`` and the floor as its version, so the
baseline grades it from the same TLS version table as any other TLS floor.
Its notes say it is a configured setting read from Azure, not a handshake
observed.

**Grades.**

* Storage account, disk and snapshot, at rest: ``strong`` when the key source
  or encryption type is one Microsoft documents, with the custody as a flag
  (``key-custody:platform-managed``, ``customer-managed`` or
  ``platform-and-customer``). Microsoft documents Azure Storage encryption,
  which cannot be switched off, and managed disk encryption as 256-bit AES
  (:data:`STORAGE_ENCRYPTION_URL`, :data:`DISK_ENCRYPTION_URL`); the export
  carries the key source, not the cipher. Any other value: ``unknown``, with
  ``ungraded:storage-key-source:<value>`` or
  ``ungraded:disk-encryption-type:<value>``.
* Storage account TLS floor: the configured minimum, graded by the
  baseline. A floor not set is graded as TLS 1.0 and flagged
  ``tls-floor-unset``: Microsoft's resource reference gives TLS 1.0 as the
  property's "default interpretation", and its page on enforcing a minimum
  TLS version (:data:`STORAGE_TLS_URL`) says an account "permits requests
  sent with TLS version 1.0 or greater if the property isn't set". The same
  page says Azure Storage itself supports only TLS 1.2 and 1.3, so the row
  records the configured floor and its documented meaning, not what the
  service negotiates. ``supportsHttpsTrafficOnly`` false adds
  ``https-only-off``.
* Recovery Services vault: ``unknown``, flagged
  ``not-assessed:backup-vault-encryption``. The query projects no encryption
  property for this type, so the row records that the vault exists and that
  its encryption was not read, never that it is unencrypted.
* Key vault: ``n/a``, since it holds keys rather than being encrypted by one.
  ``enableRbacAuthorization`` false is flagged
  ``kv-access-policy-authorisation``: Microsoft calls the access policy model
  "a legacy authorization system" and Azure RBAC "the recommended
  authorization system for the Azure Key Vault data plane"
  (:data:`KEY_VAULT_RBAC_URL`). Not set is flagged
  ``not-assessed:key-vault-authorisation``.
* Any other resource type: one ``unknown`` row, flagged
  ``ungraded:azure-resource-type:<type>``, recorded rather than dropped.

**Exposure flags on a storage account.** ``allowBlobPublicAccess`` true is
flagged ``blob-public-access``: any container in the account may then be set
for anonymous access, and "When a container is configured for anonymous
access, any client can read data in that container"
(:data:`ANONYMOUS_ACCESS_URL`). ``publicNetworkAccess`` ``Enabled`` is
flagged ``public-network-access:enabled``; not set is flagged
``public-network-access:unset``, because "By default, storage accounts allow
connections from any network" (:data:`STORAGE_NETWORK_URL`) unless network
rules restrict them, and the export does not carry the rules. Any other
value (``Disabled``, ``SecuredByPerimeter``) is recorded in ``extra``
without a flag. On a disk or snapshot, ``publicNetworkAccess`` is Microsoft's
"Policy for controlling export on the disk" (:data:`DISK_REFERENCE_URL`), so
it is recorded in ``extra`` and never graded.

**Disk names.** ``settings: {disk_name_shapes: [<pattern>, ...]}`` names
regular expressions, each with the named groups ``machine``, ``role`` and
``uid``. A disk or snapshot whose name matches one in full is shown with
those three parts separated by spaces, and each part is kept in ``extra``
(``azure_disk_machine``, ``azure_disk_role``, ``azure_disk_uid``), so the
name as Azure holds it can be rebuilt. A long name that joins words, digits
and a hexadecimal suffix can read to a secret scanner as a credential; split
into its parts, it is less likely to. With no shapes named, names are shown
as they are.

**Scope row.** One per export, ``n/a``, flagged ``scope-queried-types-only``:
how many resources of each type, in which subscriptions, whether every
listed subscription contributed a row, and the export's file date (the
export has no date column).

**Coverage gaps.** No export read: one gap. An export read: one gap saying
that databases (and their transparent data encryption) are not among the
types queried, so the storage answer is not the database answer.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

from .. import coverage, roles
from ..model import CryptoAsset, register_informational_prefixes
from ..plugins import Context, Plugin, StepResult
from ..util import file_mtime_date
from . import _entra, _table

#: The plug-in's name, and so the ``source`` of every row it writes.
NAME = "azure_resource_graph"

STORAGE_ENCRYPTION_URL = (
    "https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption")
DISK_ENCRYPTION_URL = "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption"
KEY_VAULT_RBAC_URL = (
    "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy")
ANONYMOUS_ACCESS_URL = (
    "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent")
STORAGE_NETWORK_URL = (
    "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security")
STORAGE_TLS_URL = ("https://learn.microsoft.com/en-us/azure/storage/common/"
                   "transport-layer-security-configure-minimum-version")
STORAGE_REFERENCE_URL = (
    "https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts")
DISK_REFERENCE_URL = "https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/disks"

SCOPE_FLAG = "scope-queried-types-only"
CUSTODY = "key-custody:"
BLOB_PUBLIC_FLAG = "blob-public-access"
NETWORK_ENABLED_FLAG = "public-network-access:enabled"
NETWORK_UNSET_FLAG = "public-network-access:unset"
HTTPS_OFF_FLAG = "https-only-off"
TLS_FLOOR_UNSET_FLAG = "tls-floor-unset"
ACCESS_POLICY_FLAG = "kv-access-policy-authorisation"
VAULT_NOT_ASSESSED = "not-assessed:backup-vault-encryption"
KEY_VAULT_NOT_ASSESSED = "not-assessed:key-vault-authorisation"

register_informational_prefixes(SCOPE_FLAG, "not-assessed:", f"{CUSTODY}customer-managed",
                                f"{CUSTODY}platform-and-customer")

#: Each field and the column heading it is read from unless ``settings: columns:`` names another.
HEADINGS: dict[str, str] = {
    "name": "name",
    "type": "type",
    "subscription": "subscriptionId",
    "tls_floor": "minimumTlsVersion",
    "https_only": "supportsHttpsTrafficOnly",
    "public_network": "publicNetworkAccess",
    "anonymous_blob": "allowBlobPublicAccess",
    "key_source": "keySource",
    "disk_encryption": "encryptionType",
    "disk_encryption_set": "diskEncryptionSetId",
    "rbac": "enableRbacAuthorization",
}

STORAGE, DISK, SNAPSHOT, BACKUP_VAULT, KEY_VAULT = (
    "storage account", "managed disk", "disk snapshot", "backup vault", "key vault")

#: Resource types, as Resource Graph writes them in lower case, and the kind each is read as.
KINDS = {
    "microsoft.storage/storageaccounts": STORAGE,
    "microsoft.compute/disks": DISK,
    "microsoft.compute/snapshots": SNAPSHOT,
    "microsoft.recoveryservices/vaults": BACKUP_VAULT,
    "microsoft.keyvault/vaults": KEY_VAULT,
}

#: ``encryption.keySource`` on a storage account (Microsoft's values, matched ignoring case).
KEY_SOURCES = {"microsoft.storage": "platform-managed", "microsoft.keyvault": "customer-managed"}

#: ``encryption.type`` on a managed disk or snapshot (Microsoft's values, matched ignoring case).
DISK_ENCRYPTION_TYPES = {
    "encryptionatrestwithplatformkey": "platform-managed",
    "encryptionatrestwithcustomerkey": "customer-managed",
    "encryptionatrestwithplatformandcustomerkeys": "platform-and-customer",
}

#: How each custody reads in a row's notes.
CUSTODY_WORDS = {"platform-managed": "a platform-managed key",
                 "customer-managed": "a customer-managed key",
                 "platform-and-customer": "two layers, one under a platform-managed key and one "
                                          "under a customer-managed key"}

#: ``minimumTlsVersion`` values, and the baseline's names for them.
TLS_FLOORS = {"tls1_0": "TLSv1.0", "tls1_1": "TLSv1.1", "tls1_2": "TLSv1.2",
              "tls1_3": "TLSv1.3"}
#: The floor a storage account has when the property is not set (Microsoft's resource reference).
UNSET_TLS_FLOOR = "TLSv1.0"
_OLD_FLOORS = {"tlsv1.0", "tlsv1.1"}

#: The ``extra`` note for a storage account whose public network access is not set.
NETWORK_UNSET_NOTE = ("unset (platform default admits public traffic unless network rules "
                      "restrict; network rules not in export)")
#: The ``extra`` note beside a disk's or snapshot's public network access value.
DISK_EXPORT_NOTE = "governs the disk-export data path, not general readability"

_DISK_GROUPS = ("machine", "role", "uid")


# ── reading ──

def _headings(ctx: Context) -> dict[str, str]:
    named = (ctx.settings or {}).get("columns") or {}
    out = dict(HEADINGS)
    if isinstance(named, dict):
        for field, heading in named.items():
            if field in out and isinstance(heading, str) and heading.strip():
                out[field] = heading
    return out


def _cell(row: dict[str, str], heading: str) -> str:
    """The cell under ``heading``, with blank and the text ``null`` both read as not set."""
    v = _table.value(row, heading).strip()
    return "" if v.lower() == "null" else v


def _flag(v: str) -> bool | None:
    low = v.lower()
    return True if low == "true" else False if low == "false" else None


def disk_shapes(ctx: Context) -> tuple[list[re.Pattern[str]], list[str]]:
    """The usable ``disk_name_shapes`` patterns, and those that could not be used."""
    raw = (ctx.settings or {}).get("disk_name_shapes") or []
    if isinstance(raw, str):
        raw = [raw]
    usable: list[re.Pattern[str]] = []
    unusable: list[str] = []
    for shape in raw:
        try:
            rx = re.compile(str(shape))
        except re.error:
            unusable.append(str(shape))
            continue
        if all(g in rx.groupindex for g in _DISK_GROUPS):
            usable.append(rx)
        else:
            unusable.append(str(shape))
    return usable, unusable


def split_disk_name(name: str, shapes: list[re.Pattern[str]]) -> tuple[str, str, str] | None:
    """(machine, role, uid) from the first shape matching ``name`` in full, or None."""
    for rx in shapes:
        m = rx.fullmatch(name)
        if m:
            machine, role, uid = (m.group(g) for g in _DISK_GROUPS)
            return machine, role, uid
    return None


def _subscriptions(path: Path | None) -> dict[str, str]:
    """Subscription ID → name from the companion export; empty when none was read."""
    if path is None or not path.exists():
        return {}
    try:
        rows = _table.read(path)
    except (OSError, UnicodeDecodeError, csv.Error):
        return {}
    out: dict[str, str] = {}
    for r in rows:
        sid = _table.value(r, "subscriptionId").strip()
        if sid:
            out[sid] = _table.value(r, "name").strip()
    return out


def _missing_gap(why: str) -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "no Azure Resource Graph export of storage, disk and vault encryption settings was "
        "read: whose key encrypts each storage account, disk and snapshot, each storage "
        "account's TLS floor, and whether any storage is open to anonymous or public access"
        + (f"; {why}" if why else ""),
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("Without it, whether the Azure resources that hold data are encrypted, under "
                "whose key, and whether any storage can be reached from the internet or read "
                "anonymously are all unmeasured, not absent."),
        harvest=("Run the Resource Graph query in docs/COLLECTORS.md (section "
                 "azure_resource_graph), download the results as CSV, and name the file in "
                 "the profile."),
        nature=coverage.NO_DATA)


def _database_gap() -> str:
    return coverage.gap(
        coverage.NOT_COLLECTED,
        "Azure databases' transparent data encryption: the Resource Graph export covers "
        "storage accounts, managed disks, snapshots, Recovery Services vaults and key vaults, "
        "and no database, so no Azure database has a stored-data reading",
        impact_kind=coverage.CHANGES_CONCLUSION,
        impact=("The export answers stored-data encryption for storage, disks and snapshots, "
                "and a reader may take that as the answer for the cloud as a whole. Whether "
                "each database's data is encrypted, and under whose key, is not in it."),
        harvest=("Each database's transparent data encryption state and key source, from the "
                 "Azure portal, the Azure CLI or a database administrator."),
        nature=coverage.NO_DATA)


# ── rows ──

def _storage_rows(name: str, cell: dict[str, str], base: dict, extra: dict[str, str],
                  tally: dict) -> list[CryptoAsset]:
    flags: list[str] = []
    key_raw = cell["key_source"]
    custody = KEY_SOURCES.get(key_raw.lower(), "")
    if custody:
        verdict = "strong"
        flags.append(CUSTODY + custody)
        tally["custody"][custody] += 1
        note = (f"The stored data is encrypted under {CUSTODY_WORDS[custody]} "
                f"(key source {key_raw}). Microsoft documents Azure Storage encryption as "
                "256-bit AES that cannot be switched off; the export carries the key source, "
                "not the cipher.")
    else:
        verdict = "unknown"
        flags.append(f"ungraded:storage-key-source:{key_raw or 'blank'}")
        note = (f"The export gives the key source as {key_raw or '(blank)'!r}, which is not "
                "one of the values Microsoft documents, so the row is left ungraded.")
    if _flag(cell["anonymous_blob"]) is True:
        flags.append(BLOB_PUBLIC_FLAG)
        tally["blob_public"] += 1
        note += (" Anonymous read access is allowed on this account, so any container in it "
                 "can be set so that anyone can read it with no credential.")
    public = cell["public_network"]
    if public.lower() == "enabled":
        flags.append(NETWORK_ENABLED_FLAG)
        tally["net_open"] += 1
        extra["public_network_access"] = "Enabled"
    elif public.lower() == "disabled":
        extra["public_network_access"] = "Disabled"
    elif not public:
        flags.append(NETWORK_UNSET_FLAG)
        tally["net_unset"] += 1
        extra["public_network_access"] = NETWORK_UNSET_NOTE
    else:
        extra["public_network_access"] = public
    rows = [CryptoAsset(
        name=f"Azure storage account {name}", data_state="at-rest", protocol="azure-storage",
        role=roles.cloud_resource_encryption(STORAGE, name), verdict=verdict, flags=flags,
        notes=note, extra=dict(extra), **base)]

    floor_raw = cell["tls_floor"]
    tflags: list[str] = []
    if floor_raw:
        floor = TLS_FLOORS.get(floor_raw.lower(), floor_raw)
        floor_text = (f"The account's configured minimum TLS version is {floor}; Microsoft says "
                      "a request using an older version fails.")
    else:
        floor = UNSET_TLS_FLOOR
        tflags.append(TLS_FLOOR_UNSET_FLAG)
        floor_text = ("The account's minimum TLS version is not set. Microsoft documents an "
                      "unset value as permitting requests with TLS 1.0 or later, so the floor "
                      f"is graded as {floor}.")
    https = _flag(cell["https_only"])
    if https is False:
        tflags.append(HTTPS_OFF_FLAG)
        https_text = " It also accepts plain HTTP: HTTPS-only is off."
    elif https is True:
        https_text = " HTTPS-only is on, so plain HTTP is refused."
    else:
        https_text = (" Whether it refuses plain HTTP is not in the export (Microsoft gives "
                      "HTTPS-only as the default since API version 2019-04-01).")
    if floor.lower() in _OLD_FLOORS:
        tally["floor_below"] += 1
    rows.append(CryptoAsset(
        name=f"Azure storage account {name} TLS floor", data_state="in-transit", protocol="tls",
        role=roles.cloud_storage_tls_floor(name), protocol_versions=[floor], flags=tflags,
        notes=(floor_text + https_text + " Microsoft also says Azure Storage itself supports "
               "only TLS 1.2 and 1.3. This row is the configured setting read from Azure, not "
               "a handshake observed."),
        extra=dict(extra), **base))
    return rows


def _disk_row(name: str, kind: str, cell: dict[str, str], base: dict, extra: dict[str, str],
              tally: dict, shapes: list[re.Pattern[str]]) -> CryptoAsset:
    flags: list[str] = []
    enc_raw = cell["disk_encryption"]
    custody = DISK_ENCRYPTION_TYPES.get(enc_raw.lower(), "")
    if custody:
        verdict = "strong"
        flags.append(CUSTODY + custody)
        tally["custody"][custody] += 1
        note = (f"Encrypted at rest under {CUSTODY_WORDS[custody]} ({enc_raw}). Microsoft documents "
                "the data in managed disks as encrypted with 256-bit AES.")
        if kind == SNAPSHOT:
            note += (" A snapshot carries its own encryption setting, and this one was read "
                     "from the snapshot itself, not assumed from its source disk.")
    else:
        verdict = "unknown"
        flags.append(f"ungraded:disk-encryption-type:{enc_raw or 'blank'}")
        note = (f"The export gives the encryption type as {enc_raw or '(blank)'!r}, which is "
                "not one of the values Microsoft documents, so the row is left ungraded.")
    if cell["disk_encryption_set"]:
        extra["disk_encryption_set"] = cell["disk_encryption_set"]
    if cell["public_network"]:
        extra["public_network_access"] = f"{cell['public_network']} ({DISK_EXPORT_NOTE})"
    parts = split_disk_name(name, shapes)
    display = name
    if parts:
        display = " ".join(parts)
        extra["azure_disk_machine"], extra["azure_disk_role"], extra["azure_disk_uid"] = parts
    return CryptoAsset(
        name=f"Azure {kind} {display}", data_state="at-rest", protocol="azure-disk",
        role=roles.cloud_resource_encryption(kind, display), verdict=verdict, flags=flags,
        notes=note, extra=dict(extra), **base)


def _vault_row(name: str, cell: dict[str, str], base: dict, extra: dict[str, str]) -> CryptoAsset:
    if cell["public_network"]:
        extra["public_network_access"] = cell["public_network"]
    return CryptoAsset(
        name=f"Azure backup vault {name}", data_state="at-rest", protocol="azure-backup",
        role=roles.cloud_resource_encryption(BACKUP_VAULT, name), verdict="unknown",
        flags=[VAULT_NOT_ASSESSED],
        notes=("The query projects no encryption property for a Recovery Services vault, so "
               "how its backup copies are encrypted, and under whose key, was not read. Not "
               "measured, which is not the same as not encrypted."),
        extra=dict(extra), **base)


def _key_vault_row(name: str, cell: dict[str, str], base: dict,
                   extra: dict[str, str]) -> CryptoAsset:
    rbac = _flag(cell["rbac"])
    flags: list[str] = []
    if rbac is False:
        flags.append(ACCESS_POLICY_FLAG)
        note = ("Access to the keys, secrets and certificates in this vault is authorised by "
                "access policies, which Microsoft calls a legacy authorisation system; Azure "
                "RBAC, the model Microsoft recommends for the vault's data, is off. Who holds "
                "the access policies is not in the export.")
    elif rbac is True:
        note = ("Access to the keys, secrets and certificates in this vault is authorised by "
                "Azure RBAC, the model Microsoft recommends. Who holds the roles is not in the "
                "export.")
    else:
        flags.append(KEY_VAULT_NOT_ASSESSED)
        note = ("The export gives no value for how access to this vault's contents is "
                "authorised, so neither model is assumed.")
    if cell["public_network"]:
        extra["public_network_access"] = cell["public_network"]
    return CryptoAsset(
        name=f"Azure key vault {name}", data_state="key-material", protocol="azure-keyvault",
        role=roles.cloud_resource_encryption(KEY_VAULT, name), verdict="n/a", flags=flags,
        notes=note, extra=dict(extra), **base)


def _scope_row(base: dict, kinds: Counter[str], subs_seen: Counter[str], subs: dict[str, str],
               tally: dict, unusable: list[str], when: str) -> CryptoAsset:
    n = sum(kinds.values())
    kinds_text = ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items()))
    subs_text = ", ".join(f"{s or 'subscription not given'}: {v}"
                          for s, v in sorted(subs_seen.items()))
    listed = set(subs.values())
    if subs and listed <= set(subs_seen):
        tenant = (f"The subscription list read with it names {len(subs)} subscription(s), and "
                  "every one contributed rows, so for the types queried these rows cover every "
                  "listed subscription as at the export's date.")
    elif subs:
        missing = sorted(listed - set(subs_seen))
        tenant = (f"The subscription list read with it names {len(subs)} subscription(s); "
                  f"{len(missing)} of them ({', '.join(missing)}) contributed no row (each "
                  "holds none of the queried types, or was not read).")
    else:
        tenant = ("No subscription list was read with it, so whether these subscriptions are "
                  "all there are is not known.")
    notes = (f"{n} Azure resource(s) were read ({kinds_text}), in {len(subs_seen)} "
             f"subscription(s) ({subs_text}). {tenant} The export has no date column, so it is "
             f"dated by its file date ({when or 'unavailable'}). The query covers storage "
             "accounts, managed disks, snapshots, Recovery Services vaults and key vaults "
             "only: databases, for example, are not in it, and a separate gap says so.")
    if unusable:
        notes += (f" {len(unusable)} disk name shape(s) in the settings could not be used (not "
                  "a regular expression, or without the groups machine, role and uid), so "
                  "they were ignored.")
    return CryptoAsset(
        name="Azure resource-graph encryption scope", data_state="at-rest",
        protocol="azure-at-rest", role=roles.cloud_resource_scope(), verdict="n/a",
        flags=[SCOPE_FLAG], hosts_count=n, notes=notes,
        extra={"rows": str(n),
               "subscriptions_in_rows": str(len(subs_seen)),
               "subscriptions_listed": str(len(subs)) if subs else "not supplied",
               "storage_tls_floor_below_TLSv1.2": str(tally["floor_below"]),
               "public_network_access_enabled_storage": str(tally["net_open"]),
               "public_network_access_unset_storage": str(tally["net_unset"]),
               "blob_public_access_accounts": str(tally["blob_public"]),
               **{f"key_custody_{k.replace('-', '_')}": str(v)
                  for k, v in sorted(tally["custody"].items())}},
        **base)


def read(path: Path, *, subscriptions: Path | None = None, headings: dict[str, str] | None = None,
         shapes: list[re.Pattern[str]] | None = None,
         unusable_shapes: list[str] | None = None) -> tuple[list[CryptoAsset], list[str]]:
    """The rows and gaps for one export."""
    if not path.exists():
        return [], [_missing_gap("")]
    try:
        rows = _table.read(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        return [], [_missing_gap(f"the file named could not be read ({exc})")]
    if not rows:
        return [], [_missing_gap("the file named holds no rows")]
    heads = headings or HEADINGS
    when = file_mtime_date(path) or ""
    base: dict = {"source": NAME, "source_class": "private", "collected_at": when,
            "source_name": ("Azure Resource Graph export, "
                            + (f"file dated {when}" if when else "file date unavailable"))}
    subs = _subscriptions(subscriptions)
    tally: dict = {"custody": Counter(), "floor_below": 0, "net_open": 0, "net_unset": 0,
                   "blob_public": 0}
    kinds: Counter[str] = Counter()
    subs_seen: Counter[str] = Counter()
    out: list[CryptoAsset] = []
    for r in rows:
        cell = {field: _cell(r, heading) for field, heading in heads.items()}
        name = cell["name"]
        if not name:
            continue
        rtype = cell["type"].lower()
        kind = KINDS.get(rtype, "")
        sub = subs.get(cell["subscription"], cell["subscription"])
        subs_seen[sub] += 1
        kinds[kind or rtype] += 1
        extra: dict[str, str] = {"resource_type": rtype, "subscription": sub}
        if kind == STORAGE:
            out.extend(_storage_rows(name, cell, base, extra, tally))
        elif kind in (DISK, SNAPSHOT):
            out.append(_disk_row(name, kind, cell, base, extra, tally, shapes or []))
        elif kind == BACKUP_VAULT:
            out.append(_vault_row(name, cell, base, extra))
        elif kind == KEY_VAULT:
            out.append(_key_vault_row(name, cell, base, extra))
        else:
            out.append(CryptoAsset(
                name=f"Azure resource {name}", data_state="at-rest", protocol="azure-at-rest",
                verdict="unknown", flags=[f"ungraded:azure-resource-type:{rtype}"],
                notes=(f"The export holds a resource of type {rtype or '(blank)'}, which this "
                       "reader does not place. Recorded rather than dropped."),
                extra=extra, **base))
    out.append(_scope_row(base, kinds, subs_seen, subs, tally, unusable_shapes or [], when))
    return out, [_database_gap()]


def step(ctx: Context) -> StepResult:
    """The plug-in's step: the export's rows and its gap, or a gap saying none was read."""
    if ctx.input is None:
        return StepResult(gaps=[_missing_gap("")])
    shapes, unusable = disk_shapes(ctx)
    assets, gaps = read(ctx.input, subscriptions=_entra.newest(ctx, "subscriptions"),
                        headings=_headings(ctx), shapes=shapes, unusable_shapes=unusable)
    return StepResult(records=assets, gaps=gaps)


#: The declaration. It names no default input: with none given, the step
#: still runs and records what is missing in its own gap.
PLUGIN = Plugin(name=NAME, kind="general", step=step,
                title="Azure Resource Graph export of storage, disk and vault encryption settings",
                gap_prefix=False)
