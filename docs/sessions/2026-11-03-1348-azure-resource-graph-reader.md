# 2026-11-03 — An Azure Resource Graph reader in the readers library

## What was done

- **`takestock.readers`** gains `azure_resource_graph` (`general`, no
  default input). It reads a CSV of Azure Resource Graph results over five
  resource types and writes:
  - one at-rest row per storage account, managed disk and snapshot, graded
    `strong` when the key source or encryption type is one Microsoft
    documents, with the custody as a `key-custody:` flag;
  - a second row per storage account for its configured TLS floor
    (`protocol: tls`), graded by the baseline's TLS version table; a floor
    not set is graded as TLS 1.0, which Microsoft documents an unset floor
    to permit (Microsoft also says Azure Storage itself supports only TLS 1.2
    and 1.3, so the row records the setting, not what the service
    negotiates);
  - a Recovery Services vault row, `unknown` and `not-assessed:`, since the
    query reads no encryption property for that type;
  - a key vault row, `n/a`, flagged when access policies rather than Azure
    RBAC authorise access;
  - an `unknown` row for any other type, and a scope row by type and
    subscription.
  Settings: `subscriptions` (a second export listing the subscriptions),
  `columns` (other headings for any field) and `disk_name_shapes` (regular
  expressions that split a long disk name into machine, role and suffix).
  An export read always raises one gap: databases are not among the types
  queried.
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: the reader's section, with the two Resource Graph
  queries (written from Microsoft's resource reference, not run), the
  fields and their default headings, the rows, and the Microsoft pages the
  grades rest on; and the library table row.
- Changelog.

Sources read on 4 November 2026 (New Zealand time), on learn.microsoft.com:
the resource reference pages for `Microsoft.Storage/storageAccounts`,
`Microsoft.Compute/disks`, `Microsoft.Compute/snapshots` and
`Microsoft.KeyVault/vaults`; *Enforce a minimum required version of
Transport Layer Security (TLS)* for Azure Storage; *Azure Storage encryption
for data at rest*;
*Server-side encryption of Azure managed disks*; *Firewall rules and network
access for Azure Blob, Data Lake, Queue, and Table Storage*; *Remediate
anonymous read access to blob data*; *Azure role-based access control (Azure
RBAC) vs. access policies*; and *Overview of Azure Resource Graph*.

## Checks

- Tests on exports composed in the tests (made-up resource names,
  `00000000-0000-4000-8000-…` subscription IDs, file dates in 2030).
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the two queries against a test subscription and compare the download's
  headings and value spellings (`true`/`True`, blank or `null`) with the
  reader's.
- The query reads no encryption property for Recovery Services vaults or
  databases; a reader for those would need properties this query does not
  project.
