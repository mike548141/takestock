# 2026-10-17 — Oracle TDE and Commvault readers

## What was done

- **`oracle_tde`**, in `readers/oracle_tde.py`, kind `database-encryption`:
  a CSV export of Oracle Database's Transparent Data Encryption state, one
  row per database, written from Oracle Database Reference's documentation
  of `V$ENCRYPTION_WALLET` and `V$ENCRYPTED_TABLESPACES`. A database is
  graded `weak` when its keystore is missing, closed or in another state
  that is not open, or when it is open and no tablespace is encrypted.
  Otherwise each algorithm is graded from the baseline; every AES key
  length as the unsized `aes_cbc`, because the view names no mode and the
  documented modes differ by release. Partial roll-outs and key custody are
  flagged. `docs/COLLECTORS.md` gives a query that writes the columns.
- **`commvault`**, in `readers/commvault.py`, kind `backup-encryption`: a
  CSV of storage policy copies' software encryption, in columns named after
  the console's fields, since no published report is documented to carry
  them. Ciphers and key lengths are those of Commvault's supported
  algorithms page. Encryption off, or recorded as neither on nor off, is
  `weak`; AES-256 is graded as `aes256_cbc`; a cipher the baseline does not
  grade is flagged `ungraded:` and left `unknown`. Key custody is flagged.
- **A shared CSV helper**, `readers/_table.py`: headings matched without
  regard to case, spaces or hyphens; a byte-order mark ignored; rows with no
  value skipped.
- Both readers name no default input. With none given they still run, and
  their own gap says no export was read.
- **Roles**: `database_encryption`, `backup_encryption`.
- **Docs**: both readers in the readers library table and their own
  sections in `COLLECTORS.md`; the changelog.

## Checks

- Fixtures written by hand: `tests/fixtures/oracle_tde/example-tde.csv`
  (the query's columns, with the values Oracle documents for the views) and
  `tests/fixtures/commvault/example-backup-encryption.csv` (a stub with the
  reader's columns only, said so in its test). All names are synthetic.
- New tests: every graded state and flag of both fixtures, the cipher names,
  the AES grading, headings in other forms, the three ways nothing is read,
  each row against its kind's constraints, and the declarations. Each test
  was seen to fail with the behaviour it checks changed.
- `make check`: guard, ruff, mypy and the full test suite.
- The Oracle query was written from the documentation and has not been run
  against a database.

## Left to do

- More readers for the library, one product or format at a time.
