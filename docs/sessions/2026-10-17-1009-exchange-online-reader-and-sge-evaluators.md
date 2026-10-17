# 2026-10-17 — Exchange Online reader and three SGE evaluators

## What was done

- **`exchange_online`**, in `readers/exchange_online.py`, kind `general`:
  reads the folder or zip that a new read-only PowerShell script, published
  in `docs/EXCHANGE-ONLINE-EXPORT.md`, writes (one
  `<cmdlet>.json` per `Get-*` cmdlet, and a `manifest.json` of counts and
  errors). Each file is found through the manifest's `command` and `file`
  entries, falling back to `<cmdlet>.json`. One `n/a` row per object read,
  protocol `mail-policy`, with the properties the evaluators need in
  `extra`, and a scope row. A failed cmdlet is a could-not-test gap, a
  missing one a not-collected gap.
- **The script** was written from the cmdlets' Microsoft Learn pages. Nine
  Exchange Online cmdlets by default; `-IncludeDlp` adds the mail flow rules
  and four Security & Compliance cmdlets, marked in the script and the docs
  as not yet read by takestock, and as needing Windows because Microsoft
  documents `Connect-IPPSSession` as unavailable in PowerShell 7 on Linux
  and macOS.
- **SGE evaluators** for SGE-DMARC-02, SGE-DMARC-R04 and SGE-DKIM-01, one
  row per domain, under a new `measurable` value, `inside-export`: graded
  when the observation holds the reader's rows, `no-instrument` otherwise.
  What the settings mean (which policy governs whom, whether a route lets
  the platform honour DMARC, the actions and quarantine policy in effect,
  whether a domain is signed) is decided in the reader module, each answer
  quoting the Microsoft sentence it rests on.
- **Reading decisions**, each documented in `COLLECTORS.md` and tested:
  a failing policy behind a rule that names users or groups leaves the row
  unsettled, since group membership is not exported; Enhanced Filtering
  counts only on an enabled connector, for every recipient, whose sender
  certificate name covers the MX host (addresses are not resolved, so a
  connector matched only by address is unsettled); where the route does not
  apply the DMARC setting, the spoof intelligence action is taken as the one
  in effect; a quarantine policy that lets recipients only request release
  meets SGE-DMARC-R04, because an administrator still releases; a domain
  with signing off fails SGE-DKIM-01 only where the profile or its SPF
  record shows it sends mail; any enabled outbound connector to smart hosts
  leaves the domain unsettled, signed or not, because the DKIM guide asks
  for signing at the last hop, which this reading cannot see.
- `mail-policy` joins the protocols that carry no cryptography.
- Two Microsoft 365 MX host endings are on the guard's allow list, with the
  page they come from.
- **The script is published inside a document**, as `COLLECTORS.md` already
  carries the Oracle query, so it travels with the documentation.
- **Docs**: `EXCHANGE-ONLINE-EXPORT.md` (new: how to run the script, and
  the script), `COLLECTORS.md` (the reader, its table row, how each
  requirement is decided, pages read), `SGE-NOTE.md`,
  `SECURE-GOVERNMENT-EMAIL.md`, the changelog.

## Checks

- The fixture, `tests/fixtures/exchange_online/example-widgets/`, was
  written by hand to the script's shape, with properties the cmdlet pages
  document; every name and address is synthetic. The evaluator tests build
  one small export per case.
- Each new test was seen to fail with the line it guards broken.
- `make check`: guard, ruff, mypy and the full test suite.
- The script has not been run here: no PowerShell is installed, and no
  tenant was used.

## Left to do

- A reader for the `-IncludeDlp` half, for the data loss prevention and
  keyword blocking requirements.
- Readers for other mail platforms' settings, for the same three
  requirements.
