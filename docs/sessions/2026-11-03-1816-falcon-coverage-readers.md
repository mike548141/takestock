# 2026-11-03 — CrowdStrike Falcon drive encryption and coverage readers

## What was done

- **`takestock.readers`** gains two readers (`general`, no default input)
  and one annotation:
  - `falcon_disk_encryption`: a drive encryption export, one row per machine
    row, graded from the status (compared whole, never by a word inside it)
    and the volume counts; partly encrypted machines flagged. With
    `settings: escrow:` naming the `m365_bitlocker` reader's main export,
    the machines it names are left to that reader (its existing
    `escrowed_devices()`), so a machine's at-rest state is reported once, and
    every machine kept here is flagged `key-custody-unknown`.
  - `falcon_estate_coverage`: the sensor-managed host list against every
    asset discovery reports, with discovered vendors, sensor versions,
    criticality, reduced functionality mode, quiet sensors and devices that
    cannot take the sensor, each further list named in `settings:`; and an
    environment row when `settings: environment:` names words.
  - `falcon_environment`: an `annotation` plug-in putting each machine's
    environment label on the other readers' rows (`extra.environment`, the
    key takestock's configuration register already reads), from the same
    words. The plug-in contract's annotation kind carries it; nothing in the
    host changed.
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: a shared section with the public source of each name,
  a section per reader with the heartbeat query, and the library table rows.
  Changelog.

Sources read on 4 November 2026 (New Zealand time): `elastic/integrations`
on GitHub, `packages/crowdstrike` (the sample host record, the FDR sample
`SensorHeartbeat` events and the event categorisation); the LogScale
documentation (*Event Fields*, `groupBy()`, `count()`, `selectLast()`).

Choices worth recording:

- No public description of the console's drive encryption, discovered asset
  and unsupported asset lists was found, so their default headings are plain
  names of takestock's own. The API host record's `groups` holds group IDs,
  not names, so the host groups default is takestock's own too.
- No public CrowdStrike description of reduced functionality mode was found,
  so the rows say only that such a machine counts as covered.
- Values whose meaning no public source gave have no default meaning: the
  criticality word for unset, the review status for not yet reviewed, and
  the environment words. Without them the reader counts nothing as unset or
  reviewed, and writes no environment row or label.
- A machine in host groups on both sides resolves to production and is
  marked contested, since labelling a live machine non-production would
  move it down a remediation queue.

## Checks

- Tests on exports composed in the tests (made-up machines, sensor IDs,
  groups, makers, and dates in 2030). Ten mutations of the new code each
  turned a test red (two only after a test was added for them); every
  mutated file was restored and compared byte for byte.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the heartbeat query against a tenant and compare its columns with the
  reader's defaults.
- Find a public description of the console's list headings and of reduced
  functionality mode.
