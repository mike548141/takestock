# 2026-10-21 — A maker table setting for `vsphere_lists`

## What was done

- **`vsphere_lists`** takes `settings: {makers: <csv>}`: a table of device
  maker prefixes with columns `prefix`, `maker` and, optionally, `array`,
  merged over the bundled `ARRAY_MAKERS` and `DEVICE_MAKERS`. A row names
  its prefix's maker in the datastore notes, replacing any bundled name;
  `array` (`yes`, `true`, `y` or `1`; `no`, `false`, `n` or `0`) moves the
  prefix between the array and the inside-a-host tables, and left blank
  keeps a bundled prefix's placement.
  A prefix may be written with `:` or `-` between pairs and in either case.
- Rows that cannot be used (not a six-digit prefix, no maker, an `array`
  value not among those above) are listed in a coverage gap and left out; a
  table that cannot be read, or whose heading row lacks `prefix` or
  `maker`, is a coverage gap, and the bundled tables serve alone.
- `COLLECTORS.md` describes the setting, with an example; the changelog.

## Checks

- New tests on the existing synthetic fixtures: a prefix the bundled tables
  do not name, a bundled name replaced, a prefix put on and taken off an
  array, a blank `array` value, unusable rows, an unreadable table, a table
  without the two required columns, the `array` spellings and the prefix
  spellings. Thirteen changes to the new code were each made in a scratch
  copy, and each turned at least one new test red; the unchanged copy
  stayed green.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Nothing for this setting.
