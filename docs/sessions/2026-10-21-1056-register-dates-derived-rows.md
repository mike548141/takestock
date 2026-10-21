# 2026-10-21 — the register dates a derived observation's rows by when they were read

## What was done

- **The configuration register reads when each row was read.** A derived
  observation (`takestock rerun`) carries most of its rows from an earlier
  observation and reads some plug-ins again, but the register dated every
  fact, key and relationship by the derived observation's own stamp, as if
  every row had been read that day. `cmdb.read_dates(summary, stamp)` now
  reads the `rerun` record (following `from_rerun` back through a chain of
  derived observations) and gives the full observation's date and, for each
  plug-in read again, the date of the latest observation that read it. A row
  names its plug-in in `extra.plugin`, which the plug-in host writes on every
  plug-in row.
- **What each date now is**, in a derived observation:
  - a fact's recording date and a key's merge dates are the date of the
    observation that read the row; a key's first and last seen are the
    row's own `collected_at` when it gives one, else that date;
  - a fact's valid date is the row's own `collected_at` when it gives one,
    else that same date (an environment without its own date too);
  - `installed-on` and `release-of` take the latest date among the rows
    behind them; `contains` takes the date of the row it keeps (the
    strongest evidence, then the most recent);
  - the register's own date, the count of every machine and the classes a
    machine is attributed to (`member-of`) take the full observation's date.
- A `recorded_at` given to `build` is still the recording date of every
  fact; rows are still dated as true when they were read.
- An observation that is not derived is dated exactly as before.
- Documented in `docs/CMDB.md` (*Building a register*) and in the changelog's
  unreleased `takestock rerun` entry.

## Checks

- `tests/test_cmdb_derived_dates.py`, 17 tests on the synthetic Example
  Widgets rows (`cmdbfake`): reading the record, a chain of derived
  observations, facts, valid dates, environments, the three edges, a key
  merge, a listed release, `member-of` after a re-read row, the machine
  count, an explicit recording date, and an ordinary observation unchanged.
  One test in `tests/test_rerun.py` builds the register from two real
  derived observations, one derived from the other, and checks three dates.
- Eighteen changes to the new code, one per behaviour, were each made in a
  scratch copy and run against those tests; seventeen turned a test red. The
  one that did not moves the merge date passed for a machine named only by an
  inventory's list of hosts; that key is matched on one name, so it can
  never merge and the date is never written. The code before this change
  fails the new tests too.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Nothing for this change.
