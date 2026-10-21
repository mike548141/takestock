# 2026-10-21 — the register counts a discovery total written as text

## What was done

- **A discovery source's machine count may be text.** The configuration
  register's population rows read `extra.discovered`, a discovery source's
  count of how many machines exist. A whole number was counted and anything
  else was skipped, so a reader that wrote the count as text (`"40"`) put
  no row on the *Populations* sheet. `_whole_number` now reads a whole number,
  or a string of ASCII digits with surrounding spaces ignored, and gives None
  for anything else (a word, a decimal, a sign, an empty string, other
  scripts' digits, a boolean, a float, None, a list), which is still not
  counted, as before.
- Documented in `docs/CMDB.md` (*Population counts*) and the changelog.

## Checks

- `tests/test_cmdb.py`: four values counted (`40`, `"40"`, `" 40 "`,
  `"40\n"`) and ten not counted, on the synthetic Example Widgets rows
  (`cmdbfake`). The code before this change fails the three text cases.
- Nine changes to the new code, one per behaviour, were each made in a
  scratch copy; every one turned a test red.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Nothing for this change.
