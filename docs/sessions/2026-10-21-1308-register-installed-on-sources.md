# 2026-10-21 — the register names which rows' host lists draw installed-on

## What was done

- **`installed_on_from`**, a configuration register option: the row sources
  or plug-ins (a row's `source` or its `extra.plugin`) whose lists of hosts
  (`extra.installed_on`, or a list in `extra.hosts`) draw *installed on*.
  Set in a target profile's `cmdb:` block, or passed to `build` and
  `build_register`; `ProfileOptions.build_kwargs` carries it.
- Another row's list is left unread, as if the row held none: it makes no
  machine, no hostname fact, no edge and no machine count for its
  instrument, and it is not checked. The row's own product and release are
  kept, and a row's own host still carries its software.
- Without the option every row's list is read, exactly as before, and the
  register's JSON is unchanged. When set, the JSON records it as
  `register.installed_on_from`. An empty list reads no row's list. A profile
  must give a list of non-blank names; `build` and `build_register` take a
  list or a tuple of them. Anything else (a single string, a mapping, a set,
  a number, a blank or non-text name) is refused with `ValueError`.
- Documented in `docs/CMDB.md` (*Options a profile sets*) and the changelog.

## Checks

- `tests/test_cmdb_installed_on_from.py`, 22 tests on the synthetic Example
  Widgets rows (`cmdbfake`) with two invented feeds listing hosts for one
  release: every list read by default; only a named source's, by source and
  by plug-in; a row's own host kept; an empty list; a tuple; an unread list
  neither checked nor counted; each refused shape, in a call and in a
  profile; the JSON with and without the option; the profile.
- Seventeen changes to the new code, one per behaviour, were each made in a
  scratch copy; every one turned a test red. The code before this change
  fails all 22.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Nothing for this change.
