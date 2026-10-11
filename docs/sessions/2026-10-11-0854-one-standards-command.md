# 2026-10-11 — One command for every standards check

## What was done

The standards checks now share one command, `takestock comply <standard>`,
in place of a pair of commands per standard:

- **A registry**, `src/takestock/comply.py`. Each standard registers a
  `Standard`: its id, a one-line title, the bundled requirement data it reads,
  the HTML file name it writes by default, and four functions (evaluate,
  render as text, render as HTML, and whether a *must* requirement is unmet).
  The command, `takestock comply --list` and the exit codes all follow from
  the registry, so adding a standard needs no new command.
- **The first standard, `sge`**, wraps `takestock.sge` (the grading) and
  `takestock.sge_note` (the note). Neither module's grading or output changed.
- **The command line**: `takestock comply <standard> <observation> <target>`
  writes the HTML note and prints its path (the default), or with
  `--format text` prints the plain-text report. `--out FILE` writes either
  format to a file. An unknown id exits 2 and names the known ones.
- **`takestock sge` and `takestock sge-note` are removed.** Nothing has been
  released yet, so no deprecation period is owed, and the first release ships
  only the new shape. The module entry points (`python -m takestock.sge`,
  `python -m takestock.sge_note`) are unchanged.
- **Documentation**: the README, `docs/SGE-NOTE.md`, `docs/TARGET-PROFILE.md`
  and the changelog use the new command; `docs/ARCHITECTURE.md` lists the
  registry and has a new section, *Adding a standard*, for contributors.

## What was checked

- The new command's output is byte-for-byte the same as the removed commands'
  output, compared on two inputs: an offline observation of the sample
  organisation (every requirement not measured, exit 0) and a synthetic
  observation with an unmet *must* requirement (exit 1). Text on stdout, the
  HTML file at a named path and at the default path, the printed path, stderr
  and the exit code were all identical.
- `tests/test_comply.py` holds the same comparison against the module entry
  points, plus the listing, an unknown id, missing arguments, a duplicate
  registration, the removed commands, and a toy standard registered in the
  test to show a new one is reached without touching the command.
- `make check` passed.

## What is left

Nothing for this change.
