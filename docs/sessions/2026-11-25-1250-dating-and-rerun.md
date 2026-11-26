# 2026-11-25 — When data was collected, and what a rerun runs again

**Done.** Four changes, each made in its own worktree and landed on `main`:

- The register workbook's Read me gives one date range rather
  than a date per source.
- `cmdb.read_dates` names each plug-in read again with the
  newest date its rows say their data was collected, and the register
  records it as `read_again_collected`.
- `takestock rerun` runs the late steps, coverage checks and
  annotations again over the rows, and replaces their rows and gaps. Each
  gap now records the step it is about (`summary.json` `gap_origins`;
  `coverage.Gap.origin`), so a rerun drops a re-read plug-in's earlier gaps
  whether or not their text names it. For an observation written before
  origins were recorded, three tests stand in (named, replayed, reworded).
- Every register row is dated by its own `collected_at` when it
  gives one, carried or read again, in an ordinary observation as in a
  derived one; `ReadDates.recorded` gives when the register learned it. The
  register carries `collected_from` and `collected_to`, and the Read me
  states that span.

**Checked.** The last two each passed the full test suite, ruff,
mypy and `tools/guard.py` before they were committed, and their new tests
fail on the commit before and pass after. Every commit here went through
the repository's commit hooks.

**Left.** For an observation written before gap origins were recorded, a
re-read plug-in's earlier gap is kept when that plug-in no longer files any
gap with the same first clause. `ReadDates.collected` and
`read_again_collected` still describe each re-read plug-in's newest
collection, though they no longer date any row.
