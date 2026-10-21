# 2026-10-21 — `takestock rerun`: derived observations

## What was done

- **`takestock rerun <target> --from <observation> --plugin <name>`**, in
  `rerun.py`: a new observation that holds every row, gap and raw file of an
  earlier one, except the named plug-ins' rows, which are read again from
  their inputs. Only the named plug-ins run, with the profile's annotations to
  label their rows, so nothing is looked up or probed. It suits a reader that
  has changed, or an export supplied again, when the rest of the observation
  is still current.
- **Carried rows are written exactly as stored.** The new rows are graded
  together with the carried ones (some readings compare a row with the whole
  population), and the carried rows are then written as they were. Where
  that pass would have stored a carried row differently, the record counts
  it by source and by field, without applying it.
- **Placement**: a named plug-in's new rows take the place of its first old
  row; one that wrote none before follows the nearest plug-in before it in
  the profile's `plugins:` list that has rows.
- **Annotations** label the new rows; every other plug-in's record and
  summary are the earlier observation's.
- **Gaps**: earlier gaps naming a named plug-in are dropped and its new gaps
  added. Gaps from a plug-in declared with `gap_prefix=False` cannot be told
  apart, so they are kept, a repeated one is counted rather than added twice,
  and an earlier wording stays beside a new one.
- **The record**: `summary.json["rerun"]`, and the CycloneDX property
  `takestock:derived_from`. The `observation` block says `scan: false` and
  `offline: true`, and keeps the earlier `dispositions_digest`, since the
  carried rows were judged under that set; the record carries the digest
  of the set the new rows were judged under.
- **Never a fresh measurement**: `--carry-scan` refuses a derived observation
  with its own reason, and the certificate-transparency cache passes over
  one, since its answers were fetched for the earlier observation and its
  name gives its own date.
- **Refusals**, each leaving nothing behind: no plug-in named or one named
  twice; the earlier observation missing, unfinished, without a run record or
  of another target; a name that is not a declared plug-in (a built-in
  collector is named as one), or is an annotation, a coverage check or a late
  step; a source shared with another declared plug-in (named or not) or a
  collector; a row merged across the line, or a new row that would merge with
  a carried one; a named plug-in that does not run (its input is missing).
- Documented in `ARCHITECTURE.md` (*Reading named plug-ins again*), the
  README's list of observation modes, and the changelog.

## Checks

- `tests/test_rerun.py`, 31 tests on the sample organisation with synthetic
  plug-ins reading small CSV files under `example.test`: carried rows equal
  to the stored ones, re-read rows, placement both ways, annotations, gaps
  dropped, kept and repeated, the record, the dispositions digest kept, raw
  files, the counted grading differences, a rerun of a rerun, the carry and
  cache refusals, every refusal above (two named plug-ins sharing a source
  among them), and the command line.
- Twenty-seven changes to the new code, one per behaviour, were each made
  in a scratch copy with all 31 tests in place, and each turned its test
  red; every file was restored.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Built-in ingest collectors (supplied exports read by takestock's own
  collectors) are not yet accepted by `rerun`; only plug-ins are.
- Re-grading a row that already carries the certificate-expiry note adds the
  note a second time, which the carried-row count then reports as a
  difference in `notes`. Making that pass idempotent would remove the noise.
