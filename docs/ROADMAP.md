# Roadmap

What is planned next for takestock. A finished item
moves to [`CHANGELOG.md`](../CHANGELOG.md). To propose an item, open an
issue.

## Now

- **Install from PyPI in the README's quick start.** 0.1.0 is on PyPI; the
  quick start still installs from a clone because it needs the sample in
  `examples/`.

## Next

- **Settle the command line and file formats.** The README says both may
  still change. Before 1.0, decide which output fields are stable, and record
  every change to them in the changelog until then.

- **Clear the floor's advisory checks by 2027-01-31.** `.atelier-floor.json`
  runs datescan, spellscan and wrapscan advisory while their findings are
  cleared: dates in the reference guides to write as YYYY-MM-DD, US spellings
  outside quoted titles and proper names, and long lines in the guides. Fix
  each, or mark the ones that must stay (a quoted title, a table row), then
  drop the advisory entry.

## Later

- **1.0**, once the formats are settled and a release has been used without
  a breaking change.

## Queued reviews

- ⏳ **Rule-4 cold pass queued: the floor block stamped at atelier
  `0a2b7a7`.** Refs only. Delta: the commit that adds this item (resolve with
  `git log -S'floor block stamped at atelier' -- docs/ROADMAP.md`). Intent
  record: `docs/sessions/*-adopt-atelier-floor.md`. Doctrine
  surface: atelier `PROPAGATION.md` § *The standard child doctrine block*
  (the `floor` region) at `0a2b7a7`, and its stamp rules. For a non-author to
  take; the taker writes the brief. Tier at selection: Fable, so it waits for
  the maintainer's approval of Fable work. **Not takeable by session
  `8266042b`**, which authored the adoption.
