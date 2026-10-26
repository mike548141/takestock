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

- **Wire atelier's floor checks.** The onramp now carries atelier's floor
  block, but not its scan hook, its CI floor job or an `.atelier-floor.json`.
  A run of atelier's floor (CI plane, at `0a2b7a7`) over the tree blocks on six
  checks: secretscan, leakscan, linkscan, datescan, wrapscan and spellscan;
  pathscan only warns. The secret and leak findings are test fixtures,
  documentation examples, algorithm names shaped like email addresses and the
  package's authorship lines; none reads as a real secret. Decide how the hook
  sits beside the guard, whether CI runs the floor, and what the repository
  declares; then clear or declare each finding. Waiting on the maintainer.

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
