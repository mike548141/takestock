# 2026-11-03 — A profile's own daemon-dictionary rows

## What was done

- **`<stem>.daemon-dictionary.yaml`**, a new overlay beside a target profile,
  following the `.derived-ports.yaml` pattern: one key,
  `daemon_dictionary:`, a mapping from binary name to `product`, `vendor`,
  `category`, `confidence` and optional `notes`.
- `config.load_dictionary(target=None)`: with a target, the overlay's rows are
  merged over the bundled table (or a workspace's `data/` copy). An overlay
  row replaces the row for the same binary whole; a new binary is added.
  `config.load_dictionary_overlay()` reads and checks the overlay;
  `config.dictionary_overlay_path_for_target()` finds it. The suffix is in
  `OVERLAY_SUFFIXES`, so the file is never read as a profile.
- The table's columns, categories and confidence words are now constants in
  `config` (`DICTIONARY_COLUMNS`, `DICTIONARY_CATEGORIES`,
  `DICTIONARY_CONFIDENCES`); an overlay row is checked against them when it
  is loaded. Unlike a bundled row, it needs no public document in `notes`.
- The plug-in host hands readers the merged table as `ctx.dictionary`, and
  `observe` and `rerun` pass it to `finalise`. Both commands load the overlay
  before writing anything and refuse a malformed one (`rerun` with code
  `rerun-dictionary`).
- Docs: `TARGET-PROFILE.md` (terms, workspace layout, the `data/` paragraph,
  and a section for the overlay), `PLUGINS.md` (the `dictionary` field),
  `ARCHITECTURE.md`, the head of `daemon-dictionary.csv`, and the changelog.

## Checks

- `tests/test_dictionary_overlay.py`: merging, precedence, an absent or empty
  overlay, the overlay not being a profile, merging over a workspace copy,
  thirteen malformed shapes each refused with the file named, optional notes,
  and end to end through `observe` and `rerun` with a `host-listener`
  plug-in: what the reader receives and the product each row is given.
  A rerun refusal test in `tests/test_rerun.py`, and a check in
  `tests/test_data_lists.py` that the constants match the bundled table's
  header and the vocabulary that test already holds. All binaries and
  products are made up (`widgetsrv`, Example Co).
- Twenty-one changes to the new code, each made in a scratch copy of the
  source (dropping the target at each of the five load sites, reversing the
  merge order, removing the suffix, and disabling each check in the loader),
  were run against those tests: each turned at least one test red.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- The sample organisation has no dictionary overlay; the guide shows one
  inline instead.
