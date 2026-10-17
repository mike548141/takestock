# 2026-10-17 — Register options, a schema overlay, a Jira Assets import

## What was done

- **A schema overlay.** `takestock.cmdb.apply_overlay` merges an overlay's
  wording over the register schema: the `answers`, `definition`, `note`,
  `built_from`, `asserts`, `test`, `wrong_if` and `qualifier` text of the
  families, classes, attributes and relationships the schema declares, the
  `definition`, `note` and `source` of a declared vocabulary code, and who
  holds a declared governance role. It never changes the model. An overlay
  that names something undeclared, sets any other field, gives a value that
  is not text or holds another section raises `OverlayError`, listing every
  problem at once. `load_schema(overlay)` and `build(..., schema_overlay=)`
  take one, and the register names it in `register.schema_overlay`. The
  overlay is applied to a deep copy, so the cached schema is never changed.
- **Register options from a profile.** A profile's `cmdb:` block (`title`,
  `schema_overlay`, `how_to_read`, `jira_assets`) is read by
  `cmdb.profile_options`, which refuses any other key; `takestock cmdb
  --target <profile>` (and `python -m takestock.cmdb --target`) uses it
  through `cmdb.build_and_write`. The organisation's name comes from the
  profile's `organisation`, and the workbook takes the profile's `branding`
  colours and font only when that block sets anything. `register_payload`
  and `build_register` take `organisation` and `how_to_read`; `write_outputs`
  takes `theme` and `jira_assets`.
- **A themed workbook.** `cmdb_export.workbook_style(theme)` maps a page
  theme onto the workbook: headers in `text` on `surface`, title, headings
  and contested values in `accent`, absences in `muted`, and the first font
  in the font list that is not a generic family. Without a theme the
  workbook is styled exactly as before.
- **A Jira Assets import.** `cmdb_export.jira_assets` and
  `write_jira_assets` write `jira-assets/schema-and-mapping.json` and
  `jira-assets/data.json`, in the shape Atlassian documents for Assets'
  external imports. One object type per declared class, matched on a
  *Register key* attribute, the only external-id part. *Name* is the label,
  a class attribute that shares a fixed attribute's name gets the suffix
  ` (attribute)`, and each kind of drawn relationship between two classes is
  a reference attribute resolved with `"Register key" IN (${<locator>${0}})`.
- **Overlay suffix.** `.cmdb-schema-overlay.yaml` is a registered overlay
  suffix, so such a file beside a profile is never listed as a profile.
- **The sample** profile has a `cmdb:` block and an overlay that rewords one
  attribute's note, one class's question and one governance role.
- **Docs:** `CMDB.md` gains *Options a profile sets*, *An import for Jira
  Assets* and *Rewording the schema with an overlay*; `TARGET-PROFILE.md`
  gains the `cmdb` key and the overlay file; `ARCHITECTURE.md` and the
  changelog follow.

## Checks

- The import format was taken from Atlassian's Imports REST API guide, its
  schema and mapping page, and the published JSON schema (version
  2023-10-19), which was downloaded and read. They are cited by title. The
  mapping names no `$schema`, since Atlassian applies that version to any
  document that uses external ids. The written mapping was checked
  against that schema with a small validator for the keywords it uses,
  first shown to reject a broken copy (a missing required description and an
  unknown attribute type). The form of a reference to several objects is the
  one Atlassian's knowledge base gives for imports; the files were not
  submitted to a live Assets site, and `CMDB.md` says so.
- New tests in `tests/test_cmdb_options.py`: the overlay reaching the JSON
  and workbook, every kind of refusal, the bundled schema left unchanged,
  profile options and their refusals, the command line, title, organisation
  and reading notes, the themed workbook, the import's required fields,
  object types, key, references and absences, and the sample. Each was seen
  to fail with its change switched off (fifteen separate mutations,
  restored one at a time, with the bytecode cache cleared after each).
- An offline observation of the sample, then `takestock cmdb --target
  example-widgets`, read back: the title, organisation, overlay and
  governance wording in the JSON and on the Read me sheet, and an import of
  25 object types that passes the schema check.
- `make check`: guard, ruff, mypy and the full test suite.

## Left

- Archive search folders, the other half of this session, follow in the
  next commit.
- A live submission to an Assets site has not been tried.
