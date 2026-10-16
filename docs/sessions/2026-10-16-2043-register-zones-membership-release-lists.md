# 2026-10-16 — Register: technology zones, membership by collector id, release lists

## What was done

Three changes to the configuration register (`takestock.cmdb`), one commit
each:

- **Technology zones and locations.** Machines, Software Products and
  Applications carry `technology_zone`, one of the five technology zones of
  New Zealand's GEANZ Technologies model (August 2025 baseline); machines and
  Applications carry `technology_location`, one of its two technology
  locations (cloud, on-premise). They are two attributes because a zone says
  what kind of technology an item is and a location says where it runs. The
  schema cites the model and notes its review-draft successor without
  adopting it. A schema attribute can now name a `vocabulary`, and the build
  refuses a value outside it on any row, including a row that names no item.
- **Membership by collector id.** A declared-estate row's `collectors_live`
  matches the instrument that saw a machine by its collector id or by its
  display name, so a list of collector ids now draws `member-of` edges. One
  instrument named both ways for two different classes joins a machine to
  neither, and a machine gets one edge per declared class.
- **Release lists.** A row can list releases in `extra.releases`: a product,
  a version or a vendor version line with the versions it covers, support
  status and dates, and the CVE identifiers of known exploited defects open
  against it. Each entry makes a Software Product and Software Release.
  Software Release gains `covered_versions`, `exploited_defect_ids` and
  `exploited_defects_past_due`, citing CISA's Known Exploited
  Vulnerabilities Catalog. An entry for one version is the same release a
  machine row names at that version. An entry listing several versions with
  no line is refused.

`docs/CMDB.md`, the schema, the module docstring and the changelog describe
each change.

## What was checked

- The zone and location codes and definitions were read from the model's
  published CSV export and categories workbook, and the successor's from its
  review-draft workbook.
- Each change has tests on synthetic rows. Each new line was taken out in
  turn, with the compiled-file cache cleared, and the tests that depend on it
  went red; then it was restored.
- `make check` passed after each change.

## What is left

- Deciding, on synthetic rows, when a name some rows read as a DNS name and
  others as a machine should be a DNS Name or a Host, and when a port row
  makes a Network Service of its own; then documenting each rule.
- A release list's per-version installation counts are not yet carried as
  population rows, and an entry draws no `installed-on`.
- No row path gives a Software Product or an Application a zone or location;
  those are for the organisation to fill.
