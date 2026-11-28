# 2026-11-27 — Units of work, two more readers, and "not run"

**Done.** Four changes landed on `main`, each through the commit hooks:

- **`takestock.remediation` and `takestock.fronting`**. The
  remediation view groups work into units by `effort_group`, with
  `TrackTables.from_rules`, `plan(..., tracks=)` and `source_label(...,
  labels=)` so a caller can pass its own tracks and source labels. The
  fronting count sorts service findings by what could be put in front of
  them, with `NO_ROW` for a protocol the port table does not list. A *Units
  of work* section joined `DISPOSITIONS.md`.
- **The register dates and credits an operating-system name by its own
  export**. A row may say when its name was collected
  (`extra.os_name_collected_at`, `lifecycle.OS_NAME_COLLECTED_AT_KEY`) and
  which source it was read from (`extra.os_name_source_name`). The `os`
  fact is dated, recorded and credited by them, falling back to the row's
  own. `m365_bitlocker` writes both from the device list whenever it reads
  the name there. The read-me's "collected between" range and
  `read_again_collected` now count a build or name dated apart from its row.
- **Two library readers, and "not run" in `estate`**.
  `privileged_coverage` is a coverage check over the profile's declared
  suppliers: one gap for each supplier no privileged-lens row speaks to, and
  one for the parties the information-sharing register names that no
  declaration holds. `software_support` reads a software census's files,
  named by a manifest, and writes the releases past a vendor's support date
  or with a catalogued exploited defect open, keyed on the vendor's own
  version line. A lifecycle table that is missing, not YAML or not a mapping
  is one `could-not-test` gap. In `estate`, a declared plug-in the run
  records as not run, or a library reader given no input that wrote nothing,
  now reads `instrument-not-run`, not silent.
- **"Not yet run"**. A coverage check or late step whose turn
  comes after `estate`'s has not run when `estate` reads the run, though it
  runs later in the same observation. It has its own reason,
  `not-yet-run`: where every instrument a class names did not run, the row,
  note and gap say it had not run when `estate` read the run, and the remedy
  is to declare it before `estate` or read the class from that plug-in's own
  record. Annotations, which always run after grading, and plug-ins named by
  `module:` or `path:` read as before.

**Checked.** `make check` passed after each change. Each new behaviour has a
test that fails on the commit before it.
Each change was read for meaning by a second reviewer before it was
committed. The reads led to clearer synthetic test fixtures, corrected
several doc sentences that claimed more than the code did, and fixed the
shared "not run" wording, which was false for a plug-in that runs later; all
before the commit.

**Left.**

- In a class where another named instrument ran, a silent class's note
  lists the waiting plug-in among those that produced nothing, and a
  partial class's note and gap list it among those that produced none; only
  the flag, and a silent class's gap, say it had not run yet. A note naming
  each plug-in in its own words would be truer.
- Some reader sentences say "this run", "the target profile" or "the
  organisation" where "this observation" or "the declared estate" would
  read better for any user.
