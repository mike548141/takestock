# 2026-11-27 — Build dates in the register, DNS-name helpers, post-quantum positions

**Done.** Three changes landed on `main`, each through the commit hooks:

- **The register dates and credits an operating-system build by its own
  export.** A row may say when its build was collected
  (`extra.os_collected_at`) and which source it was read from
  (`extra.os_source_name`, `lifecycle.OS_SOURCE_NAME_KEY`). The row's
  `os_version` fact is dated, recorded and credited by them; the row's
  other facts keep its own date and source. `m365_bitlocker` names the
  device list there when it reads the build from it.
- **`takestock.dnsnames`**: the DNS-name helpers moved out of
  `collectors/dns_zones` (which imports them, unchanged in behaviour), plus
  `non_public_suffixes(extra)`, `second_level_labels(extra)`,
  `declared_vendors(target)`, the vendor-word rule and the whole-word
  declared match. `config.load_vendor_domains(path)` lets a named file
  replace the bundled table. The built-in list of non-public endings holds
  only endings with a public basis (RFC-reserved names, `.arpa`,
  `.internal`, and common private-network defaults); a profile adds its own.
- **`takestock.pqc_positions`**: a format and loader for what software
  providers have published about post-quantum cryptography, with each
  entry's provenance. `source` and `read` are required; `publisher`,
  `published` and `recheck_by` are optional, with a re-check falling due a
  set number of days after `read` when no date is given. A stale entry is
  still used and is reported (`Positions.stale`, `stale: true`, and its
  cited sentence says it is due for re-checking). A provider with no entry
  is not researched, which is different from `silent`. The overlay
  `<stem>.pqc-positions.yaml` sits beside the profile; no bundled list
  ships yet.

**Checked.** The changed modules' tests pass with ruff, mypy and
`tools/guard.py` clean; each new test of the register change fails on the
commit before it. Each change was read for meaning by a second reviewer
before it was committed; one doc sentence that claimed more than the code
did was corrected before the commit.

**Left.**

- The register still dates and credits the operating-system *name* fact by
  the row, though the reader takes it from the device list; and the
  read-me's collection span does not include a build's own date.
- A reader that uses `dnsnames` and `pqc_positions` to list the outside
  parties an organisation's machines look up, with each one's published
  position, is the next piece; then a public starter list of positions,
  read fresh with its provenance.
