# 2026-11-26 — Dating BitLocker rows by the file they came from

**Done.** One change to the `m365_bitlocker` reader, landed on `main`:

- Each row is dated by the file it was read from. A device that only the
  encryption report holds is dated by that report, names it as its source,
  and its note says the escrow export does not hold it; the key-storage
  hardware row is dated by the report and the non-Windows row by the device
  list.
- A device's build and edition come from one file where one holds both:
  the device list's OS version is used as the build when it has one, and
  `extra.os_collected_at` records that file's date. Where only the edition
  is in the device list, each value carries its own date.
- `lifecycle.derive_windows_support` derives a Windows band as of
  `extra.os_collected_at` where a row carries it (`OS_COLLECTED_AT_KEY`).

**Checked.** The reader's, lifecycle, plug-in and normalise test modules
pass, with ruff, mypy, `tools/guard.py` and secretscan clean. Each new test
fails on the commit before and passes after. The commit went through the
repository's commit hooks.

**Left.** `cmdb` dates an `os_version` fact by its row's `collected_at` and
does not yet read `extra.os_collected_at`, so a register built from these
rows dates a newer build by the older file.
