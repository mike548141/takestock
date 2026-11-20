# 2026-11-20 — Mail path map: platform sources beyond headers

**From the retired session log**, word for word; only its link paths were re-pointed for this folder:

<!-- archivecut:log-entry docs/SESSIONS.md 91+2 -->
- 2026-11-20 — Mail path map: platform sources beyond headers:
  [detail](2026-11-20-0755-mailpath-platform-sources.md)


## What was done

- **`takestock.mailpath.platformlog`**: one per-message schema for mail
  platforms' own records, a check that refuses rows outside it or holding an
  address, and grouping into flows (source, direction, our domain, far
  system, connector) with counts, bytes and tallies.
- **Cloudflare**: Email Routing and Email Sending analytics
  (`emailRoutingAdaptive`, `emailSendingAdaptive`), last event per message,
  domains only.
- **`takestock.mailpath.ondmarc`**: a Red Sift OnDMARC API connector from the
  vendor's published OpenAPI specification: per-record rows where the account
  has them, per-address totals otherwise, and the vendor's own source
  classification; archives saved and read back.
- **`takestock.mailpath.google_workspace`**: Gmail log events, usage reports
  and Postmaster Tools v2 on a read-only installed-app OAuth grant with PKCE.
- **`takestock.mailpath.m365`** and `data/exports/export-m365-mail-flow.ps1`:
  a read-only Cloud Shell export of a tenant's mail flow (settings, 90 days of
  trace, optional `EmailEvents`) and its readers.
- `run`, `cli` and `report` wired to every source; docs and changelog.

## Not yet confirmed against a live service

Each module's docstring and `docs/MAILPATH.md` list what the published
references leave open (for example, how Gmail log fields nest in a Reports
API response, and some OnDMARC paging details). Every response used in the
tests is written from those references with invented values.

## Checks

`make check` at the landing: guard, ruff, mypy and the full suite.
