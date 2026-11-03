# 2026-11-03 — Three CrowdStrike Falcon traffic readers in the readers library

## What was done

- **`takestock.readers`** gains three readers (`general`, no default input),
  each reading a CSV of the Falcon endpoint sensor's network events grouped
  and counted by a LogScale query:
  - `falcon_connections` (`NetworkConnectIP4`/`IP6`): one row per
    destination port, graded by the port-encryption table over TCP, and a
    scope row;
  - `falcon_http` (`HttpRequest`): plain HTTP requests the sensor recorded, placed
    as tunnel, loopback, no Host or cleartext; one `weak` row per port the
    table does not call cleartext, an `n/a` detail row per destination, a
    tunnel split per proxy port, and loopback, no-Host and scope rows;
  - `falcon_tls_clienthello` (`TlsClientHello`): one `n/a` row per program
    asking for a lower TLS version value than the upper one, and a scope
    row. No version is named unless `settings: version_names:` maps the
    values; optional `distribution` and `platforms` exports.
- `readers/_falcon_traffic.py`: the reading the three share (headings with
  `settings: columns:`, counts, program names).
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: a shared section with the public source of every
  event and field name, a section per reader with its query, and the library
  table rows. Changelog.

Sources read on 4 November 2026 (New Zealand time):
`CrowdStrike/logscale-community-content` on GitHub (the FLTR core package's
queries and dashboards, the *Next-Gen SIEM reference dashboard*, the
`TlsVersion.logscale` transform and `Cool-Query-Friday/mappings.csv`);
`elastic/integrations` on GitHub, `packages/crowdstrike` (the Falcon Data
Replicator field list and sample events); and the LogScale documentation
pages for `count()`, `groupBy()` and `in()` (CrowdStrike Query Language
functions).

Two choices worth recording:

- The community repository maps `TlsVersion` 0 to 3 as TLS 1.0 to 1.3, and
  says its content is not a replacement for the official documentation. The
  reader therefore names no version by default; `version_names` adopts a
  mapping, and the gap raised without it cites where one is published.
- No public source places `ImageFileName` or `ComputerName` on the
  `HttpRequest` or `TlsClientHello` events, so the queries add the program by
  the process join a community query uses, group machines by `aid`, and the
  program column is optional.

## Checks

- Tests on exports composed in the tests (made-up machines and programs,
  `example.test` destinations, documentation addresses, file dates in 2030).
  The graded-elsewhere rule in `falcon_http` was removed and its test went
  red, then restored.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the queries against a tenant and compare the CSV's headings and values
  with the readers'; the joined queries in particular have not been run.
- Grade named versions: with `version_names` set, the rows still grade
  nothing.
