# 2026-11-03 — A CrowdStrike Falcon listener reader in the readers library

## What was done

- **`takestock.readers`** gains `falcon` (`general`, no default input). It
  reads an export of a Falcon sensor's `NetworkListenIP4` and
  `NetworkListenIP6` events, one row per machine, port, address family and
  bind scope, and writes:
  - one in-transit row per machine and port that the port encryption table
    knows or whose program is named, graded by the table through
    `plaintext.apply_posture` as a host listener and named by the daemon
    dictionary (`ctx.dictionary`, so a profile's overlay applies);
  - one row per program that holds more unrecognised ports on one machine
    than `dynamic_port_run` (default 20), counting them;
  - one `n/a` row counting the ports it could say nothing about;
  - one `n/a` row when no listener is bound to loopback only (saying none was
    seen when `loopback_binds_reported: true`, and that whether the sensors
    report them was not established when it is unset), or, with
    `loopback_binds_reported: false`, a row saying the source cannot see
    loopback-only listeners.
  The reader registers its rows as host-listener rows
  (`plaintext.register_host_listener_source`). Settings: `accepts` (inbound
  connections accepted, for use counts and the program behind a port),
  `hosts` (each sensor's machine name, operating system and type),
  `host_types` (further exports typing the machines; where they agree on a
  type that differs, theirs is kept), `columns` (other headings for any
  field of any export, or a list of headings), `row_limit` (default 20,000)
  and `dynamic_port_run`. Gaps: no listener export; one cut short; rows with
  no readable address; no address family; IPv4 rows only; no accept export,
  one cut short, or one with no machine column; machines with a sensor and no
  listener row; and, optional, no host export.
- `roles.py`: a machine described by its type, and role phrases for the new
  rows.
- `docs/COLLECTORS.md`: the reader's section, with three queries (written
  from CrowdStrike's public query examples and the CrowdStrike Query Language
  reference, not run), the fields and their default headings, where each
  field name comes from, the rows and the gaps; and the library table row.
- Changelog.

Sources read on 4 November 2026 (New Zealand time): the
`CrowdStrike/logscale-community-content` repository on GitHub (the query
files named in `docs/COLLECTORS.md`); Elastic's public CrowdStrike
integration (`elastic/integrations`, `packages/crowdstrike/data_stream/fdr`)
for the IPv6 event names and the fields of a `NetworkListenIP6` event; and
the `groupBy()` and `join()` pages of the CrowdStrike Query Language
reference at library.humio.com.

## Checks

- Tests on exports composed in the tests (made-up machine names under
  `example.test`, sensor IDs of one repeated digit, file dates in 2030). One
  test was shown to fail when the reader named an ambiguous runtime from the
  estate-wide join.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the three queries in a Falcon tenant and compare the download's
  headings and values (the `Protocol` number or name, a blank program, the
  `ProductType` code) with the reader's.
- Whether `groupBy()` keeps an event whose `program` is blank is not stated
  in the reference; check that the listener query returns listeners whose
  program the join did not find.
