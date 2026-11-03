# 2026-11-03 — Five CrowdStrike Falcon identity, endpoint-event and assessment readers

## What was done

- **`takestock.readers`** gains five readers (`general`, no default input):
  - `falcon_logins`: CSV exports of successful and failed sign-in activity
    (such as the Falcon console's login lists): logon type 8 records
    (`weak`), where sign-in activity concentrates, local against domain
    accounts, the sign-in paths in use, failed sign-ins and a scope row.
  - `falcon_accounts`: a CSV of the accounts the sensor saw sign in: where
    administrative privilege sits, password age in buckets, service accounts
    and a scope row.
  - `falcon_logon_events`: LogScale exports of `UserLogon`,
    `UserLogonFailed`/`UserLogonFailed2` and local group change events, read
    for where sign-ins landed; every row `n/a`.
  - `falcon_endpoint_events`: LogScale exports of USB and removable storage
    events (rows), and of sensor tampering and unsigned credential-process
    access (counted in a gap, not reported as readings).
  - `falcon_zta`: `ZeroTrustHostAssessment` events, one row per machine,
    graded on seventeen platform-integrity items, with the machine type
    taken from further exports where they agree (reusing `falcon`'s
    `host_types` reading).
- `readers/_falcon_identity.py`: what the five readers share (per-export
  headings with `settings: columns:`, Microsoft's logon type numbers and
  names, machine counting by name or sensor ID).
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: a shared section with the public source of every
  event and field name, a section per reader with its queries, and the
  library table rows. Changelog.

Sources read on 4 November 2026 (New Zealand time):
`CrowdStrike/logscale-community-content` on GitHub (*Zero Trust Host
Assessment Scores*, *Failed and Successful User Logon Events*, *User Added
to Group*, the Cool Query Friday of 29 October 2021, the FLTR device control
dashboard and core `zUsbNormalize` query); `elastic/integrations` on GitHub,
`packages/crowdstrike` (sample `ZeroTrustHostAssessment`, `UserLogon` and
`UserLogonFailed2` events, the FDR field list and the event categorisation);
`SEKOIA-IO/documentation` on GitHub (a sample Windows
`ZeroTrustHostAssessment` event); Microsoft Learn, *4624(S) An account was
successfully logged on* (the logon type table); the LogScale documentation
(*Event Fields*, `groupBy()`); and the NZISM v3.9 control text for
13.3.6.C.02 and 16.6.10.C.02.

Choices worth recording:

- No public description of the Falcon console's account and login list
  headings was found, so those two readers' default headings are plain
  names of takestock's own and an export is read by naming its headings.
- Microsoft's description of logon type 8 says the password reached the
  authentication package unhashed, that the built-in packages hash
  credentials before sending them over the network, and that the
  credentials don't traverse the network in plaintext. The rows therefore
  say the receiving machine could read the password; whether it crossed the
  network readable turns on the carrying protocol (an inference, not
  Microsoft's statement), which the exports do not show.
- The Windows assessment item names come from a third party's sample event,
  and no public definition of each item was found; the docs say so.
- The tampering and credential-process counts are held in a gap: a count
  without triage reads as an incident or an all-clear and is neither.

## Checks

- Tests on exports composed in the tests (made-up machine and account names,
  sensor IDs and device makers, file dates in 2030). Eleven mutations of the
  new code each turned a test red (two only after a test was added for
  them); every mutated file was restored and compared byte for byte.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the queries against a tenant and compare the CSVs' headings and
  values with the readers'; in particular whether `groupBy()` keeps a group
  change event that lacks `GroupRid` or `UserRid`.
- Find a public definition of each Zero Trust Assessment item.
