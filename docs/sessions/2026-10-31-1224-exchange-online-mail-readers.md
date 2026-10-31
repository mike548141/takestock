# 2026-10-31 — Three Exchange Online mail readers in the readers library

## What was done

- **`takestock.readers`** gains three readers, each with no default input:
  - `exo_client_access` (`general`): mailbox access switches, one row per
    protocol counting the mailboxes that have it on, the organisation's
    authenticated SMTP switch, and a scope row. Settings `mailboxes`,
    `transport` and `policies` name the files; with patterns, files are
    paired by the date in their names.
  - `exo_connector_messages` (`mail-transport`): a per-message transport CSV,
    one finished row per direction and path plus a scope row, source
    `mail_transport`, with the government counterparty counts the Secure
    Government Email reading uses. Setting `government_suffixes` (default
    `.govt.nz`, `.mil.nz`, `.parliament.nz`).
  - `exo_outbound_protection` (`general`): outbound counts by security type;
    setting `messages` names the per-message export it reconciles with.
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: a section for the three, the library table rows,
  and an Exchange Online PowerShell script for the mailbox access files,
  written from Microsoft's documentation and not run.
- `tools/guard-allow.txt`: Microsoft's Exchange Team blog domain, cited for
  the SMTP AUTH timeline.
- Changelog.

Sources read on 1 November 2026 (New Zealand time): on learn.microsoft.com,
*Deprecation of Basic authentication in Exchange Online*, *Enable or disable
SMTP AUTH in Exchange Online*, *How to set up a multifunction device or
application to send email using Microsoft 365 or Office 365* (TLS 1.2 or 1.3
required for client SMTP submission), *POP3 and IMAP4 in Exchange Online*,
*Deprecation of Exchange Web Services in Exchange Online*, *Disable Basic
authentication in Exchange Online* (authentication policies), the
Set-CASMailbox and Get-EXOCasMailbox cmdlet pages, *Inbound messages and
Outbound messages reports in the new EAC*, and *How to Use Conditions in
Conditional Access Policies* (a browser is a modern authentication client); and the Exchange Team blog post
*Updated Exchange Online SMTP AUTH Basic Authentication Deprecation
Timeline*. NZISM v3.9 15.2.46.C.01 and 16.7.42.C.01 were read from the
manual's published CSV.

## Checks

- Tests on fixtures composed in the tests (`example.test` addresses, made-up
  connector names, 2030 dates): three test files.
- Thirty changes to the new code, each made in a scratch copy, were run
  against those tests: all 30 turned at least one test red (one did only
  after a test was added for it) and the unchanged copy stayed green.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the PowerShell script in `docs/COLLECTORS.md` against a test tenant.
- Microsoft's documentation does not list the columns of the per-message
  and security-type downloads; the readers name the columns they read.
- Check Microsoft's SMTP AUTH position again before 2026-12-31, after which
  the reader grades an organisation-wide switch `unknown`.
