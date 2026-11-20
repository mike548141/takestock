# Mail path map

`takestock mailpath` maps how mail moves for an organisation's domains: the
routes messages took, the transport and signing on each hand-over, the
software that made each message, who sends as each domain, the volumes the
mail platform recorded, and what each domain publishes. It writes
`mailpath.json` (counts and names, never a person's address) and
`mailpath.html`, one self-contained page with every route drawn.

```text
$ takestock mailpath --organisation "Example Widgets" \
    --domain example.test --domain example.net \
    --headers exports/headers/ \
    --dmarc exports/dmarc/ \
    --cloudflare-zone example.test=<zone id> --cloudflare-keychain cloudflare-read \
    --trace exports/message-trace.csv \
    --systems example-mail-systems.yaml \
    --probe --out mailpath/
```

Every source is optional except DNS, and each has its own reach.

| Source | Option | Shows | Cannot show |
|---|---|---|---|
| Public DNS | always | Where mail is received (MX, null MX), who may send (SPF, each include named), DMARC policy and where reports go, DKIM keys at the selectors tried, MTA-STS record and policy, TLS reporting, BIMI, a signed zone (DS), DANE (TLSA per MX) | Traffic. DKIM keys at selectors nobody tried |
| MX probes | `--probe` | The TLS versions and suites each MX accepts, and its certificate | What senders actually negotiated |
| Message headers | `--headers` | Each message's route hop by hop, the TLS each receiving server recorded, how it entered the mail system (desktop client, web or API, authenticated SMTP, an internal host), DKIM signatures, the receiver's SPF, DKIM and DMARC results, the software that made it, whether the content was S/MIME or OpenPGP signed or encrypted, protective markings and sensitivity labels, its size | Messages in mailboxes nobody read |
| DMARC aggregate reports | `--dmarc`, `--cloudflare-zone` | Every system that sent as each domain to a receiver that reports, with counts and aligned SPF and DKIM results, and what the receiver did | Sizes, routes, transport; receivers that do not report; mail inside one platform |
| Message trace | `--trace` | Every message the platform handled, its size, where it entered, the connector, and the TLS recorded where the export carries it | Hops before the platform received a message or after it left |

## Directions

A message is placed by its author's domain and its recipient's domain against
the organisation's own (`--domain` and `--owned`, subdomains included):
*outbound* (ours to anyone else), *internal* (ours to ours), *inbound* (anyone
else to ours), and *sent copy* (a sender's own copy, which records how a
message entered the platform but not how it was delivered). A mailing list or
group that rewrites a message's From is seen through: the original author's
domain is read from the first ARC seal (`i=1`).

## Reading a route

A route is the list of systems a message crossed, origin first. Hops inside
one platform are one station. Each crossing between two systems carries the
transport the receiving server wrote:

- **TLS 1.2 or 1.3** where the server recorded a version.
- **TLS, version not recorded** where it recorded TLS without a version
  (`ESMTPS`, or a platform's own wording).
- **not recorded** where it wrote no TLS clause. A server that writes plain
  `ESMTP` claims, by RFC 3848, that no TLS was used, but servers write it
  regardless, so takestock records the claim (`esmtp_without_tls_claim`)
  and does not grade the leg as cleartext. The sending system's own log
  settles it; a message trace with a TLS column is such a log.

A recorded suite is what that hop chose, never the weakest the servers would
accept: the MX probes give the floor on arrival. Received headers above the
first hop a receiver trusts can be forged by a sender, so a route is evidence
of the path, not proof of it.

## Naming systems

Systems are recognised from `data/mail-systems.yaml`: public mail platforms,
sending services, gateways and DMARC reporting services, by host-name
suffixes and patterns, address ranges, SPF includes, Message-ID right-hand
sides, mailer strings and headers only one system writes. A header the
*receiving* platform stamps on mail it accepts is not taken as evidence about
the sender. A host on a private network or with an internal name is shown as
`internal host <name>` (a dashed box on the page); any other unrecognised
host is named by its registered domain.

An organisation names its own relays, gateways and partners in an overlay of
the same shape, passed with `--systems`; an overlay entry replaces a bundled
entry of the same name:

```yaml
systems:
  - name: Example Widgets relay
    kind: relay                 # mailbox, gateway, relay, client, forwarder, reporting
    host_suffixes: [relay.example.test]
    host_regex: ['^mailhost\d+$']
    addresses: [192.0.2.0/28]
    spf_includes: [spf.example.test]
```

A DMARC report names a source by its address. takestock names it by the
report's reverse DNS (looked up when the report left it out), then a
declared address range; otherwise it shows the network's owner as
`network: <owner>`, because a cloud provider's network carries its customers'
hosts as well as its own mail services.

## Inputs

- **Headers**: files of headers, one message each (`.txt`, `.eml`,
  `.headers`), or directories of them. Reading stops at the first blank line,
  so a body is never parsed. A file may begin with `#` comment lines carrying
  `# sizeEstimate N`, `# internalDate ISO` and `# labels A,B`, as a mailbox
  export that fetched headers only writes them. Keep header files outside a
  repository: they name people.
- **DMARC**: RFC 7489 aggregate reports (`.xml`, `.xml.gz`, `.zip`), or
  Cloudflare DMARC Management rows saved as `.json`. With
  `--cloudflare-zone DOMAIN=ZONE_ID` the rows are fetched live through
  Cloudflare's GraphQL analytics API (`dmarcReportsAdaptive`), in 30-day
  windows back to the plan's retention edge, and saved beside the output,
  because rows older than the retention period cannot be fetched again. The
  token needs *Email Security DMARC Reports: Read* only; it comes from
  `$CLOUDFLARE_API_TOKEN` or the keychain item `--cloudflare-keychain` names
  and is passed to `curl` on standard input.
- **Trace**: an Exchange Online message trace CSV, either
  `Get-MessageTraceV2 | Export-Csv` or the admin centre's extended report. A
  subject column is ignored and never kept. A message to several recipients
  is counted once.

## Platform logs

The mail platforms' own per-message records are the census beside the routes:
Google Workspace's Gmail log events, Defender for Office 365's `EmailEvents`
(from the Microsoft 365 export), and Cloudflare Email Routing and Email Sending.
Each source normalises its rows to one schema (`takestock.mailpath.platformlog`):

| Field | Holds |
|---|---|
| `time` | ISO 8601 |
| `direction` | `inbound`, `outbound`, `internal` or `unknown`, as the platform says |
| `sender_domain`, `recipient_domains` | domains only, never an address |
| `size` | bytes, or null |
| `tls` | `TLS 1.2`, `TLS 1.3`, `none`, … or `""` when the source does not say |
| `spf`, `dkim`, `dmarc` | the platform's result |
| `remote_host`, `remote_ip` | the far server it handed to or took from |
| `connector`, `delivery` | the route inside the platform, and what it did |
| `source` | which log the row came from |

`takestock mailpath` refuses rows with keys outside the schema or an address
where a domain belongs. The page groups them by source, direction, our domain,
far system and connector, with counts, bytes, and the transport,
authentication and outcome tallies.

| Option | Reads |
|---|---|
| `--platform-log FILE` | a JSON list of rows in the schema |
| `--cloudflare-email` | Email Routing and Sending for every `--cloudflare-zone` |
| `--m365-bundle PATH` | a Microsoft 365 export (folder or zip): settings, trace, `EmailEvents` |
| `--google-dir DIR` | a Google Workspace pull (`gmail-log.json`, `usage.json`, `postmaster.json`) |
| `--ondmarc-archive FILE` | a saved OnDMARC fetch |
| `--ondmarc-domain D` with `--ondmarc-region`, `--ondmarc-keychain` | a live OnDMARC fetch, saved beside the output |
| `--since`, `--until` | the dates of a live fetch |

## Limits

- DKIM selectors cannot be listed from DNS: the page reads the selectors seen
  in the headers and a list of common ones. A domain answering every selector
  with one record (a wildcard) is read once and shown as such.
- The headers describe only the mailboxes read; a census needs the platform's
  trace and the DMARC reports beside them.
- `--probe` connects to each MX host on port 25. Probe only hosts you are
  authorised to.

## Source: Red Sift OnDMARC

`takestock.mailpath.ondmarc` reads the DMARC aggregate data a domain's
reports deliver to Red Sift OnDMARC, through the OnDMARC V2 API (its
specification is published at `https://docs.redsift.com/ondmarc.yaml`). It
is a fetcher and a mapper; the `mailpath` command does not call it yet.

```
python -m takestock.mailpath.ondmarc --domain example.test --region uk \
    --since 2026-01-01 --until 2026-01-31 --keychain ondmarc-api-key --out ondmarc.json
```

- **Key and region.** API access is an add-on to an OnDMARC account; a
  super-user creates the key in the user profile. It comes from
  `$ONDMARC_API_KEY` (or `--env NAME`) or the keychain item `--keychain`
  names, and is passed to `curl` on standard input as
  `Authorization: Api-Key …`. The account lives in one region (`uk`, `eu` or
  `us`); a key used against another region is refused. With no `--domain`
  every domain the key can see is fetched.
- **What is fetched, per domain.** The sources list (each sender OnDMARC has
  named, with its type, business type, classification and the service's
  recommended classification) and the per-record rows of the *DMARC Analyst*
  endpoint: receiver, sending address, reverse DNS, network owner,
  header-from, envelope-from, aligned SPF and DKIM results, disposition and
  day. Those rows become the same DMARC records the report files and
  Cloudflare rows do.
- **Without DMARC Analyst** (the API answers 402), the fetch falls back to
  per-address totals for the whole period. Each address's aligned SPF and
  DKIM results survive, split exactly into both-pass, DKIM-only, SPF-only and
  neither; the receiver, envelope-from, reverse DNS, disposition (shown as
  `unknown`), day, and the header-from subdomain do not. `--no-analyst` asks
  for the totals directly.
- **What OnDMARC adds.** `sources_summary()` keeps the service's own name and
  classification for each sender (`valid`, `invalid`, `forwarder`,
  `misconfigured`, `insufficient_data`, `unknown`), beside its message and
  pass counts, because a DMARC report carries neither.
- **Refusals are recorded, not read as silence.** A call the API refuses is
  saved in the archive as a `refused` row with its status and message, noted
  on standard error, and makes the command exit with status 3. A rejected key
  stops the fetch (exit 1). Rate limiting (429) and server errors are retried
  three times.
- **The archive** (`--out`) holds the raw rows and the notes, in the format
  `takestock.ondmarc/1`; `load_archive()` reads it back. Keep it: the API
  serves only what the account still retains.
- **Not confirmed from the specification:** the analyst endpoint's largest
  page (1,000 is used), whether `to_date` is inclusive, and what the sources
  row's `blocklist_count` counts. The analyst rows roll subdomain traffic
  into the queried domain, so their totals can exceed the per-source figures
  for the same domain. Nothing in this connector has been run against the
  live API; its tests use responses written from the published
  specification.

## Source: Microsoft 365

`takestock.mailpath.m365` reads the folder or zip that
`export-m365-mail-flow.ps1` writes ([`EXCHANGE-ONLINE-EXPORT.md`](EXCHANGE-ONLINE-EXPORT.md#exporting-mail-flow-for-takestock-mailpath)):
one Cloud Shell run that exports an Exchange Online organisation's mail flow
settings, 90 days of message trace and, optionally, 30 days of Defender for
Office 365's `EmailEvents`.

| Reading | Shows | Cannot show |
|---|---|---|
| Accepted domains, connectors | Which domains the platform receives mail for; who may hand mail in and the TLS and certificate asked of them; where mail is handed out (smart hosts or MX) and the TLS level demanded (`EncryptionOnly`, `CertificateValidation`, `DomainValidation`), MTA-STS and DANE modes | What a gateway on either side does |
| DKIM signing | Which domains are signed, key size, selectors | Signing by any other sender of the domain |
| Mail flow rules | Each rule's name, state, mode, priority and the names of the conditions and actions it sets; values only for routing and TLS (`RouteMessageOutboundConnector`, `RouteMessageOutboundRequireTls`, `SetSCL`, scopes) | What a rule matches on, which is never exported |
| Mail flow status report | Daily message counts by direction and event type | Anything per message |
| Message trace | As `--trace` above; read by the same reader | As above |
| Defender `EmailEvents` | One event per message: direction, sending domain, recipient domains, size, the receiver's SPF, DKIM and DMARC verdicts, the last relaying address, the connector, what was done with it | The TLS of any hop (no column records it), messages older than 30 days |

`read_bundle(path)` returns the settings normalised, the traffic counts, the
paths of the trace and `EmailEvents` files, and `notes` saying what was
missing, refused or incomplete. `trace_flows(path, owned)` reads the trace
CSVs through the trace reader. `email_events(path)` takes the bundle or one
`EmailEvents` file (the script's CSV, the Defender portal's CSV export, or a
Graph `runHuntingQuery` response saved as JSON) and returns one event per
message in the shared event schema:

```text
time, direction (inbound | outbound | internal | unknown), sender_domain,
recipient_domains, size, tls, spf, dkim, dmarc, remote_host, remote_ip,
connector, delivery, source ("m365-emailevents")
```

A field the source does not record is `""` (`tls` and `remote_host` always,
for `EmailEvents`). Only these fields are kept, so a subject or an address in
the input never reaches the output.

## Source: Google Workspace

`takestock.mailpath.google_workspace` reads three read-only Google APIs for an
organisation whose mail is on Google Workspace. It is called by the mail-path
run, or on its own:

```text
$ python -m takestock.mailpath.google_workspace auth \
    --client-keychain google-oauth-client --token-keychain google-mail-read
$ python -m takestock.mailpath.google_workspace pull \
    --client-keychain google-oauth-client --token-keychain google-mail-read \
    --since 2026-03-01 --until 2026-03-31 --domain example.test --out google/
```

`pull` writes `gmail-log.json` (one row per message, and notes),
`usage.json` and `postmaster.json`. Each source is fetched on its own: one
refused does not stop the others, and a refusal is written as a refusal.

| API | Shows | Cannot show | Editions |
|---|---|---|---|
| [Reports API, Gmail log events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail) (`activities.list`, `applicationName=gmail`) | Each message: direction (inbound, outbound, internal), sender and recipient domains, size, the TLS version of the SMTP leg facing outside, SPF, DKIM and DMARC results, the remote server's address (and name, outbound), SMTP relay or inbound gateway, and the delivery outcome | Hops before Gmail's inbound server or after its outbound one; the name of a server connecting inbound | Only editions with audit-log eligible licences ([announcement, September 2025](https://workspaceupdates.googleblog.com/2025/09/updates-to-gmail-log-events.html)); others are refused |
| [Reports API, Gmail usage](https://developers.google.com/workspace/admin/reports/v1/appendix/usage/customer/gmail) (`customerUsageReports`, `userUsageReport`) | Daily totals: sent, received, delivered, rejected, rerouted, spam, and inbound and outbound mail encrypted and unencrypted; how many users sent or received anything | Anything per message: no domains, routes, sizes or TLS versions | All |
| [Postmaster Tools API v2](https://developers.google.com/workspace/gmail/postmaster/reference/rest) (`domains.domainStats.query`, `domains.getComplianceStatus`) | How Gmail as a receiver saw each domain's mail, daily: spam rate, SPF, DKIM and DMARC success rates, the share encrypted with TLS each way, delivery errors; bulk-sender compliance | Mail to anyone but Gmail users; domain and IP reputation (v2 does not offer them); domains not verified in Postmaster Tools by the granting account | Any account that has verified the domain |

A Gmail log row has the shape every mail-path log source shares, with `""`
where Gmail did not say:

```json
{"time": "2026-03-02T01:00:00.000Z", "direction": "inbound",
 "sender_domain": "example.org", "recipient_domains": ["example.test"],
 "size": 48213, "tls": "TLS 1.3", "spf": "pass", "dkim": "pass", "dmarc": "pass",
 "remote_host": "", "remote_ip": "203.0.113.25", "connector": "",
 "delivery": "delivered", "source": "google-gmail-log"}
```

Only domains are kept: never an address, subject, attachment name, message
body or Message-ID (the ID groups a message's delivery stages while reading
and is then dropped). Events a person caused after delivery (opening,
moving, clicking) are not mail flow and are skipped. `tls` is the weakest
version recorded on the leg facing outside, `TLS (version not recorded)`
where Gmail recorded TLS without a version, and `none` where it recorded
none. `delivery` is the worst outcome any stage recorded: bounced, dropped,
rejected, quarantined, deferred, sent, delivered or accepted.

The fields are those of Google's
[Gmail log schema](https://support.google.com/a/answer/12384955); the
Reports API page documents only `event_info`, so how the rest is nested in a
response is not published. The reader accepts either nesting or dotted
names. A request may span at most 30 days, so longer periods are fetched in
30-day windows. Usage dates are Pacific time, and the latest days may not be
available yet; the response's warnings, kept in the notes, say which.

### Setting up the grant

1. In a Google Cloud project, enable the *Admin SDK API* and the *Gmail
   Postmaster Tools API*, and create an OAuth client of type *Desktop app*.
2. Store the client in the keychain, as the console's downloaded JSON on one
   line or as `CLIENT_ID:CLIENT_SECRET`. `security` prompts for the value, so
   it never appears on a command line:
   `security add-generic-password -s google-oauth-client -a takestock -w`.
   Alternatively set `$GOOGLE_OAUTH_CLIENT_ID` and `$GOOGLE_OAUTH_CLIENT_SECRET`.
3. Run `auth` and open the URL it prints, signed in as an administrator
   with the Reports privilege (and, for Postmaster Tools, as an account that
   has verified the domains). It asks only for
   `admin.reports.audit.readonly`, `admin.reports.usage.readonly` and
   `postmaster.traffic.readonly`, with PKCE, on a redirect to a listener on
   `127.0.0.1`. It stores the refresh token in the keychain item named by
   `--token-keychain` and prints which scopes were not granted, if any. It
   never prints a token.
4. `pull` mints a short-lived access token from the refresh token each run.
   Every secret reaches `curl` on standard input.

Listing Postmaster domains would need the `postmaster.domain` scope, which
can also add and remove them, so takestock does not ask for it: name the
domains with `--domain`. A project whose consent screen is for external users
and still in *Testing* status gets refresh tokens that expire in 7 days
([Google's OAuth overview](https://developers.google.com/identity/protocols/oauth2));
an internal consent screen avoids that. Run `auth` again when `pull` reports
`invalid_grant`.
