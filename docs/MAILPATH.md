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

## Limits

- DKIM selectors cannot be listed from DNS: the page reads the selectors seen
  in the headers and a list of common ones. A domain answering every selector
  with one record (a wildcard) is read once and shown as such.
- The headers describe only the mailboxes read; a census needs the platform's
  trace and the DMARC reports beside them.
- `--probe` connects to each MX host on port 25. Probe only hosts you are
  authorised to.
