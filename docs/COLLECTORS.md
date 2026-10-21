# Collectors

A **collector** gathers one kind of evidence and returns it as rows, together
with a list of what it could not vouch for. This guide lists every collector
takestock registers: what it reads or probes, what it needs in the target
profile, which external tools it uses, and what it cannot see.

Installing the external tools, and the authorisation record active probes
need, are in [`SETUP-SCANNERS.md`](SETUP-SCANNERS.md). Readers for standard
formats and named products' exports ship with takestock as its
[readers library](#the-readers-library). A reader for an export
takestock has no collector for can be written as a plug-in, in its own
package, and run in an observation as if it were built in; see
[`PLUGINS.md`](PLUGINS.md).

## Terms used here

- **Target profile**: the YAML file in the workspace's `targets/` that says
  what to collect for one organisation: its domains, the hosts it authorises
  probes against, and settings.
- **Row**: one finding, such as a TLS endpoint, a certificate or a DMARC
  record, graded later against the algorithm baseline.
- **Coverage gap**: a question a collector was meant to answer and could
  not, recorded so a report never reads as more complete than it is.
- **Kind**: how a collector gathers evidence.

| Kind | Means |
|---|---|
| `passive` | Reads public sources (DNS, mail-authentication records, certificate-transparency logs) or supplied files, and sends nothing to the organisation's hosts |
| `active` | Sends probes to hosts. Runs only when the target profile carries an `authorisation:` record; without one it contacts nothing and reports the refusal |
| `ingest` | Reads exports someone supplied in the inbox |

The registry is `takestock.collectors.REGISTRY`. Each entry names the
collector, its module, its kind and its entry point; modules are imported
only when asked for, so a collector whose tools are missing does not stop
the others loading.

## Summary

| Collector | Kind | Reads or probes | Needs in the profile | Tools |
|---|---|---|---|---|
| `ct_dns` | passive | certificate-transparency logs; MX, SPF, DMARC, MTA-STS, TLS-RPT and DKIM records; SPF, DMARC, wildcard DKIM and null MX on parked domains; a sweep of the sub-domain names beneath each email and parked domain | `discovery.domains`, `discovery.email_domains` | `dig`, `curl` |
| `spf_senders` | passive | each email domain's SPF record, expanded | `discovery.email_domains` | `dig` |
| `dnssec` | passive | DNSSEC signing and validation | `discovery.domains` or `email_domains` | `dig` |
| `dane` | passive | TLSA records for each mail server | as `dnssec` | `dig` |
| `caa` | passive | CAA records, against the certificates found | as `dnssec` | `dig` |
| `dns_zones` | passive | supplied zone files, checked against public DNS | optional `dns_zones:` settings | `dig` |
| `tls_scan` | active | TLS versions, cipher suites, key exchange and certificate on HTTPS endpoints | `scan_targets.vpn_gateways`, `tls_443`, `mail_self`, `saas_443` | `nmap`, `openssl` |
| `ike_scan` | active | IKE proposals a remote-access gateway accepts | `scan_targets.vpn_gateways` | `ike-scan` |
| `ssh_audit` | active | SSH algorithms on internet-facing listeners | `scan_targets.ssh_22` | `ssh-audit`, or `nmap` |
| `plaintext_scan` | active | whether named ports carry traffic in clear | `plaintext_ports`, or a derived-ports overlay | `nmap`, `curl` |
| `hsts` | active | the Strict-Transport-Security header | `scan_targets.tls_443`, `mail_self`, `saas_443` | `curl`, `dig` |
| `smtp_starttls` | active | STARTTLS on the inbound mail gateways | `scan_targets.smtp_25` | `openssl`; `nmap` for the certificate |
| `implicit_tls` | active | TLS on ports 465, 993 and 995 | the cleartext probe plan | `openssl`; `nmap` for the certificate |
| `smb_scan` | active, inside | SMB dialects and message signing | `scan_targets.smb_445` and `authorisation.smb_445` | `nmap` |
| `rdp_scan` | active, inside | whether remote desktop requires authentication first | `scan_targets.rdp_3389` and `authorisation.rdp_3389` | `nmap` |
| `ssh_audit_inside` | active, inside | SSH algorithms on internal hosts, in batches | `scan_targets.ssh_inside` and `authorisation.ssh_inside` | `ssh-audit`, or `nmap` |
| `internal_scan` | active, inside | TLS, STARTTLS and cleartext on named internal services, one host and port at a time | `scan_targets.internal_services` and `authorisation.internal_services` | `nmap`, `openssl`, `curl` |
| `intel_amt` | active, inside | whether Intel AMT firmware answers on 16992 and 16993, and over what | `scan_targets.intel_amt` and `authorisation.intel_amt` | `curl`; `nmap` and `openssl` for the TLS row |
| `ssh_audit_inbox` | ingest | `ssh-audit` JSON files someone ran and supplied | optional `ssh_inbox.dir` | none |
| `winrm_config` | ingest | a WinRM configuration export: whether each Windows host requires encrypted remote administration | optional `winrm_inbox.export` | none |
| `netdev` | ingest | a network device export: cryptographic controls on switches, routers, firewalls and management equipment | optional `netdev_inbox.devices` and `netdev_inbox.expect` | none |
| `software_inventory` | ingest | a software inventory: which cryptographic providers are installed, at which versions | optional `software_inbox.export` | none |

**Inside** probes run inside the organisation's network. Each needs its own
named, dated authorisation record as well as the profile's general one, and
each host must be named one at a time.

## Shared settings

### DNS services

The DNS and certificate-transparency collectors read
`src/takestock/data/dns-services.yaml` (or a workspace copy in `data/`), and
the target profile's `dns:` mapping overrides it key by key:

| Key | Used for | When empty |
|---|---|---|
| `resolvers` | Recursive resolvers to ask, by address. Two or more let a finding be corroborated | The machine's own resolver is asked, alone |
| `validation_control` | A public zone deliberately signed wrongly, to test whether a resolver validates DNSSEC | No resolver's validation can be confirmed, and `dnssec` records that instead of a reading |
| `ct_search_api` | A certificate-transparency search endpoint (see `ct_dns`) | Certificate transparency is not read, and the run records a coverage gap |
| `caa_issuers` | Certificate-authority names, lower case, mapped to the issuer domains they use in CAA records | Every issuer is reported as unmapped, never as unauthorised |
| `takeover_namespaces` | DNS suffixes a cloud provider documents as claimable by another customer, mapped to the service | Dangling records are reported without that claim |

The shipped file leaves every key empty. Fill them from the services'
own documentation.

### Where active probes point

Active probes read host lists from `scan_targets:` in the target profile:

| Group | Holds | Read by |
|---|---|---|
| `vpn_gateways` | Remote-access gateways: `{host, ip}` | `tls_scan`, `ike_scan`, `plaintext_scan` |
| `tls_443` | The organisation's published web hosts | `tls_scan`, `hsts`, `plaintext_scan` |
| `mail_self` | The organisation's own published mail hosts | `tls_scan`, `hsts`, `plaintext_scan` |
| `saas_443` | Services an outside provider runs for the organisation: `{host, port, vendor, ...}` | `tls_scan`, `hsts` |
| `smtp_25` | Inbound mail gateways: `{host, vendor, ...}` | `smtp_starttls` |
| `ssh_22` | Internet-facing SSH listeners: a host or address, `host:port`, `[v6]:port`, or `{host, ip, port}` | `ssh_audit`, `plaintext_scan` |
| `ssh_inside` | Internal SSH hosts: `{host, batch, port}` | `ssh_audit_inside` |
| `smb_445` | Internal file servers: a host or `{host, ip}` | `smb_scan` |
| `rdp_3389` | Internal remote-desktop hosts: a host or `{host, ip, port}` | `rdp_scan` |
| `internal_services` | Internal services: `{host, port, role}`, from a fixed list of ports | `internal_scan` |
| `intel_amt` | Internal machines whose management firmware to check: a host or `{host, ip}` | `intel_amt` |

Where an entry gives both `host` and `ip`, the address is probed. Every
active collector names its rows by one rule:

- a row's `host` is the host name when the profile gives one, and the address
  only when it gives nothing else;
- its `ip` is the probed address when the row is named by a host name, and is
  blank otherwise. It never holds a host name;
- its name reads `<label> <host>:<port>`.

A collector that probes hosts drawn from several groups (`plaintext_scan`,
`implicit_tls`) finds the name for an address in any `{host, ip}` entry in
`scan_targets`. An address that two entries give two different names stays
named by its address. The configuration register keys a machine by `host`
and records its address from `ip`, so two collectors that probed one entry
add to one item rather than making two.

Every key the profile can carry is listed in
[`TARGET-PROFILE.md`](TARGET-PROFILE.md).

## The passive collectors

### `ct_dns`

**Reads** two public sources, neither of which touches the organisation's
hosts:

- **Certificate transparency.** Every publicly trusted certificate is logged.
  For each domain under `discovery.domains`, it pages through the configured
  search service and writes one row per name found (with whether it resolves
  over IPv4, IPv6 or both) and one certificate row for the most recent
  certificate on each name. The raw answers are kept in the observation as
  `raw/ct-<domain>.json`, with a page record beside them.
- **Mail authentication.** For each domain under `discovery.email_domains`,
  it reads the MX, SPF, DMARC, MTA-STS (record and policy file), TLS-RPT and
  DKIM records, then sweeps the sub-domain names beneath the domain for the
  denying SPF, empty DKIM and DMARC records a name that sends no mail should
  publish. The names come from the transparency read, the zone files supplied
  in `inbox/dns-zones/` (owner names, and the names between an owner and the
  domain), the profile's `discovery` lists and `scan_targets`, and the names
  sender policies point at (`a:`, `mx:`, `include:`, `redirect=`). Each row
  keeps every name's sources in `extra.name_sources` and counts them in
  `extra.names_by_source`. Where the profile attests a domain's zone file
  complete (`dns_zones.complete_zones`), the rows carry that reading in
  `extra.population` and list in `extra.names_disagreeing_with_zone` any name
  the live reading and the files disagree on.
- **Name servers.** For every email and parked domain it reads the NS
  records, in a row of protocol `ns` named `NS <domain>`, whose
  `extra.name_servers` lists the hosts named (lower case, sorted): who hosts
  the domain's DNS. A settled lookup with no NS record in the answer (a name
  that is not the top of its own zone) gives an empty list. The lookup settles
  or fails as the SPF and DMARC lookups do.
- **The MTA-STS policy fetch.** When `_mta-sts.<domain>` answers, the policy
  is fetched from `https://mta-sts.<domain>/.well-known/mta-sts.txt` with
  `curl`, which validates the certificate and does not follow redirects. The
  `mta-sts` row keeps `extra.policy_http_status` (absent an answer, `null`),
  `extra.policy_certificate_valid` (`false` when `curl` refused the
  certificate, exit code 60 or 51; `null` when the fetch never reached it),
  `extra.policy_fetch_error` (`curl`'s own words) and, from a 200 answer only,
  `extra.policy_version`, `extra.policy_max_age`, `extra.mode` and `extra.mx`.
  A policy RFC 8461 would not accept (a certificate that does not validate, an
  answer other than 200, or no `version: STSv1` or valid `max_age`) carries
  the flag `mta-sts-policy-invalid`. The certificate is validated against the
  trust store of the machine running takestock, so a machine whose own store
  is broken would read every policy host as invalid; the row keeps `curl`'s
  message so a reader can tell.
- **Parked domains.** A domain under `discovery.domains` and not under
  `discovery.email_domains` is *parked*: it sends and receives no mail. For
  each one it reads SPF and DMARC the same way as for an email domain; the
  TXT record at `*._domainkey.<domain>`, in a row of protocol `dkim-wildcard`
  named `DKIM wildcard <domain>`, whose `extra.present` says whether a
  `v=DKIM1` record is published there and `extra.blank` whether it is the
  empty key `v=DKIM1; p=` (flag `no-dkim-wildcard` when absent,
  `dkim-wildcard-not-blank` when it is not the empty key); and
  MX, recording whether the domain publishes a **null MX** (an MX record of
  `0 .`, RFC 7505) in a row of protocol `null-mx`, named `Null MX <domain>`.
  Its flag is one of `null-mx:published`, `null-mx:no-mx`,
  `null-mx:mail-exchangers` (real mail servers, so the domain receives mail)
  and `null-mx:alongside-other-mx` (which RFC 7505 §3 forbids). It then
  sweeps the sub-domain names the transparency read found beneath the parked
  domain, as for an email domain, into the same three rows (`ned-spf`,
  `ned-dkim`, `ned-dmarc`). Every row for a parked domain, the sweep's
  included, carries `extra.parked: true`. The DKIM and MX lookups settle or
  fail as the SPF and DMARC lookups do, and a failure line names the domain as
  parked.

  Each sweep's rows list in `extra.names_nonexistent` the names read that
  answered NXDOMAIN. A receiver gives such a name the parent's DMARC `np=`
  policy (RFC 9989 §4.7) rather than its `sp=` policy.

  Each sweep also reads the DMARC record of every name between a swept name
  and the domain, which a receiver's policy discovery passes (the DNS Tree
  Walk of RFC 9989 §4.10), whether or not the logs listed that name. The
  `ned-dmarc` row keeps them in `extra.intermediate_dmarc` (name to record,
  `""` for none), the reads that did not settle in
  `extra.intermediate_unsettled`, and the swept names with no DMARC record of
  their own in `extra.names_without_own_dmarc`.

  Each sweep also writes a row of protocol `subdomain-mail`, named
  `Mail-handling sub-domains of <domain>`, whose `extra.names` holds, for each
  swept name that shows signs of handling mail, its SPF, DMARC and MX records,
  whether it exists, and why it was judged to handle mail. Each such name is
  then read as an email domain is: `mta_sts` (the `_mta-sts` TXT record and,
  when it is published, the policy file, with the same fields as an email
  domain's `mta-sts` row), `tls_rpt` (the `_smtp._tls` TXT record, its
  `published` and `rua`), `dkim` (each selector tried that answered: its
  `selector`, `key_bits`, `public_key`, the name it was read `via`, and
  `selector_from`), and
  `dkim_selectors_tried`. A lookup that did not settle leaves its reading out
  and is named, with the replies, in the name's `not_read` and in
  `extra.names_mail_records_not_read`. Only a name whose
  lookups were all answered and whose resolvers agreed is counted either way;
  the rest are listed in `extra.names_unread` and `extra.names_unsettled`, and
  are not read further.
  The sweep's absence control is trusted when it comes back NXDOMAIN, or when a
  published wildcard answered it with exactly the wildcard's own record and a
  random name under the reserved `invalid` domain came back NXDOMAIN;
  `extra.control_basis` says which (`nxdomain` or `wildcard`). A resolver that
  answers that reserved name with records invents answers, and the basis is
  then `resolver-synthesises`, with the control untrusted.

**Missing records.** The SPF, DMARC, MTA-STS and TLS-RPT records are each
asked of every configured resolver, keeping each resolver's response code.

- When the lookup **settles** (at least one resolver replied, and every reply
  was `NOERROR` or `NXDOMAIN`), a row is written whether or not the record
  exists. A missing SPF or DMARC record gives an **absence row**:
  `extra.present` is `false`, the row carries the flag `no-spf-record` or
  `no-dmarc-record`, and `extra.lookup` holds the name asked and each
  resolver's reply and time. A missing MTA-STS or TLS-RPT record gives a row
  saying it is not published.
- When the lookup **does not settle** (a reply carried another code, such as
  `SERVFAIL`, or no resolver replied), no row is written for that record and
  the run records one failure line per domain:

  ```text
  ct_dns example.test: DNS lookups that did not settle for DMARC (_dmarc.example.test: SERVFAIL), so those records are not measured: neither present nor absent is claimed
  ```

  It is a collector failure, so `observe` exits 2, and it is kept apart from
  the certificate-transparency failures.

DKIM is the exception: a selector that does not answer gives no row,
because selectors are guessed.

**Settings.** `ct_search_api` (see [DNS services](#dns-services)) must answer
`<endpoint>?domain=<name>&include_subdomains=true&expand=dns_names&expand=issuer&expand=pubkey`
with a JSON list of issuances, paged by `after=<id>`. An API token, if the
service issues one, is read from `TAKESTOCK_CT_TOKEN`, or on macOS from a
keychain item named `takestock-ct-token`; without one the service is asked
anonymously. `discovery.dkim_selectors` lists the organisation's own DKIM
selectors, tried before a short list of common defaults.

**DKIM selectors from zone files.** DNS offers no way to list DKIM
selectors, but a zone file holds every owner name. When zone files are
supplied (the `dns_zones` inbox folder), every `<selector>._domainkey.<name>`
they hold, where `<name>` is the email domain or a name beneath it, adds
`<selector>` to the selectors tried for that domain and its swept
sub-domains, after the profile's and before the defaults. The wildcard
`*._domainkey` is not a selector and is left out. Each DKIM row's
`extra.selector_from`, and each `selector_from` in a sub-domain's `dkim`
readings, lists where the selector came from: `target profile`, `zone file`
or `common default` (more than one when it was named in more than one
place).

**Rate limits.** Search services limit how often they may be asked. A
recent answer (up to two days old) whose read finished is reused from an
earlier observation instead of asking again, and reported as reused with its
age. When the service says "wait", the remaining domains can be parked and
finished later in the same run.

**Cannot see.** Names that never appeared in a public certificate (an
internal name, or a sub-domain nobody serves TLS on); whether a server
actually presents a logged certificate; DKIM selectors nobody named and no
supplied zone file holds, since DNS offers no way to list them. A selector a
zone file holds that public DNS does not answer gives no row, as for any
selector.

### `spf_senders`

**Reads** each email domain's SPF record and expands it through every
`include:`, `redirect=`, `a` and `mx` term, writing one row per domain that
describes the whole authorised sending surface: named hosts, address ranges,
the policies traversed, and where the record stands against RFC 7208's
limits of ten DNS-consuming terms and two lookups that return nothing.

When run with probing switched on and a probe supplied by the program that
calls it, it also checks STARTTLS on each relay the SPF record names (hosts
already listed under `scan_targets.smtp_25` are not probed twice). It
checks the authorisation record itself before probing: without a complete
one it contacts nothing and records the refusal as a gap.

A relay certificate is read as `smtp_starttls` reads one; without `nmap` it
is not read, and that is recorded as a coverage gap rather than a failure.

**Cannot see.** Which of the authorised senders actually send. A relay probe
measures what the relay accepts when it **receives**, never what it
negotiates when it **delivers**.

### `dnssec`

**Reads**, for every domain under `discovery.domains` and
`discovery.email_domains`, whether several resolvers authenticated its SOA
record, the DS record at the parent, the zone's DNSKEY records, its
signature validity windows, and how it proves a name does not exist (NSEC
or NSEC3).

A resolver's "authenticated" flag counts only if that resolver validates. So
each resolver is first asked about the validation control zone; only those
that answer SERVFAIL count as validators.

Each domain lands in one state: `signed` (DS at the parent, keys in the
zone, two or more validators authenticated it), `unsigned`, `island` (keys
in the zone, no DS at the parent), `bogus` (validators refuse every answer),
or `inconclusive` / `unreadable`. Algorithm and digest strength follow the
DNSSEC algorithm implementation requirements (RFC 8624 and its successors).

**Cannot see.** Anything without `dig`: the collector then reads nothing
and says so.

### `dane`

**Reads** the MX records of the same domains, then each mail server's TLSA
records at `_25._tcp.<mail server>` through several resolvers: which
servers publish one, whether the answers were authenticated, and whether the
certificate usages are ones an SMTP client may use (DANE-TA and DANE-EE
only, RFC 7672 §3.1.3).

The Secure Government Email framework sets no DANE requirement, so a domain
without DANE is recorded as a fact, not graded as failing.

### `caa`

**Reads** each domain's CAA record set through several resolvers: which
authorities it allows, whether wildcards follow the same list, whether a
reporting address (`iodef`) is published, and whether issuance is bound to
an account (`accounturi`, RFC 8657).

It then compares today's record with the certificates `ct_dns` found, so it
runs after `ct_dns`. For each certificate it finds the record set that
governs that name (climbing from the name towards the root, RFC 8659 §3) and
asks whether the certificate's issuer is on it, using `caa_issuers` to map
issuer names to CAA identifiers.

**Cannot see.** History: DNS keeps none, so a certificate issued before the
record changed can disagree with it honestly. An issuer missing from
`caa_issuers` is reported as unmapped, never as unauthorised.

### `dns_zones`

**Reads** zone files someone supplied in the inbox, under
`inbox/dns-zones/`: `<zone>.zone` files, `private/<zone>.json` record-set
exports for private zones, and an optional `_exported-at-utc.txt` holding
when the export was taken. It is registered as passive: it sends nothing to
the organisation's hosts, and its only queries go to the configured
resolvers. It reports:

- **dangling records**: an alias, mail or service record whose target no
  longer exists, confirmed by two or more resolvers answering NXDOMAIN, and
  flagged where the target sits in a namespace listed in
  `takeover_namespaces`;
- **undelegated zones**: a zone held for a sub-domain whose parent has no NS
  record pointing to it, so none of its records is ever served;
- **names nobody measured**: published names no other row of the run covers.
  The same row lists every published name (an address or alias record in a
  served zone) in `extra.dns_names`, so the configuration register holds one
  DNS Name for each without a row per name;
- **outside services**: services named by ownership-proof TXT records or as
  the target of a pointer, mapped to their operator where the profile or
  `data/vendor-domains.csv` knows it (the proof token itself is never kept);
- a **scope row** with record counts, duplicate SPF records, and whether
  the files' apex CAA agrees with the public CAA reading.

**Settings**, all optional, under `dns_zones:` in the profile:
`resolved_names` (a CSV of names endpoints resolved, to narrow "names nobody
measured"), `resolved_names_column` (default `name`), `proof_prefixes`
(TXT key to service name) and `second_level_labels` (further labels that sit
directly under a country code as part of a public suffix).

**Cannot see.** Zones held only on internal directory DNS servers, which a
public export never contains; this is always recorded as a gap. Without
`dig`, dangling targets cannot be checked and the gap says so.

## The active collectors

Every active collector checks the authorisation record before it contacts
anything. A missing or incomplete record produces one failure line,
`REFUSED, nothing contacted`, and no rows.

With `--carry-scan`, none of them runs: their rows are carried, unchanged and
dated when measured, from an earlier `--scan` observation of the same target,
and only a carried `plaintext_scan` row graded cleartext-served on an HTTP
port is re-checked (see `docs/ARCHITECTURE.md`, *Carrying earlier probe
rows*).

### `tls_scan`

**Probes** each endpoint in `scan_targets.vpn_gateways` (port 443),
`tls_443` and `mail_self` (port 443), and `saas_443` (its `port`, default
443):

1. enumerates versions and cipher suites with nmap's `ssl-enum-ciphers`;
2. confirms each version from TLS 1.0 to 1.3 with a pinned `openssl
   s_client` handshake, because `ssl-enum-ciphers` cannot enumerate TLS 1.3;
3. makes one default handshake, with Python's own TLS library, to read the
   key-exchange group the server actually chose;
4. reads the certificate with nmap's `ssl-cert`.

Raw transcripts are written beside the observation, with session secrets
redacted.

**Cannot see.** The chosen group says only what the server picked from what
this client offered: if the local TLS library offers no post-quantum group,
the row cannot say whether the server would have chosen one. A version the
pinned handshake could not ask about is flagged as unknown, not absent; one
the local `openssl` would not offer is recorded as
`unknown-client-cannot-offer`, never as refused (see
[SETUP-SCANNERS.md](SETUP-SCANNERS.md)). Without `nmap` the scan does not
run and the run records one failure saying so. An `nmap` run that fails for
one endpoint gives it an `unknown` row saying the scan did not complete,
never one that reads like a silent port.

### `ike_scan`

**Probes** each gateway in `scan_targets.vpn_gateways` with `ike-scan`, using
a bounded number of probes:

1. **the preferred transform**: offers IKEv1 Main Mode transforms weakest
   first, then strongest first, for each authentication method in turn. If
   both orders get the same answer, the gateway enforces its own preference;
   if not, the client chooses, and a client that offers a weak transform
   first gets it;
2. **the floor and ceiling on each axis**: holding the preferred transform
   fixed, varies encryption, hash and Diffie-Hellman group one at a time. An
   accepted value weaker than the preferred one is a **downgrade surface**:
   an attacker on the path can force it;
3. **an IKEv2 answer**: one `IKE_SA_INIT` with ike-scan's default offer.

**Settings**, from the environment: `TAKESTOCK_IKE_SCAN` (the executable,
else `ike-scan` on `PATH`), `TAKESTOCK_IKE_MAX_PROBES`,
`TAKESTOCK_IKE_PROBE_DELAY` (seconds), `TAKESTOCK_IKE_RETRY` and
`TAKESTOCK_IKE_TIMEOUT_MS`.

**Cannot see.** A sweep that ran out of budget, hit an error, or got silence
where the gateway otherwise answers refusals is reported as a failure,
because its minimum and maximum then cover what was asked, not what the
gateway accepts. Without `ike-scan`, each gateway gets an `unknown` row and a
coverage gap.

### `ssh_audit`

**Probes** the listeners in `scan_targets.ssh_22` for their host keys, key
exchange, ciphers and MACs. It never attempts a login.

**Entries** take any of these forms; the port defaults to 22:

```yaml
scan_targets:
  ssh_22:
    - ssh.example.test                 # a host or address
    - ssh.example.test:2222            # host:port
    - "[2001:db8::22]:2222"            # an IPv6 address with a port, in brackets
    - {host: ssh2.example.test, ip: 203.0.113.22, port: 22}
```

A bare IPv6 address is taken whole, because its colons cannot be told from a
port separator. In the mapping form the address is probed and the row is
named after the host, with the address beside it.

**Tools.** `ssh-audit` is preferred (`TAKESTOCK_SSH_AUDIT` names it, else
`PATH`). Without it the probe falls back to nmap's `ssh2-enum-algos`, which
reads the same algorithm lists but not the banner, key sizes or known
vulnerabilities, and the row says so. With neither, each host gets an
`unknown` row saying no probe was sent.

### `plaintext_scan`

**Answers** one question per host and port: is something listening here that
carries its traffic in clear? It never sweeps ports. Every host and port
comes from the target's own files, and the whole plan is printed (and saved
beside the observation) before anything is contacted.

**The plan** comes from, in order:

1. a `probe_list:` in the derived-ports overlay beside the profile,
   `targets/<stem>.derived-ports.yaml`:

   ```yaml
   derived_ports:
     probe_list:
       web:
         hosts_from: scan_targets.tls_443
         ports: [80/tcp, 8080/tcp]
         basis: Web hosts commonly answer plain HTTP on these ports.
       budget: {hosts: 2, tcp_pairs: 4, udp_pairs: 0}
   ```

   Each section names one `scan_targets` group the profile already
   authorises, single `<port>/<transport>` entries, and a `basis` saying why
   those ports. The `budget` must match what the plan computes, so a host
   list edited without redoing the arithmetic is caught;
2. otherwise the profile's own `plaintext_ports:` list, applied to every host
   in `vpn_gateways`, `tls_443`, `mail_self` and `ssh_22`.

Applied this way, an `ssh_22` entry contributes its host only: the port in
`host:port` or `[v6]:port` is dropped, and a `{host, ip}` entry contributes
its address (the rows are still named after the host). A derived section's
`hosts_from` group is read the same way, and two entries for one host in a
group are one host.

**Refuses** (contacting nothing): ranges, comma lists or wildcards in a port;
more than 12 ports on a host, 60 hosts, or 400 host-and-port pairs in all
(refused, never truncated); a section with no basis or no TCP port; a host
claimed by two sections; a budget that does not match; and a derived plan
that would stop probing a pair the profile's own list authorises.

**Measures** with one slow `nmap -sT` connect scan per host, with the
`http-title` script. Where that reads a page on an HTTP port, one explicit
`curl http://` request confirms it, because nmap retries over TLS by itself
and a page title alone does not prove cleartext.

**Cannot see.** UDP ports are listed in the plan but not probed: the
collector speaks one scan type, an ordinary TCP connection. Port 25, and
ports where `data/port-encryption.csv` says encryption is inherent, produce
no cleartext row: whether they are encrypted is not the question, and how
strongly is for a scanner that grades encryption (`smtp_starttls` for port 25,
`implicit_tls` for 465, 993 and 995).
A port that gave no answer is unmeasured, never read as closed.

### `hsts`

**Probes** each host in `tls_443` and `mail_self`, then each `saas_443` host,
with one HTTPS request to `/` using `curl`, and grades the
`Strict-Transport-Security` header (RFC 6797):

| Header | Grade |
|---|---|
| absent, malformed, or `max-age=0` | weak |
| `max-age` under one year | acceptable, flagged |
| `max-age` of one year or more | acceptable; `includeSubDomains` and `preload` recorded |
| no HTTPS answer | unknown |

The grade never reaches `strong`: HSTS limits a downgrade of the first
request; it does not make the session stronger. The collector also records
the HTTP version that answered, any `Alt-Svc` advertisement, and the DNS
HTTPS record (RFC 9460), so a reader can see whether HTTP/3 is advertised.
DNS is asked of the resolvers every DNS collector shares (`resolvers` in the
profile's `dns:` block), else the system's resolver.

A provider's endpoint is often many machines behind one name, so each
`saas_443` host is read several times (default 3,
`TAKESTOCK_HSTS_THIRD_PARTY_READS`) and the weakest reading is reported, with
a flag when they disagree. Cookies, authorisation headers and per-request
trace ids are redacted from the saved capture.

### `smtp_starttls`

**Probes** each gateway in `scan_targets.smtp_25` with
`openssl s_client -starttls smtp`, once per version from TLS 1.0 to 1.3, and
records which versions the gateway agreed and which suite and key-exchange
group it chose.

**Concludes** a measured cleartext finding when a gateway answers EHLO
without offering STARTTLS. **Cannot see** every suite a gateway would accept:
a pinned handshake shows the one it chose at that version, so the row records
a preference, not a floor. A gateway that could not be reached is reported as
a failure, never as clean.

**The certificate.** Where a session was agreed, nmap's `ssl-cert` reads the
certificate's key, names and expiry, and a certificate that does not carry
the name the gateway was reached by is flagged `cert-name-mismatch`. Without
`nmap` the TLS rows still stand, but the certificate is not read: each such
row's notes say its key, names and expiry are unknown (not clean),
`extra.cert_detail` reads `not read: nmap is not on PATH`, and the run
records one failure line naming every endpoint affected.

### `implicit_tls`

**Probes** ports 465 (SMTPS), 993 (IMAPS) and 995 (POP3S), where TLS starts
with the first byte (RFC 8314), with a direct handshake per TLS version, and
reads the certificate. It takes its host-and-port pairs from the cleartext
probe plan, so it contacts nothing that plan has not named, and a plan that
`plaintext_scan` refuses is refused here too. It keeps four answers apart: a
session agreed (graded), something answered without completing a handshake
(flagged), connection refused (nothing listens), and no answer (unmeasured,
never read as closed).

The certificate is read, and a missing `nmap` reported, as for
`smtp_starttls`.

### `smb_scan` (inside)

**Probes** each host in `scan_targets.smb_445` with nmap's `smb-protocols`,
`smb2-security-mode` and `smb-security-mode` scripts on 445/tcp, and writes
two rows per host:

- **SMB dialects**: every dialect the server accepted, graded on the weakest
  (SMB1 is weak);
- **SMB signing**: required is acceptable; enabled but not required is
  acceptable with a flag, because a client that does not insist gets an
  unsigned session; disabled is weak.

It never authenticates, lists shares or users, or runs a vulnerability
script. nmap also sends one NetBIOS name query to 137/udp before
negotiating, and the printed budget says so.

### `rdp_scan` (inside)

**Probes** each entry in `scan_targets.rdp_3389` (port 3389 unless the entry
gives one) with nmap's `rdp-enum-encryption` script, which offers each
remote-desktop security layer in turn. The question is whether
**network-level authentication** (NLA: authentication before a session
exists) is enforced:

| The server accepts | Grade |
|---|---|
| native RDP security or plain TLS | weak: anyone is shown a login screen before authenticating |
| only CredSSP | acceptable (never strong: the TLS underneath is not measured here) |
| no negotiation data | unknown |

Native RDP security's own ciphers are recorded and graded too. It never
sends a credential or attempts a login.

### `ssh_audit_inside` (inside)

**Probes** internal SSH hosts listed in `scan_targets.ssh_inside`. Each entry
names a `host` and a `batch` (and optionally a `port`): batches are named by
the operator, never assigned by the tool, and run one after another (at most
three batches of 60 hosts), one host at a time with a pause between hosts
and a longer one between batches. The whole plan is printed before anything
is contacted. Tools as for `ssh_audit`.

### `internal_scan` (inside)

**Probes** named services inside the network for TLS, STARTTLS and
cleartext, one host and port at a time. It reads
`scan_targets.internal_services` and needs `authorisation.internal_services`
beside the profile's general record. Each entry names one host and one port,
and optionally a `role`, which becomes the row's description:

```yaml
scan_targets:
  internal_services:
    - {host: dir-01.example.test, port: 636}
    - {host: mail-01.example.test, port: 143, role: Staff mailbox retrieval}
```

**Refuses** (contacting nothing): a port that is not on the allow-list
below, an `ip:` key (name the host to probe in `host:`), a port that is not
one number, a host named twice on the same port, and lists over the
cleartext probe's ceilings (60 hosts, 12 ports on a host, 400 pairs). Adding
a port is a code change, not a profile edit.

**The allow-list**, and how each kind of port is measured:

| Kind | Ports | Measured with |
|---|---|---|
| TLS from the first byte | 443, 465, 636, 993, 995, 3269, 5986, 8443 | As `tls_scan` measures 443: nmap's suite enumeration, one pinned `openssl` handshake per version, one default handshake and nmap's `ssl-cert`. An open port that completes no handshake is then asked one plain `http://` request with `curl` |
| LDAP with StartTLS | 389 | nmap's `ssl-enum-ciphers` and `ssl-cert`, which send the StartTLS operation themselves. No pinned handshake is made, so TLS 1.3 is marked unknown |
| STARTTLS mail | 25, 110, 143, 587 | Two rows. The session row: nmap's suite enumeration over STARTTLS plus one pinned `openssl -starttls` handshake per version. The sign-in row: the capability list read on the plain connection |
| HTTP | 80, 5985, 8080 | One port-state probe with nmap, then one explicit `http://` request with `curl` |

**The sign-in row** asks whether a password is invited before encryption:
IMAP `LOGIN` without `LOGINDISABLED`, or `AUTH=PLAIN` / `AUTH=LOGIN`; POP3
`USER`, or a `PLAIN` or `LOGIN` SASL mechanism; SMTP `AUTH PLAIN` or
`AUTH LOGIN`. Any of these makes the row weak, flagged
`cleartext-auth-offered:<protocol>`, read against RFC 3501 § 6.2.3 (IMAP),
RFC 4954 § 4 (SMTP) and NZISM 16.1.33.C.01. A STARTTLS service whose
capability list names no STARTTLS is a measured cleartext finding.

**On the WinRM ports** (5985 and 5986) it also sends one unauthenticated
`POST /wsman` and records the authentication schemes the `401` answer
offers, including whether Basic is offered over plain HTTP. That moves no
verdict: an offered scheme is not an accepted one.

**Tools.** `nmap` always; `openssl` when the plan has a TLS or STARTTLS
port; `curl` when it has a TLS or HTTP port. If any needed tool is missing,
no pair is probed and the run records one failure saying so. The plan is
printed, and saved as `raw/internal-budget.txt`, before anything is
contacted.

**Cannot see.** A `400` answer to a plain request is not taken as cleartext,
because a TLS server commonly answers that way on its TLS port. A sign-in
row says what the service advertises, not what it would accept from a client
that ignored the list. A pair for which nmap produced no port table gets an
`unknown` row and a failure line, never a clean one. It never authenticates
or sends a credential.

### `intel_amt` (inside)

**Asks** whether Intel Active Management Technology (AMT), the out-of-band
management interface built into some machines' firmware, answers on the
network. AMT runs below the operating system on its own ports, so a listener
inventory taken from the operating system cannot show whether the firmware
answers. It reads `scan_targets.intel_amt` (a host, or `{host, ip}`; the
address is probed and reported) and needs `authorisation.intel_amt`.

**Sends** one unauthenticated `GET /` per port with `curl`: 16992 as
`http://`, 16993 as `https://` with the certificate not checked, because the
question is identification, not trust. Hosts go one at a time, two seconds
apart. The ports are fixed in code; a profile cannot add one. Where the 16993
request reached something, the `tls_scan` measurement follows as a second
row, `Intel AMT TLS <host>:16993`, graded by the baseline. It never sends a
credential, answers a Digest challenge, or tests for a vulnerability.

**Recognises** AMT by the `Server:` header, against the strings nmap's
service-detection database uses for it: `Intel(R) Active Management
Technology <version>`, `Intel(R) Standard Manageability <version>` and `AMT`.

| Outcome (`extra.amt_outcome`) | Means | `extra.amt_listener_finding` |
|---|---|---|
| `amt-answered` | AMT's `Server:` header came back. On 16992 the row is graded weak through the port table, which records that port as the management interface in clear; on 16993 the row stays `unknown` and the TLS row carries the strength | `confirmed` |
| `other-http` | An HTTP answer from something that is not AMT | `not-confirmed` |
| `no-http-answer` | A connection was made and no HTTP answer came back | `not-confirmed` |
| `no-connection` | Refused or no route; `curl` does not say which | `not-confirmed` |
| `no-answer` | The attempt timed out, so nothing is measured | `unmeasured` |

The listener finding is there to compare with a listener inventory.

**Tools.** `curl`; without it nothing is probed and the run records one
failure. `nmap` and `openssl` for the TLS row; without either, the TLS row is
skipped on every host, one failure says so, and the `curl` rows stand. A
host name that does not resolve is a failure for that host, and its ports
are not probed.

**Cannot see.** A `not-confirmed` is scoped to where the probe ran from: AMT
answers only on the interface its firmware is provisioned on, so it is
narrower than "AMT is off".

## The ingest collectors

### `ssh_audit_inbox`

**Reads** `ssh-audit -jj` JSON files someone ran against hosts takestock
cannot reach, one file per host, from `inbox/ssh-audit/` (or the folder
named by `ssh_inbox.dir`). Each file's `target` field names the host; the
file's modification date is recorded as when the evidence was collected.

**Cannot see** anything not supplied: a missing or empty folder is recorded
as a coverage gap saying the internal SSH configuration was not checked.

### `winrm_config`

**Reads** a Windows Remote Management (WinRM) configuration export and says,
per Windows host, whether the host *requires* encrypted remote
administration. WinRM listens on 5985 (HTTP) and 5986 (HTTPS). A listener on
5985 proves neither an exposure nor its absence: with the default Negotiate
authentication (Kerberos, or NTLM where Kerberos is not available) WinRM
encrypts each message itself, so the session is protected although the HTTP
transport is plain. Two service settings switch that protection off, and only
the configuration shows them.

**The export** is a CSV, `inbox/winrm-config.csv` unless
`winrm_inbox.export` names another file, one row per host. Columns are
matched case-blind:

| Column | Holds |
|---|---|
| `hostname` (or `computername`, `host`, `name`) | The host |
| `host_id` (or `device_id`, `asset_id`) | Optional: a stable identifier that survives a rename; preferred for matching rows |
| `allow_unencrypted_service`, `basic_service` | The two settings that decide the verdict |
| `allow_unencrypted_client`, `basic_client`, `credssp_service`, `https_listener` | Context |

Each setting reads `true` or `false` (also `1`/`0`, `yes`/`no`, `on`/`off`,
`enabled`/`disabled`). PowerShell gives them from
`Get-Item WSMan:\localhost\Service\AllowUnencrypted` and its siblings under
`Service\Auth` and `Client`.

**Grading**, one row per host on port 5985:

| Verdict | When |
|---|---|
| weak | The service accepts unencrypted messages, Basic authentication is enabled on the service, or the host as a client will send unencrypted messages. None of these is a Windows default |
| acceptable | Both deciding service settings were read and both are protective. Never strong: these are on/off settings, not graded algorithms |
| unknown | A deciding setting is blank or unreadable. A blank cell is a setting nobody collected, never a setting that is off |

Basic authentication on the **client** is on by default in Windows, so it is
recorded and explained but never flagged. CredSSP on the service is flagged
`winrm-credssp-service` (it passes the caller's credentials on to further
systems) without moving the verdict, which is about encryption. An HTTPS
listener is recorded and moves nothing: it does not close the plain-HTTP
path. The row is dated by the export file's modification date.

**Coverage gaps.** A missing or unreadable export is one gap. So are rows
that name no host or repeat one (the first row for a host wins), hosts whose
deciding settings are blank, and hosts another collector in the same run saw
listening on 5985 that the export does not cover. That last check reads the
run's other rows, so `winrm_config` runs after the probes.

### `netdev`

**Reads** cryptographic controls on network and out-of-band management
equipment (switches, routers, firewalls, wireless controllers, server
management processors, wide-area links) from a supplied export, one row per
**control** on one device or link. No outside probe reaches these settings.
The export uses a small vendor-neutral vocabulary: whoever holds the
configuration writes each control down in it, and nothing here parses a
vendor's configuration language, so a change between firmware releases
cannot silently stop a control being found.

**The export** is a CSV, `inbox/netdev-controls.csv` unless
`netdev_inbox.devices` names another file. Columns are matched case-blind:

| Column | Holds |
|---|---|
| `device` | Required: the device or link name |
| `control` | Required: one of the controls below |
| `device_class` | `switch`, `router`, `firewall`, `wireless`, `vpn-gateway`, `out-of-band`, `wan-link`, `storage` or `other` |
| `state` | `enabled` or `disabled` and their synonyms (`on`, `off`, `yes`, `no`, `configured`, `cleartext` and the like); blank or `unknown` is unknown |
| `algorithms` | `;`-separated tokens, bare (`aes256-ctr`) or placed in a baseline table (`ssh_kex=curve25519-sha256`) |
| `key_custody` | Who holds the keys (`device`, `hsm`, ...) |
| `vendor`, `peer`, `site`, `evidence`, `collected_on` | Context. `collected_on` dates the row; otherwise the file's modification date does |

| Control | What it is | Graded as |
|---|---|---|
| `ssh-mgmt` | The administrative login service | SSH key exchange, cipher, MAC and host key |
| `tls-mgmt` | The management web service | TLS versions, key exchange, signatures, ciphers, hashes |
| `ipsec` | An encrypted tunnel to another network | IKE encryption, Diffie-Hellman group, PRF |
| `macsec` | Link encryption between two devices | Cipher |
| `wifi` | A wireless network's over-the-air protection | Cipher, hash |
| `radius` | The network access authentication service | As `tls-mgmt` |
| `snmp` | The monitoring service | Cipher, hash |
| `wan-link` | A link across a network someone else runs | Cipher |
| `at-rest` | Data stored on the equipment | Cipher |
| `key-storage` | Whether a hardware key store holds the keys | Not graded: recorded as `hardware-key-store:present`, `absent` or `unknown` |

Common spellings are mapped to the names the baseline grades, as naming
differences only: MACsec `gcm-aes-128` and `gcm-aes-256` to AES-GCM, Wi-Fi
`ccmp` to AES-128-CCM and `gcmp-256` to AES-256-GCM, `tkip` and `wep` to RC4,
and an `open` network to no cipher. A bare token is placed only when the
tables that know it agree on its grade; otherwise it is flagged
`ungraded:netdev:<token>`.

**Grading** is the baseline's. Two verdicts no table can express are set
here: a control recorded **off** is weak (`encryption-off`), and a control
recorded **on** that names no algorithm stays unknown, flagged
`algorithms-not-recorded`. A control that names only some of the tables it
should is flagged `algorithms-partial:<table>`; that flag never changes the
verdict. A weak management service (`ssh-mgmt`, `tls-mgmt`, `snmp`) carries
advice on putting it behind a management network or jump host, or a reverse
proxy, where the device offers nothing stronger.

**Coverage.** `netdev_inbox.expect` lists the device classes the export
should cover (default: switch, router, firewall, wireless, out-of-band).
With no export there is one gap for the file and one per expected class.
With an export, each expected class that has no row is its own gap, rows
naming no device or no control are a gap, and a **scope row** states what the
export covers (controls, devices, classes present and absent) without
claiming a share of the estate. A missing or unreadable export never stops
the run.

### `software_inventory`

**Reads** a software inventory: one row per product installed on one
machine, as any inventory tool or a spreadsheet can produce. The probes
measure what a service negotiates; this reads what it negotiates *with*: the
TLS libraries, language runtimes and other cryptographic providers installed
on each machine.

**The export** is a CSV, `inbox/software-inventory.csv` unless
`software_inbox.export` names another file. Header names are matched
ignoring case, spaces, hyphens and underscores, and the first spelling
present wins:

| Column | Also read as | Holds |
|---|---|---|
| `host` | `hostname`, `computer name`, `computer`, `machine`, `device`, `server` | Required: the machine, by name or address |
| `product` | `product name`, `name`, `software`, `application`, `display name`, `package` | Required: the product as the inventory spells it |
| `version` | `product version`, `software version`, `display version`, `package version` | The installed version |
| `vendor` | `publisher`, `manufacturer` | Context |
| `path` | `install path`, `install location`, `location`, `file path` | Context: where the copy is installed |

**Matching.** Each product is matched against
`src/takestock/data/crypto-software.csv`. The first entry whose `match`
expression matches the start of the product name, ignoring case, names the
provider; a product no entry matches is counted on the scope row, named
in its product list, and not graded. An entry with a `branch` describes one release line of
its provider. It applies to a version that equals the branch, or continues
it with something other than a digit, once a packaging epoch such as `1:` is
set aside:

| Branch | Takes | Does not take |
|---|---|---|
| `1.0` | `1.0`, `1.0.2`, `1:1.0.2-fips` | `1.01` |
| `3` | `3.0.0` | `30.0` |

When several branches match, the longest wins, so `1.0.0` can describe a
narrower line than `1.0`. The entry's `max_tls` is the highest TLS version
that line can negotiate, and its `citation` is the public source for it.

**Rows.** One per provider and version, named `<provider> <version>`, with
the number of machines that carry it in `hosts_count` and their names in
`extra.hosts`, and again as a list in `extra.installed_on`, which the
configuration register reads. A machine name with a space in it cannot be one
host name, so it is counted in `hosts_count` and left out of `installed_on`.
The row has no `host` of its own, because it describes every machine on the
list. Machines are named by the one rule above: an address
that `scan_targets` pairs with a host name is reported by that name, so a
machine listed once by name and once by address is counted once.

| The release line | Flag | Verdict |
|---|---|---|
| caps below the baseline's floor (the lowest TLS version it grades better than weak) | `capability-ceiling:<max_tls>` | weak: nothing it negotiates can reach the floor |
| caps below TLS 1.3, at or above the floor | `capability-ceiling:<max_tls>` | unknown |
| reaches TLS 1.3 | none | unknown |
| is not on record for this version | `ungraded:crypto-software:<provider> <version>` | unknown |

A verdict stays unknown wherever the ceiling is not itself weak, because an
installed version says the most a service using it can do, not the least it
will accept. A provider found at two or more versions gets one more row,
`<provider> version spread`, flagged `version-spread:<n>` and graded `n/a`.
These are the two flags the agility reading places: a ceiling puts the row
in `replacement`, a spread in `library`.

**Lifecycle.** Each provider and version is graded against
`data/software-lifecycle.yaml` by the same function that grades any software
inventory row (`lifecycle.derive_census_support`), as a library and as an
application, under the provider's name and each spelling the export used, on
the export file's modification date. Exactly one matching lifecycle line
sets `support_status` (and `support_end` where the line gives a date it holds
to); none, or more than one, leaves both blank. A status declared in the
profile's `lifecycle:` block still wins.

**Coverage gaps.** A missing or unreadable export, one with no host or no
product column, and one with no data rows are each one gap, and the
collector then writes no rows. Rows naming no machine or no product are a
gap, and so are provider rows with no version (each kept as
`<provider> (version not recorded)`, flagged `version-unrecorded`). A
**scope row** states how many rows and machines the export lists and how
many rows named a provider, without claiming a share of the estate. It
names every product the export lists, cryptographic or not, in
`extra.software_products`: a provider by its register name, any other
product as the export first spells it. When machine names were left out of
`installed_on`, `extra.installed_on_skipped` gives how many machines and why.

**Cannot see.** A provider the register does not list; a library compiled
into another program, since an inventory lists installed packages, not what
a binary contains; and what any service using an installed provider actually
negotiates, which is for the probes.

## The readers library

takestock also ships readers for standard formats and for the exports of
named products, in `takestock.readers`. Each is a plug-in
([`PLUGINS.md`](PLUGINS.md)) that comes with takestock: a target profile
runs one by naming it in its `plugins:` list, and never otherwise. Its
`input:` there says which file or folder it reads, in place of the reader's
default.

```yaml
plugins:
  - name: sbom
    input: inbox/sbom          # a folder of CycloneDX JSON files, or one file
```

| Reader | Kind | Reads | Default input |
|---|---|---|---|
| `sbom` | `general` | CycloneDX software bills of materials (JSON): the cryptographic, identity and transport components an application declares | `inbox/sbom` |
| `oracle_tde` | `database-encryption` | An Oracle Database administrator's CSV export of Transparent Data Encryption state: keystore status and type, and encrypted tablespaces | none: name it with `input:` |
| `commvault` | `backup-encryption` | A CSV of Commvault storage policy copies' software encryption: cipher, key length and key custody | none: name it with `input:` |
| `exchange_online` | `general` | An export of Exchange Online settings (anti-phishing policies and rules, connectors, quarantine policies, DKIM signing), read for three Secure Government Email requirements | none: name it with `input:` |
| `vmware` | `general` | A CSV of vSphere VM Encryption and vSAN encryption state, one row per virtual machine or vSAN cluster, written with PowerCLI | none: name it with `input:` |
| `rvtools` | `general` | RVTools workbooks: virtual machines' firmware and secure boot, configured guest types and ESXi versions (no encryption data) | none: name a workbook or a folder with `input:` |
| `vsphere_lists` | `general` | The vSphere Client's exported lists of virtual machines, hosts and datastores: VM encryption, virtual TPM, virtualisation-based security, guest types, ESXi versions, host certificate expiry and what backs each datastore | none: name the folder with `input:` |

A reader with no default input still runs when the profile gives it none,
and records in its own coverage gap that no export was read. A profile that
names an input which does not exist gets takestock's general gap for a
missing input instead.

### `sbom`

**Reads** CycloneDX software bills of materials in JSON
([the specification](https://cyclonedx.org/specification/overview/), also
published by Ecma International): one file, or every `*.json` file directly inside a
folder, in name order. Build tools for most languages can write one. A file
whose `bomFormat` is not `CycloneDX` is not read.

**Classes.** Each component's name, and its group where the ecosystem has
one, is split into words at `.`, `-`, `_`, `/`, `@`, `:`, `+` and spaces, and
the words are looked up in six classes, in this order; the first class with a
match wins. The words are common package names across ecosystems, listed in
`takestock/readers/cyclonedx.py` (`CLASSES`).

| Class | Label | Pre-release flagged |
|---|---|---|
| `ssh` | secure-shell | yes |
| `key-management` | key and secret management | yes |
| `primitives` | cryptographic library | yes |
| `tokens` | security-token | yes |
| `identity` | authentication and identity | yes |
| `transport` | data-transport client (databases, caches, message queues) | no |

Whole words only, so `example-cryptic-names` is not a cryptographic library.
Components nested inside other components are read too.

**Rows.** For each bill of materials, one row per classified component,
named `<component> <version>`, then one for the application, named
`Application <name> <version>` from `metadata.component` (the file's name,
less its last extension, when the document names none). After every file, one scope row, `Application-layer
SBOM scope`. All have data state `discovery` and protocol `software`. A
component row is `unknown` and the others `n/a`: a bill of materials says
what is present, not how it is used.

| Flag | On |
|---|---|
| `sbom-declared-dependency`, `sbom-provides:<class>` | every component row |
| `sbom-direct-dependency` | a component the application lists itself in the `dependencies` graph |
| `sbom-prerelease-crypto` | a pre-release version (`-beta.1`, `-rc.2`, `-preview`, `-SNAPSHOT`, `2.0b1`, `.dev3`) of a component in a flagged class |
| `sbom-app-can-originate:ssh` | an `ssh` component: the application can open SSH connections itself |
| `sbom-encrypts-by-default` | a library whose documented default is to encrypt its connections, from the version that default began (`ENCRYPTS_BY_DEFAULT`, each entry with its public source). It never improves a verdict, because a connection string can turn it off |
| `sbom-subject`, `sbom-scope` | the application row, the scope row |

Every flag but `sbom-prerelease-crypto` is informational. A component row's
`extra` holds `sbom_subject`, `provides`, `purl` and `spec_version`; the
application row's holds the counts of its components, of those classified,
of those with an integrity hash and of its direct dependencies; the scope
row's, the bills of materials read and the components and classified
components across them.

**Dates.** Each application's rows are dated by its document's
`metadata.timestamp`, when the bill of materials was made, else by the
file's modification date. The scope row summarises what was read and is
undated.

**Coverage gaps.** A file that is not JSON or not CycloneDX; a folder with
no `.json` file; and, whenever at least one was read, the applications with
no bill of materials here, because each one describes only the software it
was made from.

**Cannot see.** What the running application does: a listed library may
never be called, and a feature may be off. Components no class matches,
which are counted and not reported. The XML form of CycloneDX, and a
document's `cryptoProperties`, `services` and `vulnerabilities`.

### `oracle_tde`

**Reads** a CSV export of Oracle Database's Transparent Data Encryption
(TDE) state, one row per database, made by a database administrator from
the dynamic performance views Oracle Database Reference documents:
`V$ENCRYPTION_WALLET` (the keystore), `V$ENCRYPTED_TABLESPACES` (each
encrypted tablespace and its algorithm), `DBA_TABLESPACES` (every
tablespace), `V$DATABASE` and `V$INSTANCE`. It needs only read access to
those views (`SELECT_CATALOG_ROLE` should be enough). This query writes the columns
the reader reads; save its result as CSV with headings, for example with
SQLcl's `SET SQLFORMAT CSV` or SQL*Plus's `SET MARKUP CSV ON`:

```sql
SELECT d.name              AS db_name,
       d.db_unique_name    AS db_unique_name,
       i.host_name         AS host,
       w.wallet_type       AS wallet_type,
       w.status            AS wallet_status,
       w.wallet_order      AS wallet_order,
       w.wrl_parameter     AS wrl_parameter,
       e.algorithms        AS tablespace_encryption_alg,
       NVL(e.encrypted, 0) AS encrypted_tablespace_count,
       t.total             AS tablespace_count
FROM v$database d
CROSS JOIN v$instance i
LEFT JOIN v$encryption_wallet w ON 1 = 1
CROSS JOIN (SELECT LISTAGG(alg, '/') WITHIN GROUP (ORDER BY alg) AS algorithms,
                   SUM(n) AS encrypted
            FROM (SELECT encryptionalg AS alg, COUNT(*) AS n
                  FROM v$encrypted_tablespaces
                  WHERE encryptedts = 'YES'
                  GROUP BY encryptionalg)) e
CROSS JOIN (SELECT COUNT(*) AS total FROM dba_tablespaces) t;
```

Run it on each database. In a multitenant container database, run it in each
pluggable database and add a `pdb_name` column holding that database's name,
so each row is told apart. A database with more than one keystore gives one
row per keystore. The query was written from Oracle's documentation of the
views and has not been run here against a database.

| Column | From | Read for |
|---|---|---|
| `db_name`, `db_unique_name`, `pdb_name` | `V$DATABASE`, and the pluggable database's name | The row's name: the unique name, else the name, else the host |
| `host` | `V$INSTANCE.HOST_NAME` | The row's host |
| `wallet_type` | `V$ENCRYPTION_WALLET.WALLET_TYPE` | Key custody |
| `wallet_status` | `V$ENCRYPTION_WALLET.STATUS` | Whether the keystore is open |
| `wallet_order`, `wrl_parameter` | `V$ENCRYPTION_WALLET` | Kept in `extra`; the location is a directory or a key manager's address, never a key |
| `tablespace_encryption_alg` | `V$ENCRYPTED_TABLESPACES.ENCRYPTIONALG`, joined with `/` | The algorithms graded |
| `encrypted_tablespace_count`, `tablespace_count` | counts of the two tablespace views | Whether any, and how many, tablespaces are encrypted |

Headings are matched without regard to case, spaces or hyphens, and common
synonyms are read too (Oracle's own `status`, `encryptionalg`, `con_name`,
`host_name`; `COLUMNS` in `takestock/readers/oracle_tde.py`).

**Rows.** One per database, named `Oracle TDE <name>` (with `(<pluggable
database>)` when there is one), data state `at-rest`, protocol `tde`,
software `Oracle Database`. A row with no values is skipped.

| State | Verdict | Flags |
|---|---|---|
| No keystore status, or `NOT_AVAILABLE` | `weak` | `tde-not-enabled` |
| `CLOSED` | `weak` | `wallet-closed` |
| Any other status that is not open (`UNDEFINED`, for example) | `weak` | `wallet-status:<status>` |
| Open, and no tablespace encrypted | `weak` | `tde-not-enabled`, `no-encrypted-tablespaces` |
| Open, with encrypted tablespaces | each algorithm's grade, the weakest standing | `weak-algorithm:3DES168`, `unrecognised-algorithm:<name>`, `partial-encryption:<n>-of-<m>-tablespaces` |

`OPEN`, `OPEN_NO_MASTER_KEY` and `OPEN_UNKNOWN_MASTER_KEY_STATUS` are open.
`ENCRYPTIONALG` gives a cipher and key length but not the mode, and Oracle
documents different tablespace modes in different releases (CFB before
23ai, XTS by default in later releases), so `AES128`, `AES192` and `AES256` are all graded
as the baseline's unsized `aes_cbc`, AES without authentication, never as a
sized at-rest entry. `3DES168` is `3des`. Any other algorithm leaves the
verdict `unknown`. Key custody is a flag, never a verdict:
`key-custody:file-local` for a `FILE` keystore (a software keystore, kept as a file),
`key-custody:hsm` for `HSM` or `OKV`, and `key-custody:<type>` otherwise.

**Dates.** The export carries no date, so each row is dated by the file's
modification date.

**Coverage gaps.** No input given, a file that cannot be read as CSV, or a
file with no rows: one gap saying no export was read.

**Cannot see.** Column encryption, which these views do not report; how the
keystore itself is protected; backups, exports and archived redo kept
elsewhere; and any database not in the export.

### `commvault`

**Reads** a CSV of the software encryption settings of Commvault storage
policy (or plan) copies, one row per copy. Commvault sets software
encryption on each copy: in the copy's properties, an **Encrypt Data** check
box with a **Cipher** list and a **Key Length** list (Commvault
documentation, *Configuring Software Encryption on a Primary Copy*, and the
same for a secondary copy). Commvault publishes no single report whose
columns are documented to carry these settings for every copy, so the
backup administrator records them in these columns:

| Column | Holds |
|---|---|
| `storage_policy` | The storage policy or plan |
| `copy_name` | The copy, such as `Primary`; blank for a policy with one copy |
| `storage_pool` | The storage pool, where it is named apart from the policy (optional) |
| `encryption_enabled` | `Yes` or `No` |
| `cipher` | As the Cipher list names it: `AES`, `Blowfish`, `Twofish`, `Serpent`, `GOST` or `3-DES` |
| `key_length` | `128`, `192` or `256` |
| `key_management` | Where the keys are held: `CommServe` (the default), `Via Media Password`, or the external key manager's name |

For example:

```csv
storage_policy,copy_name,encryption_enabled,cipher,key_length,key_management
Example-Daily,Primary,Yes,AES,256,CommServe
Example-Daily,Secondary,Yes,AES,128,Via Media Password
Example-Offsite,Primary,No,,,
```

Headings are matched without regard to case, spaces or hyphens, and common
synonyms are read too (`plan`, `algorithm`, `key_size`; `COLUMNS` in
`takestock/readers/commvault.py`).

**Rows.** One per copy, named `Commvault backup encryption <policy>` (the
storage pool when no policy is given) with `(<copy>)` when one is named;
data state `at-rest`, protocol `commvault-backup`, software `Commvault`.

| Setting | Verdict | Flags |
|---|---|---|
| Off (`No`, `false`, `disabled`, `none` and the like), or neither a setting nor a cipher recorded | `weak` | `encryption-off` |
| A setting that is neither on nor off | `weak` | `encryption-status:<value>` |
| On, or a cipher recorded with no setting | the cipher's grade | `weak-algorithm:<cipher>` when it grades `weak`; `ungraded:symmetric:<name>` when the baseline does not grade it, and `ungraded:symmetric:` with no name when encryption is on and no cipher is recorded |

AES with a 256-bit key is graded as the baseline's `aes256_cbc` and AES with
another key length as `aes_cbc` (Commvault's *Supported Algorithms for
Software Encryption* gives AES's mode as CBC); `Rijndael` is AES; Blowfish,
Twofish, Serpent, GOST and 3-DES are graded by name. Key custody is a flag,
never a verdict: `key-custody:commserve-db`, `key-custody:media-password`,
or `key-custody:<name>` for any other value.

**Dates.** The settings carry no date, so each row is dated by the file's
modification date.

**Coverage gaps.** No input given, a file that cannot be read as CSV, or a
file with no rows: one gap saying no export was read.

**Cannot see.** Hardware encryption done by a tape drive; encryption of data
on its way to the backup; whether copies are immutable; and any policy or
copy missing from the CSV.

### `exchange_online`

**Reads** the folder, or a zip of it, that
the script in [`EXCHANGE-ONLINE-EXPORT.md`](EXCHANGE-ONLINE-EXPORT.md)
writes. The script is read-only: it runs nine Exchange Online PowerShell
`Get-*` cmdlets and writes each one's objects, whole, to `<cmdlet>.json`, with
a `manifest.json` recording each cmdlet's count or error. Run it in
PowerShell with the ExchangeOnlineManagement module, signed in with an
account that can read Exchange Online configuration.
The script has not been run by takestock's own tests: the reader's fixture is
written by hand to the shape the script writes.

```yaml
plugins:
  - name: exchange_online
    input: inbox/exchange-online-settings-2030-01-31T0900Z.zip
```

| Cmdlet | What is read from it |
|---|---|
| `Get-AcceptedDomain` | Each domain, and which one is the tenant's initial domain |
| `Get-DkimSigningConfig` | Whether DKIM signing is enabled for each domain, and its status |
| `Get-AntiPhishPolicy` | Each policy's DMARC handling (`HonorDmarcPolicy`, `DmarcRejectAction`, `DmarcQuarantineAction`), its spoof intelligence action (`AuthenticationFailAction`) and quarantine policy (`SpoofQuarantineTag`), and whether it is the default or a preset policy |
| `Get-AntiPhishRule` | Which custom policy applies to whom (`SentTo`, `SentToMemberOf`, `RecipientDomainIs` and their exceptions), its `Priority` and `State` |
| `Get-EOPProtectionPolicyRule`, `Get-ATPProtectionPolicyRule` | The same for the Standard and Strict preset security policies |
| `Get-InboundConnector` | Whether each connector is enabled, and its Enhanced Filtering settings (`EFSkipLastIP`, `EFSkipIPs`, `EFUsers`) and sender certificate name |
| `Get-OutboundConnector` | Whether each connector is enabled and hands mail to smart hosts, and for which domains or mail flow rule |
| `Get-QuarantinePolicy` | Whether recipients may release (`PermissionToRelease`) or only request release (`PermissionToRequestRelease`) of mail held under each policy |

The script's `-IncludeDlp` switch also exports the mail flow rules and the
Microsoft Purview data loss prevention policies and sensitivity labels.
**takestock does not read those yet.** The Purview half needs
`Connect-IPPSSession`, which Microsoft says *"isn't available in PowerShell 7
on Linux clients"* (nor on macOS), so it needs Windows.

**Rows.** One per object read, named `Exchange Online <setting> <name>`
(for example `Exchange Online inbound connector From the mail gateway`), and
a scope row, `Exchange Online settings export scope`, recording when the
export was taken and each cmdlet's count, failure or absence. Every row has
data state `email-auth`, protocol `mail-policy` and verdict `n/a`: a setting
carries no cryptographic primitive to grade. `extra` holds `setting` and the
properties above, in lower case with words joined by `_`. Rows are dated by
the manifest's `pulled_utc`, else the file's modification date.

**What it settles.** The [Secure Government Email reading](SGE-NOTE.md)
grades three requirements from these rows, which are otherwise
`no-instrument`: one row per domain for each.

| Requirement | Met when | Not met when | Left unsettled when |
|---|---|---|---|
| SGE-DMARC-02, inbound mail checked for DMARC and acted on (must) | every anti-phishing policy that governs the domain's recipients has `HonorDmarcPolicy` true, with `Reject` or `Quarantine` for a sender's `p=reject` and `Quarantine` or `MoveToJmf` (the Junk Email folder) for `p=quarantine`, **and** the domain's MX records point to Microsoft 365, or to another service whose mail arrives on an enabled inbound connector with Enhanced Filtering on for every recipient | a policy that certainly governs recipients ignores DMARC; or the MX points elsewhere and no enabled connector has Enhanced Filtering, or only for listed recipients | the observation holds no MX reading; an Enhanced Filtering connector is not tied to the MX host (below); a policy that fails governs only recipients a rule names |
| SGE-DMARC-R04, mail failing DMARC goes to an administrator quarantine (should) | the actions in effect quarantine or reject, and the quarantine policy in effect does not let recipients release | an action in effect is `MoveToJmf` (the Junk Email folder), or the quarantine policy lets recipients release | the quarantine policy is not in the export; the answer turns on an unsettled route |
| SGE-DKIM-01, all outbound mail DKIM signed (must) | signing is enabled (with status `Valid`, where a status is recorded), or the domain is the tenant's initial domain, and no enabled outbound connector hands mail to smart hosts | signing is off, the domain sends mail, and no enabled outbound connector hands mail to smart hosts | signing is off and the domain sends no mail, or nothing shows whether it does; an enabled outbound connector hands mail to smart hosts, where the service beyond may sign or not |

How each is decided, from Microsoft Learn:

- **Which policy governs whom.** Microsoft's order of precedence is the
  Strict preset, the Standard preset, custom policies by priority (*"a lower
  number indicates a higher priority"*), then the default policy, which
  *"applies to all recipients"* (*Preset security policies*; *Anti-phishing
  policies*). A preset with no enabled rule applies to no one (*"Until you
  turn on the profiles and assign users to them, the Standard and Strict
  preset security policies are assigned to no one"*), and nor does a
  disabled custom rule. Different types of recipient condition combine with
  AND, so a rule limited by domain alone takes every recipient of its
  domains, and the walk stops there. A rule naming users or groups takes
  some recipients: the export holds no group membership, so a failing policy
  behind such a rule, or after one, leaves the row unsettled rather than
  failed.
- **The route.** *"If the MX record for the Microsoft 365 domain points to a
  non-Microsoft service or device that sits in front of Microsoft 365, the
  Honor DMARC policy setting is applied only if Enhanced Filtering for
  Connectors is enabled for the connector that receives inbound messages"*
  (*Anti-phishing policies*). Microsoft 365's own MX hosts end
  `mail.protection.outlook.com`, `mail.eo.outlook.com`,
  `mail.protection.outlook.de` or `mx.microsoft` (*How SMTP DNS-based
  Authentication of Named Entities (DANE) works*).
  Enhanced Filtering is on when `EFSkipLastIP` is true, or when it is false
  and `EFSkipIPs` lists addresses; with an empty `EFUsers` it *"is applied to
  all recipients"*, and with a list it *"is effective only on messages where
  all recipients are specified here"* (*Enhanced filtering for connectors*).
  A connector is tied to the MX host when its `TlsSenderCertificateName`
  covers the host's name. The reader does not resolve addresses, so a
  connector identified only by its sender addresses leaves the row
  unsettled.
- **The actions.** With `HonorDmarcPolicy` true, `DmarcRejectAction` and
  `DmarcQuarantineAction` act on a sender's `p=reject` and `p=quarantine`;
  false, *"The AuthenticationFailAction parameter specifies the action to take
  on the message"* (*Set-AntiPhishPolicy*). Where the route does not apply
  the setting, the reading takes the false case. *"If you select Quarantine
  the message as an action, the system uses the quarantine policy selected
  for spoof intelligence protection"*: `SpoofQuarantineTag`, whose default is
  `DefaultFullAccessPolicy` or `NotificationEnabledPolicy`, both Full access
  (*Quarantine policies*).
- **Request release counts as met.** A quarantine policy that lets
  recipients only request release leaves the release to an administrator:
  Microsoft says Limited access lets users do anything *"except release them
  from quarantine without admin approval"* (*Quarantine policies*), which is
  the framework's *"release only by administrators"*. Whether the
  administrator reviews before approving is not in the export.
- **Signing.** For a custom domain *"Currently, no DKIM signing occurs for
  outbound mail from custom domains"* until signing is configured, so a
  domain with no signing configuration is unsigned; the initial domain is
  signed automatically (*How to use DKIM for email in your custom domain*).
  Whether a domain sends mail is read from the profile (listed under
  `discovery.email_domains`, or parked), then its SPF record (senders named,
  or `v=spf1 -all` alone). With no such evidence, an unsigned domain is
  unsettled, never passed.

**Coverage gaps.** No input, an input that is neither a folder nor a zip, or
one holding none of the nine readings: one gap saying no export was read. A
cmdlet the manifest records as failed is a could-not-test gap quoting its
error; one with no file is a not-collected gap.

**Cannot see.** Anything outside Exchange Online: a mail gateway in front of
it (its own DMARC handling and quarantine) or on the outbound path (whether
it signs again or breaks the signature), and other services that send as the
organisation's domains. The overrides Microsoft lists for the DMARC setting
(safe sender lists, the spoof intelligence insight, the Tenant Allow/Block
List, allowed sender lists in anti-spam policies, mail flow rules) and group
membership are not exported.

Pages read, on Microsoft Learn (learn.microsoft.com), by title:
*Anti-phishing policies in Microsoft 365*; *Preset security policies*;
*Quarantine policies*; *Enhanced filtering for connectors in Exchange Online*;
*How to use DKIM for email in your custom domain*; *How SMTP DNS-based
Authentication of Named Entities (DANE) works*; *About the Exchange Online
PowerShell V3 module*; and the Exchange PowerShell cmdlet pages for each
cmdlet the script runs and for Set-AntiPhishPolicy, Set-AntiPhishRule,
Set-InboundConnector and Set-OutboundConnector.

### `vmware`

**Reads** a CSV of vSphere's two encryption controls for data at rest, one
row per virtual machine or vSAN cluster: **VM Encryption** (set per machine
through its storage policy; it encrypts the machine's disks, configuration
file and core dumps) and **vSAN data-at-rest encryption** (set per cluster;
it encrypts everything on the cluster's datastore). Both need a key
provider configured in vCenter, and both use one fixed cipher, XTS-AES-256
(Broadcom's vSphere 8.0 documentation, *How vSphere Virtual Machine
Encryption Protects Your Environment* and *How vSAN Data-At-Rest Encryption
Works*).

| Column | Holds |
|---|---|
| `scope` | `vm` for a virtual machine; `vsan-cluster` (or `vsan`, `cluster`) for a vSAN cluster |
| `name` | The machine or cluster |
| `encrypted` | `Yes` or `No` (`true`, `enabled` and their opposites are read too) |
| `key_provider` | The key provider's name in vCenter |
| `key_provider_type` | `Standard` (a key server reached over KMIP), `Trusted` (vSphere Trust Authority) or `Native Key Provider` |
| `cipher` | Optional; blank is read as the XTS-AES-256 vSphere uses |

Headings are matched without regard to case, spaces or hyphens, and common
synonyms are read too (`vm_name`, `kms`, `algorithm`; `COLUMNS` in
`takestock/readers/vmware.py`). This PowerCLI script writes the columns from
each machine's `Config.KeyId` (set only on an encrypted machine; its
`ProviderId.Id` names the key provider) and each vSAN cluster's
configuration. Fill in `key_provider_type` from vCenter's list of key
providers. It was written from VMware's API and PowerCLI documentation and
has not been run here; check the vSAN property names against your PowerCLI
version.

```powershell
Connect-VIServer -Server vcenter.example.test
$rows = foreach ($vm in Get-VM) {
    $key = $vm.ExtensionData.Config.KeyId
    [pscustomobject]@{
        scope = 'vm'; name = $vm.Name
        encrypted = if ($key) { 'Yes' } else { 'No' }
        key_provider = if ($key) { $key.ProviderId.Id } else { '' }
        key_provider_type = ''; cipher = ''
    }
}
$rows += foreach ($cluster in Get-Cluster | Where-Object VsanEnabled) {
    $config = Get-VsanClusterConfiguration -Cluster $cluster
    [pscustomobject]@{
        scope = 'vsan-cluster'; name = $cluster.Name
        encrypted = if ($config.EncryptionEnabled) { 'Yes' } else { 'No' }
        key_provider = "$($config.KmsCluster)"
        key_provider_type = ''; cipher = ''
    }
}
$rows | Export-Csv -NoTypeInformation -Path vmware-encryption.csv
```

**Rows.** One per line, named `VMware vSphere VM Encryption <name>` (protocol
`vm-encryption`) or `VMware vSAN <name>` (protocol `vsan-encryption`), data
state `at-rest`.

| Recorded | Verdict | Flags |
|---|---|---|
| A machine with encryption off, or nothing recorded | `n/a` | `vm-encryption-off`: a fact, not a grade, because the storage beneath may encrypt its files |
| A vSAN cluster with encryption off, or nothing recorded | `weak` | `encryption-off` |
| A setting that is neither on nor off | `weak` | `encryption-status:<value>` |
| On, or a key provider or cipher with no setting | the cipher's grade (`aes256_xts` is `strong`) | `ungraded:symmetric:<name>` for a cipher the baseline does not grade, left `unknown` |

Key custody is a flag, never a verdict: `key-custody:native-key-provider`,
`key-custody:trust-authority`, `key-custody:external-kms`, or
`key-custody:<name>` when only the key provider's name is recorded.

**Settings.** `vsphere_lists:` names the folder of vSphere Client list
exports the `vsphere_lists` reader reads. When it holds a virtual-machine
list, which reports each machine's encryption, a missing export here is not
a gap.

```yaml
plugins:
  - name: vmware
    input: inbox/vmware-encryption.csv
    settings: {vsphere_lists: inbox/vsphere}
```

**Dates.** The export carries no date, so each row is dated by the file's
modification date.

**Coverage gaps.** No input given, a file that cannot be read as CSV, or a
file with no rows, unless the named list exports answer it: one gap saying
no export was read.

**Cannot see.** Encryption done by a storage array or by the disks beneath a
datastore; whether vMotion traffic or memory is encrypted; how the key
provider protects its keys; and any machine or cluster not in the export.

### `rvtools`

**Reads** RVTools workbooks. RVTools is a free Windows tool that reads a
vCenter or ESXi host through the vSphere API and writes a workbook with one
sheet per subject, named `RVTools_export_all_<date>_<time>.xlsx` by default.
The input is one workbook or a folder of them (every `.xlsx` directly inside
it, in name order). With more than one vCenter, put a label before the
default name (`SiteA_RVTools_export_all_…`): the text before `_RVTools` is the
row's site, and the date in the name is the export's date.

| Sheet | Columns read |
|---|---|
| `vInfo` | `VM`, `Powerstate`, `Template`, `SRM Placeholder`, `Firmware`, `EFI Secure boot`, `OS according to the configuration file` |
| `vHost` | `Host`, `ESX Version` |

An RVTools workbook has no column for VM encryption, a key provider or a
cipher, so every row is a census graded `n/a`, and the scope row says so.
Templates and Site Recovery Manager placeholders (stand-ins at a recovery
site for machines that run elsewhere) are rows in `vInfo` and are not
counted as machines.

**Rows**, all data state `platform-integrity`, protocol `firmware`:

| Row | Over | Flags |
|---|---|---|
| `VM firmware EFI, secure boot on` | machines powered on | `vm-firmware-census:<n>` |
| `VM firmware EFI, secure boot off` | machines powered on | `vm-firmware-census:<n>`, `secure-boot-off:<n>` |
| `VM firmware BIOS (legacy)`: no secure boot is possible without a firmware change | machines powered on | `vm-firmware-census:<n>`, `legacy-bios:<n>` |
| `VM firmware <value>` for any other value | machines powered on | `vm-firmware-census:<n>` |
| one per `ESX Version` | hosts | `esxi-version-census:<n>` |
| `Guest OS <type>`, as configured, not as measured inside the guest | machines | `guest-os-census:<n>` |
| `Virtual estate scope`: rows, templates, placeholders, machines, powered on, hosts, per site | all | `scope-rvtools-no-encryption-data` |

**Settings.** `vsphere_lists:`, as for `vmware`. When the named folder holds
a virtual-machine list, the vSphere Client's lists are read for machines,
hosts, guest types and ESXi versions, so only the firmware rows are written
here, with a shorter scope row.

**Dates.** Every row is dated by the oldest workbook's date, and its notes
say it describes the estate as it was then.

**Coverage gaps.** A folder with no workbook, or a workbook that cannot be
opened or has no `vInfo` rows. With no input, nothing is written: an
inventory answers no cryptographic question by itself.

**Cannot see.** Encryption of any kind; what runs inside a guest; and any
vCenter not exported.

### `vsphere_lists`

**Reads** the vSphere Client's own exports of its inventory lists. Each list
(a datacenter's virtual machines, a vCenter's hosts, its datastores) has an
**Export** action that saves the columns on screen as a CSV file, named
after the list: `vmsForDatacenter_Name`, `hostsForVCenter_Name` and
`datastoresForVCenter_Name`. The input is a folder of them. With more than
one vCenter, add a label after the list name
(`vmsForDatacenter_Name SiteA.csv`): it is the row's site, taken from the
file and never from a machine's name, since a machine replicated from
another vCenter keeps its name. Show these columns before exporting:

| List | Columns read |
|---|---|
| Virtual machines | `Name`, `State`, `Guest OS`, `Managed By`, `Encryption`, `TPM`, `VBS`, and Site Recovery Manager's `com.vmware.vcDr:::protected` attribute if shown |
| Hosts | `Name`, `Cluster`, `Version`, `Certificate Valid To` |
| Datastores | `Name`, `Type`, `Device`, `Access`, `Capacity` |

Headings are matched without regard to case or line breaks. Site Recovery
Manager placeholders (`Managed By` naming Site Recovery Manager) are left
out of every count but the scope row's.

**Rows.**

| Row | Verdict | Flags |
|---|---|---|
| `VM encryption, <site> vCenter`: machines with VM Encryption on and off | `n/a`, or the cipher's grade when any machine is encrypted | `vsphere-vm-census:<n>`, `vm-encryption-off:<n>` (a fact, not a grade), `ungraded:vm-encryption:<value>` |
| `Virtual TPM, <site> vCenter` | `n/a` | `vsphere-vm-census:<n>`, `vtpm-absent:<n>` |
| `Virtualisation-based security setting, <site> vCenter`, over Windows machines | `n/a` | `vsphere-vm-census:<n>`, `vbs-enabled:<n>` |
| `vSphere guest OS <type>`, with its support status | `n/a` | `guest-os-census:<n>` |
| `ESXi host certificate <host>` | `unknown` | `expired` or `expiry-soon` as at the export date; `not-assessed:certificate-key-and-signature` |
| `VMware ESXi <version>`, with its support status | `n/a` | `esxi-version-census:<n>` |
| `Datastores, <site> vCenter` | `n/a` | `datastore-census:<n>` |
| `vSphere list exports scope` | `n/a` | `scope-vsphere-lists` |

A virtual TPM, like VM encryption, needs a key provider in vCenter
(Broadcom, *Enable vTPM for an Existing Virtual Machine*: "You must create a
key provider before you can add a vTPM").

**Support status** is looked up in a software lifecycle table in the format
of `data/software-lifecycle.yaml`, by the guest type (kind `os`) or by
`VMware ESXi <version>` (kind `hypervisor`), exact matches only, on the
export's date. The bundled table is used unless `settings:` names another:

```yaml
plugins:
  - name: vsphere_lists
    input: inbox/vsphere
    settings: {lifecycle: data/my-lifecycle.yaml}
```

**Datastores.** A device's NAA identifier (`naa.6…`, `naa.5…`) carries its
maker's IEEE organisationally unique identifier. A datastore on a
storage-array maker's prefix (`ARRAY_MAKERS` in
`takestock/readers/vsphere_lists.py`, from the IEEE registry) or on a
virtual-volume container counts as on an array; any other prefix counts as
disks inside a host, and none as not placed. Datastores on disks inside
hosts are a coverage gap, because the list does not say whether those disks
encrypt.

**Dates.** The exports carry no date, so every row is dated by the oldest
file's modification date, and certificate expiry is counted from that date.

**Coverage gaps.** An export that cannot be read; a lifecycle table named in
`settings:` that cannot be read; datastores on disks inside hosts. With no
input, or none of the three lists in the folder, nothing is written.

**Cannot see.** The key provider setting itself; which datastore holds which
machine's disks; whether any storage encrypts; anything inside a guest; and a
host certificate's key, algorithm and issuer.
