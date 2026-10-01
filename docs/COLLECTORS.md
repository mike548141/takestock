# Collectors

A **collector** gathers one kind of evidence and returns it as rows, together
with a list of what it could not vouch for. This guide lists every collector
takestock registers: what it reads or probes, what it needs in the target
profile, which external tools it uses, and what it cannot see.

Installing the external tools, and the authorisation record active probes
need, are in [`SETUP-SCANNERS.md`](SETUP-SCANNERS.md).

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
| `ct_dns` | passive | certificate-transparency logs; MX, SPF, DMARC, MTA-STS, TLS-RPT and DKIM records | `discovery.domains`, `discovery.email_domains` | `dig`, `curl` |
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
| `smtp_starttls` | active | STARTTLS on the inbound mail gateways | `scan_targets.smtp_25` | `openssl` |
| `implicit_tls` | active | TLS on ports 465, 993 and 995 | the cleartext probe plan | `openssl` |
| `smb_scan` | active, inside | SMB dialects and message signing | `scan_targets.smb_445` and `authorisation.smb_445` | `nmap` |
| `rdp_scan` | active, inside | whether remote desktop requires authentication first | `scan_targets.rdp_3389` and `authorisation.rdp_3389` | `nmap` |
| `ssh_audit_inside` | active, inside | SSH algorithms on internal hosts, in batches | `scan_targets.ssh_inside` and `authorisation.ssh_inside` | `ssh-audit`, or `nmap` |
| `ssh_audit_inbox` | ingest | `ssh-audit` JSON files someone ran and supplied | optional `ssh_inbox.dir` | none |

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
| `ssh_22` | Internet-facing SSH listeners: a host, `host:port`, or `{host, ip}` | `ssh_audit`, `plaintext_scan` |
| `ssh_inside` | Internal SSH hosts: `{host, batch, port}` | `ssh_audit_inside` |
| `smb_445` | Internal file servers: a host or `{host, ip}` | `smb_scan` |
| `rdp_3389` | Internal remote-desktop hosts: a host or `{host, ip, port}` | `rdp_scan` |

Where an entry gives both `host` and `ip`, the address is probed and the name
reported.

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
  DKIM records, then sweeps the sub-domain names the transparency read found
  for the denying SPF, empty DKIM and DMARC records a name that sends no mail
  should publish.

**Settings.** `ct_search_api` (see [DNS services](#dns-services)) must answer
`<endpoint>?domain=<name>&include_subdomains=true&expand=dns_names&expand=issuer&expand=pubkey`
with a JSON list of issuances, paged by `after=<id>`. An API token, if the
service issues one, is read from `TAKESTOCK_CT_TOKEN`, or on macOS from a
keychain item named `takestock-ct-token`; without one the service is asked
anonymously. `discovery.dkim_selectors` lists the organisation's own DKIM
selectors, tried before a short list of common defaults.

**Rate limits.** Search services limit how often they may be asked. A
recent answer (up to two days old) whose read finished is reused from an
earlier observation instead of asking again, and reported as reused with its
age. When the service says "wait", the remaining domains can be parked and
finished later in the same run.

**Cannot see.** Names that never appeared in a public certificate (an
internal name, or a sub-domain nobody serves TLS on); whether a server
actually presents a logged certificate; DKIM selectors nobody named, since
DNS offers no way to list them.

### `spf_senders`

**Reads** each email domain's SPF record and expands it through every
`include:`, `redirect=`, `a` and `mx` term, writing one row per domain that
describes the whole authorised sending surface: named hosts, address ranges,
the policies traversed, and where the record stands against RFC 7208's
limits of ten DNS-consuming terms and two lookups that return nothing.

When run with probing switched on and a probe supplied by the program that
calls it, it also checks STARTTLS on each relay the SPF record names (hosts
already listed under `scan_targets.smtp_25` are not probed twice). The
collector does not check the authorisation record itself; the calling
program must.

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
- **names nobody measured**: published names no other row of the run covers;
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
pinned handshake could not ask about is flagged as unknown, not absent.
Without `nmap`, every endpoint gets an `unknown` row whose note reads like
an endpoint that did not answer; check that `nmap` is installed before
reading such rows.

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
DNS is asked of the profile's `dns_resolvers:` list, else the system's
resolver.

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

### `implicit_tls`

**Probes** ports 465 (SMTPS), 993 (IMAPS) and 995 (POP3S), where TLS starts
with the first byte (RFC 8314), with a direct handshake per TLS version, and
reads the certificate. It takes its host-and-port pairs from the cleartext
probe plan, so it contacts nothing that plan has not named, and a plan that
`plaintext_scan` refuses is refused here too. It keeps four answers apart: a
session agreed (graded), something answered without completing a handshake
(flagged), connection refused (nothing listens), and no answer (unmeasured,
never read as closed).

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

## The ingest collector

### `ssh_audit_inbox`

**Reads** `ssh-audit -jj` JSON files someone ran against hosts takestock
cannot reach, one file per host, from `inbox/ssh-audit/` (or the folder
named by `ssh_inbox.dir`). Each file's `target` field names the host; the
file's modification date is recorded as when the evidence was collected.

**Cannot see** anything not supplied: a missing or empty folder is recorded
as a coverage gap saying the internal SSH configuration was not checked.
