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
| `ct_dns` | passive | certificate-transparency logs; MX, SPF, DMARC, MTA-STS, TLS-RPT and DKIM records; SPF, DMARC and null MX on parked domains | `discovery.domains`, `discovery.email_domains` | `dig`, `curl` |
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
  DKIM records, then sweeps the sub-domain names the transparency read found
  for the denying SPF, empty DKIM and DMARC records a name that sends no mail
  should publish.
- **Parked domains.** A domain under `discovery.domains` and not under
  `discovery.email_domains` is *parked*: it sends and receives no mail. For
  each one it reads SPF and DMARC the same way as for an email domain, and
  MX, recording whether the domain publishes a **null MX** (an MX record of
  `0 .`, RFC 7505) in a row of protocol `null-mx`, named `Null MX <domain>`.
  Its flag is one of `null-mx:published`, `null-mx:no-mx`,
  `null-mx:mail-exchangers` (real mail servers, so the domain receives mail)
  and `null-mx:alongside-other-mx` (which RFC 7505 §3 forbids). Every row for
  a parked domain carries `extra.parked: true`. The MX lookup settles or fails
  as the SPF and DMARC lookups do, and a failure line names the domain as
  parked.

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
advice on putting it behind a secure access edge where the device offers
nothing stronger.

**Coverage.** `netdev_inbox.expect` lists the device classes the export
should cover (default: switch, router, firewall, wireless, out-of-band).
With no export there is one gap for the file and one per expected class.
With an export, each expected class that has no row is its own gap, rows
naming no device or no control are a gap, and a **scope row** states what the
export covers (controls, devices, classes present and absent) without
claiming a share of the estate. A missing or unreadable export never stops
the run.
