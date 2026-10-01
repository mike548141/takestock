# The workspace and the target profile

takestock keeps everything about one organisation in a **workspace**, and is
told what to collect by a **target profile** in it. This guide describes the
workspace layout, how takestock finds it, and every key a target profile and
its overlays can carry. The sample organisation in
`examples/example-widgets/` is the worked example throughout.

## Terms used here

- **Workspace**: a directory holding one organisation's material: its
  profiles, the exports supplied for it, and the observations taken of it.
- **Target profile**: a YAML file under the workspace's `targets/` that says
  what to collect for one organisation.
- **Overlay**: a file beside a profile, named after it, that adds to it:
  `<stem>.dispositions.yaml`, `<stem>.derived-ports.yaml` and
  `<stem>.ipam.yaml`. An overlay is never read as a profile.
- **Inbox**: the directory supplied exports are read from.
- **Observation**: one run's output directory, named by its UTC time stamp.

## The workspace

```text
<workspace>/
  targets/
    example-widgets.yaml                  the target profile
    example-widgets.dispositions.yaml     overlay: the organisation's own decisions
    example-widgets.derived-ports.yaml    overlay: a cleartext probe plan (optional)
    example-widgets.ipam.yaml             overlay: the IP address plan file
  inbox/                                  exports supplied by hand
  observations/
    2030-01-31T0930Z/                     one observation
    latest -> 2030-01-31T0930Z
  data/                                   optional replacements for the bundled data files
```

The sample keeps its exports in `exports/` rather than `inbox/`, so its
commands pass `--inbox exports` (or `--exports exports` for the IP plan).

### Which directory is the workspace

In order:

1. `--workspace DIR` on any subcommand;
2. the `TAKESTOCK_HOME` environment variable;
3. the current directory.

A relative path in either of the first two is read from the current
directory. Keeping the workspace apart from the package means one
installation can serve any number of estates.

### Which directory is the inbox

In order:

1. `--inbox DIR` on `takestock observe` (`takestock ipam` takes
   `--exports DIR` instead, for the plan's sources);
2. the `TAKESTOCK_INBOX` environment variable;
3. `<workspace>/inbox`.

A path in a profile that starts with `inbox/` (such as
`inbox/ssh-audit`) resolves inside whichever inbox is in effect, so the inbox
can move without editing profiles. Any other relative path is read from the
workspace; an absolute path is used as given.

### Bundled data and a workspace's `data/`

The package ships its data files in `src/takestock/data/`: the algorithm
baseline, the disposition rules, the register schema, the requirements
catalogue, the Secure Government Email requirement set, the DNS services
file, the port-encryption table, the daemon dictionary and the lifecycle and
vendor lists.

A workspace may hold its own copy of any of them in `data/`, under the same
file name, and that copy is used instead. **This happens only when the
workspace was named explicitly**, by `--workspace` or `TAKESTOCK_HOME`. A
workspace that is merely the current directory never replaces a data file,
so a stray `data/` folder wherever a command happens to be run cannot change
how anything is graded.

A copy replaces the bundled file whole; nothing is merged.

### Observations

`takestock observe` writes `observations/<stamp>/`, where the stamp is the
UTC minute of the run (`2030-01-31T0930Z`), and points `observations/latest`
at it. Inside:

| Path | Holds |
|---|---|
| `assets.json` | Every row, graded and with its disposition |
| `summary.json` | Counts, coverage gaps with their classifications, collector failures, findings, each row's dispensation state, which collectors ran and which did not, and why |
| `bom.cdx.json` | The rows as a CycloneDX 1.6 cryptographic bill of materials. Written last, so its presence marks a finished run |
| `raw/` | Every transcript and reply the collectors kept |

The other commands write beside these by default: `cmdb/`,
`requirements/` and `sge-note.html`.

An observation is never overwritten. Two runs in the same minute into the
same workspace are refused; wait a minute rather than deleting the
directory, which may belong to a run still in progress.

## Naming a profile

Commands that take a target accept a path or a bare name. In order,
takestock tries the path relative to the workspace, the path as given, and
`targets/<name>.yaml`. So, inside the sample workspace, `example-widgets`,
`targets/example-widgets.yaml` and an absolute path all name the same file.

Profiles, overlays, the IP plan file and the YAML data files (except the
register schema) are loaded safely and **refuse a key declared twice** in
one mapping. Plain YAML keeps the second block and drops the first without a
word; takestock stops and names both lines.

## The target profile, key by key

Every key is optional unless a collector you want to run needs it. A key no
collector reads is ignored.

| Key | Holds | Read by |
|---|---|---|
| `name` | A short name for the profile | page titles and the observation record, when `organisation` is absent |
| `organisation` | `{name: ...}`, or a plain string | every HTML output, the observation record |
| `branding` | Colours, fonts and a logo for the HTML outputs | every HTML output |
| `discovery` | The domains to look up, and DKIM selectors | the passive DNS collectors, the SGE note |
| `dns` | Public DNS services, overriding `data/dns-services.yaml` key by key | the DNS and certificate-transparency collectors |
| `dns_resolvers` | Resolvers for the DNS HTTPS-record lookup | `hsts` |
| `authorisation` | Who authorised active probing, of what, and when | every active collector |
| `scan_targets` | The hosts each active probe may contact, by group | the active collectors |
| `plaintext_ports` | Ports to check for cleartext on the published hosts | `plaintext_scan`, `implicit_tls` |
| `ssh_inbox` | Where supplied `ssh-audit` JSON files are | `ssh_audit_inbox` |
| `winrm_inbox` | Where the WinRM configuration export is | `winrm_config` |
| `netdev_inbox` | Where the network device export is, and which device classes to expect | `netdev` |
| `dns_zones` | Settings for reading supplied zone files | `dns_zones` |
| `third_party` | Outside providers and the domains they operate | dispositions, `dns_zones` |
| `infrastructure` | Infrastructure providers and their domains | `dns_zones` |
| `lifecycle` | Planned migration and vendor support, per host | every observation |
| `sge` | Settings for the Secure Government Email reading | the SGE note and the asset marking |

### `name` and `organisation`

```yaml
name: example-widgets

organisation:
  name: Example Widgets Ltd
```

The organisation's name comes from `organisation.name` (or `organisation`
as a string; `org` is accepted as a synonym), then `name`.

### `branding`

```yaml
branding:
  name: Example Widgets Ltd        # alt text for the logo
  logo: brand/logo.svg             # relative to the profile; embedded in the page
  font: "Example Sans, sans-serif" # a CSS font-family list
  mono: "ui-monospace, monospace"
  palette:                         # light-scheme colour tokens
    accent: "#7a1f4d"
  palette_dark:                    # dark-scheme colour tokens
    accent: "#f0b8d8"
```

Every field is optional; the sample leaves the block empty and gets a
neutral palette and the system font. A palette may set only the tokens the
page shell defines (`bg`, `surface`, `text`, `muted`, `accent`, `border`,
and a foreground and background for each result: `pass_fg`, `pass_bg`,
`fail_fg`, `fail_bg`, `unmeasured_fg`, `unmeasured_bg`); an unknown token
stops the build. An override whose text falls below the WCAG 2.2 AA contrast
minimum is reported as a warning.

### `discovery`

```yaml
discovery:
  domains: [example.com, example.net]
  email_domains: [example.com, example.net]
  dkim_selectors: [mail2030]
```

| Field | Means |
|---|---|
| `domains` | Domains whose certificates (from certificate-transparency logs) and DNSSEC are read |
| `email_domains` | Domains whose mail-authentication records (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) are read and graded against Secure Government Email. `takestock sge-note` refuses a profile with none |
| `dkim_selectors` | The organisation's own DKIM selector names, tried before a short list of common defaults. DNS offers no way to list selectors |

### `dns`

Overrides the bundled `data/dns-services.yaml`, key by key. An empty value
leaves the file's value in place.

```yaml
dns:
  resolvers: [192.0.2.53, 198.51.100.53]
  validation_control: <a public zone deliberately signed wrongly>
  ct_search_api: <a certificate-transparency search endpoint>
  caa_issuers: {}
  takeover_namespaces: {}
```

| Field | Means | When empty |
|---|---|---|
| `resolvers` | Recursive resolvers to ask, by address; two or more let a reading be corroborated | The machine's own resolver is asked alone, and the observation records a gap saying so |
| `validation_control` | A zone signed wrongly on purpose: a validating resolver answers SERVFAIL for it | No resolver's DNSSEC validation can be confirmed |
| `ct_search_api` | The certificate-transparency search endpoint ([`COLLECTORS.md`](COLLECTORS.md) gives the query it must answer) | Certificate transparency is not read, and a gap is recorded |
| `caa_issuers` | Certificate-authority names, lower case, mapped to the issuer domains they use in CAA records | Every issuer is reported as unmapped |
| `takeover_namespaces` | DNS suffixes a cloud provider documents as claimable by another customer, mapped to the service | Dangling records are reported without that claim |

The bundled file leaves every key empty. An unconfigured service is a
coverage gap, not a failure, so the run still exits 0 or 1.

### `dns_resolvers`

A list of resolver addresses for the `hsts` collector's DNS HTTPS-record
lookup. Without it, the machine's own resolver is asked.

### `authorisation`

Active probes run only with `--scan`, and only while this record is
complete. All three fields must be present and non-empty.

```yaml
authorisation:
  scope: >-
    Loopback addresses, the documentation ranges 192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24 and 2001:db8::/32, and names under example.test. Nothing else.
  authorised_by: Example Widgets Ltd, IT manager (a fictional person)
  date: "2030-01-31"
```

A probe that runs **inside** the network also needs its own record, keyed by
the `scan_targets` group it reads, with the same three fields:

```yaml
authorisation:
  # ... the general record, as above ...
  smb_445:
    scope: File servers on the head-office network
    authorised_by: Infrastructure lead
    date: "2030-01-31"
```

The inside groups are `smb_445`, `rdp_3389`, `ssh_inside`,
`internal_services` and `intel_amt`. A profile that does not declare one of
those groups never hears from its probe; a profile that declares the group,
even empty, must carry its record. See
[`SETUP-SCANNERS.md`](SETUP-SCANNERS.md#the-authorisation-record).

### `scan_targets`

The hosts each active probe may contact, by group. Where an entry gives both
`host` and `ip`, the address is probed; which one names the row depends on
the collector (see
[`COLLECTORS.md`](COLLECTORS.md#where-active-probes-point)).

| Group | Entry | Read by |
|---|---|---|
| `vpn_gateways` | `{host, ip}`, optionally `site` | `tls_scan` (443), `ike_scan`, `plaintext_scan` |
| `tls_443` | a host name: the organisation's published web hosts | `tls_scan`, `hsts`, `plaintext_scan` |
| `mail_self` | a host name: the organisation's own published mail hosts | `tls_scan`, `hsts`, `plaintext_scan` |
| `saas_443` | `{host}`, optionally `port` (default 443), `vendor`, `service`, `carries`, `domains`: a service an outside provider runs for the organisation | `tls_scan`, `hsts` |
| `smtp_25` | `{host}`, optionally `vendor`, `service`, `carries`, `domains`: an inbound mail gateway | `smtp_starttls`, `spf_senders` |
| `ssh_22` | a host or address, `host:port`, `[v6]:port`, or `{host, ip, port}` (port default 22): an internet-facing SSH listener. Given `host` and `ip`, the address is probed and the row named after the host, with the address beside it | `ssh_audit`, `plaintext_scan` |
| `ssh_inside` | `{host, batch}`, optionally `ip`, `port` (default 22) | `ssh_audit_inside` |
| `smb_445` | a host, or `{host, ip}` | `smb_scan` |
| `rdp_3389` | a host, or `{host, ip, port}` (default 3389) | `rdp_scan` |
| `internal_services` | `{host, port}`, optionally `role`; no `ip`. The port must be one the collector knows | `internal_scan` |
| `intel_amt` | a host, or `{host, ip}` | `intel_amt` |

`vendor`, `service` and `carries` (what information the service carries)
feed the plain-language description each row is given. A `saas_443` or
`smtp_25` host counts as operated by an outside provider when dispositions
are proposed (see [`DISPOSITIONS.md`](DISPOSITIONS.md)), and its `domains`
let `dns_zones` name the provider behind a record.

The inside groups accept at most 60 hosts each; `ssh_inside` at most three
batches of 60. Batches are named by the operator and run one after another.
`internal_services` accepts only the ports listed in
`takestock.collectors.internal_scan.INTERNAL_PORTS`; adding one is a code
change, not a profile edit.

### `plaintext_ports`

```yaml
plaintext_ports: ["21/tcp", "80/tcp", "110/tcp", "465/tcp", "993/tcp"]
```

Single `<port>/<transport>` entries, applied to every host in
`vpn_gateways`, `tls_443`, `mail_self` and `ssh_22`. Ranges, comma lists and
wildcards are refused, as are more than 12 ports on a host, 60 hosts, or 400
host-and-port pairs in all. `implicit_tls` takes its 465, 993 and 995 pairs
from the same plan. A derived-ports overlay, when present, replaces this list
(see below).

### `ssh_inbox`, `winrm_inbox` and `netdev_inbox`

Where the ingest collectors find their exports. Each has a default inside
the inbox, so the keys are needed only to move a file.

```yaml
ssh_inbox:
  dir: inbox/ssh-audit                 # ssh-audit -jj JSON, one file per host
winrm_inbox:
  export: inbox/winrm-config.csv       # one row per Windows host
netdev_inbox:
  devices: inbox/netdev-controls.csv   # one row per control on a device or link
  expect: [switch, router, firewall, wireless, out-of-band]
```

`netdev_inbox.expect` lists the device classes the export should cover;
each one with no row becomes its own coverage gap. Without it, the five
classes shown are expected. The classes an export may use are `switch`,
`router`, `firewall`, `wireless`, `vpn-gateway`, `out-of-band`, `wan-link`,
`storage` and `other`. The columns each export takes are described in the
module docstrings of `takestock.collectors.winrm_config` and
`takestock.collectors.netdev`.

### `dns_zones`

The `dns_zones` collector reads zone files from `inbox/dns-zones/`
(`<zone>.zone`, `private/<zone>.json` record-set exports, and an optional
`_exported-at-utc.txt` holding when the export was taken). Its settings are
all optional:

| Field | Means |
|---|---|
| `resolved_names` | A CSV of names endpoints resolved, to narrow the list of published names nobody measured |
| `resolved_names_column` | That CSV's column of names (default `name`) |
| `proof_prefixes` | Ownership-proof TXT record prefixes, mapped to the service each names |
| `second_level_labels` | Further labels that sit directly under a country code as part of a public suffix (`co`, `com`, `net`, `org`, `ac` and `gov` are built in) |

### `third_party` and `infrastructure`

```yaml
third_party:
  - name: Example Hosting
    domains: [hosting.example.net]
infrastructure:
  - name: Example Networks
    domains: [cdn.example.net]
```

Both name outside organisations and the domains they operate, so a DNS
record pointing into one of those domains is attributed to them. A
`third_party` entry also marks every host under its domains as operated
elsewhere when dispositions are proposed.

### `lifecycle`

```yaml
lifecycle:
  migration_strategy:
    retire: ['^build-01\.example\.test$']
  support_status:
    end-of-support:
      - {match: '^build-01\.example\.test$', ends: "2029-12-31"}
```

Each entry is a regular expression matched against a row's host or name.

| Field | Means |
|---|---|
| `migration_strategy` | `{strategy: [pattern, ...]}`, where a strategy is one of `rehost`, `replatform`, `repurchase`, `refactor`, `retire`, `retain`. A word covering two of them is refused |
| `support_status` | `{status: [pattern or {match, ends}, ...]}`, where a status is one of `supported`, `security-only`, `end-of-support`, `end-of-life`. `ends` records when support ends |

Both are recorded beside the grade and never change it. A pattern that
matches no row is listed in `summary.json`, because it is usually a typing
slip or a host since gone.

### `sge`

```yaml
sge:
  bulk_mail_domains: [bulk.example.net]
```

`bulk_mail_domains` are bulk-mail providers' SPF policy domains. A domain
whose SPF record authorises one of them is annotated as a reason the strict
DKIM alignment recommendation may not apply, without changing its verdict.
See [`SGE-NOTE.md`](SGE-NOTE.md).

## Overlays

An overlay sits beside the profile and takes its name from the profile's
file name: `targets/example-widgets.yaml` has
`targets/example-widgets.dispositions.yaml`, and so on. Each is optional.

### `<stem>.dispositions.yaml`

The organisation's own decisions about what to do with its findings. It may
hold only these sections, and any other top-level key stops loading:

| Section | Holds |
|---|---|
| `programme` | Programme settings, such as `pqc_target_year` |
| `ladder` | A replacement for the default ladder of tracks |
| `rules` | Match-and-propose rules checked before the bundled ones |
| `decisions` | The organisation's own decisions, checked first of all |
| `adoptions` | Bundled rules the organisation adopts as written, by id and hash |
| `dispensations` | Recorded exceptions to mandatory controls, assessed per row on every observation and written to `summary.json` |

The sample records one decision, and one dispensation for the same server
(see [`DISPOSITIONS.md`](DISPOSITIONS.md#dispensations)):

```yaml
decisions:
  - match:
      host_pattern: '^build-01\.example\.test$'
      protocol: ssh
    disposition: accept-replacement-planned
    reason: >
      The build server is being replaced by a hosted build service, so its SSH
      settings are left as they are until it is switched off.
    until: the hosted build service runs every build
    review: "2030-06"
```

Every field is described in [`DISPOSITIONS.md`](DISPOSITIONS.md).

### `<stem>.derived-ports.yaml`

A cleartext probe plan that replaces `plaintext_ports`, section by section,
under one key:

```yaml
derived_ports:
  derived_on: "2030-01-31"
  authority: Infrastructure lead
  probe_list:
    web:
      hosts_from: scan_targets.tls_443
      ports: [80/tcp, 8080/tcp]
      basis: Web hosts commonly answer plain HTTP on these ports.
    budget: {hosts: 2, tcp_pairs: 4, udp_pairs: 0}
```

| Field | Means |
|---|---|
| `probe_list.<section>.hosts_from` | One `scan_targets` group the profile already holds |
| `probe_list.<section>.ports` | Single `<port>/<transport>` entries; at least one must be TCP |
| `probe_list.<section>.basis` | Why these ports, in a sentence. Required |
| `probe_list.budget` | `hosts`, `tcp_pairs` and `udp_pairs`, which must equal what the plan computes |
| `derived_on`, `authority` | When and by whom the plan was derived; recorded with the plan |

A plan is refused if its budget does not match, a host is claimed by two
sections, or it would stop probing a pair the profile's own
`plaintext_ports` authorises. UDP ports are listed but not probed.

### `<stem>.ipam.yaml`

The IP address plan file: sites, subnets, sources, documented addresses,
mirrors and actions. It is read by `takestock ipam`, never by an
observation, and is described in full in [`IPAM.md`](IPAM.md). The sample's
is `examples/example-widgets/targets/example-widgets.ipam.yaml`.

## The sample, read through

`examples/example-widgets/targets/example-widgets.yaml` uses most of the
keys above:

- `name`, `organisation` and an empty `branding` block;
- `discovery.domains` and `discovery.email_domains`, both `example.com` and
  `example.net`;
- a general `authorisation` record, and no inside groups, so no inside probe
  ever runs for it;
- `scan_targets` with published web and mail hosts, one remote-access
  gateway, one inbound mail gateway and one internet-facing SSH listener;
- `plaintext_ports`;
- `ssh_inbox.dir`, pointing at the supplied `ssh-audit` files;
- a `lifecycle` block marking the build server for retirement and out of
  support.

Its supplied exports, in `examples/example-widgets/exports/`, are two
`ssh-audit` files, a zone export under `dns-zones/`, a WinRM configuration
export and a network device export, which are what an offline observation
reads (through `ssh_audit_inbox`, `dns_zones`, `winrm_config` and
`netdev`), plus the asset register, laptop check-in log and zone file the IP
plan reads.

## Environment variables

| Variable | Sets |
|---|---|
| `TAKESTOCK_HOME` | The workspace |
| `TAKESTOCK_INBOX` | The inbox |
| `TAKESTOCK_CT_TOKEN` | The certificate-transparency search service's API token, if it issues one |
| `TAKESTOCK_SSH_AUDIT`, `TAKESTOCK_IKE_SCAN` | The `ssh-audit` and `ike-scan` executables |
| `TAKESTOCK_IKE_MAX_PROBES`, `TAKESTOCK_IKE_PROBE_DELAY`, `TAKESTOCK_IKE_RETRY`, `TAKESTOCK_IKE_TIMEOUT_MS` | The IKE probe's budget and pacing |
| `TAKESTOCK_HSTS_THIRD_PARTY_READS` | How many times each outside provider's endpoint is read |

The probe settings are described in [`SETUP-SCANNERS.md`](SETUP-SCANNERS.md).
