# The IP address plan

takestock builds an **IP address plan**: every site, every subnet, and every
address the evidence places in them, each with the source that reported it
and that source's date. It answers an engineer's first questions about a
network: which ranges the organisation holds, where each one lives, what is on
it, and how sure the evidence is.

No single export answers all of those, so the plan joins two kinds of input:

- a **plan file** holding what no export states: the sites, what each subnet
  is for, and which sources to read and how;
- **sources**: exports (CSV files, DNS zone files, saved internet-registry
  answers, or anything a plugged-in reader understands) and dated documents.

The sample organisation, Example Widgets Ltd, has a complete plan file and
exports under `examples/example-widgets/`. Every example below comes from it.

## Terms used here

- **Site**: a place or network the organisation runs, holding one or more
  address ranges.
- **Subnet**: a block of addresses inside a site, declared in the plan file
  or by a source.
- **Sighting**: one source saying one address was associated with one name.
- **Placed**: a sighting is placed in the most specific subnet that holds its
  address. A sighting that cannot be placed is **set aside**, with a reason.
- **Evidence class**: how far a source's sightings go (see
  [Evidence classes](#evidence-classes)).

## The rule the plan file follows

**The plan file never asserts an address on its own authority.** A subnet
entry cannot list addresses; the build refuses one that tries. An address
enters the plan only from a source, or from a `documented_addresses` entry
that names a document source with its own date. Every address in the output
can therefore be traced to something outside the plan file.

## Building a plan

```bash
takestock ipam <plan.ipam.yaml> <out_dir> [--exports <dir>] [--lookup-asn] [--workspace <dir>]
```

For the sample, from the repository root:

```console
$ takestock ipam examples/example-widgets/targets/example-widgets.ipam.yaml out \
    --exports examples/example-widgets/exports
out/example-widgets.json
out/example-widgets.csv
out/example-widgets.html
```

The command exits 0 when the plan is written and 2 on an error.

- Source paths in the plan file are read relative to `--exports`. Without
  it they are read from the workspace's `inbox/` (or the directory named by
  `TAKESTOCK_INBOX`).
- `--lookup-asn` first looks the plan's public addresses up with the
  internet registries (see
  [Internet-registry lookups](#internet-registry-lookups)), which sends
  them over the network. Without it, saved answers are read and nothing is
  sent.
- A source whose input is missing stops the build: a plan built from fewer
  exports than it names would read as complete and not be. The one exception
  is a source of kind `asn-lookups`, whose folder may not exist yet.
- The plan is named after its file: `example-widgets.ipam.yaml` writes
  `example-widgets.json`, `.csv` and `.html`.
- The organisation's name and branding come from the target profile beside
  the plan file (`example-widgets.yaml`) when there is one, otherwise from
  the plan file's own `organisation:` block.

## The plan file

The plan file is YAML, named `<stem>.ipam.yaml`, and usually sits in the
workspace's `targets/` beside the target profile. Top-level keys:

| Key | Holds |
|---|---|
| `organisation` | `{name: ...}`, used when no target profile sits beside the file |
| `title`, `subtitle`, `summary` | The page's heading, lead line and opening paragraphs |
| `audience` | Who the plan is written for, shown under the heading |
| `part`, `author` | A short label shown above the page's title (the part of a larger set the page belongs to, say) and a line shown under it (who prepared it) |
| `sites` | Every site, with its address ranges |
| `subnets` | Every subnet the organisation knows of, with what it is for |
| `host_internal_ranges` | Ranges that exist only inside a machine |
| `sources` | Every export and document to read |
| `documented_addresses` | Addresses known only from a dated document |
| `mirrors` | Pairs of sites laid out alike, to compare |
| `segment_codes` | What the parts of segment names mean |
| `exposure_chains` | The path a request takes from the internet to a service |
| `actions` | Follow-up items tied to subnets |
| `asn_lookup` | Settings for internet-registry lookups |

### Sites

```yaml
sites:
  - id: head-office
    name: Head office
    kind: office
    description: Offices, the server room and the main print room.
    ranges: [192.0.2.0/24, "2001:db8:10::/48"]
  - id: showroom
    name: Showroom
    kind: office
    status: planned
    ranges: ["2001:db8:30::/48"]
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique; subnets and sources refer to it |
| `name` | no | Shown on the page; defaults to the id |
| `kind` | no | Any word (`office`, `warehouse`, `internet-facing`); sites are counted by kind |
| `status` | no | `in use` by default; anything else (such as `planned`) is shown beside the name |
| `ranges` | no | The address ranges the site holds. A subnet a source declares is given to the site whose range holds it most specifically, even when the source names another site (see [Which site a declared subnet belongs to](#which-site-a-declared-subnet-belongs-to)) |
| `description`, `location`, `operator` | no | Shown on the site's card |

### Subnets

```yaml
subnets:
  - {cidr: 192.0.2.0/26, site: head-office, environment: production, purpose: Servers,
     vlan: 10, confidence: confirmed}
  - {cidr: 192.0.2.64/26, site: head-office, purpose: Staff devices, vlan: 20,
     addressing: dynamic}
  - {cidr: 192.0.2.192/27, site: head-office, purpose: Network device management, vlan: 99,
     evidence: [network-diagram], only_sources: [network-diagram, asset-register]}
```

| Field | Required | Meaning |
|---|---|---|
| `cidr` | yes | The block; listed once only |
| `site` | yes | A declared site id |
| `purpose`, `environment`, `confidence`, `notes` | no | Free text, shown and written to the CSV |
| `vlan` | no | A number. Two subnets of the same IP version on one VLAN at one site are flagged |
| `addressing` | no | `dynamic`, `pool` or `overlay` mark a subnet whose addresses change hands, so two machine names on one address are expected rather than a conflict; `static` (the default) marks fixed addresses. Any other value is listed under [Checks](#checks) and treated as `static` |
| `scope` | no | `public` or `private`; worked out from the address when absent |
| `evidence` | no | Source ids that vouch for the subnet itself, usually a document |
| `only_sources` | no | Only these sources may place addresses here; others are set aside |

`addresses` is not allowed.

### Sources

```yaml
sources:
  - id: asset-register
    kind: csv
    label: Asset register export
    path: asset-register.csv
    as_of: 2030-03-01
    as_of_basis: exported
    columns: {ip: Address, name: Device, date: Last seen, mac: MAC, site: Location,
              kind: Type}
    authoritative_for: [warehouse]
    supersedes: [asset-register-previous]
  - id: laptop-checkins
    kind: csv
    label: Laptop check-in log
    path: laptop-checkins.csv
    as_of: 2030-02-28
    as_of_basis: exported
    roams: true
    columns: {ip: IP, name: Computer, date: Seen}
  - id: network-diagram
    kind: document
    label: Network diagram
    as_of: 2030-02-10
    as_of_basis: issued
```

| Field | Meaning |
|---|---|
| `id`, `kind` | Required. `kind` names a reader (`csv`, `dns-zones`, `asn-lookups`, or one you plug in), or `document` / `record` for a dated document that has no file to read |
| `label` | The name shown everywhere; defaults to the id |
| `path` or `paths` | The input, relative to the exports directory unless absolute. Not used by documents |
| `as_of`, `as_of_basis` | The source's date, and what the date means (`exported`, `issued`; default `dated`) |
| `evidence` | `observed` or `named`, to override the reader's default |
| `name_is` | What the name column identifies: `machine` (default), `alias` (another name for the address), `label` (a description) or `history` (a machine that has held the address at some time, from a source listing every address a device has reported) |
| `roams` | `true` for a source that reports addresses a machine held anywhere: home networks, hotspots, its own container bridges |
| `authoritative_for` | Site ids for which this source is the reference |
| `supersedes` | Source ids this one replaces |
| `cannot_see` | For a source that `supersedes` another: detail values of sightings or segments it would never list, as `{key: [values]}` (for example `{device_kind: [Printer]}` for a newer register that lists only computers). Compared ignoring case |
| `columns`, `delimiter` | For `csv` sources (see [Readers](#readers)) |

Three of these change how sightings are placed:

- **A roaming source cannot found a subnet.** It can only place an address
  inside a subnet the plan already holds; everything else it reports is set
  aside.
- **Inside a site with an authoritative source**, a roaming source's address
  is accepted only where the authoritative source holds the same address.
  An address another source places there that the authoritative source does
  not list is flagged.
- **A superseding source** marks names only the older source gave as
  previous names, and flags addresses that only the older source reports,
  except where the older source's sighting carries a value the newer one's
  `cannot_see` names: the newer source would not have listed it anyway.
  The same goes for segments: a segment only replaced sources list, which a
  newer source that lists segments of its own does not, is marked
  `superseded_by` that source, kept in the plan with its subnet and the
  older source's date, and left out of the segment and VLAN counts and the
  VLAN check. A newer source that lists no segments at all cannot retire
  one, because its silence says nothing about them.

### Documented addresses

```yaml
documented_addresses:
  - {ip: 192.0.2.193, name: core-sw-01, source: network-diagram,
     note: core switch management interface}
```

`source` must be a declared source of kind `document` or `record`, so the
address carries that document's date.

### Ranges inside a machine

```yaml
host_internal_ranges:
  - {cidr: "2001:db8:ffff::/48", reason: container bridge on staff laptops}
```

An address inside one of these describes no network, so it is set aside with
the reason given.

### Mirrors

```yaml
mirrors:
  - name: Head office and warehouse layouts
    left: {site: head-office, prefix: 192.0.2.0/24}
    right: {site: warehouse, prefix: 198.51.100.0/24}
```

Two prefixes of the same size are compared position by position: each subnet
at an offset inside one is paired with the subnet at the same offset in the
other. A one-sided row is either a real difference or a network no source
saw at one of the sites.

### Segment codes

```yaml
segment_codes:
  lab: {}
  app-db: {meaning: Application databases}
  prd: {meaning: production, environment: production}
  users: Staff devices
```

Segments a reader reports (see [Plugging in a reader](#plugging-in-a-reader))
are often named by a convention whose parts mean something. Each code maps
to a meaning and, optionally, the environment it marks; a plain string is a
meaning on its own. A segment's name is split at hyphens, underscores, dots
and spaces, and parts that are only digits (a VLAN number, or an address
written into the name) are dropped. Each part, or run of up to three parts
joined by hyphens, that matches a code (ignoring case, longest first) is
replaced by its meaning. A code with no meaning is dropped, for a part that
says where a segment is defined rather than what it carries. A part no code
matches is kept as it is.

With the codes above, a segment named `lab-app-db-prd-110` reads as
*Application databases, production*, in the `production` environment. When
any code is declared, every segment carries `meaning`, and a subnet a segment
declares takes that reading as its purpose and the environment as its own.

### Exposure chains

```yaml
exposure_chains:
  - name: Public web service
    source: service-design
    hops:
      - {label: public address, address: 203.0.113.5}
      - {label: load balancer, address: 192.0.2.10, name: lb-01}
      - {label: web workers, address: 192.0.2.64/27}
```

An exposure chain is the path a request takes from the internet to a
service, hop by hop, as a declared source describes it. Like a documented
address, it rests on that source and carries its date. Each hop needs a
`label` and an `address`, and a chain needs at least two hops.

A hop's `address` is one address, or a network in CIDR form when the hop is
a group of machines a request may reach any one of, such as the workers
behind a load balancer. A network must be written from its first address
(`192.0.2.64/27`, not `192.0.2.70/27`), because a range with stray host bits
is usually a typing slip. The plan writes such a hop as `network` rather than
`address`, and the page shows it as a network. A network of one address
(`/32`, `/128`) is read as that address, and anything else is refused.

### Actions

```yaml
actions:
  - id: A1
    title: Confirm whether the spare public block is still held
    subnets: [203.0.113.16/28]
    detail: The network diagram lists it, and no export shows anything using it.
```

Each action is listed on its own, and its id is written against every
subnet it names.

## Placing addresses

Every sighting is checked in this order:

1. **Describes no network**: a value that is not an address, or a loopback,
   link-local, unspecified or multicast address. Set aside.
2. **Inside a machine**: inside a `host_internal_ranges` entry. Set aside.
3. **Outside every subnet**: set aside. An address outside the plan never
   becomes a subnet of its own.
4. **Restricted subnet**: the subnet's `only_sources` does not include this
   source. Set aside.
5. **Roaming, inside an authoritative site**: the authoritative source does
   not hold the address. Set aside.
6. Otherwise placed in the **most specific** subnet holding it.

Each placed address records every name and source that reported it, its
evidence classes, the first and last dates it was seen in use, the last date
a name or document vouched for it, and any of these flags:

| Flag | Raised when |
|---|---|
| several machine names | two or more machines claim the address in a subnet with fixed addressing. Only `machine` names count: an alias, a label or a past holder from a `history` source never makes a conflict |
| previous names | a superseded source named a different machine |
| not in the authoritative source | the site's authoritative source does not list it |
| only in a superseded source | every source that saw it in use has been replaced, and the newer one no longer reports it |
| source says another site | the source's own site column names a different site |

### How an address was given out

An address also carries `assignment` (`static`, `dynamic`, or `disputed`
when its sources disagree) and `assignment_basis` (each statement, naming
its source) when a source says how it was given out. A reader says so in a
sighting's detail, in either of two ways:

- `allocation`: `static` or `dynamic`, as a cloud platform's list of network
  interfaces states it (the `csv` reader's `assignment` column lands here);
- `dhcp`: true or false, as a host's interface settings state it. DHCP off
  means a fixed address.

An address seen on a VLAN carries `vlans`, from a `vlan` number in a
sighting's detail. A subnet's own VLANs come from the plan file and from
segments, never from its addresses.

## Evidence classes

| Class | Shown as | Means |
|---|---|---|
| `observed` | seen in use | The source saw the address in use |
| `named` | named | A name was configured for the address (a DNS record), which does not show it is in use |
| `documented` | documented | A document says so |

Each reader has a default class, and a source can override it with
`evidence:`. Documents are always `documented`. When the plan counts
addresses, one seen in use by any source counts as seen in use; otherwise
one with a name counts as named; the rest count as documented only.

## Readers

A reader turns one source's files into sightings. Three ship with the
package.

### `csv` (default class: observed)

Reads any CSV using the source's `columns:` mapping, from the plan's field
names to the file's header names:

| Field | Required | Becomes |
|---|---|---|
| `ip` | yes | The address. A cell may hold several, separated by spaces, commas, semicolons or bars; a token that is not an address is counted and skipped |
| `name` | no | The name the sighting carries |
| `date` | no | The date the address was seen (the `YYYY-MM-DD` the value starts with) |
| `mac`, `site`, `kind` | no | Kept with the sighting; `site` is compared with the subnet's site |
| `assignment` | no | How the address was given out, `static` or `dynamic` (see [How an address was given out](#how-an-address-was-given-out)) |
| `vlan` | no | The VLAN the address was seen on |

A header the mapping names but the file lacks stops the build. `delimiter`
sets the field separator (default `,`).

### `dns-zones` (default class: named)

Reads zone files (`<origin>.zone`), private-zone record-set exports
(`<zone>.json`), or a directory holding `*.zone` files and an optional
`private/` directory of `*.json` exports. It takes:

- every A and AAAA record, as an alias for the address;
- every single-address `ip4:` or `ip6:` mechanism in an SPF record, as an
  authorised mail sender for that name.

### `asn-lookups` (default class: named)

Reads the internet-registry answers `--lookup-asn` saved (see below). It
adds no sightings; it attaches who announces and who holds each public
address and subnet. If nothing has been saved yet, the source carries a
note rather than stopping the build.

### Plugging in a reader

A reader is a function `fn(source, paths, harvest)`:

- `source` is the source's plan-file entry, as a dictionary;
- `paths` are its resolved input paths, all of which exist;
- `harvest` is a `takestock.ipam.Harvest` to add to:
  - `harvest.sightings.append(Sighting(ip, name, source["id"], seen, detail, name_is))`;
    `detail` may carry `allocation`, `dhcp` and `vlan`, which the plan reads
    (see [How an address was given out](#how-an-address-was-given-out)), and
    anything else, which is kept with the sighting;
  - `harvest.segments.append(Segment(source["id"], site, name, vlan, subnet, switch, detail))`
    for a layer-2 network (a VLAN or switch port group) the source reports;
    `detail` is optional, and a newer source's `cannot_see` is compared with
    it;
  - `harvest.declared[cidr] = {"source": source["id"], "name": ..., "site": ...}`
    for a subnet the source states exists;
  - `harvest.notes[source["id"]].append("...")` for a line shown beside the
    source.

Register it in code:

```python
from takestock import ipam

def read_switch_export(source, paths, harvest):
    ...

ipam.register_reader("switch-export", read_switch_export, evidence="observed")
```

`optional=True` makes a missing input a note instead of an error. Or ship it
in your own package under the entry-point group `takestock.ipam_readers`,
and takestock finds it when a source names that kind:

```toml
[project.entry-points."takestock.ipam_readers"]
switch-export = "mypackage.readers:read_switch_export"
```

A reader loaded this way takes the defaults (required input, class
`observed`); a source can still set `evidence:`.

Segments and declared subnets only arrive through plugged-in readers. A
subnet a source declares that the plan file lacks is added with
`origin: declared by a source`, and its `confidence` follows the source's
evidence class:

- **`measured`** when the source is of class `observed`. A source that reads
  a running system is already trusted to have seen its addresses in use, and
  the networks the same reading lists (a cloud platform's subnets, a
  hypervisor's port groups) are configured on that system, so they are a
  measurement too. Reading them as weaker than the addresses inside them
  would be inconsistent.
- **`declared`** for any other source, whose statement is a claim rather
  than a reading of the system.

A reader whose subnets come from free text someone typed (a subnet written
into a segment's name, say) rather than from the system's configuration can
give its source `evidence: named`, so they read `declared`.

### Which site a declared subnet belongs to

A subnet a source declares goes to the site whose range in the plan file
holds it most specifically. Only when no declared range holds it does the
site the source itself reports stand, and with neither it goes under
"unassigned". The plan file's ranges are the operator's own statement of
where addresses live. A source's site is usually where its export was taken,
which for a platform serving more than one site is not where every network
it lists lives. The segment row itself keeps the site its source reported,
so the two can still be compared.

## Checks

The plan lists what a reviewer should look at, each found in the data:

| Check | Means |
|---|---|
| One address, several machine names | Two or more machines at one address in a subnet with fixed addressing: a record is out of date, or the address is in conflict |
| One VLAN carrying several subnets at a site | Two subnets of the same IP version on one VLAN: usually a typing slip |
| A source places the address at another site | The source's site column disagrees with the plan |
| Missing from the site's authoritative source | The authoritative source does not list an address inside its site |
| Seen only in a source a newer one replaced | The machine may have gone or moved |
| Subnets with no addresses found | Either unused, or used by machines no source covers |
| Subnets known only from documents | Nothing read from the network confirms they exist. A `record` source counts as a document: a public record such as a certificate-transparency log entry shows that a certificate was issued for a name, not that anything answers at the address, so it documents the subnet without confirming it |
| Unknown addressing values | A subnet's `addressing` is not `static`, `dynamic`, `pool` or `overlay`, so it is treated as `static`: usually a typing slip |

The sample is built to trigger every check once, except an unknown
addressing value, which a finished plan file should not have. For example,
its asset register gives `192.0.2.130` to both `print-01` and `print-02` in the fixed
printer subnet, and its laptop check-in log reports a loopback address, an
address inside the container-bridge range, and an address outside every
subnet, each of which is set aside with its reason.

## What it writes

| File | Holds |
|---|---|
| `<stem>.json` | The whole plan: sources, sites, subnets with their addresses, segments, mirrors, actions, checks, counts and what was set aside |
| `<stem>.csv` | One row per subnet: site, purpose, VLANs, addresses found against usable, confidence, evidence dates and sources, registry details, action ids |
| `<stem>.html` | The plan as one self-contained page |

Before anything is written, local input paths are removed, and the build
refuses to write a value shaped like a credential (a private-key block, an
access key, or a `password=`-style pair). An export carrying one is a
finding to deal with at its source, not something to copy into a plan.

The configuration register can read `<stem>.json` too, when asked: `takestock
cmdb <observation> --ip-plan <stem>.json` makes an item for each machine the
plan names at an address (see
[`CMDB.md`](CMDB.md#machines-from-an-ip-address-plan)). Nothing reads the plan
into the register unless it is named that way.

## The page

The page is drawn entirely from the plan, so it cannot disagree with the
JSON and CSV beside it. Its sections:

- **Overview**: the summary, headline counts, the date range of the evidence,
  an address finder, and links to every check that found something;
- **Sites**, **Subnets** (with a filter), **Addresses** (per subnet, with
  every source and flag);
- **VLANs and segments**, **Mirrored sites**, **Public ranges** and
  **Actions**, each drawn only when there is something to show;
- **To look at**: every check;
- **Set aside**: every sighting not placed, by source and reason;
- **Sources**: each source's kind, evidence class, date and notes.

Without scripts the page reads as one long document and prints that way.
With them, the sections become tabs, the subnet table can be filtered, and
the address finder answers *which subnet holds this address?* in the
browser, naming the subnet, its site and purpose, and the names the plan
holds for the address. Given a MAC address (in any of the usual spellings:
`02:00:00:00:00:10`, `02-00-00-00-00-10`, `0200.0000.0010`) it lists every
address a source saw that MAC address at, and the subnet holding each.

The view is kept in the page's address, so a copied link opens where it was
copied: `#subnets` opens a section, `#find=192.0.2.10` runs the address
finder, and `#filter=printer` filters the subnet table. A document preview
may show the page inside a sandboxed frame where the address cannot be
changed; there the page works the same, and only the address stays as it
was. Every value from the data is escaped before it reaches the page.

`takestock.ipam_view.render(plan, theme, part=..., author=...)` lets a
caller set the part label and author line in place of the plan's own.

## Internet-registry lookups

`--lookup-asn` asks two public services who announces and who holds each
public address in the plan (and the first address of each public subnet):

- an **IP-to-ASN whois service** that takes bulk queries over the whois
  protocol (TCP port 43) in the Team Cymru bulk verbose format. No host is
  built in: name one in the plan file after reading the service's own
  documentation:

  ```yaml
  asn_lookup:
    whois_host: <the service's whois host>
  ```

  Without it, only RDAP is asked.
- **RDAP** (RFC 9083), the registries' structured replacement for whois. The
  right registry for each address is found from IANA's bootstrap files
  (RFC 9224), fetched with `curl`.

The plan file must declare a source of kind `asn-lookups`; its `path` is the
folder the answers are saved in (`_index.json`, `cymru-<date>.txt`, and one
`rdap/<address>.json` per address). An address already in the index is not
asked again, and later builds read the saved answers without going to the
network.

This sends the plan's public addresses to outside services. Leave the flag
off if that is not acceptable.

## What it cannot see

The plan knows what its sources saw, on the dates they were taken. It holds
no DHCP server configuration, so it knows addresses that were in use, not the
ranges a server hands out. An empty subnet may be unused or simply outside
every source's view.
