# takestock

Take stock of an IT estate: what it runs, how it is protected, and what it
needs next.

takestock collects evidence about an estate (public DNS and certificate
logs, network probes you have authorised, and exports from the management
tools you already run), grades what it finds against published standards,
and writes:

| Output | What it is | Command |
|---|---|---|
| **Observation** | Every row found, graded, with the coverage gaps, as JSON and as a CycloneDX 1.6 cryptographic bill of materials (CBOM) | `takestock observe` |
| **Configuration register** | A draft CMDB: a schema plus every configuration item found, with how strongly each fact is known | `takestock cmdb` |
| **IP address plan** | Every site, subnet and address the evidence shows, each with its source and date | `takestock ipam` |
| **Secure Government Email note** | Every requirement of New Zealand's Secure Government Email framework, read as met, not met or not measured | `takestock comply sge` (HTML), `takestock comply sge --format text` (plain text) |
| **Requirements** | Requirements derived from the findings, written from public standards, ready to put to a supplier | `takestock requirements` |

> **Status:** version 0.1.0, alpha. The commands work end to end on the
> sample organisation below; the command line and file formats may still
> change before 1.0, and [`CHANGELOG.md`](CHANGELOG.md) records each change.

## Install

takestock needs Python 3.11 or later. From a clone of this repository:

```bash
make venv                 # .venv with takestock installed in editable mode, plus the dev tools
. .venv/bin/activate
takestock --version       # takestock 0.1.0
```

Or into an environment of your own: `pip install -e .` (add `'.[dev]'` for
the test tools). `pip install takestock` installs the released package from
PyPI without a clone; the quick start below still needs the sample in
`examples/`, which is in the repository, not the package. The only Python
dependencies are PyYAML and openpyxl.

The collectors that probe hosts and query DNS drive external programs
(`dig`, `curl`, `nmap`, `openssl`, `ssh-audit`, `ike-scan`). None is needed
for the quick start below. [`docs/SETUP-SCANNERS.md`](docs/SETUP-SCANNERS.md)
says which collector needs which, and how to install them.

Exports from named products and standard formats are read by takestock's
**readers library**: readers that ship with takestock and run when a target
profile names them, such as `sbom` for CycloneDX software bills of materials
([`docs/COLLECTORS.md`](docs/COLLECTORS.md#the-readers-library)). A reader for
an export the library does not cover can be written as a plug-in
([`docs/PLUGINS.md`](docs/PLUGINS.md)).

## Quick start on the sample organisation

`examples/example-widgets/` is a complete workspace for **Example Widgets
Ltd**, a fictional manufacturer. Every name in it is a reserved domain and
every address is from a documentation range, so nothing in it is a real host.
It is graded against the bundled New Zealand standards (the NZISM, Secure
Government Email and the Protective Security Requirements), which are
defaults that any organisation, public or private, can adopt as they are or
replace with its own (see
[`docs/TARGET-PROFILE.md`](docs/TARGET-PROFILE.md#bundled-data-and-a-workspaces-data)).

Copy it somewhere and work inside the copy, which makes the copy the
workspace:

```bash
cp -R examples/example-widgets /tmp/example-widgets
cd /tmp/example-widgets
```

**1. Take an observation**, offline, so nothing is sent over the network and
only the supplied exports are read:

```console
$ takestock observe example-widgets --offline --inbox exports
observing Example Widgets Ltd into observations/2030-01-31T0930Z
  inbox: /tmp/example-widgets/exports
  · ssh_audit_inbox
  · netdev
  · software_inventory
  · dns_zones
  · winrm_config
observations/2030-01-31T0930Z
18 assets; verdicts {'weak': 2, 'strong': 3, 'unknown': 5, 'acceptable': 2, 'n/a': 6}; 5 coverage gap(s); 2 finding(s)
```

The observation directory is named for the UTC minute of the run, and
`observations/latest` points at the newest one. The command exits 1 because
it found two weak rows (see [Exit codes](#exit-codes)). The five coverage
gaps record what this run could not see, including the seventeen collectors
an offline run does not start.

**2. Build the configuration register** from it:

```console
$ takestock cmdb observations/latest
observations/latest/cmdb/cmdb.json
observations/latest/cmdb/csv/account.csv
...
observations/latest/cmdb/cmdb.xlsx
observations/latest/cmdb/keys.jsonl
```

**3. Build the IP address plan** from the plan file and the exports it names:

```console
$ takestock ipam targets/example-widgets.ipam.yaml ipam --exports exports
ipam/example-widgets.json
ipam/example-widgets.csv
ipam/example-widgets.html
```

**4. Write the Secure Government Email note** for the profile's email domains:

```console
$ takestock comply sge observations/latest example-widgets
observations/latest/sge-note.html
```

Offline, no mail record was read, so every requirement in the note reads
*not measured*, with the reason.
`sge` is the framework's id. `takestock comply --list` shows every standard
takestock can read an observation against, and `--format text` prints the
same reading as plain text instead of writing the note.

**5. Derive requirements** from the findings and gaps:

```console
$ takestock requirements observations/latest
observations/latest/requirements/requirements.md
observations/latest/requirements/requirements.xlsx
observations/latest/requirements/requirements.json
6 requirement(s) derived
```

Run `takestock <command> --help` for every option.

## What the tool writes, and what a person writes

takestock measures and drafts. It does not decide, and it cannot know what
only people know.

| takestock produces | A person supplies |
|---|---|
| Graded rows, coverage gaps and the CBOM (`assets.json`, `summary.json`, `bom.cdx.json`, and the raw transcripts under `raw/`) | The **target profile**: the domains, the hosts authorised for probing, and the authorisation record for them |
| A proposed **disposition** for every graded row: a track, a reason and an effort size | The organisation's **decisions**, ladder, adoptions and dispensations, in a dispositions overlay beside the profile |
| A draft register of every item an instrument saw | Owners, services, contracts, sites and anything else no instrument reads |
| An IP plan placing every address an export or a dated document names | The **plan file**: sites, what each subnet is for, which sources to read |
| A conformance note that marks every requirement it cannot measure | The evidence only the organisation holds, such as its own mail transport logs |
| Requirements with standards, tests and an evidence sentence | The supplier's answers, in the columns the workbook leaves empty |
| | The **exports** in the inbox, and lifecycle facts such as a planned retirement |

Every output says what it could not see. An empty section means *not
measured* unless the output says otherwise.

## Safety

Collectors come in three kinds:

| Kind | Sends | Runs |
|---|---|---|
| **passive** | DNS queries and certificate-log searches to public services; nothing to the organisation's hosts | on every observation, unless `--offline` |
| **active** | Probes to the organisation's hosts | only with `--scan`, and only when the target profile carries a complete `authorisation:` record |
| **ingest** | Nothing: reads exports someone supplied | always |

- Without a complete authorisation record, `--scan` is refused before
  anything is written or contacted. For a profile with no record at all:

  ```console
  $ takestock observe example-widgets --scan
  takestock: REFUSED, nothing written or contacted: --scan needs an authorisation record in the target profile: no `authorisation:` stanza in the target profile
  ```

  `--scan` and `--offline` together are refused too.
- `--carry-scan <observation>` takes a new observation without probing
  again: the passive and ingest collectors run afresh, and the rows an
  earlier `--scan` observation of the same target measured are carried in,
  each keeping the date it was measured. An observation older than
  `--carry-max-age` days (31 unless set) is refused. A carried row graded
  cleartext-served on an HTTP port is re-checked with one plain-HTTP
  request, so a carry needs the authorisation record too whenever there is
  such a row; without it the carry is refused before anything is sent.
  `summary.json` records the carry under `carried_scan`. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#carrying-earlier-probe-rows-carrypy).
- `takestock rerun <target> --from <observation> --plugin <name>` derives a
  new observation from an earlier one: every row is carried as it was
  stored, except the named plug-ins' rows, which are read again from their
  inputs. Nothing is looked up or probed. `summary.json` records the
  observation it was derived from under `rerun`. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#reading-named-plug-ins-again-rerunpy).
- Probes that run inside a network each need their own named, dated record
  as well, and every host must be named one at a time. Ranges, wildcards and
  lists over a ceiling are refused, never cut short.
- No probe sweeps ports or logs in. Each contacts only the hosts and ports
  the profile names, and the list-driven probes print their whole plan
  before contacting anything.
- The authorisation record is a record of who authorised what, not a
  security control. Run probes only against hosts you are authorised to
  test.
- Observations map where an estate's cryptography is weak and how its hosts
  are named. Treat them, and every report built from them, as sensitive, and
  keep them out of any repository you publish. This repository's
  `.gitignore` ignores any `inbox/` or `observations/` directory.

## Exit codes

Every command follows one contract, so a script can act on the result:

| Code | Means |
|---|---|
| `0` | Clean: the command did its work and found nothing adverse |
| `1` | Findings present: `observe` found a weak verdict or work on an out-of-cycle rung; `comply` found an unmet MUST requirement; `requirements` derived at least one requirement |
| `2` | Error: bad arguments, an unreadable input, a refused scan, or an observation that could not judge because a collector failed. The observation is still written, and `summary.json` lists the failures |

## Documentation

| Guide | Covers |
|---|---|
| [`docs/TARGET-PROFILE.md`](docs/TARGET-PROFILE.md) | The workspace, the target profile and its overlays, key by key |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The pipeline, the data model, the registries, and how to add a collector |
| [`docs/COLLECTORS.md`](docs/COLLECTORS.md) | What each collector and library reader reads or probes, and what it cannot see |
| [`docs/PLUGINS.md`](docs/PLUGINS.md) | Writing a plug-in collector for an export takestock has no reader for |
| [`docs/SETUP-SCANNERS.md`](docs/SETUP-SCANNERS.md) | The external tools, and the authorisation record |
| [`docs/DISPOSITIONS.md`](docs/DISPOSITIONS.md) | What to do about each finding: tracks, rules, decisions and dispensations |
| [`docs/CMDB.md`](docs/CMDB.md) | The configuration register |
| [`docs/IPAM.md`](docs/IPAM.md) | The IP address plan |
| [`docs/SGE-NOTE.md`](docs/SGE-NOTE.md) | The Secure Government Email note |
| [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | Requirements derived from the findings |
| [`docs/STANDARDS.md`](docs/STANDARDS.md) | The standards takestock grades against, and where they disagree |
| [`docs/SECURE-GOVERNMENT-EMAIL.md`](docs/SECURE-GOVERNMENT-EMAIL.md) | How takestock reads the Secure Government Email framework |
| [`docs/OBLIGATIONS.md`](docs/OBLIGATIONS.md) | The New Zealand laws and policies above the technical standards |
| [`docs/RISK-SCALE.md`](docs/RISK-SCALE.md) | The New Zealand government risk scale |
| [`docs/CONTINUOUS-ASSURANCE.md`](docs/CONTINUOUS-ASSURANCE.md) | How peer frameworks keep a security authorisation current |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: run `make hooks` once,
then `make check`. takestock carries **no organisation's data**: every
example and fixture is synthetic, and `tools/guard.py` enforces the parts of
that rule a machine can check. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
