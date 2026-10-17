# Architecture

How takestock turns a target profile into an observation and its outputs:
the pipeline, the data model, the places a module plugs in, and how to add a
collector. Module names are under `src/takestock/`.

## Terms used here

- **Row**: one `CryptoAsset`: one observed use of cryptography, or of its
  absence (a listener, a certificate, a mail record, a device control).
- **Failure**: something a collector was asked to do and could not, such as
  a configured service that errored. A failure means the observation cannot
  judge everything it was asked to.
- **Coverage gap**: a question a collector was meant to answer and could
  not, recorded with why. A gap narrows what the observation claims; it is
  not a failure.
- **Finding**: a row judged adverse: a `weak` verdict, or a disposition on an
  out-of-cycle rung such as `critical`.

## The pipeline

```text
target profile ──┐
inbox exports ───┤
public DNS, logs ┼─► collectors ─► rows + failures + gaps
authorised hosts ┘   (collectors/*)          │
                                             ▼
                 observe.py ─► normalise.finalise ─► sge.apply_conformance ─► findings, summary
                                (merge, lifecycle,                               │
                                 grading, disposition)                           ▼
                                                    observations/<stamp>/  assets.json
                                                                           summary.json
                                                                           bom.cdx.json, raw/
                                                                                 │
                       ┌────────────────────────┬────────────────────────┬──────┘
                       ▼                        ▼                        ▼
                  cmdb.py                 requirements.py         comply.py ─► sge.py + sge_note.py
              (configuration register)  (requirements register)  (standards conformance)

plan file + exports ─► ipam.py + ipam_view.py ─► IP address plan   (reads no observation)
```

### 1. Collect (`observe.py`, `collectors/`)

`observe.observe(target, Options)` takes one observation:

1. **Refuse early.** With `scan`, an incomplete `authorisation:` record
   (`inside_scope.scan_authorisation_problems`) refuses the whole run before
   anything is written or contacted. So do `scan` with `offline`, a
   `collectors:` block naming a collector that is not registered, and an
   observation directory that already exists.
2. **Decide what runs.** For each registered collector, `_why_not` gives a
   reason it does not run: the target profile turned it off
   (`collectors.disabled`, with the profile's reason); an offline run, for anything but an ingest
   collector or an offline-safe step; or an active collector without `scan`. Each reason becomes one coverage gap naming the
   collectors it held back. In a carried run (`carry_scan`, below) the
   active collectors do not run either: those that ran in the earlier
   observation are carried, and the rest are skipped with the reason that
   observation recorded.
3. **Run the early steps**, in registration order, then finish any
   certificate-transparency domains that were parked while a search service
   asked the run to wait, then the profile's ordinary **plug-ins**
   (`plugins.py`, below), then the **late** steps, which read the rows the
   earlier ones produced (`caa`, `dns_zones`, `winrm_config`), then the late
   plug-ins and coverage checks.
4. **Contain failure.** A collector that raises is recorded as a failure and
   the run continues. What a collector returns in its failures list is split
   by `observe.split_failures`: a `coverage.Gap` (a service nobody
   configured) is a gap; anything else is a failure. A plug-in is contained
   the same way, but whatever goes wrong with one (it cannot be found, has
   no input, raises, or returns records its kind's schema refuses) is
   recorded as a gap naming it, not as a failure.

Each collector step returns `(rows, failures, gaps)`. The adapters in
`observe.py` (`_rows_and_failures`, `_ingest`, `_port_probe`) fit each
collector's own signature to that shape.

### Carrying earlier probe rows (`carry.py`)

`Options(carry_scan=<observation>)`, or `takestock observe <target>
--carry-scan <observation>` on the command line, takes an observation without
probing again. The passive and ingest collectors run afresh; in place of the
active probes, the rows an earlier `--scan` observation of the same target
measured are carried in, and the raw transcripts beside them are copied.

- **What is carried.** Every row whose `source` is an active collector's,
  except `ssh_audit` rows read from supplied files, plus the `spf_senders`
  rows its relay probe wrote, which are handed to that collector in place of
  the probe. Each row is unchanged: its `source`, `collected_at` and notes are
  the earlier run's. The `ike_scan` and `hsts` gaps are worked out again from
  the carried rows; the relays that did not answer are read back from the
  earlier `summary.json`. Top-level raw files are copied except the
  certificate-transparency answers (`ct-*`), and never over a file this run
  wrote.
- **Refused, before anything is written or sent:** with `scan` or `offline`;
  when the earlier observation cannot be found or read, or has not finished;
  when it is older than `carry_max_age_days` (`--carry-max-age`, default
  `carry.CARRY_MAX_AGE_DAYS`, 31) or dated after this run; when it was taken
  of another target or organisation; when it was not a `--scan` run (a carry
  of a carry is refused, so a carry always reaches back to the run that
  measured); and when an active collector or `spf_senders` failed in it. An
  archived observation is unpacked first (`obsarchive.unpacked`).
- **The one live contact.** A carried `plaintext_scan` row graded
  `cleartext-served` on a port that speaks HTTP is re-checked with the one
  plain-HTTP request `plaintext_scan.verify_cleartext_http` sends. The row
  keeps its `collected_at`, and `extra.cleartext_verified_on` holds the
  request's date. That request is a probe, so when there is such a row the
  carry is refused, before anything is sent, unless the profile carries the
  complete `authorisation:` record `--scan` needs.
- **The record.** `summary.json` gains `carried_scan` (present only on a
  carried run):

  ```json
  "carried_scan": {
    "from_observation": "2030-01-20T0930Z",
    "from_collected_at": "2030-01-20T09:30:00Z",
    "measured": ["2030-01-20"],
    "age_days": 11,
    "max_age_days": 31,
    "collectors": ["tls_scan", "ike_scan", "..."],
    "rows": 5,
    "by_source": {"plaintext_scan": 2, "spf_senders": 1, "ssh_audit": 1, "tls_scan": 1},
    "raw_files": 1,
    "rechecked": [{"host": "shop.example.test", "port": "80",
                   "before": "cleartext-served", "after": "cleartext-served",
                   "collected_at": "2030-01-20", "verified_on": "2030-01-31",
                   "status": "HTTP/1.1 200 OK"}]
  }
  ```

  The `observation` block's `scan` is `false` and `collectors_carried` names
  the carried collectors; `bom.cdx.json` carries the property
  `takestock:carried_scan` with the earlier stamp. Late plug-ins, coverage
  checks and annotations see the carried collectors as `ctx.run.carried`.

### 2. Normalise and grade (`normalise.py`, `policy.py`, `disposition.py`)

`normalise.finalise` makes the run's rows one consistent set, in order:

1. **merge** rows that describe the same thing (the same
   `CryptoAsset.bom_ref()`);
2. **lifecycle**: migration strategy and support status from the profile,
   then support derived from the bundled Windows lifecycle data
   (`lifecycle.py`). A derived status is marked
   `extra.support_status_basis: derived`, and a program that reads stored
   rows back can derive them again against a newer table with
   `lifecycle.derive_windows_support(assets, dataset, rederive=True)`;
3. **readings across rows**: a key served by more than one host, a port-80
   redirect nothing stops being stripped, HTTP readings carried onto the TLS
   row for the same endpoint, certificate expiry from a live handshake in
   preference to a log;
4. **software names** from the daemon dictionary;
5. **grading** by `policy.Policy` against `data/baseline.yaml`, and a
   **disposition** from the organisation's decisions and the generic rules
   (`disposition.py`);
6. **usage bands** (`usage.py`) and **evidence depth** (`depth.py`).

Then any **annotation** plug-ins add `extra` keys to the graded rows (they
can add a key, never change one), each plug-in's `summarise` reads its own
graded rows, `normalise.not_measured_gaps` turns each `not-measured:` flag into a
gap, `sge.apply_conformance` marks rows behind an unmet Secure Government
Email MUST, `normalise.findings` picks out the findings,
`dispensation.payload` assesses each row's dispensation state on the
observation's date, and `normalise.summarise` counts everything
(post-quantum readiness, plaintext, dispositions, agility, hardware or
software binding, evidence depth, the gaps and their classifications) into
`summary.json`, with the dispensation states under `dispensations` and each
declared plug-in's record under `plugins`.

### 3. Write (`model.py`)

`assets.json` and `summary.json` are written, then `bom.cdx.json`
(`model.to_cyclonedx`), last, so its presence marks a finished run, and
`observations/latest` is pointed at the new directory.

`summary.json["complete"]` is true only when no collector failed and no
required gap is open. The command's exit code is 2 when a collector failed,
else 1 when there are findings, else 0.

### 4. Outputs

Each output reads a finished observation, never the network:

| Module | Reads | Writes |
|---|---|---|
| `cmdb.py`, `cmdb_export.py` | `assets.json`, `summary.json`, `data/cmdb-schema.yaml` | `cmdb/`: JSON, a CSV per class, a workbook and the key ledger |
| `requirements.py` | `assets.json`, the gaps in `summary.json`, `data/requirements-catalogue.yaml` | `requirements/`: Markdown, a workbook and JSON |
| `comply.py`, over `sge.py` and `sge_note.py` | `assets.json`, `raw/`, `data/secure-government-email.yaml`, the profile | `sge-note.html`, or the report as text |
| `ipam.py`, `ipam_view.py` | an `<stem>.ipam.yaml` plan file and the exports it names | `<stem>.json`, `.csv` and `.html` |

Every HTML page uses one shell, `htmlpage.py`: self-contained, light and dark
schemes, a print stylesheet, no external fonts or scripts, and the profile's
`branding:` applied.

`cli.py` is a thin layer over these modules; each subcommand calls one
module's functions, and every module stays usable from Python.

## The data model

### `CryptoAsset` (`model.py`)

One row. Its fields, by purpose:

| Purpose | Fields |
|---|---|
| What and where | `name`, `data_state` (`in-transit`, `certificate`, `email-auth`, `at-rest`, `discovery`, `estate`, `third-party` and so on), `protocol`, `role` (a plain-language sentence from `roles.py`), `host`, `ip`, `port`, `internet_facing`, `serial` |
| Software | `software`, `software_binary`, `version` |
| Provenance | `source` (the collector), `source_class`, `source_name`, `collected_at` |
| The cryptography | `protocol_versions`, `key_exchange`, `signatures`, `symmetric`, `hashes` |
| The grade | `verdict`, `flags`, `citations`, `evidence_depth` |
| Post-quantum | `pq_kex`, `pq_sig` and their `*_basis` |
| What to do | `disposition`, `disposition_basis` (`proposed` or `decided`), `disposition_reason`, `disposition_until`, `disposition_review`, `effort`, `effort_group`, `pqc_deadline` |
| A named standard's reading | `standards_verdict`, `standards_requirement`, `standards_observed`, `standards_citation` |
| Lifecycle and use | `migration_strategy`, `support_status`, `support_end`, `usage_count`, `usage_band`, `hosts_count` |
| Everything else | `notes`, and `extra`: whatever a collector measured that has no field of its own |

`bom_ref()` derives a stable reference from the row's state, protocol, host,
port and name, so the same thing gets the same reference on every run.

### Verdicts

| Verdict | Means |
|---|---|
| `weak`, `acceptable`, `strong`, `pqc` | The four grades, weakest first. A row is graded as the weakest thing it accepts |
| `unknown` | Cryptography is present and nothing observed could be graded. An `ungraded:<table>:<token>` flag names what the baseline lacked |
| `n/a` | The row carries no cryptographic primitive by nature (a discovered name, a mail policy record). Never a gap |

The baseline (`data/baseline.yaml`) maps every token a collector can report
to a grade, table by table, with the citation behind it.

### Flags

A flag is a short, machine-readable string on a row: `weak-dh`, `expired`,
or a prefix and a value, such as `deprecated-protocol:` followed by the
version the instrument reported. Two kinds:

- **adverse** flags say something is wrong;
- **informational** flags state a fact or a limit on what was measured
  (`ungraded:`, `not-measured:`, an unreachable host). Their first
  appearance is never read as the estate getting worse.

`model.is_informational_flag(flag)` is the one test of which kind a flag is.
A collector registers its informational flags when it is imported (see
[Registries](#registries-where-a-module-plugs-in)). A program embedding
takestock that classifies one of them differently, for example counting an
expiring certificate as a finding, declares it with
`model.declare_adverse(*prefixes)`. A declared flag, or any flag beginning
with a declared prefix, is then never informational, whichever module
registered it and whether that happened before or after the declaration.
`model.adverse_prefixes()` reads the declarations back, and
`model.informational_prefixes()` leaves out every entry a declaration
covers.

Requirements triggers and disposition rules match on flags, so a flag's
spelling is part of the interface.

### Post-quantum readiness

`pq_kex` (key establishment) and `pq_sig` (signatures) each read `ready`,
`hybrid` or `classical`, or, when there is no reading, `gap` or `n/a` with a
basis saying why. Rows doing a job only with classical public-key
cryptography also carry `quantum-vulnerable-kex` or
`quantum-vulnerable-signature`.

### Gaps (`coverage.py`)

A `Gap` is the sentence a reader sees, carrying three classifications:

| Classification | Values |
|---|---|
| kind: why the answer is missing | `not-collected`, `could-not-test`, `extent-unknown`, `not-measured` (and `unclassified` when read back from an older file) |
| impact kind: what it costs a reader | `changes-conclusion`, `narrows-confidence`, `impact-unwritten` |
| nature: nothing held, or held too coarsely | `no-data`, `low-fidelity`, `nature-unstated` |

`summary.json` keeps the gap sentences in `gaps` and each classification in a
parallel list (`gap_kinds`, `gap_impact_kinds`, `gap_natures` and so on), so
they survive a round trip through JSON.

## Registries: where a module plugs in

Each of these is a function or table a module calls when it is imported, so
a new collector or reader declares itself without editing a central list
(the first two excepted).

| Registry | Declares | Shipped entries |
|---|---|---|
| `collectors.register(name, module, kind, function="collect")`; `collectors.REGISTRY` | A collector: its module, its kind (`passive`, `active`, `ingest`) and its entry point | Twenty-two, listed in `collectors/__init__.py` |
| `observe.PLANS` | How an observation runs each registered collector: its step, and whether it is `late` or `offline`-safe | One per collector; a collector without one is skipped and recorded as a gap |
| `model.register_informational_prefixes(*prefixes)` | Flags, or flag prefixes ending in `:`, that are informational | Built-in list in `model.py`, plus many collectors' own |
| `model.declare_adverse(*prefixes)` | Flags, or flag prefixes, that are adverse whatever is registered as informational. For a program embedding takestock | None |
| `depth.register_flags(rung, *flags, convention=False)` | Flags that lift a row to an evidence-depth rung (`key-management`, `key`, `posture`), or record an unanswered question (`unanswered`) | Built-in lists in `depth.py` |
| `plaintext.register_host_listener_source(source, marker)` | A source whose rows are listening ports seen from the host itself | None |
| `binding.register_binding(binding, protocols=..., data_states=...)` | Protocols or data states bound to `hardware` or `software` | Built-in tables in `binding.py` |
| `cmdb.register_source_strength(source, strength)` | The evidence strength a source's rows carry in the register when a row does not say (for example `reported` for a management system's own records) | None: rows default to `measured` |
| `config.register_overlay_suffix(*suffixes)` | File suffixes beside a profile that are overlays, never profiles | `.dispositions.yaml`, `.derived-ports.yaml`, and `.ipam.yaml` (registered by `ipam.py`) |
| `ipam.register_reader(kind, fn, optional=False, evidence="observed", replace=False)`, or the entry-point group `takestock.ipam_readers` | A reader for one kind of IP plan source | `csv`, `dns-zones`, `asn-lookups` |
| `plugins.Plugin(...)`, found in takestock's readers library (`readers/`), through the entry-point group `takestock.collectors`, or by a profile's `module:` or `path:` | A plug-in collector: its name, kind, input and step. It runs only when the profile's `plugins:` list names it (see [`PLUGINS.md`](PLUGINS.md)) | The readers library, listed in `readers/__init__.py` ([`COLLECTORS.md`](COLLECTORS.md#the-readers-library)) |
| `comply.register(Standard(...))`; `comply.REGISTRY` | A standard `takestock comply` can read an observation against: its id, title, requirement data, and its evaluate, text, HTML and unmet functions (see [Adding a standard](#adding-a-standard)) | `sge`, registered in `comply.py` |
| `coverage.SCOPE_AREAS` | Whole areas of an assessment, so a gap that names a whole area (undone work, not a gap) is refused | Empty: a caller fills it or passes its own |

## Data files

`src/takestock/data/` holds everything the code grades against, so a
standard can change without a code change. Each is read through
`config.data_file`, which prefers a named workspace's `data/` copy (see
[`TARGET-PROFILE.md`](TARGET-PROFILE.md#bundled-data-and-a-workspaces-data)).

| File | Holds |
|---|---|
| `baseline.yaml` | The algorithm baseline: every token's grade, by table, with citations |
| `dispositions.yaml` | The default ladder and the generic disposition rules |
| `cmdb-schema.yaml` | The register's classes, attributes, relationships and vocabularies |
| `requirements-catalogue.yaml` | Requirement templates and their triggers |
| `secure-government-email.yaml` | The Secure Government Email requirement set |
| `dns-services.yaml` | Public resolvers, a DNSSEC validation control, a certificate-transparency endpoint, CAA issuers and takeover namespaces; shipped empty |
| `port-encryption.csv` | Each well-known port's posture (`encrypted`, `opportunistic` or `cleartext`), exposure and remedy |
| `daemon-dictionary.csv` | Process binary names mapped to products |
| `vendor-domains.csv` | Public vendor domains, for naming the operator of an outside service |
| `windows-lifecycle.yaml`, `software-lifecycle.yaml` | Vendor support dates, filled from public sources |
| `crypto-software.csv` | Cryptographic libraries, and the highest TLS version a release line can negotiate, from public sources. Read by `software_inventory` |
| `plugin-kinds.yaml` | The record schema of each plug-in kind, and how its records become rows. The contract with plug-ins, so it is read from the package only and a workspace copy is ignored |

## Adding a collector

A reader for an export that need not ship with takestock can be a plug-in
in its own package instead, with no change here; see
[`PLUGINS.md`](PLUGINS.md). A collector inside the package:

1. **Write the module**, `src/takestock/collectors/<name>.py`, with an entry
   point that takes the loaded profile first and returns
   `(rows, failures_or_gaps)`. An active probe's entry point starts
   `(target, raw_dir, ref_time, ...)`; an ingest collector's is
   `(target, root=None)` and reads its export with `config.inbox_path`. Its
   docstring says what it reads or sends, what it cannot see, and its
   profile keys.
2. **Gate before contacting anything.** An outside-in probe checks
   `inside_scope.scan_refusal(SOURCE, target)` and returns that line as its
   only failure when refused. An inside probe reads its hosts only through
   `inside_scope.entries(target, group)`, which demands the group's own
   authorisation record, and names each host one at a time
   (`entry_address`, `check_unique`, `check_ceiling`). Refuse, never
   truncate.
   Name each row by the rule in `identity.py`: `host` is the host name when
   the profile gives one and the address otherwise, and `ip` holds the probed
   address when the row is named by a host name. A collector that probes at
   an address passes its rows through `identity.report_as` with
   `identity.names_by_address(target)`.
3. **Run external programs through `util.run`**, so tests can replace it,
   and save each transcript under `raw_dir`.
4. **Say what was not seen.** Return a `coverage.gap(...)` for every
   question the collector could not answer, a missing export included. A
   missing tool is a gap or an `unknown` row, never a clean result.
5. **Grade through the baseline.** Put the tokens the collector reports in
   the row's cryptography fields; add any token the baseline lacks to
   `data/baseline.yaml` with its citation, or leave it to be flagged
   `ungraded:`.
6. **Register it** in `collectors/__init__.py`
   (`register("<name>", "<module>", "<kind>")`) and give it a step in
   `observe.PLANS`, using an existing adapter where the signature fits. Set
   `late=True` if it reads other collectors' rows and `offline=True` if it
   sends nothing over the network.
7. **Declare its flags**: informational ones with
   `model.register_informational_prefixes`, depth rungs with
   `depth.register_flags`, and any new protocol's hardware or software
   binding with `binding.register_binding`. If it reads an overlay file,
   register the suffix with `config.register_overlay_suffix`.
8. **Test it on synthetic fixtures** (see
   [`CONTRIBUTING.md`](../CONTRIBUTING.md)): its parsing, its refusals, and
   that it contacts nothing it was not told to.
9. **Document it**: its section in [`COLLECTORS.md`](COLLECTORS.md), its
   profile keys in [`TARGET-PROFILE.md`](TARGET-PROFILE.md), and its tools
   in [`SETUP-SCANNERS.md`](SETUP-SCANNERS.md).

`tests/test_observe.py` checks that every registered collector has a step,
and `tests/test_probe_registry.py` checks each active probe's kind and
signature.

## Adding a standard

`takestock comply <standard>` reads one observation against one standard.
The command has no code of its own for any standard: it looks the id up in
`comply.REGISTRY`, so a new standard needs no new command. To add one:

1. **Encode the requirements as data**, in `src/takestock/data/<name>.yaml`,
   each with its level and the sentence that decides it, quoted from the
   published standard with its source. Add the file to the
   [data files](#data-files) table.
2. **Write the grading**, in its own module: a function that takes the
   observation's rows and the profile's settings and returns a result object
   with one reading per requirement and subject, each *met*, *not met* or
   *not measured* with the reason. A requirement nothing in the observation
   can settle is *not measured*, never met.
3. **Write the renderers**: one function that returns the result as plain
   text, and one that returns it as a complete HTML page through
   `htmlpage.page`, so it shares the shell and the profile's branding.
4. **Register it**, with `comply.register(comply.Standard(...))`, giving
   - `id`: what follows `takestock comply`, lower case;
   - `title`: one line for `takestock comply --list`;
   - `data`: the requirement data file;
   - `html_name`: the HTML file written inside the observation directory
     when `--out` is not given;
   - `evaluate(observation_dir, target)`, `text(result, observation_dir,
     target)`, `html(result, observation_dir, target)` and `unmet(result)`.
     `unmet` returns true when a requirement stated as *must* is not met,
     which makes the command exit 1. `evaluate` raises
     `comply.NothingToRead` when the profile names nothing the standard
     applies to, which exits 2.

   Import the standard's modules inside those functions, not at the top of
   the registering module, so `takestock comply --list` stays quick.
   `sge`, at the end of `comply.py`, is the worked example: it wraps
   `sge.py` (the grading) and `sge_note.py` (the note).
5. **Test it** as `tests/test_comply.py` tests `sge`: it is listed, each
   format renders, and an unmet *must* exits 1.
6. **Document it**: a guide in `docs/`, a row in the README's outputs table,
   and an entry in `CHANGELOG.md`.
