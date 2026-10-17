# Plug-in collectors

takestock ships readers for the exports it knows (see
[`COLLECTORS.md`](COLLECTORS.md)). Many organisations hold evidence in
exports it has no reader for: an endpoint management or inventory tool's
software or disk encryption report, a directory's authentication settings, a
mail platform's per-message trace, a virtualisation inventory, a backup or
database encryption report. A
**plug-in** is a small reader for one such export. It lives in the
organisation's own package, outside takestock, and an observation runs it as
if it were built in.

takestock owns the contract: what a plug-in receives, the fields its records
carry, how those records become rows and how the rows are graded. A plug-in
translates its export into records and stops there.

takestock also ships plug-ins of its own: the **readers library**
(`takestock.readers`), readers for standard formats and named products'
exports, written to this same contract. A profile names one exactly as it
names an installed plug-in, and like any plug-in it runs only when named.
They are listed in
[`COLLECTORS.md`](COLLECTORS.md#the-readers-library).

## Terms used here

- **Plug-in**: one reader, declared with a `Plugin` object.
- **Kind**: the sort of evidence a plug-in reads. Each row kind has a fixed
  **record schema** (the fields a record may carry), listed
  [below](#the-kinds). The [`general`](#general) kind has none: its plug-ins
  return finished rows.
- **Record**: one mapping of field names to values, which a plug-in returns
  for each thing it read.
- **Row**, **coverage gap**: as in [`ARCHITECTURE.md`](ARCHITECTURE.md#terms-used-here).
- **Step**: the plug-in's function that takestock calls during an
  observation.

## A worked example

[`examples/plugin-disk-encryption/`](../examples/plugin-disk-encryption/) is a
complete plug-in for Example Widgets Ltd (a fictional manufacturer), reading
disk encryption state from an invented tool's CSV export. It is written to be
copied. Its declaration is:

```python
PLUGIN = Plugin(
    name="example-disk-encryption",
    kind="endpoint-encryption",
    step=read,
    input="inbox/disk-encryption.csv",
    title="Disk encryption export (example tool)",
    data_files=("cipher-names.csv",),
    summarise=summarise,
)
```

and its step returns one record per volume:

```python
{"device": "laptop-01.example.test", "volume": "C:", "state": "encrypted",
 "method": "aes-256-xts", "key_protectors": ["tpm+pin"], "recovery_key_escrowed": True}
```

takestock checks each record, writes the row
`Disk encryption laptop-01.example.test C:`, and grades it `strong` from the
baseline's `aes256_xts` entry.

## Declaring a plug-in in the target profile

Nothing runs until the target profile's `plugins:` list names it:

```yaml
plugins:
  - name: example-disk-encryption          # required
    input: inbox/disk-encryption.csv       # optional: overrides the plug-in's own default
    required: true                         # optional, default true
    settings: {site: head-office}          # optional: handed to the step as ctx.settings
  - name: local-reader
    path: plugins/local_reader.py          # a Python file in the workspace
  - name: packaged-reader
    module: widgets_readers.mail:PLUGINS   # an importable module, and optionally an attribute
```

A bare string (`- example-disk-encryption`) is the same as `{name: ...}`.

| Key | Holds |
|---|---|
| `name` | The plug-in's name, as its `Plugin` declares it |
| `module` | An importable module, `package.module` or `package.module:attribute`. Without an attribute, `PLUGIN` is read |
| `path` | A Python file, relative to the workspace, whose `PLUGIN` is read |
| `input` | The path the step reads, written as any profile path (`inbox/<file>`); `""` for none |
| `required` | `false` makes the plug-in's "not run" gap optional, so it does not mark the observation incomplete |
| `settings` | Anything the plug-in documents; takestock passes it through unread |

A plug-in that reads the same evidence as a built-in collector, from another
source, can stand in for it: turn the built-in off under `collectors.disabled`
([`TARGET-PROFILE.md`](TARGET-PROFILE.md#collectors)), with the reason, so the
observation does not also report the built-in's export as missing.

## How takestock finds a plug-in

Three ways, and a profile may mix them:

- **takestock's readers library** is part of the package, so every
  installation has it. It is read from the package itself, not from installed
  package metadata, so a clone and an installed copy find the same readers.
- **An installed package** names its plug-ins under the entry-point group
  `takestock.collectors`, as the example does in its `pyproject.toml`:

  ```toml
  [project.entry-points."takestock.collectors"]
  example-disk-encryption = "example_disk_encryption:PLUGIN"
  ```

- **The target profile** names a `module:` or a `path:`, for a reader that is
  not packaged.

An entry point may name one `Plugin`, a list of them, or a function taking no
arguments that returns either. So may `module:` and `path:`.

A name given alone (no `module:` or `path:`) is looked up in the library and
the installed packages. When two different plug-ins answer to it (one in the
library and one in a package, or one in each of two packages), it is **not
run**: running either would be a guess. The gap says who offers the name, and
the profile chooses with `module:`, for example
`module: takestock.readers:PLUGINS` for the library's reader, or the
package's own module for the other. The same plug-in offered twice, such as
by two entry points of one package, is one offer.

Both exist because they suit different owners. An entry point is the right
home for a reader several workspaces share: it is installed once, versioned,
and found without anyone writing a path. A module or file path suits a reader
that belongs to one workspace and has no package of its own. In both cases
**the profile decides what runs**: an installed plug-in that a profile does
not name never runs for it, so installing a package never quietly changes
what another organisation's observation reads. Installed plug-ins a profile
does not name are listed in `summary.json` under
`plugins_installed_not_declared`; the library's readers are not, since every
installation has them.

## Writing a plug-in

### The declaration

```python
from takestock.plugins import Context, Plugin, StepResult
```

| `Plugin` field | Holds |
|---|---|
| `name` | Lower-case letters, digits, `-` and `_`, starting with a letter. It is the `source` of the rows the plug-in writes, unless the kind fixes one |
| `kind` | One of the [row kinds](#the-kinds), or [`general`](#general), `coverage-check` or `annotation` |
| `step` | The function takestock calls: `step(ctx: Context)` |
| `input` | The default input path (`inbox/<file>`), or `""` when the step reads none |
| `late` | `True` to run after every built-in collector, seeing their rows |
| `title` | What the input is, for a reader; it becomes each row's `source_name` |
| `data_files` | The plug-in's own reference files, by plain file name |
| `data_dir` | Where those files are; by default the directory of the module defining `step` |
| `summarise` | Optional: `summarise(ctx, rows)` called after grading with the plug-in's own graded rows, returning a mapping for `summary.json` |
| `annotation_keys` | For an annotation only: the `extra` keys it writes. takestock removes them from every row before the annotation runs (see [below](#capabilities)) |
| `gap_prefix` | `True` (the default) starts each gap the step returns with ``plug-in `<name>`:``. `False` files the step's gaps exactly as written, for a plug-in whose gap sentences are written for the report's reader rather than the tool's operator |
| `date_rows` | `True` (the default) dates a row the plug-in left undated. `False` leaves it undated (see [below](#capabilities)) |

A malformed declaration (an unknown kind, a name with spaces, a data file
given as a path) raises when the plug-in's module is imported. takestock
records that as the plug-in not loading, and the observation continues.

### What the step receives

`ctx` is a `Context`. The profile, the reference data and the rows are
copies, so a step that changes them changes nothing outside itself.

| `Context` field | Holds |
|---|---|
| `input` | The input as a `Path`, resolved against the workspace inbox exactly as a built-in ingest collector's export is; `None` when the plug-in reads none |
| `inbox_path(rel)` | Resolves any further path the same way |
| `ref_time` | The observation's reference time |
| `raw_dir` | `raw/plugins/<name>/` inside the observation, created for the plug-in, for anything it wants kept beside the result |
| `collected_on` | The input file's modification date, or the observation's date: the default date on every row |
| `target`, `settings` | The loaded target profile, and the declaration's `settings:` |
| `policy`, `baseline` | The grader over the algorithm baseline, and the baseline itself |
| `dictionary` | The daemon dictionary: process binary names mapped to products |
| `port_table` | The port-encryption table, indexed as `takestock.plaintext` reads it |
| `assets` | The rows collected so far. Empty for an ordinary step; filled for a late step, a coverage check and an annotation |
| `run` | How the observation has gone so far, as a `RunInfo` (below). `None` for an ordinary step; filled for a late step, a coverage check and an annotation |
| `data_file(name)` | The path of one of the plug-in's declared data files |

`ctx.run` is a `RunInfo`:

| `RunInfo` field | Holds |
|---|---|
| `collectors` | Every built-in collector registered in this takestock |
| `ran` | The built-in collectors that ran |
| `skipped` | The built-in collectors that did not run, each with the reason (such as `active probes need --scan`) |
| `failed` | The built-in collectors that reported a real failure or stopped with an error |
| `carried` | The active collectors whose rows were carried from an earlier observation instead of probing again (`--carry-scan`); in neither `ran` nor `skipped` |
| `plugins` | Each declared plug-in's status so far: `ran`, `not-run` (its `summary.json` record says why) or `pending` (its turn has not come; a plug-in reading this sees itself as pending) |
| `scan`, `offline` | The observation's options |

A tool that runs the plug-ins itself passes one to `Host.run(..., run=)`
and `Host.annotate(..., run=)`; `takestock.observe.run_info(run)` builds it
from an observation's `Run`. When none is passed, `ctx.run` is `None`.

### What the step returns

A `StepResult`, or a plain list of records:

| `StepResult` field | Holds |
|---|---|
| `records` | One mapping per thing read, with the kind's fields. A finished `CryptoAsset` is accepted too (see below), and is the only thing a `general` plug-in returns |
| `gaps` | What the plug-in could not read, made with `takestock.coverage.gap(...)`. A plain string is filed as a could-not-test gap |
| `summary` | A mapping written under the plug-in's name in `summary.json`. It must be expressible as JSON |
| `annotations` | For the `annotation` kind only: `{bom_ref: {key: value}}`, each value anything expressible as JSON |

Records are the normal return. They keep grading in one place: every plug-in
of a kind is named and graded the same way, whatever product it reads. A
plug-in that already builds rows of its own may return finished
`CryptoAsset` rows instead. Each is held to its kind's row constraints (the
data states and protocols that kind's rows use, and any `extra` keys other
parts of takestock read), its `extra` must be expressible as JSON, and its
`source` is always replaced with the plug-in's name, so no plug-in can write
rows that read as another collector's. A finished row keeps the
`source_name` and `collected_at` the plug-in gave it; one left undated is
dated as a record without `collected_on` is, unless `date_rows` is `False`.

### When steps run

| Step | Runs |
|---|---|
| ordinary | after the built-in collectors' early steps, before their late ones, so a built-in late step (such as `winrm_config`) sees the plug-in's rows |
| `late=True` | after every built-in step, with the rows so far in `ctx.assets` |
| `coverage-check` | as a late step. It returns gaps only; a row it returns is refused, with a gap saying so |
| `annotation` | after grading, before the summary, with every graded row in `ctx.assets` |

Plug-ins of one phase run in the order the profile lists them. They read
files, never the network, so they run in an offline observation too.

### Capabilities

**Reading other rows (late steps and coverage checks).** A coverage check
compares a list of what should exist with what the other collectors saw, and
returns a gap for each difference. For example, a device list against the
devices that any collector produced a row for:

```python
def check(ctx: Context) -> StepResult:
    seen = {a.host for a in ctx.assets if a.host}
    missing = sorted(set(expected_devices(ctx)) - seen)
    return StepResult(gaps=[coverage.gap(
        coverage.EXTENT_UNKNOWN, f"{len(missing)} device(s) on the list were seen by no collector",
        impact_kind=coverage.NARROWS_CONFIDENCE,
        impact="Whatever those devices run is missing from every count.",
        nature=coverage.NO_DATA)] if missing else [])
```

A check comparing a list of what should have run with what did
reads `ctx.run`, so it can tell a collector that is not part of this
takestock, one that was skipped (and why), and one that ran and found
nothing:

```python
def expected(ctx: Context) -> StepResult:
    gaps = []
    for name in ("netdev", "software_inventory"):
        if name not in ctx.run.collectors:
            gaps.append(f"{name} is not a collector this takestock has")
        elif name in ctx.run.skipped:
            gaps.append(f"{name} did not run: {ctx.run.skipped[name]}")
    return StepResult(gaps=gaps)
```

**Adding a label to other rows (annotations).** An annotation returns, for
each row it labels, the row's `bom_ref()` and the keys to add to its `extra`.
A value may be anything expressible as JSON except null: text, a number,
true or false, or a list or mapping of those, so a label can carry its own
date and source. It may add a key, and may repeat a key's existing value, but
never change one: a key already holding another value is refused, and so is
an unknown reference. Refusals are one gap. An annotation runs after grading,
so it moves no verdict, flag or count.

A row read again from an earlier observation, or carried into this one, may
already hold a label an earlier run wrote. Declare the keys an annotation
writes in `annotation_keys`, and takestock removes them from every row before
the annotation runs (whether or not its step then runs), so each label is this
run's own and a changed label is not refused as a change. Choose keys no
other collector writes: every row loses them. `plugin`, which names the
plug-in that wrote a row, cannot be declared.

```python
def label(ctx: Context) -> StepResult:
    production = production_hosts(ctx)
    tag = {"name": "production", "source": "service register", "as_of": "2030-01-31"}
    return StepResult(annotations={a.bom_ref(): {"environment": tag}
                                   for a in ctx.assets if a.host in production})

PLUGIN = Plugin(name="environments", kind="annotation", step=label,
                annotation_keys=("environment",))
```

**Leaving rows undated.** takestock dates every row a plug-in returns
without a date: by the input file's modification date, or else the
observation's date. That suits a row recording something read at a time. A
row that instead states what a declaration says, or what a comparison
between other rows found, was not read at any time, and a date would present
it as a reading. Declare `date_rows=False` and takestock leaves such rows
undated, in an ordinary or a late step alike. A date the plug-in gives a row
itself (a finished row's `collected_at`, or a record's `collected_on`) is
kept either way.

```python
def compare(ctx: Context) -> StepResult:
    declared = declared_hosts(ctx)
    seen = {a.host for a in ctx.assets}
    return StepResult(records=[
        CryptoAsset(name=f"Declared but not seen: {host}", data_state="inventory",
                    host=host, verdict="unknown")
        for host in sorted(declared - seen)])

PLUGIN = Plugin(name="declared-vs-seen", kind="general", step=compare, late=True,
                date_rows=False)
```

**Contributing to the summary.** Whatever the step returns as `summary`, and
whatever `summarise` returns after grading, is written in `summary.json`
under `plugins.<name>.summary`. A contribution that is not a mapping, or not
expressible as JSON, is left out with a gap.

**Its own data files.** A plug-in that needs a lookup table of its own (the
example maps its tool's cipher labels to baseline names) declares it in
`data_files` and reads it with `ctx.data_file(name)`. That only ever returns
a file from the plug-in's own directory, and takestock's data files
(`config.data_file`) never read from it, so a plug-in file named
`baseline.yaml` changes no grade.

**Host listeners.** A `host-listener` plug-in reports ports a program is
listening on, as the machine itself sees them. takestock registers its rows
with `plaintext.register_host_listener_source`, so the port table's reading
of an out-of-band management port seen only from the host is applied to them,
and kept current when a stored observation is re-read.

### What is recorded when a plug-in does not run

An absent plug-in never reads as a clean result. Each of these is a coverage
gap naming the plug-in, and the plug-in's `summary.json` record says
`status: not-run` with the reason:

| Situation | Gap |
|---|---|
| declared, and not installed; its module or file will not load; or it defines no plug-in of that name | could not test |
| declared by name alone, and two different plug-ins answer to the name | could not test |
| its input does not exist (the step is not called) | not collected |
| its step raised (the error is quoted) or returned something other than a `StepResult` or a list | could not test |

These gaps are required unless the declaration says `required: false`, so a
declared plug-in that did not run marks the observation incomplete
(`summary.json["complete"]` is false). None of them is a collector failure:
the run continues and the exit code is decided by the other collectors and
the findings.

Two more gaps record a plug-in that ran but returned less than it should:

- records that do not match the kind's schema are left out, and one gap
  gives how many and quotes the first problems (an unknown field, a missing
  required field, a value outside a choice). The valid records are written;
- a row kind that returned no records at all is a gap, because an empty
  result may be an empty export, a filter, or a layout the plug-in does not
  read. That gap is not added when the step returned a gap of its own, which
  has already said why nothing came back, nor for a `general` plug-in, which
  says for itself what an empty result means.

Whatever `gap_prefix` says, the gaps takestock writes about a plug-in (not
run, records refused, a summary not written) always name it, and
`summary.json["plugins"]` always holds its record.

### What `summary.json` records

`summary.json["plugins"]` holds one record per declared plug-in:

| Key | Holds |
|---|---|
| `kind` | The plug-in's kind |
| `status` | `ran` or `not-run` |
| `reason` | Why it did not run |
| `origin` | `library` (takestock's readers library), `entry point`, `module <name>` or `path <file>` |
| `input` | The input path as resolved |
| `records`, `rows`, `invalid` | Records returned, rows written, records refused |
| `problems` | The first few reasons records were refused |
| `annotated` | For an annotation: how many rows it labelled |
| `summary` | The plug-in's own contribution |

## The kinds

### Rules every row kind shares

The schema is in `src/takestock/data/plugin-kinds.yaml`, the machine-readable
form of this section. It is always read from the package; a workspace's
`data/` copy is ignored, because it is the contract and not a policy.

Each field has a type:

| Type | Accepts |
|---|---|
| text | a string, trimmed. A required text field must not be blank |
| count | a whole number, zero or more; `"1,200"` reads as 1200 |
| port | a whole number from 1 to 65535 |
| flag | true or false; also yes/no, on/off, 1/0 |
| date | `YYYY-MM-DD`; a longer timestamp is cut to its date |
| tokens | a list of strings, or one string split on `;` or `,` |
| choice | one of the listed values, ignoring case. Common spellings are accepted as synonyms (`yes` for `encrypted`, `enforced` for `on`), listed in the schema file |

Every row kind also accepts:

- `collected_on` (date): when the record was true. Without it the row is
  dated by the input file's modification date, then the observation's date,
  unless the plug-in declares `date_rows=False`, when it stays undated;
- any field starting `x_`, the plug-in's own, copied into the row's `extra`
  unchanged (text, numbers, true or false, or a list of those).

**Any other field makes the record invalid**, so a misspelt field name is
reported instead of silently dropped.

**Algorithms** are placed by the baseline, as `netdev` places them: a token
written `table=value` goes to that table, and a bare token goes to the one
table that knows it. Each kind lists the tables its controls may use, and
some kinds map common spellings first (listed in the schema file under
`aliases`). A token no table places is flagged `ungraded:<kind>:<token>`
and the row stays unknown, never passed.

**The control state.** Four kinds (`directory`, `virtualisation`,
`backup-encryption`, `database-encryption`) describe controls. Each control
is named for the protection it gives, so its `state` is one of:

| State | Means | Also written |
|---|---|---|
| `on` | the protection is in place | `enabled`, `yes`, `true`, `required`, `enforced`, `configured`, `present`, `encrypted`, `blocked`, `refused` |
| `off` | it is not | `disabled`, `no`, `false`, `not-required`, `not-enforced`, `not-configured`, `absent`, `allowed`, `unencrypted`, `cleartext` |
| `partial` | it covers only part of the subject | `some`, `mixed`, `opportunistic` |
| `unknown` | not recorded | blank, `not-checked` |

and each control is graded one of three ways:

| Graded on | `on` | `off` | `partial` | `unknown` |
|---|---|---|---|---|
| algorithms | the baseline grades the tokens; none recorded is unknown, flagged `algorithms-not-recorded` | weak, `encryption-off` | weak, `control-partial:<control>` | unknown, `control-state-unknown` |
| setting | acceptable: an on-or-off setting is never strong | weak, `control-off:<control>` | weak, `control-partial:<control>` | unknown, `control-state-unknown` |
| presence | not graded (`n/a`), flagged `<control>:present` | `n/a`, `<control>:absent` | `n/a`, `<control>:partial` | `n/a`, `<control>:unknown` |

A partial control is weak because a row is graded on the weakest thing it
accepts: part of the subject has no protection. Its algorithms are kept in
`extra` and not graded, since they describe only the protected part.

Control rows are named `<control label> <subject>` and carry the control,
its state and every other field in `extra`.

### `endpoint-software`

Installed software, one record per product on one device.

| Field | Type | Required | Holds |
|---|---|---|---|
| `device` | text | yes | The machine, by name or address |
| `product` | text | yes | The product as the inventory spells it |
| `version` | text | | The installed version |
| `vendor` | text | | The publisher |
| `path` | text | | Where the copy is installed |

**Rows and grading** are exactly those of the built-in `software_inventory`
collector ([`COLLECTORS.md`](COLLECTORS.md#software_inventory)): products
are matched against `data/crypto-software.csv`, one row per cryptographic
provider and version (data state `software`), a version-spread row, and a
scope row named `<title> scope`. A product the register does not list is
counted and named on the scope row, not graded.

### `endpoint-encryption`

Disk encryption state, one record per volume on one device.

| Field | Type | Required | Holds |
|---|---|---|---|
| `device` | text | yes | The machine, by name or address |
| `volume` | text | yes | The volume, drive or partition |
| `state` | choice | yes | `encrypted`, `not-encrypted`, `in-progress`, `suspended` or `unknown` |
| `method` | text | | The cipher and mode, such as `aes-256-xts` |
| `volume_type` | choice | | `operating-system`, `data`, `removable` or `unknown` |
| `key_protectors` | tokens | | How the volume is unlocked, such as `tpm`, `tpm+pin`, `password`, `recovery-key` |
| `recovery_key_escrowed` | flag | | Whether a recovery key is held somewhere other than the device |
| `device_id` | text | | A stable identifier that survives a rename |

**Rows**: one per record, named `Disk encryption <device> <volume>`, data
state `at-rest`, protocol `disk-encryption`. The device is named by the rule
in [`COLLECTORS.md`](COLLECTORS.md#where-active-probes-point).

| State | Grade |
|---|---|
| `encrypted` with a `method` | the baseline grades the cipher (`aes-256-xts` and `xts-aes-256` both mean `aes256_xts`) |
| `encrypted` without one | unknown, `algorithms-not-recorded` |
| `not-encrypted` | weak, `encryption-off` |
| `suspended` | weak, `encryption-suspended`: the key is readable from the disk |
| `in-progress` | unknown, `encryption-in-progress` |
| `unknown` | unknown, `control-state-unknown` |

`recovery_key_escrowed: false` adds `recovery-key-not-escrowed`; `true` adds
the informational `recovery-key-escrowed`. Neither moves the verdict, which
is about the encryption.

### `directory`

Identity and authentication settings, one record per setting of one
directory, domain or tenant.

| Field | Type | Required | Holds |
|---|---|---|---|
| `directory` | text | yes | The directory, domain or tenant the setting belongs to |
| `setting` | choice | yes | One of the settings below |
| `state` | control state | yes | Whether the protection is in place |
| `algorithms` | tokens | | For `kerberos-encryption`: the encryption types allowed |
| `scope` | text | | Which part of the directory the reading covers |
| `server` | text | | The server the reading was taken from, when it is one server; it becomes the row's host |

| Setting | Graded on | Protocol |
|---|---|---|
| `ldap-signing-required` | setting | `ldap` |
| `ldap-channel-binding-required` | setting | `ldap` |
| `kerberos-encryption` | algorithms (symmetric) | `kerberos` |
| `ntlmv1-refused` | setting | `ntlm` |
| `legacy-authentication-blocked` | setting | `legacy-authentication` |
| `mfa-required` | setting | `mfa` |

Rows have data state `identity`. Kerberos encryption types are mapped before
grading: the AES types (RFC 3962, RFC 8009) use AES in a CBC mode, so they
grade as `aes_cbc`; RFC 8429 deprecates the RC4 and DES types, which grade as
`rc4` and `des`.

### `mail-transport`

The transport encryption a mail delivery negotiated. A record may describe
one message, or a count of messages that share a direction, path and TLS
version, so a per-message trace and a per-route report both fit.

| Field | Type | Required | Holds |
|---|---|---|---|
| `direction` | choice | yes | `inbound` or `outbound` |
| `tls_version` | text | yes | The version negotiated, such as `TLS1.2` (`TLS 1.2` and `TLSv1.2` are read the same), or `none` for no transport encryption |
| `messages` | count | | How many messages the record stands for; 1 when absent |
| `path` | text | | The route (a connector, relay or rule); `direct` when absent |
| `route_configured` | flag | | Whether a configured route, such as a connector or relay definition, governed the path |
| `date` | date | | The day the mail was sent or received |
| `counterparty_domain` | text | | The other party's mail domain |
| `government` | flag | | Whether the other party is a government organisation. Supply it on every record or none |
| `government_basis` | text | | How a government counterparty was identified |

**Rows**: records are added up, one row per direction and path, named
`<Direction> mail via <path>`, plus a scope row named `<title> scope`. Every
row has data state `in-transit`, protocol `smtp` and **source
`mail_transport`, whatever the plug-in is called**, because that is the
source the [Secure Government Email reading](SGE-NOTE.md) reads the sending
half of SGE-TLS-01 and the SGE-ITLS-01 population from. Each path row's
`extra` holds `direction`, `messages`, `no_tls_messages`, `tls_distribution`
(such as `TLS1.2=900; TLS1.3=100; No TLS=3`), `connector_present` (`yes` or
`no` when `route_configured` was given), `counterparty_domains` and, from the
dates, the `window` the records cover. When the records carry `government`,
each path row also holds the `govt_` counts that reading uses, and the scope
row the union of government counterparty domains. Who mailed whom is never
kept: only counts and a tally of domains.

**Grading**: a path that carried any message with no TLS is weak, flagged
`mail-cleartext-delivery:<direction>`. Otherwise it is the weakest grade the
baseline gives the TLS versions seen, with `deprecated-protocol:<version>`
for each weak one. A version the baseline does not know is flagged
`ungraded:tls_versions:<version>`. The scope row is not graded. A plug-in's
`x_` fields are not carried onto these rows, because each row adds up many
records.

### `virtualisation`

Encryption controls on a virtualisation platform, one record per control on
one virtual machine, host, cluster or datastore.

| Field | Type | Required | Holds |
|---|---|---|---|
| `object` | text | yes | The virtual machine, host, cluster or datastore; it becomes the row's host |
| `object_type` | choice | | `vm`, `host`, `cluster`, `datastore` or `other` |
| `control` | choice | yes | One of the controls below |
| `state` | control state | yes | Whether the control is in place |
| `algorithms` | tokens | | The algorithms the control uses |
| `key_service` | text | | The key management service that holds the keys |
| `platform` | text | | The virtualisation product |
| `version` | text | | The product version |

| Control | Graded on | Data state, protocol |
|---|---|---|
| `vm-encryption` | algorithms (symmetric) | `at-rest`, `vm-encryption` |
| `migration-encryption` | algorithms (symmetric) | `in-transit`, `vm-migration` |
| `datastore-encryption` | algorithms (symmetric) | `at-rest`, `datastore-encryption` |
| `management-tls` | algorithms (TLS versions, symmetric, key exchange, signatures) | `in-transit`, `tls` |
| `key-management` | presence | `at-rest`, `key-management` |

### `backup-encryption`

Encryption of backups, one record per control on one backup job, policy or
storage target.

| Field | Type | Required | Holds |
|---|---|---|---|
| `target` | text | yes | The backup job, policy or storage target |
| `control` | choice | yes | `at-rest` (stored copies) or `in-transit` (copies being made or moved) |
| `state` | control state | yes | Whether the control is in place |
| `algorithms` | tokens | | The algorithms the control uses |
| `key_custody` | choice | | Who holds the keys: `product`, `customer`, `hsm`, `external-kms` or `unknown` |
| `location` | choice | | `on-premises`, `cloud`, `offsite` or `unknown` |
| `immutable` | flag | | Whether stored copies cannot be changed or deleted before they expire |
| `platform` | text | | The backup product |

| Control | Graded on | Data state, protocol |
|---|---|---|
| `at-rest` | algorithms (symmetric) | `at-rest`, `backup-encryption` |
| `in-transit` | algorithms (TLS versions, symmetric) | `in-transit`, `tls` |

### `database-encryption`

Encryption controls on a database, one record per control on one database
or instance.

| Field | Type | Required | Holds |
|---|---|---|---|
| `database` | text | yes | The database or instance |
| `control` | choice | yes | One of the controls below (`tde` is read as `storage`) |
| `state` | control state | yes | Whether the control is in place |
| `algorithms` | tokens | | The algorithms the control uses |
| `key_custody` | choice | | Where the master key is kept: `software`, `hsm`, `external-kms` or `unknown` |
| `engine` | text | | The database product |
| `version` | text | | The product version |
| `server` | text | | The machine the database runs on; it becomes the row's host |

| Control | Graded on | Data state, protocol |
|---|---|---|
| `storage` | algorithms (symmetric) | `at-rest`, `database-encryption` |
| `column` | algorithms (symmetric) | `at-rest`, `column-encryption` |
| `backup` | algorithms (symmetric) | `at-rest`, `database-backup-encryption` |
| `transport` | algorithms (TLS versions, symmetric) | `in-transit`, `tls` |

A control that can carry TLS versions has protocol `tls`, because the grader
reads TLS versions only on a TLS row.

### `host-listener`

Listening ports as the machine itself reports them, one record per program
listening on one port.

| Field | Type | Required | Holds |
|---|---|---|---|
| `device` | text | yes | The machine, by name or address |
| `port` | port | yes | The listening port |
| `transport` | choice | yes | `tcp` or `udp` |
| `process` | text | | The program listening, by its binary name; the daemon dictionary names the product |
| `address` | text | | The address the program is bound to |

**Rows**: one per record, named `Host listener <device>:<port>/<transport>`,
data state `in-transit`, protocol from the port table (else the transport).
The port table's posture is applied as for a listener seen from the host:
a cleartext port is weak and flagged `plaintext:<protocol>`; a port that can
upgrade in band is flagged `unverified-encryption:<protocol>`, a coverage
question rather than a finding; an encrypted one stays unknown until a probe
grades it. An out-of-band management port seen only from the host is
recorded with its exposure unmeasured.

### `general`

Evidence that fits none of the record schemas above, such as a certificate
inventory, a configuration audit, or a key store listing. A `general` plug-in
has no record schema, so it builds its rows itself and returns them as
finished `CryptoAsset` rows. It may be ordinary or `late`.

Each row is held to what every row must satisfy, whatever its kind: a name, a
verdict from the verdict order (`weak`, `acceptable`, `strong`, `pqc`,
`unknown` or `n/a`), and an `extra` expressible as JSON. Any data state and
protocol are accepted. A row that fails is left out and counted in a gap, as
for any kind. The rows that pass are stamped and graded like every other
row: `source` becomes the plug-in's name, and the grader reads the row's
algorithms against the baseline.

A record mapping returned under `general` is refused, counted under
`invalid`, and named in one gap, because there is no schema to build a row
from. An empty result is not a gap by itself: a `general` plug-in that found
nothing, and wants a reader to know why, returns a gap saying so.

```python
def read(ctx: Context) -> StepResult:
    rows = [CryptoAsset(name=f"Configuration audit {device}", data_state="configuration",
                        protocol="config-audit", host=device, extra={"compliant": ok})
            for device, ok in audit_results(ctx.input)]
    return StepResult(records=rows)

PLUGIN = Plugin(name="example-config-audit", kind="general", step=read,
                input="inbox/config-audit.csv", title="Configuration audit export (example tool)")
```

## Making a new kind

A kind is a change to takestock, not to a plug-in: an entry in
`data/plugin-kinds.yaml`, the shape that turns its records into rows in
`plugin_kinds.py`, a section here, and tests. Keep its fields to what any
product of that kind records, named for what they mean, never after one
product's export.
