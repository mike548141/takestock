# Dispositions: what to do about each finding

A grade says how strong something is. It does not say what to do about it,
when, or how big the job is. takestock answers those with a **disposition**
on every graded row, and, for rows that breach a mandatory control, says
whether a recorded exception covers the decision to wait.

## Terms used here

- **Disposition**: a **track** (where the work sits), a plain-language
  **reason**, an **effort** size and, for an acceptance, what ends it. It sits
  beside the grade and never changes it: a weak cipher on an accepted track
  is still weak.
- **Ladder**: the time-ordered tracks work can be placed on, most urgent
  first. Each step is a **rung**.
- **Fixed tracks**: tracks beside the ladder that say why something is not
  being acted on in the ordinary way.
- **Rule**: a generic match-and-propose entry. Its result is **proposed**.
- **Decision**: an organisation's own entry, made by a person. Its result is
  **decided**.
- **Overlay**: the organisation's file of its own ladder, rules, decisions,
  adoptions and dispensations, beside its target profile.
- **Dispensation**: a recorded, authorised exception to a mandatory control,
  in the sense the New Zealand Information Security Manual (NZISM) uses.

## Where dispositions come from

Two files:

| File | Holds |
|---|---|
| `src/takestock/data/dispositions.yaml` | The default ladder and the generic rules. Ships with the tool; holds nothing about any organisation, and its `decisions:` list is always empty. |
| `targets/<stem>.dispositions.yaml` | The organisation's overlay, beside its target profile `targets/<stem>.yaml`. Optional. |

For each row, the first match wins, in this order:

1. the overlay's **decisions**, then the tool's (which are empty);
2. the overlay's **rules**, then the tool's rules, each list in file order;
3. nothing: the row has no disposition, and its basis is `none`.

A decision's result has basis `decided`. A rule's has basis `proposed`,
unless the organisation has **adopted** that rule (see
[Adopting a generic rule](#adopting-a-generic-rule)).

Because the first match wins, **order is meaning**. Several default rules
exist only to claim rows before a broader rule below them does.

## The ladder

The default ladder has four rungs:

| Track | Label | Means |
|---|---|---|
| `critical` | Critical | Fix immediately, out of cycle. The bar is exploitability, not algorithm strength: the finding must plausibly let someone readily obtain data they are not authorised to see, or get onto the network. A weak algorithm alone is not critical. |
| `wave-1` | Wave 1 | The highest-priority scheduled work |
| `wave-2` | Wave 2 | The next priority, or work that depends on an earlier wave |
| `wave-3` | Wave 3 | The priority after that |

`critical` is marked `out_of_cycle: true`: its work does not wait for a
planning cycle.

No default rule proposes `wave-2` or `wave-3`. Putting work in a later wave
is a programme commitment, and that is the organisation's decision. So are
the waves' dates: the tool supplies none.

An overlay may declare its own `ladder:`, which **replaces** the default.
The replacement must still contain every rung any loaded rule or decision
proposes; loading stops otherwise.

```yaml
ladder:
  - {track: critical, label: Critical, out_of_cycle: true}
  - {track: next-quarter, label: Next quarter}
  - {track: wave-1, label: This year}
```

## The fixed tracks

| Track | Label | Use it when |
|---|---|---|
| `pqc-migrate` | Post-quantum migration | Nothing is weak today, and the classical key exchange or signature still has to move to post-quantum cryptography |
| `retire-planned` | Retire — replacement planned | Acceptable today, and still being withdrawn (SHA-1 used as a MAC, for example) |
| `defer-migration` | Defer — migrating or retiring | The system is being migrated off or retired, and its current exposure is tolerable meanwhile |
| `accept-replacement-planned` | Accept until replaced | A planned replacement will remove the control, and it is tolerable until then |
| `accept-no-alternative` | Accept — no encrypted option | No encrypted alternative exists that the organisation could realistically adopt |
| `no-action` | No action | Nothing is owed |

### Acceptances: what ends them, and when they are looked at again

Three tracks accept a finding rather than schedule its removal:
`accept-replacement-planned`, `accept-no-alternative` and `retire-planned`.
Each should carry two things, and they answer different questions:

- **`until:`** names, in plain language, the condition that ends the
  acceptance ("the provider publishes a usable policy on this endpoint"). An
  acceptance without one is reported as open-ended, which is a weaker claim.
- **`review:`** is the date it is next looked at, `YYYY-MM-DD` or `YYYY-MM`
  (a month review falls due at the end of that month). Once that date has
  passed the acceptance has **lapsed**, and the finding counts in full until
  someone renews it. An acceptance with no review date is reported as such.

## Effort

Every entry with an `effort:` (`S`, `M`, `L` or `XL`) must say how it is
owed, with `effort_scope:`. There is no default.

| `effort_scope` | Means |
|---|---|
| `per-asset` | Each matching row is its own job |
| `per-rule` | Every matching row shares one unit of work, grouped by the entry's `id` |

One configuration change that reaches many servers is one piece of work;
multiplying its size by the number of servers would misstate it. A generic
rule declares `per-rule` only where the fix is single by nature (one policy,
one programme). Where it depends on how an estate is run, the rule says
`per-asset`, and an organisation that manages that class centrally groups it
with a decision in its overlay.

Loading stops if any entry carries `effort:` without `effort_scope:`. An
entry that declares `per-rule` and has no `id` cannot be grouped; takestock
counts its rows as one unit each and reports the problem with
`takestock.disposition.integrity_problems`.

## Post-quantum dates

A row carrying `quantum-vulnerable-kex` or `quantum-vulnerable-signature`
owes the organisation's post-quantum target year, if the overlay sets one:

```yaml
programme:
  pqc_target_year: 2032
```

An entry may set its own `pqc_deadline:` instead. Without either, the
deadline is blank: the tool supplies no date of its own.

## The default rules, in order

| Rule | Proposes | Matches |
|---|---|---|
| `accept-no-alternative-cleartext` | accept-no-alternative | a cleartext service flagged as having no encrypted alternative |
| `cleartext-service` | wave-1 | any other service carrying traffic in clear, except one carrying only device metadata |
| `anonymous-key-exchange` | critical | an anonymous key exchange is accepted |
| `null-cipher` | critical | a NULL cipher suite is accepted |
| `sslv2-or-sslv3-offered` | critical | SSL 2.0 or 3.0 is offered |
| `export-grade-crypto` | critical | an export-grade suite is accepted |
| `cleartext-device-metadata` | wave-1, per rule | cleartext device-discovery traffic (UPnP, SSDP, WSD, mDNS) |
| `accept-no-alternative-provider-hsts` | accept-no-alternative | no usable HSTS policy, on an endpoint the target profile declares an outside provider runs |
| `no-usable-hsts-policy` | wave-1 | no usable HSTS policy anywhere else |
| `dns-zone-unsigned` | wave-1 | a zone that is unsigned, or signed with no DS record at the parent |
| `internet-facing-weak` | wave-1 | anything weak and internet-facing; checked before every softening track below, so none can absorb it |
| `dkim-weak-key` | wave-1 | a DKIM key of 1024 bits or fewer |
| `dmarc-subdomains-unprotected` | wave-1 | a DMARC record with `sp=none` |
| `spf-softfail` | wave-1 | an SPF record ending `~all` |
| `weak-not-internet-facing` | wave-1 | anything else weak |
| `accept-replacement-tolerable-control` | accept-replacement-planned | not weak, and marked `replaced_by` |
| `defer-migration-retiring-infrastructure` | defer-migration, per rule | not weak, and marked `retiring_by` |
| `retire-planned-sha1-still-accepted` | retire-planned, per rule | acceptable or strong, and still using SHA-1 |
| `pqc-migrate-key-establishment` | pqc-migrate, per rule | acceptable or strong, with a classical key exchange |
| `pqc-migrate-signature-only` | pqc-migrate, per rule | acceptable or strong, with a classical signature only |
| `no-action-strong-or-pqc` | no-action | strong or post-quantum, with neither quantum-vulnerability flag |

The two dormant rules (`replaced_by`, `retiring_by`) fire only after a person
marks a row: whether a planned change replaces a control is a judgement only
a person can make.

Each rule's full `reason:` in the data file is written for the reader of a
report: what the exposure is, why the rung, and what the fix involves.

## Writing an overlay

The overlay may hold only these sections; any other top-level key stops
loading, so a misspelt section cannot silently drop decisions:

`programme`, `ladder`, `rules`, `decisions`, `adoptions`, `dispensations`.

### Match blocks

Rules, decisions and dispensations select rows with a `match:` block. Every
key in it must hold. An unknown key is an error, never a silent miss.

| Key | Holds when |
|---|---|
| `verdict`, `data_state`, `protocol`, `source` | the row's field is this value or one of this list |
| `internet_facing` | the row's flag equals `true` or `false` |
| `flags_any`, `flags_all`, `flags_none` | the row carries any, all, or none of these flags |
| `flags_prefix_any`, `flags_prefix_none` | some flag, or no flag, starts with one of these prefixes |
| `host_pattern` | this regular expression is found in the row's host |
| `extra_true` | this key in the row's `extra` is truthy |
| `extra_any` | each named `extra` field equals one of the allowed values (case ignored) |
| `primitive_any` | the row uses one of these primitives in its key exchange, signatures, ciphers or hashes; a TLS suite name is split into its parts, so `sha1` reaches a `..._SHA` suite |
| `third_party` | `true` when the target profile declares an outside provider runs the host (`scan_targets.saas_443` and `scan_targets.smtp_25` hosts, and the `domains` of `third_party:` entries); `false` otherwise |

### A decision

```yaml
decisions:
  - id: central-cipher-policy
    when: 2030-02-01
    match:
      protocol: tls
      host_pattern: "\\.example\\.test$"
      flags_any: [cbc-mode]
    disposition: wave-1
    effort: M
    effort_scope: per-rule
    reason: >
      Every web front end takes its cipher list from one central policy, so
      removing CBC suites is one change, made once.
```

An entry needs a `match`, a `disposition` (a rung or a fixed track) and a
`reason`; `effort` and `effort_scope` go together. `until:` and `review:`
belong on acceptances only. `takestock.disposition.validate_rule(entry)`
lists every problem with one entry.

### Adopting a generic rule

An organisation that agrees with a generic rule as written can **adopt** it,
which turns that rule's results from `proposed` into `decided`. An adoption
names the rule by id and records the hash of its exact wording:

```yaml
adoptions:
  - rules: [spf-softfail]
    rule_hashes: {spf-softfail: "sha256:<the rule's current hash>"}
```

Print the current hashes with:

```python
from takestock.disposition import load_dispositions, rule_hash
for rule in load_dispositions().rules:
    print(rule["id"], rule_hash(rule))
```

The hash ignores the rule's id and changes in whitespace. If the rule is
later reworded, the adoption stops applying, the rule's results go back to
`proposed`, and `DispositionRules.adoption_drift()` lists it: an adoption
covers the wording that was read, not whatever the rule later says.

### Recording which set was used

`takestock.disposition.set_digest(rules)` is a short hash of everything that
decides a disposition: programme, ladder, rules, decisions, adoptions and
the target profile's outside-provider declarations. Recorded with an
observation, it lets a later report say whether it judged the rows against
the same set or a changed one (`render_basis`). What was measured does not
change when the dispositions do; what it is judged against does.

## Dispensations

Deciding that a finding can wait is a priority call. It is not, by itself, a
position on compliance. Where a finding breaches a MUST-level NZISM control,
the manual lets the control go unmet only under a **dispensation**, and says
who grants one and what it must record. takestock checks each row against
the dispensations the overlay records.

### Which rows need one

Only breaches takestock can see count: a row whose grading cites a control
the baseline marks as breached at a binding level. A row with none is
`not-applicable`, which means no breach is **visible to this tool**, not that
none exists. A cited control whose text carries a condition the tool cannot
settle is reported as a **question**, never a breach.

### A dispensation record

```yaml
dispensations:
  - id: DSP-01
    match:
      protocol: ike
      host_pattern: "^vpn\\.example\\.test$"
    controls: ["17.2.19.C.01"]
    authority: Accreditation Authority (Chief Information Security Officer)
    reason: The gateway's firmware cannot offer a larger Diffie-Hellman group.
    multi_agency_effect: None; the gateway serves this organisation only.
    alternative_mitigations: Access limited to managed devices with certificates.
    mitigation_strength: Strong for the device population it covers.
    residual_risk: Low, accepted until the gateway is replaced.
    review_by: 2030-06
```

| Field | Required by | Means |
|---|---|---|
| `match`, `controls` | takestock | Which rows, and which controls, it covers. A record covers a row only if its `controls` include **every** control the row breaches |
| `authority` | NZISM `1.1.64.C.01` (MUST) | Granted by the Accreditation Authority |
| `reason`, `multi_agency_effect`, `alternative_mitigations`, `mitigation_strength`, `residual_risk`, `review_by` | NZISM `1.1.65.C.01` (MUST) | The six elements of the risk assessment. `review_by` must be a date (`YYYY-MM-DD` or `YYYY-MM`) |
| `parties_consulted` | NZISM `1.1.67.C.01` (MUST) | Required only when the record sets `multi_agency: true` |

The record itself is the retained record `1.1.69.C.01` asks for. Annual
review (`1.1.68.C.01`) is a SHOULD.

A dispensation's `match` block uses the same keys as a disposition's, but it
is checked without the target profile's outside-provider list, so
`third_party: true` never holds there.

### The states

| State | Means | Adverse |
|---|---|---|
| `not-applicable` | No breach of a MUST-level control is visible here | |
| `acting` | Breaches a MUST-level control, and sits on an out-of-cycle rung | |
| `undecided` | Breaches a MUST-level control, and no disposition is recorded | |
| `no-dispensation` | Deferred, and breaches a MUST-level control with no dispensation recorded | yes |
| `incomplete` | A dispensation is recorded but lacks something the manual requires; the missing elements are named | yes |
| `lapsed` | A dispensation is recorded and complete, and its review date has passed | yes |
| `covered` | Deferred under a recorded dispensation | |

The first record whose `match` fits the row and whose `controls` cover every
breach is used. A malformed record is never refused: it is assessed
`incomplete`, naming what is missing, so the gap shows in the report rather
than in an error.
