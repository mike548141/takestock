# Requirements derived from the findings

takestock turns an observation's findings into **requirements** a supplier
or a delivery team can answer: each one written from public standards, each
raised only when something in the observation calls for it, and each
carrying an evidence sentence built from that observation's own counts and
hosts.

## Terms used here

- **Catalogue**: `src/takestock/data/requirements-catalogue.yaml`, the
  library of requirement templates. Nothing in it belongs to any one
  organisation.
- **Template**: one catalogue entry: the requirement's wording, the
  standards it rests on, how to test it, and the rule that raises it.
- **Trigger**: the rule (`triggered_by`) that decides whether a template is
  raised, written as one or more **clauses**.
- **Finding**: anything a clause can match: a graded row of the observation
  (an *asset*), a domain missing a record, or a **coverage gap** (a question
  the run meant to answer and could not).

## Producing the register

```bash
takestock requirements <observation_dir> [<out_dir>] [--catalogue <catalogue.yaml>] [--workspace <dir>]
```

For the sample organisation, from inside a copy of its workspace (see the
README's quick start):

```console
$ takestock requirements observations/latest
observations/latest/requirements/requirements.md
observations/latest/requirements/requirements.xlsx
observations/latest/requirements/requirements.json
6 requirement(s) derived
```

`out_dir` defaults to `<observation_dir>/requirements`. The command exits 1
when at least one requirement was derived, 0 when none was, and 2 on an
error.

It reads the observation's `assets.json` and, if present, `summary.json`,
whose `gaps` list (and the parallel `gap_kinds` list) holds the coverage
gaps. A gap with no kind reads as `unclassified`.

Only templates at least one clause matches are written. A template nothing
triggers is left out entirely, so the register is as long as the findings
make it and no longer.

The catalogue is the one `--catalogue` names if given; otherwise
`data/requirements-catalogue.yaml` in the workspace, when the workspace was
named with `--workspace` or `TAKESTOCK_HOME` and holds one; otherwise the
copy in the package.

## What it writes

| File | Holds |
|---|---|
| `requirements.md` | The register as prose: a count by level, then one block per requirement with its area, statement, standards, tests and evidence |
| `requirements.xlsx` | One row per requirement, plus three empty columns for a supplier to answer: a response (a drop-down of *Comply*, *Partly comply*, *Do not comply*), an explanation and an evidence reference |
| `requirements.json` | The same, as data, with each clause's count, hosts and row references |

The **evidence sentence** names each matching clause with its count and the
hosts behind it, for example:

> Triggered by 2 assets where SSL or a TLS version below 1.2 is accepted
> (mail.example.test:25, www.example.test:443).

At most five hosts are named, then "and N more". A gap clause quotes up to
two of the gaps instead.

## Levels

Each requirement carries one level, read as New Zealand's Protective
Security Requirements read them (INFOSEC policy framework v2.0, paragraphs
11 to 15):

| Level | Means |
|---|---|
| MUST | Mandatory |
| SHOULD | Recommended for organisations with moderate risk and above |
| COULD | Recommended for organisations with high risk and above |

The requirement's level is a choice made when writing the template. Each
standard it cites also carries the level **that source** gives it, so a
reader sees both: a requirement may be a MUST here while one of its sources
says SHOULD, or the reverse. A New Zealand control binds only an
organisation mandated to apply it, or one that adopts it by choice or
contract; see [`STANDARDS.md`](STANDARDS.md).

## The catalogue format

```yaml
version: 1

requirements:
  - id: TLS.1
    level: MUST
    area: Transport encryption
    name: Refuse SSL and every TLS version below 1.2
    statement: >
      Every service that offers TLS MUST refuse SSL 2.0, SSL 3.0, TLS 1.0 and
      TLS 1.1, by configuration that the supplier documents ...
    standards:
      - ref: IETF RFC 8996, sections 4 and 5
        level: MUST NOT
        says: TLS 1.0 and TLS 1.1 "MUST NOT be used"; servers must not negotiate either.
    selection_test: >
      The bidder states, for each component that terminates TLS, the lowest
      version it can be configured to accept ...
    acceptance_test: >
      A version scan of every delivered TLS endpoint shows no handshake
      completing below TLS 1.2.
    triggered_by:
      - protocol: tls
        flags_prefix_any: ["deprecated-protocol:"]
        finding: SSL or a TLS version below 1.2 is accepted
```

| Field | Meaning |
|---|---|
| `id` | Stable and unique, written `<AREA>.<n>` |
| `level` | `MUST`, `SHOULD` or `COULD` |
| `area` | A short grouping label |
| `name` | One line, used as the heading |
| `statement` | The requirement in full, as a supplier would answer it |
| `standards` | What it rests on. Each entry needs `ref` (document and section or control), `level` (the force that source gives it) and `says` |
| `selection_test` | How a bid is tested before a supplier is chosen |
| `acceptance_test` | How delivered work is tested before it is accepted |
| `triggered_by` | One or more clauses; the requirement is raised when **any** clause matches |

Every field is required. The loader refuses the whole catalogue, naming the
entry, for a missing field, an unknown level, a duplicate id, a standard
without `ref`, `level` and `says`, or a clause it cannot read.

## Trigger clauses

Every clause has a `finding` phrase. It completes the sentence "*n* assets
where …", "*n* domains where …" or "*n* coverage gaps where …", so write it
to read that way. Within one clause **every key must hold** for the same
finding. There are three kinds of clause, and one clause is only ever one
kind.

### Asset clause

Matches rows of `assets.json`. Any of these keys, combined:

| Key | Holds when |
|---|---|
| `verdict` | the row's grade is this value, or one of this list (`weak`, `acceptable`, `strong`, `pqc`, `unknown`, `n/a`) |
| `data_state` | the row's kind is this value or one of this list (`in-transit`, `certificate`, `email-auth` …) |
| `protocol` | the row's protocol is this value or one of this list (`tls`, `ssh`, `ike`, `dmarc` …) |
| `source` | the row came from this collector or one of this list |
| `disposition` | the row's disposition track is this value or one of this list (rows carry one only once dispositions are applied; see [`DISPOSITIONS.md`](DISPOSITIONS.md)) |
| `internet_facing` | the row is (`true`) or is not (`false`) marked internet-facing |
| `flags_any` | the row carries at least one of these flags |
| `flags_all` | the row carries all of these flags |
| `flags_none` | the row carries none of these flags |
| `flags_prefix_any` | a flag starts with one of these prefixes |
| `flags_prefix_none` | no flag starts with any of these prefixes |
| `extra_true` | this key in the row's `extra` is present and truthy |
| `versions_none` | the row lists TLS versions and **none** of these is among them. A row that lists no versions does not match, so "TLS 1.3 was not offered" is never raised where versions were not read |

Flags are short, machine-readable findings collectors attach to rows, such
as `weak-dh`, `expired`, or `deprecated-protocol:` followed by the version
the instrument reported. A clause on flags reads them exactly; use a prefix
key where a flag carries a value after a colon, because the value's spelling
varies by instrument.

### Absent clause

```yaml
- absent: {anchor: mx, missing: dmarc}
  finding: MX records are published and no DMARC record is
```

Matches every host that has a row of the `anchor` protocol and no row of the
`missing` one. It counts **domains**, not assets.

### Gap clause

```yaml
- gap_kinds: [not-collected, extent-unknown]
  finding: an input was not collected or is known to be incomplete
```

Matches the observation's coverage gaps of these kinds: `not-collected`,
`could-not-test`, `extent-unknown`, `not-measured` or `unclassified`.

## What the catalogue covers

| Area | Requirements |
|---|---|
| Transport encryption | TLS.1 refuse SSL and TLS below 1.2 (MUST); TLS.2 offer TLS 1.3 (SHOULD); TLS.3 refuse NULL, anonymous, export-grade and broken suites (MUST); TLS.4 forward-secret, authenticated-encryption suites only (SHOULD); TLS.5 minimum key-exchange, key and hash strengths (MUST) |
| Certificates | CERT.1 renew before expiry (MUST); CERT.2 present a certificate that names the service (MUST); CERT.3 monitor certificate-transparency logs (SHOULD) |
| Web | WEB.1 publish an HSTS policy (SHOULD) |
| Mail | MAIL.1 offer TLS on every internet mail server (MUST); MAIL.2 MTA-STS in enforce mode (SHOULD); MAIL.3 a TLS reporting record (SHOULD); MAIL.4 one SPF record ending in a hard fail (MUST); MAIL.5 DKIM keys of at least 2048 bits (SHOULD); MAIL.6 DMARC reject, including subdomains (MUST); MAIL.7 DANE for inbound mail servers (COULD) |
| Remote administration | SSH.1 current SSH algorithms only (MUST); REM.1 authentication before a remote desktop session starts (MUST) |
| Remote access | VPN.1 strong IKE and IPsec proposals only (MUST); VPN.2 IKEv2, retire IKEv1 (SHOULD) |
| Cleartext services | CLR.1 encrypt or retire cleartext services (SHOULD); CLR.2 isolate those with no encrypted alternative (SHOULD); CLR.3 turn off device-discovery protocols nothing depends on (COULD) |
| DNS | DNS.1 sign zones with DNSSEC (SHOULD); DNS.2 current DNSSEC algorithms and valid signatures (MUST); DNS.3 CAA records (SHOULD) |
| Key management | KEY.1 a cryptographic inventory, and algorithms changed by configuration (SHOULD) |
| Post-quantum readiness | PQC.1 hybrid post-quantum key establishment (SHOULD); PQC.2 commit to post-quantum signatures and certificates (SHOULD) |
| Evidence | GAP.1 supply the configuration evidence the assessment could not collect (SHOULD); GAP.2 let the organisation measure what it is buying (SHOULD) |

## Extending or overriding the catalogue

The catalogue is replaced as a whole, never merged. To change it:

1. Copy `src/takestock/data/requirements-catalogue.yaml` to
   `data/requirements-catalogue.yaml` in a named workspace (or anywhere,
   and pass its path with `--catalogue`).
2. Edit the copy: reword a statement, change a level to suit the
   organisation's risk appetite, add a template, or delete one.
3. Keep each `standards` entry honest: quote the source's own level, not the
   level you chose for the requirement.

When adding a template:

- Write the trigger from flags and fields a collector actually produces.
  A clause on a flag no collector raises never fires, and the loader cannot
  tell.
- Prefer a narrow clause. A clause such as `verdict: weak` alone matches
  every weak row in the estate.
- Give each clause its own `finding` phrase, so the evidence sentence says
  which part of the rule fired.
- Run the register against an observation you know, and read the evidence
  sentence back: it should name exactly the rows you expected.
