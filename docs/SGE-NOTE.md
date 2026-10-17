# The Secure Government Email conformance note

takestock reads an organisation's mail configuration against New Zealand's
**Secure Government Email (SGE) Common Implementation Framework** and writes
the result as a self-contained HTML **conformance note**. Every requirement
in the framework gets a row, including those nothing outside the
organisation can see, and every row says *met*, *not met* or *not
measured*, with the reason.

How takestock reads the framework itself (which sentences decide a level,
where its documents disagree) is in
[`SECURE-GOVERNMENT-EMAIL.md`](SECURE-GOVERNMENT-EMAIL.md). This guide is
about the note: what it shows, how each verdict is decided, and what
evidence settles each kind of requirement.

## Terms used here

- **Requirement set**: `src/takestock/data/secure-government-email.yaml`,
  the framework's requirements in machine-readable form. Each carries its
  level, the deciding sentence quoted verbatim, the document it came from,
  and what would settle it.
- **Reading**: one requirement read against one **subject**: an email
  domain, a mail host, a mail path, or the organisation as a whole.
- **Email domain**: a domain named under `discovery.email_domains` in the
  target profile.
- **Parked domain**: a domain named under `discovery.domains` and not under
  `discovery.email_domains`. It is read as a domain that sends and receives
  no mail.
- **Sweep**: the reading of each sub-domain name found in
  certificate-transparency logs, for the records a name that sends no mail
  should publish. It runs beneath each email domain and each parked domain.

## Producing the note

The note is one of the standards checks run by `takestock comply`; `sge` is
the framework's id there (`takestock comply --list` shows every standard):

```bash
takestock comply sge <observation_dir> <target> [--out <file.html>] [--workspace <dir>]
```

`<target>` is the profile the observation was taken for, as a name or a
path. For the sample organisation, from inside a copy of its workspace (see
the README's quick start):

```console
$ takestock comply sge observations/latest example-widgets
observations/latest/sge-note.html
```

The note is the command's default output. It is written to
`<observation_dir>/sge-note.html` unless `--out` names another file, and the
command prints the path it wrote. The command exits 1 when any requirement stated as
*must* is not met, 0 otherwise, and 2 on an error, including a profile that
names neither `discovery.email_domains` nor a parked domain. (The sample's offline observation reads
no mail records, so every requirement is *not measured* and it exits 0.)

For the same reading as plain text on the terminal, one line per reading
and a closing list of unmet *must* requirements, add `--format text`:

```bash
takestock comply sge <observation_dir> <target> --format text [--out <file.txt>] [--workspace <dir>]
```

It takes the same arguments, prints the report (or, with `--out`, writes it
to that file and prints the file's path), and exits the same way: 1 when a
*must* requirement is not met, 0 otherwise, 2 on an error.

The module behind it can also be run directly, reading an observation by
its directory name under the workspace's `observations/` (default
`latest`), and with `--json` it prints every reading as data:

```bash
TAKESTOCK_HOME=<workspace> python -m takestock.sge <target-name> [--observation <name>] [--json]
```

It exits 1 when a *must* requirement is not met, 0 otherwise, and 2 when the
arguments are wrong or an input cannot be read. `python -m takestock.sge_note
<observation_dir> <target.yaml> <out.html>` writes the note and exits the
same way.

The target profile supplies:

| Key | Used for |
|---|---|
| `discovery.email_domains` | The email domains read |
| `discovery.domains` | Any domain here and not under `email_domains` is read as a parked domain |
| `organisation` | The name in the note's title |
| `branding` | Colours, fonts and logo for the page |
| `sge.bulk_mail_domains` | The SPF policy domains of bulk-mail providers, used to annotate one recommendation (see below) |

## What the note shows

1. **Summary**: how many requirements are met, not met and not measured,
   at each level; which *must* requirements are not met, and for which
   subjects; and why the unmeasured ones could not be measured.
2. **Requirement by requirement**, grouped by level: each with its deciding
   sentence, where that sentence was read, what it applies to, its source
   document, and a table of readings (subject, result, what was observed,
   and the explanation).
3. **Parked domains**, when the profile has any: each parked domain against
   the framework's requirements for domains that send no mail (the blank SPF
   record `v=spf1 -all`, a `p=reject` DMARC policy with no `sp=` or `np=`
   weaker than reject, strict alignment with a reporting address, and the
   empty DKIM key `v=DKIM1; p=` at `*._domainkey.<domain>`), the two
   recommendations read from the same records (no SPF2.0 record, SGE-SPF-R02,
   and none of the DMARC tags the guide says not to use, SGE-DMARC-R03), whether it
   publishes a null MX, and the record text read. The swept names beneath
   each parked domain have a line of their own, *sub-domains of* the domain,
   read as in [Read from the sub-domain sweep](#read-from-the-sub-domain-sweep).
   The same readings also appear, marked *(parked)*, in their requirements'
   tables, so an unmet *must* on a parked domain counts like any other.
   Where an observation holds a parked domain's SPF or DMARC row unmarked as a
   parked reading (taken while the domain was not listed as parked, say), the
   row is graded all the same and the explanation says so.
4. **Not measured, and what would settle it**: every unsettled reading,
   with the evidence that would settle it.
5. **DNS records read, per domain**: the record text as read for each email
   domain, and which requirements read it.
6. **What this note cannot show**: the limits of reading a mail
   configuration from outside.
7. **Appendix: evidence files**: the observation's `assets.json` and every
   file under its `raw/` and `evidence/` directories, each with its size and
   SHA-256 digest, so a reader can confirm they hold the same files.

The note carries the framework's own implementation date as the
framework's, beside the summary.

## Levels

The note groups requirements in two levels:

| Level | Includes | An unmet one is |
|---|---|---|
| **Must** | sentences that say *must*, *must not* or *mandatory* | a breach of the framework |
| **Recommended** | sentences that say *should*, *recommended* or *advised*, and bare instructions that carry no keyword | a recommendation not followed, never a breach |

## How a verdict is decided

### One reading

Each reading has one of three results:

| Result | Means |
|---|---|
| **Met** (`pass`) | The evidence shows the requirement is satisfied for this subject |
| **Not met** (`fail`) | The evidence shows it is not |
| **Not measured** | The evidence cannot settle it, for one of three reasons |

The three reasons a reading is not measured:

| Reason | Means |
|---|---|
| `no-instrument` | Nothing outside the organisation can see this |
| `not-collected` | Visible from outside, but nothing in this observation reads it |
| `inconclusive` | The check ran and could not settle it |

### One requirement

A requirement's result is worked out from all its readings:

- **not met** if any reading failed;
- **met** only if there is at least one reading and every one passed;
- otherwise **not measured**.

One reading that could not be measured therefore leaves the requirement
unmeasured, never met. "No *must* requirement was found unmet" is not the
same as conformance, and the note says so whenever unmeasured requirements
remain.

### Readings that can only fail

The sweep reads the sub-domain names certificate-transparency logs list. That
is a floor, not the full set: a name nobody has served TLS on never appears.
So for the sub-domain requirements one name without the required record
settles the requirement as **not met**, while any number of names carrying it
leaves it **not measured**. These readings can report a breach and can never
report conformance.

The sweep also asks for a name nobody has registered in the same batch. It
should come back NXDOMAIN. A published wildcard (`*.<domain>`) answers it too,
because the control is a name that does not exist directly beneath the domain.
A wildcard does not answer every name, though: it never answers a name that
exists, and it does not answer beneath one either, including an empty
non-terminal (a name that owns no record but has names beneath it, such as
`a.example.com` when only `_dmarc.a.example.com` is published). RFC 4592 sets
this out in §2.2.1 and §2.2.2, and §3.3.1 says the only wildcard that can
answer is the one directly beneath the closest existing name. When the control's
answer is exactly the wildcard's record, the resolvers agree, and they are seen
returning real TXT records, the wildcard explains it and the sweep still grades.
Each name is then read for its own response code and agreed records, a wildcard
answer being the record a receiver is given for that name, so a compliant
`*.<domain>` record of `v=spf1 -all` counts for every name it answers. If the
control answers and no wildcard explains it, the run cannot tell an absent
record from a resolver that did not reply, and nothing is graded from it. A
name whose resolvers gave different records is listed and counted neither way.

## What evidence settles each requirement

The rows below come from an observation. The DNS and policy readings come
from the `ct_dns` collector, the receiving mail hosts' TLS from
`smtp_starttls`, and the sender-policy lookups from `spf_senders` (see
[`COLLECTORS.md`](COLLECTORS.md)).

### A missing record, and a lookup that did not settle

`ct_dns` asks every configured resolver for each mail-authentication record
and keeps each resolver's response code. Two cases are kept apart:

- **The lookup settled** (at least one resolver replied, and every reply
  was `NOERROR` or `NXDOMAIN`) and no SPF or DMARC record came back. That
  is a measured absence: the observation holds a row for the record with
  `extra.present: false`, the flag `no-spf-record` or `no-dmarc-record`, and
  the resolvers' replies. The note grades it **not met** where the
  requirement needs the record, and quotes the replies as the evidence.
- **The lookup did not settle** (a reply carried another code, such as
  `SERVFAIL`, or no resolver replied). Nothing is claimed either way: the
  observation holds no row for that record, the run records one collector
  failure per domain naming the records and the replies (so `observe` exits
  2), and the note reads the requirement as **not measured**.

The same holds for the MTA-STS and TLS-RPT records: a settled lookup gives
a row (published or not), an unsettled one gives none. DKIM is different:
selectors cannot be listed, so a selector that does not answer proves
nothing and gives no row.

### Read from public DNS and the MTA-STS policy

In the table, **none published** means a settled lookup found no such
record, and **no reading** means the observation holds no row for it: the
lookup did not settle, or the run read no DNS (an offline run, for
example). See [A missing record, and a lookup that did not
settle](#a-missing-record-and-a-lookup-that-did-not-settle).

| Requirement | Level | Reads | Met | Not met | Not measured |
|---|---|---|---|---|---|
| SGE-SPF-01 SPF ending in hardfail | must | the domain's SPF record | ends `-all` | ends `~all`, or neither; or no SPF record published | no SPF reading |
| SGE-DMARC-01 DMARC reject | must | the DMARC record | `p=reject` at 100% (`pct` absent or 100) | any other policy, or `pct` below 100; or no DMARC record published | no DMARC reading |
| SGE-MTASTS-01 MTA-STS in enforce mode | must | the `_mta-sts` record and the policy file | `mode: enforce` in a valid policy | no record published, or any other mode; or the policy is not valid: the policy host's certificate does not validate, the answer is not HTTP 200 (a redirect included), or the policy lacks `version: STSv1` or a `max_age` of whole seconds up to 31557600 (RFC 8461 §3.2 and §3.3) | no MTA-STS reading, or the fetch got no answer (no connection, or a timeout), so the mode was not read |
| SGE-MTASTS-02 every MX listed, no wildcards | must | the policy's `mx:` lines against the MX records | every MX host matched, no wildcard | an MX host unmatched, or a wildcard used | no record published, or a policy that is not valid (both graded under SGE-MTASTS-01), unreachable policy, no MTA-STS reading, or no MX reading |
| SGE-TLSRPT-01 TLS reporting | must | the record at `_smtp._tls.<domain>` | published with a `rua=` address | not published, or no `rua=` | no TLS-RPT reading: the lookup did not settle, or was not made (`inconclusive`) |
| SGE-DMARC-04 a DMARC reporting tool | must | the DMARC record's `rua=` | never: a published address is consistent with a tool, not proof of one | no `rua=` address, or no DMARC record published | an address is published (`no-instrument`), or no DMARC reading |
| SGE-DKIM-R01 2048-bit DKIM keys | recommended | the key at each selector that answered | 2048 bits or more | shorter | no selector answered, no size could be read, or every selector that answered publishes the empty key `v=DKIM1; p=` (revoked) |
| SGE-DMARC-R01 strict DKIM alignment where no bulk mail | recommended | `adkim` | `adkim=s` | never | relaxed alignment: whether the domain sends bulk mail is not established; no DMARC record published (the missing record is graded under SGE-DMARC-01); or no DMARC reading |
| SGE-DMARC-R02 strict SPF alignment | recommended | `aspf` | `aspf=s` | relaxed, including by omission; or no DMARC record published | no DMARC reading |
| SGE-DMARC-R03 unwanted DMARC tags absent | recommended | the record's tags | none of `ruf`, `fo`, `pct`, `rf`, `ri` | any of them present | no DMARC record published (graded under SGE-DMARC-01), or no DMARC reading. The swept names' own records are read on a row of their own (below) |
| SGE-SPF-R01 no `ptr`, no overly broad ranges | recommended | the SPF terms | never: breadth of a range cannot be judged from DNS | `ptr` used | no `ptr` (`inconclusive`); no SPF record published (graded under SGE-SPF-01); or no SPF reading |
| SGE-SPF-R02 no legacy SPF2.0 records | recommended | every TXT record at the domain | no SPF2.0 record | one or more published | no SPF reading, or the observation kept only the first SPF record |
| SGE-DKIM-R02 a key per sending platform | recommended | the public keys of the selectors that answered | never | two selectors publish one key | no key shared (other selectors may exist), or every selector that answered publishes the empty key (revoked) |

A missing record is graded once, under the requirement that needs it. The
recommendations that read a record's contents (SGE-DMARC-R01, SGE-DMARC-R03,
SGE-SPF-R01) then read *not measured*, naming the requirement that carries
the finding, rather than repeating it. SGE-DMARC-R02 and SGE-DMARC-04 are the
exceptions: with no DMARC record, no alignment and no reporting address is
published at all, so each is *not met* in its own right.

For SGE-DMARC-R01, a domain whose sender policy authorises one of the
`sge.bulk_mail_domains` is annotated as a reason to think the
recommendation may not apply, without changing the verdict.

DKIM selectors cannot be listed from DNS, so only the selectors the target
profile names under `discovery.dkim_selectors`, any the supplied zone files
publish beneath the domain, and a short list of common defaults are tried. A
selector that does not answer proves nothing.

A selector that answers with the empty key `v=DKIM1; p=` has revoked its key
(RFC 6376 defines an empty `p=` value as a revoked key): there is no key to
size or to compare. It is not graded
under SGE-DKIM-R01 or SGE-DKIM-R02, and the note beside the domain's other rows
names it, so a reader can see it was read. When every selector that answered
publishes the empty key, each requirement gives the domain one *not measured*
row saying so. A row that does not keep the public key (an observation taken
before keys were kept) is not read as revoked.

### Read from the sub-domain sweep

| Requirement | Level | Not met when | Otherwise |
|---|---|---|---|
| SGE-NED-SPF-01 a denying SPF record (`v=spf1 -all`) on names that send no mail | must | any swept name lacks it | not measured |
| SGE-NED-DKIM-01 an empty DKIM key (`v=DKIM1; p=`) on names that send no mail | must | any swept name lacks it | not measured |
| SGE-NED-DMARC-01 a rejecting DMARC policy on names that send no mail | must | the email domain's own record sets `sp=none`, or `np=` weaker than `reject` (RFC 9989's policy for names that do not exist); or a swept name's own record, or the record policy discovery finds for it (RFC 9989 §4.10; `sp=` for a name that exists, `np=` for one that answers NXDOMAIN), does not reject all failing mail; or a swept name has no record and none is found for it | not measured |
| SGE-NED-DMARC-R01 strict alignment and a reporting address on those names | recommended | a swept name, on its own record or the one policy discovery finds for it, lacks `adkim=s`, `aspf=s` or `rua=`, or has no record and none is found for it | not measured |
| SGE-DMARC-R05 `sp=` only on organisational domains | recommended | a swept sub-domain publishes its own `sp=` | not measured |
| SGE-DMARC-R03 unwanted DMARC tags absent | recommended | a swept sub-domain's own record carries `ruf`, `fo`, `pct`, `rf` or `ri` | not measured |

SGE-DMARC-R03 is read here with the subject *sub-domains of* the domain, beside
the domain's own row, and only where the observation holds a sweep with names
in scope; a name without a record of its own is given the domain's record,
which the domain's own row already reads.

Names the sweep finds sending mail are excluded and listed; names it could
not read are listed as not read, so not counted either way. A name with no
DMARC record of its own is read against the record RFC 9989's policy
discovery finds for it (§4.10): usually the domain's own, and a record at a
name between them only where §4.10.2 makes that name the Organizational
Domain (see [`SECURE-GOVERNMENT-EMAIL.md`](SECURE-GOVERNMENT-EMAIL.md), *DMARC
policy discovery*). The note beside the row names each swept name governed by
such a record, and each counted neither way because a name on its walk could
not be read. The same rows are read beneath each parked domain, with the
subject *sub-domains of* the domain; there the parked domain's own `sp=` and
`np=` are graded on its own row, so SGE-NED-DMARC-01 beneath it reads only the
swept names.

### Read on discovered sub-domains that handle mail

The sweep sets aside the names that show signs of handling mail: they publish
MX, the parent's sender policy names them, or their own sender policy
authorises senders. To a receiver those are email domains, so they are read
against the rules for email domains, one row per parent domain, with the
subject *mail-handling sub-domains of* the parent, marked *(discovered)*
rather than taken from the profile. The SPF, DMARC and MX records come from
the sweep; each such name is then also read for its MTA-STS record and policy
file, its TLS-RPT record and its DKIM keys under each selector tried, as an
email domain is.

| Requirement | Level | Not met when | Otherwise |
|---|---|---|---|
| SGE-SPF-01 SPF ending `-all` | must | a name publishes no SPF record, or one ending `~all` or neither | not measured |
| SGE-DMARC-01 `p=reject` | must | a name's own DMARC record does not reject all failing mail; or it has none and the record policy discovery finds for it (`sp=` for a name that exists, `np=` for one that does not, then `p=`) does not; or none is found | not measured |
| SGE-DMARC-04 a DMARC reporting tool | must | the DMARC record a receiver applies to a name (its own, or the one policy discovery finds) has no `rua=` address, or no record applies | not measured |
| SGE-MTASTS-01 MTA-STS in enforce mode | must | a name publishes no `_mta-sts` record; or its policy is not valid (the certificate does not validate, the answer is not HTTP 200, or `version: STSv1` or a valid `max_age` is missing); or its mode is not `enforce` | not measured |
| SGE-MTASTS-02 every MX listed, no wildcards | must | a name's valid policy has no `mx:` line matching one of its MX hosts, or uses a wildcard entry | not measured |
| SGE-TLSRPT-01 TLS reporting | must | a name publishes no `_smtp._tls` record, or one with no `rua=` address | not measured |
| SGE-DMARC-R02 strict SPF alignment | recommended | the DMARC record a receiver applies to a name sets relaxed SPF alignment, or omits `aspf=`, or no record applies | not measured |
| SGE-DMARC-R05 `sp=` only on organisational domains | recommended | a name's own DMARC record sets `sp=` | not measured |
| SGE-DMARC-R03 unwanted DMARC tags absent | recommended | a name's own DMARC record carries `ruf`, `fo`, `pct`, `rf` or `ri` | not measured |
| SGE-DKIM-R01 2048-bit DKIM keys | recommended | a key under a selector that answered is shorter than 2048 bits | not measured |
| SGE-DKIM-R02 a distinct key per selector | recommended | a name's key is published under more than one selector name, anywhere in the observation | not measured |

A name without a DMARC record of its own is not failed for that alone, because
a receiver applies to it the record its policy discovery finds. A name is
counted neither way, left out of the names read and listed with the reason in
the note beside the row, when what a requirement needs was not read: a lookup
that did not settle, a policy file this machine could not fetch, no key under
any selector tried (selector names cannot be listed, so silence proves
nothing), or a policy discovery that passes a name that could not be read. An
observation that never read a name's MTA-STS, TLS-RPT or DKIM records shows
those rows as not collected. As with every sweep, the names are a floor, so
these rows can fail and never pass. A parent whose sweep found no such name has
no row.

### Read from the mail hosts

**SGE-TLS-01, TLS 1.2 minimum on email connections** (must) has two halves.

The **receiving** half is read per MX host, from the STARTTLS probe of that
host on port 25, the port an inbound sender delivers to. Every host the
domains' MX records name gets a row, probed or not; a TLS row for the host on
another port, or with no port (a certificate-log record of the name), reads
another service and is not used:

| Result | When |
|---|---|
| Met | the host offers at least one version at or above TLS 1.2, and none of SSL 2.0, SSL 3.0, TLS 1.0 or TLS 1.1 |
| Not met | it offers a forbidden version, or it answers without offering STARTTLS at all |
| Not measured | the host has no STARTTLS probe on port 25 (list it under `scan_targets.smtp_25` and run with `--scan`); the host gave no version list; its versions could not be placed against the floor; or no MX host was read at all |

A host that *accepts* TLS 1.0 permits what the framework forbids, but a
probe cannot see what senders actually negotiate.

The **sending** half needs the organisation's own record of each outbound
delivery: rows with `source: mail_transport` and `extra.direction: outbound`,
each giving `messages`, `no_tls_messages` and a `tls_distribution` such as
`TLS1.2=900; TLS1.3=100`. Any collector, including one an organisation plugs
in, can supply such rows (a plug-in of the `mail-transport` kind writes them;
see [`PLUGINS.md`](PLUGINS.md#mail-transport)); without them this half is
*not measured*. With them,
any delivery with no TLS, or at a forbidden version, is *not met*.

**SGE-ITLS-01, Implicit TLS configured and enforced** (must) can at best be
*not measured*. A transport export that separates mail exchanged with
government organisations (`govt_messages`, `govt_no_tls_messages` and
related fields on the same rows) lets the note report how much of that mail
crossed in clear. But no per-message record shows the port or how the
session was set up, so a forced-STARTTLS path and an Implicit TLS path look
the same. Whether the requirement applies also depends on membership of the
SGE Restricted Group, which nothing read here establishes.

The **receiving** side gets one row per MX host, read from the same port-25
STARTTLS probe as SGE-TLS-01, and it too is never better than *not measured*.
A host offering no STARTTLS cannot receive another organisation's mail under
TLS at all, and the row says so (the same host fails SGE-TLS-01); a host
offering it shows a necessary condition only, because whether it refuses a
sender that does not start TLS cannot be seen without delivering mail. A host
with no port-25 probe is *not collected*. No Secure Government Email document
names a port. The `implicit_tls` collector's rows (ports 465, 993 and 995) are
not read here: they show RFC 8314 Implicit TLS for mail submission and mailbox
access, which RFC 8314 §1 says does not cover relay between mail servers.

### Read from the mail platform's own settings

Three requirements cannot be seen from outside, but an export of the mail
platform's settings settles them. Their `measurable` value is
`inside-export`. With no such export in the observation each stays *not
measured* with the reason `no-instrument`, like the list below, and says
that an export would settle it. With one, each gets a row per domain:

- SGE-DMARC-02 inbound mail checked for DMARC and acted on: met where every
  policy governing the domain's recipients honours the sender's DMARC policy
  and the route the mail arrives by lets it, which behind a mail service in
  front of the platform needs Enhanced Filtering on the receiving connector;
- SGE-DMARC-R04 failed mail to an administrator quarantine, not a junk
  folder: met where the actions in effect quarantine or reject, and
  recipients cannot release from the quarantine policy in effect;
- SGE-DKIM-01 all outbound mail DKIM signed: met where the platform signs
  the domain's mail and hands none of it to another service; not met where
  it does not sign a domain that sends mail and hands none of it on.

takestock reads Exchange Online's settings with the `exchange_online` reader.
How each row is decided, and what it cannot see (a mail service in front of
or behind the platform, other services sending as the domain), is in
[`COLLECTORS.md`](COLLECTORS.md#exchange_online). Every row says when the
export was taken.

### Not observable from outside

These are listed so the note covers every requirement. Each carries
*not measured* with the reason `no-instrument`, and the evidence that would
settle it:

- SGE-DKIM-02 third-party platforms sign with the organisation's domain;
- SGE-DMARC-03 DMARC reports reviewed regularly;
- SGE-DLP-01 and SGE-DLP-02 data loss prevention and keyword blocking;
- SGE-MTASTS-R01 the policy host secure and highly available;
- SGE-DLP-R01 the minimum keyword list blocked;
- SGE-TLS-R01 unencrypted mail monitored;
- SGE-TLS-R02 systems that cannot use TLS raised as a risk.

SGE-DMARC-R06 (bulk mail from a separate sub-domain) is visible in
principle, from the sending sources DMARC aggregate reports name, but
nothing reads those yet, so it is `not-collected`.

## Marking the assets

`takestock.sge.apply_conformance(assets, domains)` runs the same evaluation
and marks every asset row behind an unmet *must* with
`standards_verdict: non-conformant`, the requirement, what was observed and
the citation. The asset's own grade is not changed: the standard's verdict
sits beside it.

## Changing the requirement set

Copy `src/takestock/data/secure-government-email.yaml` to
`data/secure-government-email.yaml` in the workspace and edit the copy, for
example when the framework publishes a new version. The copy is read only
when the workspace is named with `--workspace` or `TAKESTOCK_HOME`. Each requirement has:

| Field | Meaning |
|---|---|
| `id`, `title` | The requirement's identifier and one-line name |
| `level` | `must` or `recommended` |
| `level_basis` | `quote` (the deciding sentence, verbatim), `where` it was read, and `judgement` when the level needed one |
| `scope` | `email-domain`, `non-email-domain`, `mail-path` or `organisation` |
| `text`, `source`, `document` | The requirement's wording and where it came from; `document` names an entry under `documents:` so the note can cite its version, date, index and digest |
| `measurable` | `observed`, `not-collected`, `no-instrument` or `inside-export` (read from an export of the mail platform's settings when one is supplied) |
| `settled_by` | The evidence that would settle it, printed in the note |
| `note`, `partial`, `awaiting` | Explanations; `partial` says what a reading does not cover and is quoted into the row; `awaiting` says what a `not-collected` row is waiting for |

A few requirements carry settings their evaluator reads:
`forbidden_versions` and `minimum_version` (SGE-TLS-01), `minimum_bits`
(SGE-DKIM-R01), `tags` (SGE-DMARC-R03) and `record` (the sub-domain DKIM
requirement checks it against the name the sweep actually read).

Only the requirement ids takestock has an evaluator for are graded from
evidence. A requirement marked `observed` that has no evaluator is reported
as *not measured* (`not-collected`, "no evaluator is wired for it"), so a new
row can be added to the set without being silently graded.
