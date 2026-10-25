# Secure Government Email: how takestock reads the framework

The **Secure Government Email (SGE) Common Implementation Framework** is New
Zealand's all-of-government standard for securing email between government
agencies and the people they correspond with. It replaces a gateway service
with open standards published in DNS. This document records what the
framework requires as takestock reads it, which of those requirements can be
measured from outside an organisation and which cannot, and where the
framework's own documents disagree with each other or with the standards they
build on.

Read [`STANDARDS.md`](STANDARDS.md) first for how compliance words (MUST,
SHOULD) are read across all the standards takestock uses.

## Terms used here

- **SPF** (Sender Policy Framework, RFC 7208): a DNS record listing the
  servers allowed to send mail for a domain. It ends in a qualifier: `-all`
  (*hardfail*: reject anything else) or `~all` (*softfail*: accept but mark).
- **DKIM** (DomainKeys Identified Mail, RFC 6376): a signature added to each
  outgoing message, checked against a public key published in DNS under a
  *selector* name (`<selector>._domainkey.<domain>`).
- **DMARC** (Domain-based Message Authentication, Reporting and Conformance):
  a DNS record at `_dmarc.<domain>` telling receivers what to do with mail
  that fails SPF and DKIM alignment (`p=none`, `quarantine` or `reject`), and
  where to send reports (`rua=`). Originally RFC 7489, now RFC 9989.
- **Alignment**: whether the domain SPF or DKIM authenticated matches the
  domain in the visible From address. *Strict* (`adkim=s`, `aspf=s`) needs an
  exact match; *relaxed* (`r`, the default) accepts a sub-domain.
- **MTA-STS** (Mail Transfer Agent Strict Transport Security, RFC 8461): a
  policy, announced in DNS and published over HTTPS, telling sending servers to
  deliver to this domain only over verified TLS.
- **TLS-RPT** (SMTP TLS Reporting, RFC 8460): a DNS record at
  `_smtp._tls.<domain>` asking senders to report TLS delivery failures.
- **STARTTLS** (RFC 3207): the SMTP command that upgrades a plain connection to
  TLS. Used this way, without enforcement, it is called *opportunistic TLS*:
  if TLS fails, mail can still flow unencrypted.
- **DLP** (data loss prevention): rules that block messages by content, here by
  their protective marking.
- **Email-enabled domain**: a domain that sends or receives mail.
  **Non-email-enabled domain**: one that does neither, including any
  sub-domain, which the framework says *"can consist of as little as a single
  A record"*.

## What the framework is

| Aspect | What the framework says | Where |
|---|---|---|
| Purpose | Improve the security of external email, reduce domain spoofing, and enable the retirement of the SEEMail (Secure Encrypted Email) service | Framework §1 *Purpose* |
| Approach | DNS-published email security controls applied to all mail, not only mail tagged for the old gateway; extended to all New Zealand government agencies | Framework §2 *Introduction* |
| Approval | Supported by the Secure Government Email Architecture, approved in March 2024 by the Government Chief Information Security Officer and the SEEMail Security Working Group | Framework §2 (web version) |
| Classification ceiling | *"Unclassified email and email classified IN-CONFIDENCE and below"*. RESTRICTED and SENSITIVE mail needs membership of the separate **Restricted Group**, whose agencies must have their ICT services formally certified and accredited to RESTRICTED in writing | Framework §3; SGE home page, *Restricted Group* |
| Accountability | Certification and accreditation, and any exceptions, stay with each agency | Framework §3 |
| Timeline | Agencies are to implement the framework by **October 2026**; SEEMail *"is intended to be decommissioned in 2026"* | Framework §6; SGE home page |
| Monitoring | The government's digital services team monitors SPF, DMARC and MTA-STS settings first, and later DKIM, and follows up on changes such as an SPF record moving from `-all` to `~all` | Framework §7 |

**The framework builds on the NZISM rather than replacing it.** Each
deployment guide opens with what NZISM §15.2 (*Email Infrastructure*) already
directs and then says where the framework goes further, often by turning an
NZISM SHOULD into a framework *must*: MTA-STS in `enforce` is a framework
*must*, while NZISM `15.2.48.C.01` is a SHOULD. The NZISM still applies beside
it, and some of its controls are stricter than the framework (a DKIM key, for
example; see [`STANDARDS.md`](STANDARDS.md)).

### The documents

All published on the SGE page of digital.govt.nz. The SHA-256 prefix lets a
reader confirm they hold the same file.

| Document | Version and date (as printed) | Index number | SHA-256 (first 16) |
|---|---|---|---|
| Common Implementation Framework (PDF) | v1.1 | none printed | `3f00d7b16cd85e36` |
| Common Implementation Framework (web page) | page last updated 9 September 2026 | none | n/a |
| SPF Deployment Guide | v1.0, 3 November 2025 | `AoGSD.SGE.Guidance.2025_249` | `ca53bf325c14574a` |
| DKIM Deployment Guide | v1.0, 4 November 2025 | `AoGSD.SGE.Guidance.2025_250` | `d8ae0fc9042404e2` |
| DMARC Deployment Guide | v1.0, 4 November 2025 | `AoGSD.SGE.Guidance.2025_252` | `c9e12c4494a95d7a` |
| TLS-RPT Deployment Guide | v1.0, 4 November 2025 | `AoGSD.SGE.Guidance.2025_254` | `799e2162d5ef4c0c` |
| MTA-STS Deployment Guide | v1.1, 5 November 2025 | `AoGSD.SGE.Guidance.2025_256` | `41642bd45b8be21f` |
| TLS Deployment Guide | v1.0 in its control table; file named v2.0; 2 February 2026 | `GDSD.SGE.Guidance.2026_043` | `346d10ac3e2f3794` |
| Keyword Blocking Deployment Guide | v1.2 in its control table; file named v2.2; 12 February 2026 | `GDSD.SGE.Guidance.2026_040` | `c487970ff0041d7f` |
| SGE Keyword Blocking Scripts (text) | none | none | `8576399f6c620d6b` |

Home page:
<https://www.digital.govt.nz/products-and-services/products-and-services-a-z/secure-government-email>.
Web framework:
<https://www.digital.govt.nz/products-and-services/products-and-services-a-z/secure-government-email/secure-government-email-common-implementation-framework>.
Each PDF is linked from the home page. The site's bot protection serves a
placeholder page to simple HTTP clients; a full browser engine retrieves the
real documents.

## How takestock reads the level of a requirement

The framework does not declare a keyword convention, so takestock applies the
IETF one that the NZISM itself uses (RFC 2119; NZISM §1.1.40):

1. **MUST** where a sentence stating the requirement says *must*, *must not*,
   *mandatory* or *required* (RFC 2119 §1 treats REQUIRED as MUST).
2. **SHOULD** where it says *should*, *recommended* or *strongly recommended*.
3. **Directive, level unstated** where the only wording is an instruction
   without a keyword (*needs to*, *Ensure…*, *Set…*, *Do not…*). takestock
   reports these with the recommendations and never as a breach of a MUST.
4. **The strongest sentence wins.** The framework, its checklist and seven
   guides often state the same requirement in different words. takestock
   searches all of them and grades on the strongest sentence it finds, citing
   that sentence.
5. **Headings and list lead-ins do not grade.** A heading such as *TLS
   requirement*, or the lead-in *"The technologies required to be deployed"*,
   gives no item a level of its own.
6. **Where a guide quotes an NZISM control, the level is read from the NZISM**,
   not from the guide's paraphrase, because the guides sometimes misstate it
   (see *Contradictions* below).

## The requirements

### All email-enabled domains

| Requirement | Level | Deciding sentence | Source |
|---|---|---|---|
| TLS 1.2 minimum; TLS 1.1, 1.0, SSL, no TLS and unencrypted sending not used | MUST | *"A minimum of TLS1.2 must be used. TLS1.1, 1.0, SSL, no-TLS, or sending unencrypted must not be used."* | Framework §8 |
| TLS reporting enabled | MUST | *"All email sending domains must have TLS Reporting enabled."* | Framework §8; TLS-RPT guide §3 |
| TLS-RPT record form: version `v=TLSRPTv1`, name `_smtp._tls`, a reporting address | MUST | *"You must have a version number of 1 (v=TLSRPTv1)"*; *"You must include a Reporting Address (RUA)"* | TLS-RPT guide §4 |
| SPF record ending in `-all` | MUST | *"All email sending domains must have an SPF record and it must end with a hardfail -all"* | Framework §8; SPF guide §3 |
| All outbound mail DKIM signed | MUST | *"All outbound email from all sending services must be DKIM signed."* | Framework §8; DKIM guide §3 |
| Signing at the last hop where an external security provider relays outbound mail | MUST | *"DKIM signing must happen at that point"* | DKIM guide §4 |
| Third-party sending platforms sign with the organisation's own domain | MUST | *"You must configure the platform to sign emails using your domain"* | DKIM guide Appendix 1 |
| DMARC policy `p=reject` | MUST | *"All domains must have a p=reject DMARC policy."* | DMARC guide §3 (the framework's own §8 says *"needs to be set"*) |
| Inbound mail checked for DMARC and acted on | MUST | *"Inbound emails must be checked for DMARC compliance and acted on based on the sending domain's DMARC policy."* | Framework §8. RFC 9989 §7.4 forbids rejecting solely on a `p=reject` policy; see the inbound DMARC handling section of [`STANDARDS.md`](STANDARDS.md) |
| DMARC reports reviewed regularly | MUST | *"DMARC Reports must be reviewed on a regular basis."* | DMARC guide §3; NZISM `15.2.36.C.04` (MUST) |
| A DMARC reporting tool in use | MUST | *"A DMARC reporting tool is required."* | Framework §4; DMARC guide §4 step 1 |
| MTA-STS enabled in `enforce` mode | MUST | *"An MTA record must be defined and set to enforce."* | Framework §10 checklist (§8 says *"needs to be enabled"*) |
| MTA-STS policy lists every MX host, without wildcards | MUST | *"The MX entries must match all MX servers configured for your domain"*; *"You must not use * wildcards"* | MTA-STS guide §4 step 2 |
| MTA-STS policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` | MUST | *"This file must be named mta-sts.txt and hosted using https"* | MTA-STS guide §4 step 2 |
| "Implicit TLS" enforced | MUST, but narrowed | *"Implicit TLS must be configured and enforced for all connections."* Later narrowed to mail between government organisations, and mandatory only within the Restricted Group | Framework §10; TLS guide §3 and §4.5. See *Contradictions* |
| DLP enforced in line with the NZISM | MUST | *"DLP must be enabled in line with your agencies requirements under the NZISM."* | Framework §10 checklist |
| Outbound mail marked above the path's classification blocked; inbound mail marked above the system's accreditation rejected, logged and reported | MUST | NZISM `15.2.40.C.01` and `15.2.41.C.01`, both MUST, quoted by the guide | Keyword Blocking guide §3 |
| DKIM keys of 2048 bits | SHOULD | *"The use of 2048-bit RSA keys are strongly recommended."* 1024-bit keys may be used *"on legacy systems if needed"* | DKIM guide §4.2 and Appendix 2 |
| Strict DKIM alignment (`adkim=s`) where the domain sends no bulk mail | SHOULD | *"adkim=s is recommended where domains are not involved with bulk mail sending."* | Framework §8 |
| Strict SPF alignment (`aspf=s`) | SHOULD | *"for DMARC aspf=s should be used"* | DMARC guide §4 step 2 |
| No `ruf`, `fo`, `pct`, `rf` or `ri` tags | SHOULD | *"The following tags are not required and should not be used"* | DMARC guide Appendix 2 |
| `sp=` only on organisational domains | SHOULD | *"sp= should only ever be set on organisation level domains."* | DMARC guide §4 step 2 |
| `p=quarantine` not used as a step | SHOULD | *"There is also a p=quarantine option, which is not recommended."* | DMARC guide §4 step 2 and Appendix 2 |
| Mail failing DMARC goes to an administrator quarantine, never a user's junk folder | SHOULD | *"Emails which fail DMARC … should never make it to the users' mailboxes."* | Framework §8 |
| Bulk senders on a separate sub-domain | SHOULD | *"The recommended solution is to have bulk mail senders operating from a different subdomain"* | Framework §8 |
| One DKIM selector and key per sending platform | SHOULD | *"each platform should be configured with its own DKIM selector"* | DKIM guide Appendix 1 |
| No `ptr` mechanism, no overly broad address ranges in SPF | Directive | *"Do not use ptr or overly broad IP ranges."* | SPF guide §4 step 6 |
| Legacy `spf2.0` records removed | SHOULD | *"If you have SPF2.0 type records these should be removed from DNS."* | SPF guide Appendix 2 |
| MTA-STS policy hosted securely and highly available | SHOULD | *"The mta-sts.txt file should be accessible in a highly available location."* | MTA-STS guide §4 step 2 and Appendix 2 |
| Minimum keyword list blocked | SHOULD | *"It recommends, at a minimum, the following keywords be added to your DLP block lists"* | Keyword Blocking guide §3 |
| Unencrypted mail in and out reviewed | SHOULD | *"It is recommended email platform administrators review their TLS-RPT logs or TLS session logs"* | TLS guide §4.4 |
| Platforms that cannot use TLS raised as a security risk | SHOULD | *"It is recommended where Agencies platforms do not support TLS … this be raised as a security risk"* | TLS guide Appendix 1 |

**`p=reject` and mailing lists.** RFC 9989 §7.4 advises domains whose users
post to mailing lists not to publish `p=reject`. An organisation this framework
binds meets `p=reject` anyway, records the tension openly, and reduces the cost
by DKIM-signing all mail and telling users that taking part in mailing lists
may be hindered. [`STANDARDS.md`](STANDARDS.md) sets out how, in its section
on DMARC `p=reject`.

The framework's bulk-mail allowance does not change this. It relaxes
alignment, not the policy: strict DKIM alignment is recommended only *"where
domains are not involved with bulk mail sending"*, and bulk senders are
recommended onto *"a different subdomain to end users"* (Framework §8). The
`p=reject` requirement has no such condition (*"DMARC needs to be set to
p=reject on all email enabled domains"*, Framework §8), so a bulk-mail
sub-domain still publishes `p=reject`. Relaxed alignment would not help with
mailing lists either: a list that rewrites the subject or body breaks the DKIM
signature itself, and relays from its own servers so SPF fails.

### All non-email-enabled domains and sub-domains

The framework says this requirement *"remains even if the root level domain
has SP=reject set within its DMARC record"*, because SPF and DKIM lookups do
not climb to the parent domain (framework §9).

| Requirement | Level | Deciding sentence | Source |
|---|---|---|---|
| SPF record `v=spf1 -all` | MUST | *"Blank SPF records with a -all suffix must be configured on non-email enabled domains."* | SPF guide §3; framework §9 |
| DKIM record with an empty key, `v=DKIM1; p=` | MUST | *"Blank DKIM records must be configured on non-email enabled domains."* | DKIM guide §3; framework §9 |
| DMARC `p=reject` | MUST | *"All domains must have a p=reject DMARC policy."* | DMARC guide §3 |
| Strict alignment on SPF and DKIM, and a reporting address | Directive | *"Set every sub-domains' DMARC record to …"* | Framework §10 checklist |

An empty DKIM key is a defined state, not an error: RFC 6376 §3.6.1 says *"An
empty value means that this public key has been revoked"*, so any signature
claiming that domain fails.

### Parked domains

A **parked domain** is one an organisation holds that sends and receives no
mail. takestock treats a domain listed under `discovery.domains` and not under
`discovery.email_domains` as parked, because whether a domain sends mail
cannot be seen in DNS. The framework's requirements for non-email-enabled
domains apply to it directly, and takestock grades it on its own records:

| Record | Level | Basis |
|---|---|---|
| SPF `v=spf1 -all`, with no other mechanism | MUST | SGE SPF guide §3 (the row above). The M3AAWG *Protecting Parked Domains Best Common Practices* (December 2015) say parked domains *"should publish a SPF TXT record in DNS that is referred to as a "naked" -all"* |
| DMARC `p=reject`, and no `sp=` or `np=` weaker than `reject` | MUST | SGE DMARC guide §3 (the row above). M3AAWG: parked domains *"should publish a DMARC TXT record in DNS which specifies "p=reject""*. A record that sets `sp=` or `np=` to `none` or `quarantine` fails, and one with neither passes on its `p=reject`; see below |
| Strict alignment and a reporting address | Directive | Framework §10 checklist (the row above) |
| No SPF2.0 record | SHOULD | SPF guide Appendix 2, read from the TXT records the SPF reading kept, as for an email domain |
| None of the DMARC tags `ruf`, `fo`, `pct`, `rf`, `ri` | SHOULD | DMARC guide Appendix 2, read from the parked domain's own DMARC record, as for an email domain; a missing record is graded under the DMARC row |
| Empty DKIM key `v=DKIM1; p=` at `*._domainkey.<domain>` | MUST | DKIM guide §3 (the row above). Read at the wildcard name: the empty key passes; no DKIM record there, or one carrying a key, fails; a lookup that does not settle is not measured |
| Null MX (`0 .`) | Not an SGE requirement | RFC 7505 §3 defines it: *"To indicate that a domain does not accept email, it advertises a single MX RR … with an RDATA section consisting of preference number 0 and a zero-length label"*, and *"A domain that advertises a null MX MUST NOT advertise any other MX RR."* M3AAWG calls it *"The recommended way to indicate that a domain is not meant to receive email"*. The UK NCSC's *Protecting parked domains* guidance says *"If you have an A record on your domain, but no MX records, you should create a null MX record"* |

**The sub-domain policy on a parked domain.** The DMARC requirement's
deciding sentence is *"All domains must have a p=reject DMARC policy"* (DMARC
guide §3), and the framework applies it to *"all non-email domains,
sub-domains and all new domains"* (§9). The names beneath a parked domain send
no mail either. A name with no DMARC record of its own is given the parent's
`sp=` policy, or its `p=` policy when `sp=` is absent (RFC 7489 §6.3; RFC
9989, which obsoletes it, keeps the tag). So a parked domain whose record says
`sp=none` or `sp=quarantine` leaves those names without a reject policy, and
its row fails even when it reads `p=reject`. The framework's sentence that
the requirement *"remains even if the root level domain has SP=reject set"*
makes `sp=reject` necessary, not sufficient: each name beneath still needs its
own SPF and DKIM records, which the sweep below reads.

**Names that do not exist: `np=`.** RFC 9989, which obsoletes RFC 7489, adds
the `np=` tag. Its §4.7 defines it as the policy *"for non-existent subdomains
of the given Organizational Domain"*, and says *"It applies only to
non-existent subdomains of the Organizational Domain queried and not to either
existing subdomains or the domain itself"*, and *"If the "np" tag is absent,
the policy specified by the "sp" tag (if the "sp" tag is present) or the policy
specified by the "p" tag (if the "sp" tag is not present) MUST be applied for
non-existent subdomains."* A name that does not exist publishes no record of its
own, so `np=` is the only policy a receiver applies to mail claiming one. An
`np=` of `none` or `quarantine` therefore leaves every such name without a
reject policy, against the framework's requirement for sub-domains and *"all
new domains"*. takestock fails it wherever it reads a domain's record for the
names beneath: on a parked domain's own DMARC row, and on an email domain's
SGE-NED-DMARC-01 row. An absent `np=` inherits `sp=` or `p=`, which are graded
already. In the sweep, a swept name that answers NXDOMAIN is given the
parent's `np=`, and a name that exists its `sp=`.

**The names beneath a parked domain.** Certificate transparency is searched
for every domain under `discovery.domains`, parked ones included, and the names
it finds beneath a parked domain are swept exactly as an email domain's are:
each name's SPF, wildcard DKIM and DMARC records are read, with an absence
control in the same batch. They are graded against SGE-NED-SPF-01,
SGE-NED-DKIM-01, SGE-NED-DMARC-01, SGE-NED-DMARC-R01, SGE-DMARC-R05 and
SGE-DMARC-R03 (the names' own DMARC records), in rows
marked *(parked)* whose subject is *sub-domains of* the parked domain, so they
sit beside, and never merge with, the rows for the parked domain's own records.
A name with no DMARC record of its own is read through the parked domain's own
record, which a receiver applies to it. As with every sweep, the names are a
floor: a name without the required record is a breach, and any number of names
carrying it settles nothing, so these rows can fail and pass only on an attested
zone file (below). A name the
sweep finds sending mail (it publishes MX, is named in the parent's sender
policy, or authorises senders) is excluded from them and graded against the
rules for email domains instead (below). The row's note says a name is graded
that way only when the same observation holds a usable mail-handling reading
of it; otherwise it says the name was set aside and is not graded as an email
domain either.

**Sub-domains that handle mail.** A name beneath an email or parked domain that
publishes MX, is named in the parent's sender policy, or publishes a sender
policy authorising senders is, to a receiver, an email domain. The framework's
rules for email domains are written for *"all email sending domains"* (SPF,
TLS-RPT) and, in the deployment checklist, *"all email enabled domains"*
(MTA-STS), so takestock reads these names against them, in rows marked
*(discovered)* whose subject is *mail-handling sub-domains of* the parent:

| Requirement | What is read for each name |
|---|---|
| SGE-SPF-01 | Its SPF record, held by the sweep |
| SGE-DMARC-01, SGE-DMARC-04, SGE-DMARC-R02 | The DMARC record a receiver applies to it: its own, or the one policy discovery finds (see *DMARC policy discovery* below), with its `sp=` for a name that exists, its `np=` for one that does not, then its `p=`; its `rua=`; its `aspf=` |
| SGE-DMARC-R03, SGE-DMARC-R05 | Its own DMARC record, for the tags the guide says not to use, and for `sp=` |
| SGE-MTASTS-01, SGE-MTASTS-02 | The TXT record at `_mta-sts.<name>` (RFC 8461 §3.1) and, when it is published, the policy file fetched from `https://mta-sts.<name>/.well-known/mta-sts.txt` with certificate validation. The same checks as for an email domain: a certificate that does not validate, an answer other than 200 or a redirect (§3.3), a missing `version: STSv1` or a bad `max_age` (§3.2) fail; so does a mode other than `enforce`; the policy's `mx:` lines are compared with the name's own MX records |
| SGE-TLSRPT-01 | The TXT record at `_smtp._tls.<name>` (RFC 8460 §3), which must be `v=TLSRPTv1` with a `rua=` address |
| SGE-DKIM-R01, SGE-DKIM-R02 | The DKIM key at `<selector>._domainkey.<name>` (RFC 6376 §3.6.2, the DNS binding) under each selector tried: the profile's `discovery.dkim_selectors`, then any the supplied zone files publish beneath the domain, then the common ones, as for an email domain. Key size, and a key published under two selector names |

SGE-DMARC-R01 is not read for these names. It applies only where a domain sends
no bulk mail, which is not visible from outside, so even an email domain's row
for it never fails, and these rows can only fail.

What each name costs: two TXT lookups asked of every configured resolver, one
HTTPS fetch where an `_mta-sts` record is published (a sender fetches no policy
without one, RFC 8461 §3.1, so neither does takestock), and a CNAME and a TXT
lookup per DKIM selector tried. The names are those the sweep already read and
settled, so the sweep's ceiling of names applies; they are read with the sweep's
concurrency, and the TXT lookups with its tries and timeouts. Nothing is read beneath a domain whose sweep
control was not trusted, and nothing at all in an observation run with
`--offline`, which reads no DNS.

A name is counted neither way, and listed with the reason, when what a
requirement needs was not read: a lookup that did not settle (kept per name in
`extra.names_mail_records_not_read`), a policy file the instrument could not
fetch, no key under any selector tried (selector names cannot be listed, so
silence proves nothing; a selector giving the empty key `v=DKIM1; p=` has revoked
its key, RFC 6376 §3.6.1, and is no key either), or a DMARC policy walk through a name that was not
read. An observation taken before these records were read shows the rows as
not collected.

These rows can fail and never pass, even on an attested zone file. An attested
zone file makes the list of *names* complete; it does not make the list of
*sending domains* complete, because which names send mail is judged from what
DNS shows (an MX record, a sender policy that authorises senders, the parent's
sender policy naming the name), and a name can send mail with none of those.

**Which names the sweep reads.** The sweep reads every name the observation
knows beneath a domain, and keeps with each where it came from
(`extra.name_sources`, counted in `extra.names_by_source`):

| Source | Names |
|---|---|
| certificate transparency | names in the public certificates the logs hold |
| zone file | every owner name in a supplied zone file (`inbox/dns-zones/<zone>.zone`), and every name between an owner and the domain, which exists as an empty non-terminal when it owns no record (RFC 4592 §2.2.2) |
| target profile | names under `discovery.domains` and `discovery.email_domains` |
| scan targets | host names under `scan_targets` |
| sender policy | the `a:`, `mx:`, `include:` and `redirect=` targets of the domain's own SPF record, and of every SPF record in a supplied zone file |

A name with a label that is not letters, digits and hyphens (an underscore
attribute leaf such as `_dmarc`, RFC 8552 §1.1, or a wildcard) is not read: RFC
5321 §4.1.2 builds a mail domain from such labels only, so no message can claim
to come from it. Private-zone exports are not read, because a receiver asks the
public DNS.

**When a sweep may pass: an attested zone file.** A list of names is a floor
unless something says it is the whole population. A zone file can, when the
organisation that runs it says so. The target profile records that statement:

```yaml
dns_zones:
  complete_zones:
    - zone: example.com
      attested_by: Example Widgets Ltd, DNS administrator
      attested_on: "2030-01-31"
```

The sweep's rows for names that send no mail (SGE-NED-SPF-01, SGE-NED-DKIM-01,
SGE-NED-DMARC-01, SGE-NED-DMARC-R01, SGE-DMARC-R05 and SGE-DMARC-R03 over the
swept names) then pass, rather than staying not measured, when every name read
meets the requirement and all of these hold:

- the attestation names who made it and when;
- a zone file whose origin is the domain was supplied, and every line of it was
  understood;
- every zone it delegates beneath the domain (an NS record below its apex) was
  supplied and attested the same way;
- every name was read and settled, none was beyond the sweep's ceiling, and no
  DMARC policy walk passed a name that was not read;
- the live reading agrees with the files: no name the files list came back
  NXDOMAIN, and no name they do not list exists (unless the files hold a
  wildcard, which answers unlisted names).

The passing row names the attestation, so a reader sees what the verdict rests
on. Where a zone file is attested and one of these fails, the row stays not
measured and says which. The rows for names that handle mail never pass (see
*Sub-domains that handle mail* above).

**DMARC policy discovery.** RFC 9989, which obsoletes RFC 7489, replaces RFC
7489's reliance on a public suffix list with a *DNS Tree Walk* (§4.10). For a name with no DMARC
record of its own, a receiver walks up the tree and applies the record of the
name's *Organizational Domain* (§4.10.1), chosen from the records the walk
finds, longest name first (§4.10.2): a record carrying `psd=n` is the
Organizational Domain; one carrying `psd=y` makes the name one label below it
the Organizational Domain; otherwise it is the record at the name with the
fewest labels. So a record at an intermediate name, such as
`mail.example.com`, governs `a.mail.example.com` only when it carries `psd=n`,
when the record above it carries `psd=y`, or when nothing above it publishes a
record. The sweep reads the DMARC record of every name a walk from a swept name
passes on the way to the domain, including names the certificate logs never
listed, and takestock applies the walk to the swept names that publish no
record of their own (SGE-NED-DMARC-01, SGE-NED-DMARC-R01, and SGE-DMARC-01 on
names that handle mail). A name whose walk passes a name that could not be read
is counted neither way. The walk is read no higher than the domain the profile
names, so a public suffix domain's record is not read. An observation taken
before the sweep read these intermediate names is read as before: each name
falls back to the domain's own record.

**Wildcards and the absence control.** Each sweep asks, in the same batch, for
a name nobody registers, which should come back NXDOMAIN; if it answers, the
resolvers may not be telling absences apart. A published wildcard answers that
name too. When the control's answer is exactly the wildcard's record, the
resolvers agree, and they are seen returning real TXT records, takestock treats
the wildcard as explaining it, and reads each name for its own response code and
agreed records, a wildcard answer being that name's effective record. A
wildcard `*.<domain>` carrying `v=spf1 -all` is therefore graded as the
compliant record it is, for every name it answers; a name that exists with no
record of its own is not covered by a wildcard, and is read as missing it. Nor
is a name beneath one that exists: under RFC 4592 a wildcard answers only a
name that does not exist and whose closest existing ancestor is the
wildcard's own parent (§3.3.1), so `*.example.com` does not answer
`x.a.example.com` when `a.example.com` exists, even as an empty non-terminal
that owns no record but has names beneath it (§2.2.1, §2.2.2). An
answer at the control that no wildcard explains still stops the batch from
being graded in either direction. A name whose resolvers gave different records
is counted neither way.

**A resolver that invents answers.** A resolver that gave one fixed TXT record
to every question would look, to the checks above, like a wildcard. So when the
control answers, the sweep also asks for a random name under `invalid`, a name
reserved never to exist (RFC 2606 §2; RFC 6761 §6.4 says a caching server
*"SHOULD generate immediate negative responses for all such queries"*), where no
wildcard of the domain's can answer and, once the root has denied `invalid`,
nothing beneath it exists (RFC 8020 §2). A resolver that answers it with records
is inventing answers: the sweep's rows say so, as an unusable resolver reading
rather than a wildcard (`extra.control_basis` is `resolver-synthesises`), and
nothing in the batch is graded. The wildcard reading also needs that name to
come back NXDOMAIN from every resolver, so a resolver that will not say (one
that answers SERVFAIL, say) leaves a domain with a wildcard ungraded.

**An observation whose rows are not marked parked.** The DNS collector marks
each reading of a parked domain `extra.parked`. An observation taken while the
domain was listed as an email domain, or by a tool that does not mark the rows,
may hold the domain's SPF and DMARC rows unmarked. They are the same DNS records
read the same way, so takestock grades them and says beside the grade that the
row was not marked. A requirement with no reading of the domain at all, in an
observation with no parked reading of any domain, is reported as not collected,
with that reason, rather than as a lookup that did not settle.

The null MX is reported beside the graded rows, never as a breach of the
framework. A parked domain that publishes MX records naming mail servers
receives mail, which contradicts the profile; takestock reports that reading
rather than deciding which is right.

## What can be measured from outside, and what cannot

takestock measures an organisation's domains from the public internet,
without credentials. Three kinds of evidence are available.

| Probe | What it shows | Requirements it can grade |
|---|---|---|
| DNS queries | The SPF, DMARC, TLS-RPT and MTA-STS records; DKIM keys at selectors that are already known; the MX records; the same for each sub-domain found handling mail | SPF `-all`; `ptr` use; `spf2.0` records; DMARC `p=`, `sp=`, `np=`, alignment tags, unwanted tags, presence of `rua=`; TLS-RPT record form; MTA-STS record; the non-email-enabled records on every name takestock knows of; DKIM key length on known selectors |
| HTTPS fetch of the MTA-STS policy, with certificate validation | The policy's `version`, `mode`, `max_age` and `mx:` lines, the HTTP status, and whether the policy host presents a valid certificate | MTA-STS in `enforce`, in a policy valid under RFC 8461 §3.2 and §3.3; MX list complete and without wildcards |
| SMTP connection to each inbound MX, on port 25 | Whether STARTTLS is offered, which TLS versions the server accepts, and its certificate | Whether the domain's receiving servers *accept* TLS below 1.2, or accept mail without TLS |

Limits that every report should carry:

- **Accepting is not using.** A receiving server that still accepts TLS 1.0
  permits what the framework forbids, but a probe cannot see what senders
  actually negotiate. Mail the organisation *sends* is not visible at all.
- **DKIM selectors cannot be listed.** DNS offers no way to enumerate the
  names under `_domainkey`. takestock can check keys only at selectors it has
  been told about or has seen in message headers. Absence of a key at a
  guessed selector proves nothing.
- **A published key is not a signed message.** *"All outbound email … must be
  DKIM signed"* is a statement about mail flow. A key in DNS shows that signing
  is possible, not that every service signs.
- **Sub-domain checks can fail, and pass only on an attested zone file.** The
  list of sub-domains takestock knows is drawn from certificate-transparency
  logs, supplied zone files, the target profile and the names sender policies
  point at. That is a floor, not the full population. A known name without the
  required records settles the requirement as unmet; any number of compliant
  names does not settle it as met, unless the profile attests a zone file
  complete (see *Which names the sweep reads* above).
- **Some conditions are invisible.** Whether a domain sends bulk mail decides
  whether strict DKIM alignment is recommended at all, and whether a domain
  sends mail at all decides whether the email-enabled or non-email-enabled
  rules apply. Neither is visible from DNS. Where a condition cannot be
  settled, takestock reports the observed value and marks the verdict
  *not measured*, rather than assuming the condition.
- **No external view of the inside.** Inbound DMARC enforcement, report
  review, the reporting tool, DLP and keyword blocking, where failed mail is
  quarantined, TLS monitoring, and whether the policy host is highly
  available cannot be observed from outside. takestock lists them with the
  reason, so the conformance table shows every requirement.
- **An inside export settles three of them.** Whether outbound mail is DKIM
  signed (SGE-DKIM-01), whether inbound mail is checked for DMARC and acted
  on (SGE-DMARC-02) and where mail failing DMARC goes (SGE-DMARC-R04) are
  settings of the receiving and sending mail platform. Given an export of
  them, takestock grades each per domain from the platform's own
  configuration; for Exchange Online, with the `exchange_online` reader
  ([`COLLECTORS.md`](COLLECTORS.md#exchange_online)) and the read-only export
  script in [`EXCHANGE-ONLINE-EXPORT.md`](EXCHANGE-ONLINE-EXPORT.md).
  The reading stops at the platform's edge: a mail service in front of it,
  which may do its own DMARC handling and quarantine, and other services
  that send as the organisation, stay outside it. Behind such a service,
  Exchange Online honours a sender's DMARC policy only with Enhanced
  Filtering on the connector that receives the mail, so a tenant configured
  to honour DMARC can still not do so. The requirements are the
  organisation's, not the platform's, so where the platform does not apply
  the setting behind such a service, SGE-DMARC-02 and a failure of
  SGE-DMARC-R04 are graded *not measured*: the service in front may check
  DMARC and act on it before the platform sees the mail.

### SPF's two lookup limits

The framework requires an SPF record ending in `-all`; whether that record can
be evaluated at all is set by RFC 7208 §4.6.4, which has two limits of
different force:

- **Ten DNS-consuming terms, a MUST.** *"SPF implementations MUST limit the
  total number of those terms to 10 during SPF evaluation… If this limit is
  exceeded, the implementation MUST return "permerror"."* The terms that cost
  a lookup are `include`, `a`, `mx`, `ptr`, `exists` and `redirect`. Address
  ranges (`ip4:`, `ip6:`) cost none, which is why replacing names with ranges
  is the usual cure for a long record.
- **Two void lookups, a SHOULD.** A *void lookup* is a DNS query made during
  evaluation that returns no answer or a name that does not exist. *"SPF
  implementations SHOULD limit "void lookups" to two. An implementation MAY
  choose to make such a limit configurable. In this case, a default of two is
  RECOMMENDED. Exceeding the limit produces a "permerror" result."*

Because the second limit is a SHOULD and may be configured, two conforming
receivers can evaluate the same record differently, one passing it and one
returning `permerror`.

Under DMARC, an SPF `permerror` is not a pass, so on mail where an evaluator
returns it, a `p=reject` policy rests on DKIM alone (RFC 9989 §5.3.5).
takestock counts both limits when it expands an SPF record and reports the
number of DNS-consuming terms and void lookups it reached. Where the resolver
reports a status for each answer, the reading is stamped with that resolver
and the time; where it does not, the void count is reported as not measured.

## What the framework does not say

- **No cipher suite, key-exchange or curve requirement.** The TLS requirement
  is a version floor and nothing more.
- **No required DKIM key length.** 2048 bits is strongly recommended and 1024
  is allowed on legacy systems. A 1024-bit DKIM key does not breach SGE; it
  may breach other standards (see [`STANDARDS.md`](STANDARDS.md)).
- **No DKIM key rotation schedule.** Rotation appears only as a benefit of
  provider-managed keys (DKIM guide §4.1).
- **No required MTA-STS `max_age`.** The guide's example uses `604800` (seven
  days) and calls it *"a good default"*.
- **No DANE requirement.** See *Contradictions* below.
- **No post-quantum content.**

## Contradictions and gaps in the framework's own documents

Each item below is in the published documents themselves. Where a takestock
verdict depends on one, the verdict names the document it followed.

1. **"Implicit TLS": universal, then narrowed, then universal again.** The
   framework checklist (§10) says *"Implicit TLS must be configured and
   enforced for all connections"*. The newer TLS Deployment Guide (§3) records
   that early adopters found this *"would likely impact email flows"* and says
   *"the requirement has been further defined as applying to all email
   transmitted between Government organisations"*; its §4.5 makes it
   *"mandatory and enforced"* only between Restricted Group members. The
   MTA-STS guide (Appendix 1 and Appendix 2), dated before the TLS guide,
   still says sending in the clear *"is not permitted"* and that such a
   connection *"will be denied"*. takestock follows the newer, narrower
   reading and says so in the finding.
2. **"Implicit TLS" means something else in the IETF.** RFC 8314 §2 defines
   Implicit TLS as TLS negotiated *"whenever a TCP connection is made on a
   particular TCP port that is used exclusively by that server for TLS
   connections"*, for mail submission and mailbox access, and its §1 says it
   *"does not address the use of TLS with SMTP for message relay"*. The SGE
   documents use the term to mean *TLS required, with no fall-back to
   cleartext*, on server-to-server relay. A reader who knows the RFC meaning
   will misread the requirement.
3. **Two guides cited but not published.** The MTA-STS guide refers to an
   *"Implicit TLS Configuration Guide"* (§3) and an *"Implicit TLS deployment
   guide"* (Appendix 1); the TLS guide refers to a *"Secure Government Email
   Restricted Group Connectors Deployment Guide"* (§4.5). Neither appears among
   the documents linked from the SGE home page.
4. **The NZISM control for reviewing DMARC reports.** The PDF framework (§8)
   and the DMARC guide (§4 step 1) cite `15.2.36.C.06`. NZISM v3.9 has no such
   control; the review requirement is `15.2.36.C.04` (MUST), which the web
   framework cites correctly.
5. **An SPF statement tied to a TLS control.** The SPF guide (Appendix 1)
   says a domain-specific `~all` exception is *"outside the bounds of the
   Framework which is bound to the NZISM, control 15.2.48.C.02"*. In NZISM v3.9
   that control is *"Agencies MUST use TLS 1.2 or above when implementing
   MTA-STS"*.
6. **The TLS guide understates the NZISM.** TLS guide §3 says the NZISM
   *"directs that Agencies SHOULD enable opportunistic TLS"*. NZISM
   `15.2.47.C.01` is a **MUST**.
7. **Requirements attributed to the NZISM that its controls do not state.**
   The SPF and DKIM guides (§3) say the NZISM *"requires SPF"* and *"requires
   DKIM be configured across all domains irrespective of whether those
   domains are used in association with email"*, and the DKIM guide (§4.4)
   says *"The NZISM requires blank DKIM records"*. The NZISM's SPF and DKIM
   controls (`15.2.49`, `15.2.50`) do not say this. The blank records appear
   in context paragraph §15.2.18, which says operators *"can publish"* them.
   The SGE guides' own MUST sentences stand on their own; only the
   attribution is wrong.
8. **A malformed example DMARC record.** The framework's Table 5 and its
   checklist (§10), in both the web and PDF versions, print
   `V=DMARC1;p=reject; adkim-s; aspf=s; rua=…`. The tag needs `adkim=s`
   (RFC 9989 §4.7). Copied literally, the broken tag is a syntax error that
   *"MUST be discarded in favor of default values (if any) or ignored
   outright"* (RFC 9989 §4.8), the default is relaxed (§4.7), and DKIM
   alignment stays relaxed on exactly the domains the record is meant to lock
   down. The same example appears in NZISM §15.2.18.
9. **A malformed example DKIM record name.** The framework's Table 4 and the
   DKIM guide (§4.4) give the name as `*._domainkey<yourdomainname>`, without
   the dot before the domain. The working name is
   `*._domainkey.example.com`.
10. **Which certificate the MTA-STS policy host needs.** The MTA-STS guide's
    step 2 says the certificate *"must include either"* the domain itself or a
    wildcard for it. Its Appendix 1 says it *"must match the MX hostname listed
    in your MTA-STS policy file"*. RFC 8461 §3.3 requires a certificate valid
    for the policy host, `mta-sts.<domain>`. Of the three, only the wildcard
    option in step 2 satisfies the RFC; a certificate for the bare domain, or
    for an MX host, does not. takestock validates the policy host the RFC's
    way.
11. **One day called seven.** The MTA-STS guide's FAQ says *"a max_age of
    86400 (7 days)"*. 86400 seconds is one day; the guide's own step 2 says,
    correctly, that 604800 seconds is seven days.
12. **MX wildcards.** The guide forbids `*` in the policy's `mx:` lines. RFC
    8461 §3.2 allows them (its example is `mx: *.example.net`). This is a tightening by the
    framework, not an error, and takestock grades the framework's rule as the
    framework's.
13. **DANE: three positions.** The framework (§8) says MTA-STS *"will be
    superseded by DANE"*. The MTA-STS guide says *"The use of DANE is not
    recommended at this stage"*, because the government DNS service provides
    DNSSEC only for domains it hosts. NZISM §15.2.29 says DANE and MTA-STS *"do
    not conflict and can be implemented in parallel"*.
14. **DMARC has a new standard.** The DMARC guide (Appendix 2) describes
    DMARCbis as still in draft. It is now RFC 9989 (IETF, May 2026), which
    obsoletes RFC 7489 and RFC 9091. Three consequences:
    - RFC 9989 removes the `pct`, `rf` and `ri` tags and adds `np`, `psd` and
      `t` (Appendix C.5). The guide's advice not to use the first three now
      matches the standard.
    - RFC 9989 replaces the public suffix list with a DNS tree walk that
      starts at the author domain's parent (§4.10.1). The guide's statement
      that DMARC *"will not look for a policy at the intermediary level"*
      describes RFC 7489 behaviour.
    - RFC 9989 §7.4 says domains whose users might post to mailing lists
      *"SHOULD NOT publish Domain Owner Assessment Policies of "p=reject""*,
      and that a domain wishing to do so *"SHOULD"* first publish `p=none` for
      at least a month and then `p=quarantine` for as long again. The
      framework requires `p=reject` on all domains and advises against
      `p=quarantine` as a step. A report should cite each where it relies on
      it, and not present either as the other's view.
15. **The classification ceiling, said two ways.** The home page says SGE
    *"protects information classified as IN-CONFIDENCE, SENSITIVE or
    RESTRICTED"*. The framework (§3) says it covers mail *"classified
    IN-CONFIDENCE and below"*, with higher classifications handled through the
    Restricted Group.
16. **"Sending" or "enabled".** TLS reporting and SPF are required on *"email
    sending domains"* (framework §8), while the TLS-RPT guide (§4) asks for a
    record *"for each of your mail enabled domains"*. A domain that receives
    mail but never sends it falls between the two wordings. takestock reports
    which wording it applied.
17. **The lead agency is named three ways.** The PDF framework names the
    Department of Internal Affairs; the web framework names the Government
    Digital Delivery Agency; the home page names the Government Chief Digital
    Office within the Department of Internal Affairs.

## Every obliging sentence in the source documents

The requirement table above lists what the framework requires. This register
is the check on that table: every sentence in the framework, its home page and
its guides that obliges or advises an agency, with the level its own words
carry and how takestock treats it. A requirement nobody modelled can only be
found by reading this way, from the first page of each document to the last.

**Level**, from the sentence's own words, under the rules in *How takestock
reads the level of a requirement*: **must** (*must*, *must not*,
*mandatory*); **required** (*is* or *are required*, which RFC 2119 treats as
MUST); **should** (*should*, *recommended*, *strongly recommended*, *best
practice*, *important*); **directive** (*needs to*, *will need to*, or a bare
instruction such as *Ensure* or *Set*); **lead-in** (a section's opening
words, which grade nothing). Two levels joined by `·` mark a row that groups
sentences of different force.

**Treated as**: *Row* names the requirement in the tables above. *Step* is a
deployment step or sequence: how to reach a required state, not a state of the
domain. *Other standard* restates an RFC, the NZISM or the PSR. *Platform
route* is one platform's way of meeting a row. *Restricted Group* applies only
to members of that group. *Permissive*, *Future* and *Procurement* allow
something, announce something, or advise on buying.

### Common Implementation Framework v1.1

| § | Sentence (quoted or closely paraphrased) | Level | Treated as |
|---|---|---|---|
| 3 | New Zealand government information, including email, *"requires protective marking"* | directive | Other standard: the PSR, which the framework says it does not change |
| 4 | The technologies *"required to be deployed"*: TLS 1.2 or later including Implicit TLS, TLS reporting, SPF, DKIM, DMARC, MTA-STS, DLP | lead-in | Each technology has its own row |
| 4 | *"A DMARC reporting tool is required"* | required | Row: a DMARC reporting tool in use |
| 5 | It is *"important for Agencies to use a DMARC reporting tool"* | should | Row: a DMARC reporting tool in use |
| 6 | Agencies implement the framework by October 2026 | directive | The framework's deadline |
| 8 | *"A minimum of TLS1.2 must be used. TLS1.1, 1.0, SSL, no-TLS, or sending unencrypted must not be used."* | must | Row: TLS 1.2 minimum |
| 8 | Microsoft 365 *"requires the configuration of an Outbound Connector requiring TLS, and a mail flow rule rejecting non-TLS connections inbound"* | directive | Platform route to Implicit TLS |
| 8 | Google Workspace administrators *"will need to manually disable TLS1.0 and 1.1"* | directive | Platform route to TLS 1.2 minimum |
| 8 | *"All email sending domains must have TLS Reporting enabled"* | must | Row: TLS reporting enabled |
| 8 | Every sending domain *"must have an SPF record and it must end with a hardfail -all"* | must | Row: SPF record ending in `-all` |
| 8 | *"consideration must be given to all servers and services which may send email"*; all valid source servers *"must be identified and included"* before the switch | must | Step |
| 8 | DMARC reports *"should be reviewed looking for messages which are hitting the softfail controls"* | should | Step |
| 8 | *"the suffix should be changed from ~all to -all"* | should | Row: SPF record ending in `-all` |
| 8 | DKIM signing *"needs to be provided on the exit points of all systems"*, *"applied at the last MX server"* | must · directive | Rows: all outbound mail DKIM signed; signing at the last hop |
| 8 | *"It is recommended that strict alignment be implemented"* for DKIM | should | Row: strict DKIM alignment |
| 8 | *"adkim=s is recommended where domains are not involved with bulk mail sending"* | should | Row: strict DKIM alignment, with its condition |
| 8 | *"The recommended solution is to have bulk mail senders operating from a different subdomain to end users"* | should | Row: bulk senders on a separate sub-domain |
| 8 | *"Inbound emails must be checked for DMARC compliance and acted on based on the sending domain's DMARC policy"* | must | Row: inbound mail checked for DMARC |
| 8 | For other providers it is *"up to the Agency to check and ensure their email service performs DMARC checks"* | directive | Row: inbound mail checked for DMARC |
| 8 | Mail failing DMARC *"should never make it to the users' mailboxes"*: quarantined mail to the platform quarantine, not a junk folder; rejected mail dropped | should | Row: failing mail to an administrator quarantine |
| 8 | The NZISM *"requires Agencies to review DMARC reports"*, so *"a DMARC reporting tool is required"* | required | Rows: DMARC reports reviewed; a DMARC reporting tool in use |
| 8 | *"DMARC needs to be set to p=reject on all email enabled domains"* | directive | Row: DMARC `p=reject` (the DMARC guide's *must* decides the level) |
| 8 | *"Agencies are required to review and apply their own DLP settings"*; *"Enforce DLP in line with the PSR and NZISM requirements"* | required · directive | Row: DLP enforced |
| 8 | *"MTA-STS needs to be enabled and set to 'enforce' on all email enabled domains"* | directive | Row: MTA-STS in `enforce` (the checklist's *must* decides the level) |
| 9 | The requirement *"remains even if the root level domain has SP=reject"* and covers *"all non-email domains, sub-domains and all new domains"* | directive | Scope of the non-email-enabled rows |
| 9 | *"The required SPF record needs to deny all senders"* (*required* is an adjective here) | directive | Row: blank SPF record |
| 9 | A blank DKIM key on every non-email-enabled name | directive | Row: empty DKIM key |
| 9 | DMARC `p=reject`, strict SPF and DKIM alignment, and a reporting address | directive | Rows: non-email DMARC `p=reject`; strict alignment and a reporting address |
| 10 | The deployment checklist, eleven rows | must · should · directive | Each maps to a row above. Three say *must* (MTA-STS, Implicit TLS, DLP), one says *should* (`adkim=s`), and the rest are bare instructions. The DKIM row limits signing to mail *"to Agencies or public destinations"* |

### SGE home page

| Sentence | Level | Treated as |
|---|---|---|
| Restricted Group agencies *"must confirm that their ICT services … are formally certified and accredited in writing to RESTRICTED"* | must | Restricted Group |
| *"Other agencies should block information tagged at this level"* | should | Rows: DLP enforced; marked mail blocked |

### SPF Deployment Guide v1.0

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | *"All mail sending domains must have an SPF record finishing with -all"* | must | Row: SPF record ending in `-all` |
| 3 | *"Blank SPF records with a -all suffix must be configured on non-email enabled domains"* | must | Row: blank SPF record |
| 3 | *"Inbound emails must be scanned and acted on with SPF"*, which the guide places under DMARC | must | Row: inbound mail checked for DMARC |
| 4 | *"You must identify all servers or services which send email on behalf of your domain"* | must | Step |
| 4 | *"it is recommended you start with ~all"* | should | Step: a starting point, ending at `-all` |
| 4 | Specialist sending platforms *"should be specifically checked to ensure propagation"* | should | Step |
| 4, step 6 | Best practice: review quarterly, use change management, keep an inventory of sending services, respect the lookup limit, *"Do not use ptr or overly broad IP ranges"*, prefer `-all`, monitor with DMARC reports, keep a changelog, test before deploying | should · directive | Row: no `ptr`, no overly broad ranges. The lookup limit is RFC 7208's (see *SPF's two lookup limits*). The rest are practices |
| 4.1 | An external gateway's address *"must be contained in your SPF record"* | must | Step: whether the list of senders is complete shows in DMARC aggregate reports, not in the record |
| 4.1 | Address rewriting by a gateway *"needs to be confirmed with the supplier"* | directive | Step |
| 4.2 | *"each subdomain must have its own blank SPF record"* | must | Row: blank SPF record |
| 4.3 | *"Migrating from SPF ~all to -all is required"*, followed by a seven-step method | required | Row: SPF record ending in `-all`; the method is steps |
| App. 1 | For services that must fail SPF, it is *"recommended the sending service be configured on a separate sub domain"* | should | Permissive: the guide calls a domain-specific exception *"outside the bounds of the Framework"* |
| App. 2 | *"If you have SPF2.0 type records these should be removed from DNS"* | should | Row: legacy `spf2.0` records removed |
| App. 2 | A `redirect=` is acceptable *"so long as the lookup results in a -all suffix"* | — | Permissive: an evaluator has to follow the redirect to see how the policy ends |
| App. 2 | *"It is invalid to have multiple SPF records"* | — | Other standard (RFC 7208) |
| App. 2 | `-all` is *"Required for SGE Framework and NZISM Compliance"* | required | Row: SPF record ending in `-all` |

### DKIM Deployment Guide v1.0

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | *"All outbound email from all sending services must be DKIM signed"* | must | Row: all outbound mail DKIM signed |
| 3 | *"Blank DKIM records must be configured on non-email enabled domains"* | must | Row: empty DKIM key |
| 3 | Inbound DKIM checking, which the guide places under DMARC | must | Row: inbound mail checked for DMARC |
| 4 | Where an external security provider relays outbound mail, *"DKIM signing must happen at that point"* | must | Row: signing at the last hop |
| 4.1 | *"make sure you copy the M365 statements exactly"* | directive | Step |
| 4.2 | *"The use of 2048-bit RSA keys are strongly recommended"* | should | Row: DKIM keys of 2048 bits |
| 4.3 | In the third-party platform example, records *"must be added"* to DNS | must | Step |
| 4.4 | *"The NZISM requires blank DKIM records"* on non-email-enabled domains | directive | Row: empty DKIM key. The attribution to the NZISM is not supported by its controls (*Contradictions*, item 7) |
| App. 1 | *"You must configure the platform to sign emails using your domain"* | must | Row: third-party platforms sign with the organisation's own domain |
| App. 1 | *"each platform should be configured with its own DKIM selector"*; do not use the same private key across several services | should | Row: one DKIM selector and key per sending platform |
| App. 1 | Best practice: custom signing, unique selectors, relaxed alignment *"only if needed"*, monitoring through DMARC reports, testing first | should | The rows above; testing is a step |
| App. 2 | A separate sub-domain for each external sender *"is best practice"* | should | Row: bulk senders on a separate sub-domain |
| App. 2 | 2048-bit keys *"on all systems which support them"*, with 1024-bit keys allowed *"on legacy systems"* | should | Row: DKIM keys of 2048 bits |
| App. 2 | For 4096-bit keys, *"ensure you've verified full end-to-end compatibility"* | directive | Step |

### DMARC Deployment Guide v1.0

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | *"All domains must have a p=reject DMARC policy"* | must | Rows: DMARC `p=reject`, for email-enabled and non-email-enabled domains |
| 3 | *"DMARC Reports must be reviewed on a regular basis"* | must | Row: DMARC reports reviewed |
| 3 | *"Inbound emails must be scanned by DMARC and acted on"* | must | Row: inbound mail checked for DMARC |
| 4 | *"You must have SPF and DKIM configured prior to setting a DMARC policy"* | must | Step |
| 4, step 1 | *"a DMARC reporting tool is required"* | required | Row: a DMARC reporting tool in use |
| 4, step 2 | `p=quarantine` *"is not recommended"* | should | Row: `p=quarantine` not used as a step |
| 4, step 2 | *"sp= should only ever be set on organisation level domains"* | should | Row: `sp=` only on organisational domains |
| 4, step 2 | Strict DKIM alignment *"(recommended)"*, *"adkim=s should be used"* | should | Row: strict DKIM alignment, with the framework's bulk-mail condition |
| 4, step 2 | Strict SPF alignment *"(recommended)"*, *"aspf=s should be used"* | should | Row: strict SPF alignment |
| 4, step 2 | Forensic (`ruf`) reports *"should not be used"* | should | Row: no `ruf`, `fo`, `pct`, `rf` or `ri` tags |
| 4, step 5 | *"recommended you monitor these reports for a minimum of 4 weeks"* before moving to reject | should | Step |
| 4, step 7 | *"Implement ongoing monitoring of your DMARC records"* | directive | Row: DMARC reports reviewed |
| 4 | *"The framework requires p=reject policies are applied to all non-mail-enabled domains"* | directive | Row: non-email DMARC `p=reject` |
| 4 | *"The Framework requires inbound emails are checked for DMARC compliance and acted on"* | directive | Row: inbound mail checked for DMARC |
| App. 1 | It is *"important you understand DMARC and apply relevant settings … on your inbound email"* | should | Row: inbound mail checked for DMARC |
| App. 2 | *"No. Do not enable RUF reporting"*; `ruf` *"should be removed"*, and `fo` *"should also be removed"* | should | Row: no `ruf`, `fo`, `pct`, `rf` or `ri` tags |
| App. 2 | `np=reject` *"should be expected"* and *"will be added to the framework in future"* | — | Future |
| App. 2 | Tags that *"should not be used"*: `ruf`, `fo`, `pct`, `rf`, `ri` | should | Row: no `ruf`, `fo`, `pct`, `rf` or `ri` tags |
| App. 3 | When choosing a reporting supplier, *"you should consider"* a list of features | should | Procurement |

### TLS-RPT Deployment Guide v1.0

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | *"All email sending domains must have TLS Reporting enabled"* | must | Row: TLS reporting enabled |
| 4 | A DNS record *"for each of your mail enabled domains"* (*mail enabled*, where §3 says *sending*) | directive | Row: TLS reporting enabled (*Contradictions*, item 16) |
| 4, step 2 | The version *"must"* be `v=TLSRPTv1`, the name *"must"* be `_smtp._tls`, and *"You must include a Reporting Address"* | must | Row: TLS-RPT record form |
| 4, step 1 | The DMARC reporting service *"is the best place to send TLS reports"* | should | Procurement |
| 4, step 2 | A reporting percentage below 100% means missing reports | — | Other standard: a sender's behaviour, not a record setting |

### MTA-STS Deployment Guide v1.1

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | MTA-STS enabled and set to enforce on all email-enabled domains | directive | Row: MTA-STS in `enforce` |
| 4 | *"TLS Reporting needs to be in place prior to configuring MTA-STS"* | directive | Step; the end state is the TLS reporting row |
| 4, step 1 | The TXT record's time to live, *"86400 (24 Hours, recommended)"* | should | Step: step 5 of the same guide offers 3600 before enforcing |
| 4, step 1 | *"The v= … must be v=STSv1 exactly"* | must | Part of the row MTA-STS in `enforce` |
| 4, step 2 | *"The mode should be set to testing"* on first deployment | should | Step |
| 4, step 2 | *"The MX entries must match all MX servers configured for your domain"*; *"You must not use * wildcards in the mx records"* | must | Row: policy lists every MX host, without wildcards |
| 4, step 2 | The policy file *"must be named mta-sts.txt and hosted using https"* under `/.well-known/`, with a certificate from a public authority that *"must"* match | must | Row: MTA-STS policy location (which certificate: *Contradictions*, item 10) |
| 4, step 2 | The file *"should be accessible in a highly available location"* | should | Row: policy hosted securely and highly available |
| 4, step 4 | *"Ensure that legitimate email traffic is not being disrupted before enforcing"* | directive | Step |
| App. 1 | *"the SGE Framework also requires the use of implicit TLS meaning sending in the clear is not permitted"* | directive | Row: Implicit TLS, since narrowed (*Contradictions*, item 1) |
| App. 1 | The certificate *"must match the MX hostname listed in your MTA-STS policy file"* | must | Contradicts step 2 and RFC 8461 (*Contradictions*, item 10) |
| App. 2 | The policy *"should be hosted in a high security, highly available location"* | should | Row: policy hosted securely and highly available |
| App. 2 | *"The use of DANE is not recommended at this stage"* | should | No row (*Contradictions*, item 13) |

### TLS Deployment Guide (v1.0 in its control table)

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | TLS 1.2 minimum on all email connections; older versions and cleartext *"must not be used"* | must | Row: TLS 1.2 minimum |
| 3 | Implicit TLS *"further defined as applying to all email transmitted between Government organisations"* | directive | Row: Implicit TLS, narrowed |
| 4.1 | *"Recipient domain administrators should confirm they have MTA-STS enabled"* | should | Row: MTA-STS in `enforce` |
| 4.1 | Other platforms *"need to review their services"*; on Google Workspace *"you must configure TLS compliance rules"* | directive · must | Platform route to TLS 1.2 minimum |
| 4.2 | Where a platform cannot send over TLS, it is *"strongly recommended you engage with the supplier"* | should | Row: platforms that cannot use TLS raised as a security risk |
| 4.3 | For legacy systems, administrators *"should review their use"*, and organisations *"need to carefully consider the data being transmitted"* | should | Row: platforms that cannot use TLS raised as a security risk |
| 4.4 | *"recommended email platform administrators review their TLS-RPT logs or TLS session logs"* to see what mail is sent or received unencrypted | should | Row: unencrypted mail in and out reviewed |
| 4.4 | *"If it is your systems which do not support TLS, measures should be taken to address this"* | should | Row: platforms that cannot use TLS raised as a security risk |
| 4.5 | *"Implicit TLS is mandatory and enforced on all email between members of the SGE Restricted Group"* | must | Restricted Group |
| App. 1 | *"Agencies will need to monitor their Mail Flow Reports to confirm if they are sending or receiving email via non-TLS channels"* | directive | Row: unencrypted mail in and out reviewed |
| App. 1 | It is *"recommended … this be raised as a security risk, and options to secure the platforms be considered"* | should | Row: platforms that cannot use TLS raised as a security risk |
| 5.1 | A destination moving to a service with TLS 1.1 or 1.0 *"will require the disabling"* of both | directive | Row: TLS 1.2 minimum |

### Keyword Blocking Deployment Guide (v1.2 in its control table) and scripts

| § | Sentence | Level | Treated as |
|---|---|---|---|
| 3 | NZISM `15.2.40.C.01`: agencies *"MUST configure systems to block any outbound emails with a protective marking"* above the classification of the path | must | Rows: DLP enforced; marked mail blocked |
| 3 | NZISM `15.2.41.C.01`: agencies *"MUST configure email systems to reject, log and report inbound emails"* marked above the receiving system's accreditation | must | Row: marked mail blocked. The guide quotes the control whole; the framework's own sentences ask only for blocking |
| 3 | *"The SGE Framework requires Data Loss Prevention (DLP) be enforced in line with the PSR and NZISM"* | directive | Row: DLP enforced |
| 3 | The guide *"recommends, at a minimum, the following keywords be added to your DLP block lists"* | should | Row: minimum keyword list blocked |
| 3 | In the note for Restricted Group members: *"These keyword blocks must be in place before you exit SEEMail"* | must | Restricted Group. Read more broadly, it would make the blocks a precondition of leaving SEEMail for every agency |
| 4 | *"inbound email still needs to be blocked at the gateway"*; *"the applicable keywords are blocked on inbound and outbound mail flows"* | directive | Row: marked mail blocked |
| 5 | It is *"strongly recommended this is done via PowerShell"* | should | Step |
| 8.1 | The old SEEMail trigger words are *"no longer required"* | — | Permissive |
| 8.2 | During migration, tagged inbound mail *"should be blocked, or encapsulated with a warning, at the SEEMail gateway"*, and agencies *"need to consider possible mail flow and reporting impacts"* | should | Step, during migration only |
| App. 2 | Mail classified above IN-CONFIDENCE is *"not permitted to be received via email sources outside of Restricted Group members"* | directive | Row: marked mail blocked |
| Scripts | *"You must have PowerShell 5.1 or 7+"* | must | Step |

## How takestock reports SGE conformance

- **Every requirement gets a row, including those it cannot measure.** A
  conformance table that silently drops the unmeasurable rows reads as full
  coverage.
- **Per domain, not per organisation.** Domains that share a mail service can
  still differ in their SPF, DKIM and DMARC records.
- **Only an unmet MUST is called a breach.** An unmet SHOULD or directive is
  reported as such.
- **Name the bar.** An SGE verdict is an SGE verdict; where the NZISM or an RFC
  sets a different bar, the finding says which one it applied.
- **Keep the framework's deadline beside the finding**, as the framework's
  own date.

## Sources read for this document

| Publisher | Document | Where |
|---|---|---|
| Government Chief Digital Officer | SGE home page; Common Implementation Framework (web and PDF v1.1); SPF, DKIM, DMARC, TLS-RPT, MTA-STS, TLS and Keyword Blocking Deployment Guides; Keyword Blocking Scripts | <https://www.digital.govt.nz/products-and-services/products-and-services-a-z/secure-government-email> and the documents linked from it |
| GCSB | NZISM v3.9, §15.2 *Email Infrastructure* | <https://nzism.gcsb.govt.nz/ism-document> |
| IETF | RFC 2119, RFC 3207, RFC 6376, RFC 7208, RFC 7489, RFC 7505, RFC 8301, RFC 8314, RFC 8460, RFC 8461, RFC 8996, RFC 9989 | <https://www.rfc-editor.org/rfc/> |
| M3AAWG (Messaging, Malware and Mobile Anti-Abuse Working Group) | *Protecting Parked Domains Best Common Practices*, updated December 2015 | the M3AAWG website, published documents |
| UK National Cyber Security Centre | *Protecting parked domains for the UK public sector* (blog post) | the UK NCSC website, blog posts |
