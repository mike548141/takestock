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
| Inbound mail checked for DMARC and acted on | MUST | *"Inbound emails must be checked for DMARC compliance and acted on based on the sending domain's DMARC policy."* | Framework §8 |
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

## What can be measured from outside, and what cannot

takestock measures an organisation's domains from the public internet,
without credentials. Three kinds of evidence are available.

| Probe | What it shows | Requirements it can grade |
|---|---|---|
| DNS queries | The SPF, DMARC, TLS-RPT and MTA-STS records; DKIM keys at selectors that are already known; the MX records | SPF `-all`; `ptr` use; `spf2.0` records; DMARC `p=`, `sp=`, alignment tags, unwanted tags, presence of `rua=`; TLS-RPT record form; MTA-STS record; the non-email-enabled records on every name takestock knows of; DKIM key length on known selectors |
| HTTPS fetch of the MTA-STS policy, with certificate validation | The policy's mode and `mx:` lines, and whether the policy host presents a valid certificate | MTA-STS in `enforce`; MX list complete and without wildcards |
| SMTP connection to each inbound MX | Whether STARTTLS is offered, which TLS versions the server accepts, and its certificate | Whether the domain's receiving servers *accept* TLS below 1.2, or accept mail without TLS |

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
- **Sub-domain checks can fail but never pass.** The list of sub-domains
  takestock knows is a floor drawn from DNS and certificate logs, not the full
  population. A known name without the required records settles the
  requirement as unmet; any number of compliant names does not settle it as
  met.
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
   (RFC 7489 §6.4). Copied literally, the broken tag is discarded (RFC 7489
   §6.3) and DKIM alignment stays relaxed on exactly the domains the record is
   meant to lock down. The same example appears in NZISM §15.2.18.
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
| IETF | RFC 2119, RFC 3207, RFC 6376, RFC 7208, RFC 7489, RFC 8301, RFC 8314, RFC 8460, RFC 8461, RFC 8996, RFC 9989 | <https://www.rfc-editor.org/rfc/> |
