# Standards takestock grades against

This document says which published standards takestock uses to grade what it
finds, who each standard is written for, how they rank against each other, how
their compliance words are read, and where they disagree. It is written for
anyone who has to defend a grade: to an auditor, a board, or a supplier.

Every claim below cites the publisher, the document and the section it comes
from. Dates are the documents' own publication or version dates.

Companion documents:

- [`SECURE-GOVERNMENT-EMAIL.md`](SECURE-GOVERNMENT-EMAIL.md): New Zealand's
  email security framework, which takestock treats as a separate requirement
  set.
- [`OBLIGATIONS.md`](OBLIGATIONS.md): the laws and government policies that
  sit above these technical standards.
- [`RISK-SCALE.md`](RISK-SCALE.md): the New Zealand government risk scale, for
  turning a finding into a risk rating.
- [`CONTINUOUS-ASSURANCE.md`](CONTINUOUS-ASSURANCE.md): how peer frameworks
  keep a security authorisation current without a fixed-term certificate.

## Terms used here

- **Primitive**: a single cryptographic building block, such as an algorithm
  (AES, RSA), a key size, a curve (P-256) or a protocol version (TLS 1.2).
- **Control**: a numbered requirement in a standard, such as NZISM control
  `17.2.19.C.01`.
- **Compliance level**: the force of a control, written as a keyword. **MUST**
  and **MUST NOT** are mandatory. **SHOULD** and **SHOULD NOT** are
  recommended practice that may be departed from with a recorded reason. The
  keywords come from the Internet Engineering Task Force (IETF): RFC 2119 *Key
  words for use in RFCs to Indicate Requirement Levels*, which also treats
  **REQUIRED** and **SHALL** as equal to MUST, and RFC 8174, which limits the
  special meaning to words written in capitals.
- **Post-quantum cryptography (PQC)**: algorithms designed to stay secure
  against an attacker with a large quantum computer. The current standards are
  ML-KEM (key establishment), ML-DSA and SLH-DSA (signatures).
- **Security strength**: the work needed to break a primitive, in bits. A
  strength of 112 bits means about 2^112 operations. NIST uses it to compare
  primitives of different kinds.

## The standards, and whom they bind

| Standard | Publisher | Version used | Written for | What takestock uses it for |
|---|---|---|---|---|
| New Zealand Information Security Manual (NZISM) | Government Communications Security Bureau (GCSB), published by the Government Chief Information Security Officer | v3.9 | New Zealand government departments and agencies; Crown entities, local government and the private sector are *encouraged* to use it (§1.1.2) | The primary bar for classical cryptography, email security and patching |
| Protective Security Requirements (PSR), INFOSEC policy framework | New Zealand Government (PSR) | v2.0 | Organisations mandated to implement the PSR; others are encouraged to adopt it | Governance wrapper. It delegates technical detail to the NZISM, requires system assurance for ICT systems (INFOSEC 3.1) and compensating measures where a MUST cannot be met |
| Minimum Cyber Security Standards | National Cyber Security Centre (NCSC NZ) | 2025 edition | GCISO-mandated agencies, which must implement them; others may adopt them | Maturity criteria, mapped to NZISM controls |
| Secure Government Email (SGE) Common Implementation Framework | Government Chief Digital Officer, on digital.govt.nz | Framework v1.1 and seven deployment guides | New Zealand government agencies | A separate email requirement set. See the companion document |
| FIPS 203, 204 and 205 | US National Institute of Standards and Technology (NIST) | Final, 13 August 2024 | US federal systems; widely used as the reference elsewhere | Which algorithms count as post-quantum |
| FIPS 186-5; SP 800-57 Part 1 Rev. 5; SP 800-131A Rev. 2; SP 800-52 Rev. 2 | NIST | Final (2023; May 2020; March 2019; August 2019) | US federal systems | Classical thresholds, security strengths, TLS configuration |
| NIST IR 8547 *Transition to Post-Quantum Cryptography Standards* | NIST | **Initial public draft**, 12 November 2024 | US federal systems | Calibration for when classical public-key cryptography is expected to retire |
| Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) | US National Security Agency (NSA) | Advisory Ver. 1.0, September 2022 | US National Security Systems only | Calibration for post-quantum dates by category of equipment |
| Information Security Manual (ISM), *Guidelines for cryptography* | Australian Signals Directorate (ASD) | September 2026 edition | Australian government systems | Calibration only: the nearest cross-check for a New Zealand reader |
| IETF RFCs (TLS, SMTP security, SPF, DKIM, DMARC, MTA-STS, TLS-RPT) | IETF, via the RFC Editor | As cited | Anyone implementing the protocol | Whether a configuration is valid at all |

Sources for the table: NZISM §1.1.2 and §1.2
(<https://nzism.gcsb.govt.nz/ism-document>); NCSC NZ, *NZISM v3.9 Release*
(<https://www.ncsc.govt.nz/news/nzism-v3-9-release/>), release dated 9 May
2025, and the manual's own footer, *"Last updated on November-2025. Version
3.9"*; PSR, *INFOSEC: Information Security, Protective Security Requirements
Policy Framework*, change log and paragraphs 2–3
(<https://www.protectivesecurity.govt.nz/assets/psr/INFOSEC-policy.pdf>); NCSC
NZ, *Minimum Cyber Security Standards*, introduction
(<https://www.ncsc.govt.nz/protect-your-organisation/minimum-cyber-security-standards/>);
NIST publication pages for each document at <https://csrc.nist.gov/pubs/>;
NSA, *Announcing the Commercial National Security Algorithm Suite 2.0*
(cybersecurity advisory PP-22-1338, Ver. 1.0), linked from NSA's press release
of the same name; ASD, *Information Security Manual: Guidelines for
cryptography*, published on the Australian Cyber Security Centre website.

**Versions of the NZISM.** Version 3.9 was released on 9 May 2025, and the
manual's footer reads *"Last updated on November-2025. Version 3.9"*. The two
dates describe one version: the first is the release, the second the site's
last-updated stamp, which is also why the publisher's XML export of v3.9 is
titled *November 2025*. Say which of the two a date refers to. NCSC NZ's
release notes record that v3.9 changed Chapters 7 and 16, §11.8 and §18.2, and
that the last substantive change to Chapter 17 was v3.7 (28 February 2024),
which revised §17.9 *Key Management*. The manual is one long page with an
anchor per chapter and section: Chapter 17 is `#Chapter-15745` and §17.2 is
`#Section-15853` at <https://nzism.gcsb.govt.nz/ism-document>.

### What "binds" means for the New Zealand standards

The NZISM states its own legal force plainly. Its §1.2.6 says the overarching
requirement to protect information is mandatory for departments and agencies,
but *"compliance with the NZISM is not required as a matter of law. The
controls in the NZISM could be made binding on departments and agencies,
either by legislation, or Cabinet direction."* The PSR supplies that direction
for mandated agencies (NZISM §1.2.7 names Cabinet Directive CAB MIN (14)
39/38), and the GCISO-mandated agencies are those the PSR lists as mandated
(NZISM §1.2.9).

That gives two cases, and takestock grades the same way in both:

- an organisation the PSR **mandates**, for which the NZISM is binding by
  Cabinet direction; and
- an organisation that **adopts** the NZISM voluntarily, or is **required by a
  contract** to meet it, for which it is not imposed by law.

A report should say which case applies, and not call the standard "mandatory"
without saying why.

The PSR draws the same line in its own words: it is *"primarily intended for
use by organisations that implement the Protective Security Requirements
(PSR)"*, both those *"mandated to implement the PSR"* and those that do so *"on
a voluntary basis"*, and *"non-mandated organisations in the public and
private sectors are encouraged to adopt the PSR"* (INFOSEC v2.0, paragraphs
2–3).

## How compliance levels are read

**NZISM.** Controls use RFC 2119 language (§1.1.40). A MUST or MUST NOT
control is a *baseline* control: its use is *"essential in order to
effectively manage the identified risk, unless the control is demonstrably not
relevant to the respective system"* (§1.1.45), and MUST controls *"take
precedence over SHOULD and SHOULD NOT controls"* (§1.1.46). A SHOULD control is
*"good and recommended practice"* that may be left out for a valid reason,
such as a control of equal strength being used instead (§1.1.47). Each control
also carries a classification scope, for example *All Classifications* or
*Confidential* and above; takestock records both the level and the scope.

**PSR.** The INFOSEC framework adds a third level. MUST is mandatory for all
levels of risk; SHOULD is *"recommended for organisations with moderate and
above risks"*; and COULD is *"recommended for organisations with high and
above risks"* (INFOSEC v2.0, paragraphs 11–15). The NZISM has no COULD.
An organisation *"must implement all mandatory measures unless it can
demonstrate that a given measure is not relevant in its context"*, and *"If a
mandatory measure cannot be directly implemented, suitable compensating
measures MUST be in place to manage identified risks"* (paragraphs 12–13).

**PSR system assurance.** INFOSEC 3.1, *"Ensure appropriate system assurance
for ICT systems"*, says an organisation *"MUST conduct the appropriate system
assurance activities required for the type of security measures being
implemented as stated in the NZISM"* (paragraph 184). Agencies *"MUST either:
a. adopt the NZISM continuous monitoring model; and/or b. follow the
certification and accreditation process defined in the NZISM"* for all ICT
systems (paragraph 185), and organisations *"MUST plan for the certification
and accreditation of physical buildings, security and equipment alongside ICT
system assurance"* (paragraph 186). NZISM v3.9, the version takestock grades
against, sets out certification and accreditation in Chapter 4 and describes
no continuous monitoring model. See [`OBLIGATIONS.md`](OBLIGATIONS.md) for
what this means for a finding.

**Deferring a MUST.** The NZISM's route for not meeting a baseline control is
a **dispensation**, not silence:

| Control | Level | Requirement |
|---|---|---|
| `1.1.64.C.01` | MUST | A dispensation for any baseline control is granted by the system's Accreditation Authority |
| `1.1.65.C.01` | MUST | The system owner completes a risk assessment recording the reason, the effect on other systems, the alternative mitigations and their strength, the residual risk, and a review date |
| `1.1.68.C.01` | SHOULD | Decisions to be non-compliant are reviewed at least annually |
| `1.1.69.C.01` | MUST | A record of the risk assessment and decision is kept |

The manual also says that accepting risk *"without due consideration is NOT
adequate or acceptable"* (§1.1.51). It expects that agencies *"may not be able
to immediately implement all controls"*, and that good risk management will
*"prepare a timeline and process by which the agency can implement all
appropriate controls"*, adding that *"Simply acknowledging risks and not
providing the means to implement controls does not represent effective risk
management"* (§1.1.52 to §1.1.53). A phased plan is therefore what the manual
asks for, provided each phase has a date and a means. takestock reports an unmet MUST
as unmet even where the organisation has decided to wait, and leaves room
beside it for the dispensation that authorises the wait. For an organisation
that implements the PSR, paragraph 13 of INFOSEC (quoted above) adds that
compensating measures must be in place while the measure is unmet.

## Precedence: which standard decides a grade

takestock applies the standards in this order. The order is a design choice
for New Zealand users, stated here so that it can be reviewed.

1. **New Zealand first.** Where the NZISM sets a requirement for a primitive,
   that requirement grades it, at the level the NZISM states.
2. **NIST where New Zealand is silent.** The NZISM approves no post-quantum
   algorithm (§2.4.8, quoted below) and says GCSB will consider international
   standards for incorporation when they are published (§2.4.9). takestock
   therefore uses NIST's FIPS 203, 204 and 205 to decide what counts as
   post-quantum, and NIST SP 800-57 Part 1 for security strengths.
3. **Foreign dates are calibration, never obligation.** The transition years
   in NIST IR 8547 (a draft), CNSA 2.0 (US National Security Systems) and the
   ASD ISM (Australian government) bind none of their readers in New Zealand.
   takestock may show them to help plan, labelled with the population each
   applies to.
4. **The protocol's own RFC decides validity.** A record that fails its RFC's
   syntax is reported as invalid regardless of what any policy wants.
5. **Say which bar produced a verdict.** Where two standards disagree, a
   finding names the one it was graded against. A reader who cannot tell them
   apart will assume the strictest belongs to the standard named, which
   overstates the obligation.

The Secure Government Email framework is graded as its own requirement set and
does not feed into the cryptographic grades: it answers whether a domain's
mail configuration conforms to a named framework, not whether a primitive is
strong enough.

## What NZISM Chapter 17 requires of classical cryptography

All from NZISM v3.9, §17.2 *Approved Cryptographic Algorithms*, unless stated.
Every control below applies at All Classifications.

| Control | Level | Requirement |
|---|---|---|
| `17.2.17.C.01` | MUST | Only approved algorithms can be used in an unevaluated product that implements both approved and non-approved ones |
| `17.2.18.C.01` | SHOULD | Use ECDH and ECDSA for all new systems, upgrades and major modifications |
| `17.2.19.C.01` | MUST | Diffie-Hellman (DH) modulus of at least 3072 bits |
| `17.2.20.C.01`, `.C.02` | MUST | A device that cannot reach the required key length is reconfigured to the longest feasible length, and scheduled for replacement, *"as a matter of urgency"* |
| `17.2.22.C.01` | MUST | ECDH: *"MUST implement the curve P-384"* |
| `17.2.23.C.01` | MUST | ECDSA: *"MUST implement the curve P-384"* |
| `17.2.24.C.01` | MUST | RSA for signatures and session-key transport: modulus of at least 3072 bits |
| `17.2.24.C.03` | SHOULD | The same, at least 4096 bits |
| `17.2.25.C.01` | MUST | RSA keys *"within internet X.509 Public Key Infrastructure certificates"*: at least 2048 bits |
| `17.2.26.C.01` | MUST | SHA-2 for new systems; SHA-1 only for legacy systems |
| `17.2.26.C.02`, `.C.03` | MUST | At least SHA-384 for integrity protection of RESTRICTED/SENSITIVE information and above; at least SHA-256 otherwise |
| `17.2.28.C.01` | SHOULD NOT | Electronic Code Book (ECB) mode for symmetric encryption |

Context paragraph §17.2.12 adds that SHA-1, 3DES and DSA *"MUST NOT be used for
new implementations"* and are approved only for processing already-protected
information.

Two of these controls need care when a key size sits between them:

- **Diffie-Hellman.** `17.2.19.C.01` sets 3072 bits as a MUST. The only other
  control in the manual that mentions DH is `17.8.15.C.01`, a SHOULD to *"use
  the largest modulus size available"*, so nothing offers a lower floor and a
  2048-bit group fails `17.2.19.C.01` plainly.
- **RSA-2048.** `17.2.24.C.01` asks for at least 3072 bits for signatures and
  session-key transport; `17.2.25.C.01` asks for at least 2048 bits for RSA
  keys *"within internet X.509 Public Key Infrastructure certificates"*. A key
  read from a public certificate is inside the second control's scope. Whether
  that more specific control displaces the general one, for a key that also
  signs a TLS handshake, the text does not say. A report should cite both and
  state which reading it applied.

Key management in the same chapter sets no numbers. `17.1.58.C.01` (SHOULD)
asks agencies to establish cryptoperiods for all keys, and `17.1.58.C.02`
(SHOULD) to derive them from a risk assessment; the manual states no rotation
period. `17.9.33.C.02` (SHOULD) asks for audits of cryptographic system
material on handover, on a change of personnel and at least annually: an audit
cadence, not a key lifetime.

Hardware security modules (§17.10): `17.10.12.C.03` (SHOULD, All
Classifications) asks agencies to consider an HSM when assessing risk or
designing network and security architectures, and `17.10.12.C.01` says the
same as a MUST at CONFIDENTIAL, SECRET and TOP SECRET. No control in Chapter
17 requires a FIPS 140 validation level. FIPS 140 appears only in §17.1's
explanatory text, as the US validation programme on whose results GCSB may, at
its discretion, reduce the scope of a cryptographic evaluation. A claim that
the NZISM requires a particular FIPS 140 level, or a particular rotation
period, has no control behind it.

### Post-quantum preparation (NZISM §2.4)

The NZISM's post-quantum material sits in Chapter 2, not Chapter 17.

- §2.4.8: *"Currently there are no post-quantum cryptographic systems approved
  for use in the NZISM, however there are actions that agencies can undertake
  to prepare for the time when such systems are approved."*
- §2.4.10: GCSB *"may deprecate or withdraw support for existing classical
  cryptographic standards"*, and agencies *"should therefore be prepared to
  transition away from these algorithms possibly in the next 2-3 years"*. This
  is hedged twice (*may*, *possibly*) and is relative to an undated paragraph.
  It is not a deadline.
- §2.4.11: until quantum-resistant algorithms are standardised, *"maintain or
  strengthen"* the existing position using Chapter 17.
- §2.4.13.C.01 to .C.07: seven controls, every one **SHOULD** at All
  Classifications. They ask for awareness of developments, an inventory of
  long-lived sensitive datasets, **an inventory of systems using cryptographic
  technologies** (`2.4.13.C.03`), marking public-key systems as quantum
  vulnerable in risk assessments, a priority order, named prioritisation
  factors (`2.4.13.C.06`: high-value asset, sensitivity of what it protects,
  dependants, how long the data must stay protected), and a transition plan.

`2.4.13.C.03` describes the inventory takestock produces. Cite it at the level
it states: SHOULD.

## Endpoint and device configuration

New Zealand publishes requirements for configuring workstations, servers and
mobile devices at three levels. It does not publish a per-setting hardening
guide for any operating system.

| Level | Instrument | Written for | What it gives |
|---|---|---|---|
| Control text | NZISM v3.9 Chapter 14 (standard operating environments; application allow listing), Chapter 20 (virtualisation) and Chapter 22 (distributed working: agency-owned mobile devices, working from home, bring your own device) | As for the NZISM as a whole | 123 numbered controls: §14.1 has 13, §14.2 13, §20.2.14 7, §22.1 29, §22.3 2 and §22.4 59. Each carries a compliance level and a classification scope |
| Maturity criteria | NCSC NZ *Minimum Cyber Security Standards* 2025: standard 4 *Secure Configuration of Software*, 5 *Patching* and 8 *Least Privilege* | *"intended for GCISO-mandated agencies who will be required to implement them, however non-mandated agencies wishing to adopt the Standards are also welcome to do so"* | Four maturity levels per standard, written as testable statements and mapped to NZISM controls |
| Implementation guidance | NCSC NZ *Protect your organisation* pages on application control, mobile device management, bring your own device, patching, least privilege, asset lifecycle and edge devices | Guidance | Method and success criteria |

The controls to cite, at the level each states (CID is the control's numeric
identifier in the publisher's export):

| Control | CID | Level | Scope | What it requires |
|---|---:|---|---|---|
| `14.1.9.C.01` | 1158 | MUST | All Classifications, *"for all servers and workstations"* | A technical specification agreed for each platform; a standard configuration per operating system type and version; users cannot install or disable software without approval; patching kept up to date |
| `14.1.8.C.01` | 1149 | SHOULD | All Classifications | The eight things a hardened standard operating environment covers, from removing unneeded components to protecting logs |
| `14.2.4.C.01` | 1234 | SHOULD | All Classifications | Application allow listing as part of the standard operating environment for workstations, servers and other network devices |
| `14.2.5.C.01` | 1242 | MUST | All Classifications | A system user cannot disable the allow listing mechanism |
| `20.2.14.C.05` | 4895 | SHOULD | All Classifications, virtualisation hosts only | Harden host operating systems *"following an agency or other approved hardening guide"* |
| `22.1.10.C.01`, `.C.03` | 4471, 4473 | MUST, SHOULD | All Classifications | A mobile device usage policy; a mobile device management system |
| `22.1.17.C.02` | 4504 | SHOULD | All Classifications | Control mobile device configuration *"in the same manner as devices in the agency's office environment"* |
| `22.4.11.C.09`, `.C.12` | 4663, 4666 | MUST | All Classifications | For bring your own device: a list of permitted operating systems including version numbers; a device management system with nine named minimum capabilities, including a health check before connection |

Three readings go wrong in the direction that overstates the obligation:

- Implementing application allow listing at all (`14.2.4.C.01`) is a
  **SHOULD**. Only *"a user cannot disable it"* (`14.2.5.C.01`) is a MUST.
- `20.2.14.C.05` reaches **virtualisation hosts**, not endpoints in general.
- Bring your own device is **§22.4**. Some cross-references inside the manual,
  and NCSC NZ's guidance page on the subject, still print the older §21.4.

**Where CIS fits.** §20.2.11, the virtualisation references table, lists
*"Virtual Machine Security Guidelines"* published by the Center for Internet
Security and sourced to the CIS Benchmarks on that body's website, beside ACSC's
*Guidelines for System Hardening*, NIST SP 800-125, DISA STIGs and an ISACA
checklist. It is a references table, not a control, and it names no benchmark
version or profile level, so it does not make CIS a NZISM requirement. It does
place CIS inside the New Zealand manual's own reference set: a CIS profile
adopted as the specification that `14.1.9.C.01` asks for follows the manual's
signposting rather than substituting foreign guidance for a domestic silence.

**The maturity scale.** Minimum Cyber Security Standard 4 quotes `14.1.9.C.01`
in full, as a MUST, in its table of applicable NZISM controls. Its level CS-CMM
1 reads *"Baseline security configuration guides do not exist, and
best-practice adherence is ad-hoc"*; the minimum, CS-CMM 2, reads *"Baseline
security configuration guides are developed, incorporating vendor and
best-practice publications"*. So the state of an organisation's build
standards can be placed on a published New Zealand scale. Standard 8 is
written at the endpoint too: CS-CMM 2 *"Local admin rights on workstations are
limited where possible"*; CS-CMM 3 *"granted by exception only"*.

**Cite the manual, not the mapping tables.** Standard 5's table prints
`12.4.4.C.01` (CID 3448) beside the sentence *"Agencies SHOULD apply all
critical security patches…"*, which is the text and level of `12.4.4.C.04`
(CID 3451). The real `12.4.4.C.01` is a MUST at CONFIDENTIAL and above (see
*Severity labels and remediation clocks* below).

**The PSR delegates.** The PSR INFOSEC policy framework (v2.0) contains no
configuration content: the words *workstation*, *endpoint* and *harden* do not
occur in it. Its INFOSEC 2 requires security measures *"in line with"* the
NZISM, and the only device-level MUSTs are in INFOSEC 4.2 (paragraph 193):
protect ICT equipment, *"including personal devices"*, from malware, and apply
security patches and updates regularly.

**digital.govt.nz** has one relevant artefact, the *Guide to managing updates
on remote endpoints* (last updated 9 July 2020), which is specific to Windows
and Microsoft 365. Its site search found no workstation hardening or build
standard.

So the accurate statement is that New Zealand requires an approved baseline
configuration (`14.1.9.C.01`, `20.2.14.C.05`, Minimum Standard 4) and leaves
its content to the organisation, which may draw on vendor and CIS guidance.
"New Zealand publishes no endpoint guidance" is wrong; "New Zealand publishes no
per-setting hardening guide" is right.

**Reading these sites.** `nzism.gcsb.govt.nz`, `protectivesecurity.govt.nz`
and `digital.govt.nz` answer simple HTTP clients and headless browsers with a
short placeholder page and HTTP 200, so an empty fetch is a failed fetch, not
an empty document. A full browser reads them, after loading the site's home
page first. `ncsc.govt.nz` serves full pages to simple clients; its
`sitemap.xml` is the reliable index, because its on-site search is rendered in
the browser and shows no results to a fetcher.

## Where the standards disagree

### Between standards

| Question | NZISM v3.9 | NIST | CNSA 2.0 (US NSS) | ASD ISM (Australia) |
|---|---|---|---|---|
| Finite-field DH minimum | 3072 bits, MUST (`17.2.19.C.01`) | 2048 bits gives 112-bit strength (SP 800-57 Pt 1, Table 2), which SP 800-131A Rev. 2 rates acceptable | Replaced by post-quantum key establishment | Not approved beyond 2030 |
| Elliptic curves | *"MUST implement the curve P-384"* for ECDH and ECDSA | P-256 gives 128-bit strength (SP 800-57 Pt 1, Table 2) | Replaced by post-quantum algorithms | ECDH and ECDSA not approved beyond 2030 |
| RSA minimum | 3072 bits for signatures and key transport; 2048 in internet X.509 certificates | 2048 bits gives 112-bit strength; SP 800-131A Rev. 2 rates a modulus of 2048 bits or more acceptable | Replaced | Not approved beyond 2030 |
| AES key size | No control states one; the §17.2.13 summary table lists a 256-bit minimum as guidance (see *Inside the NZISM itself*) | AES-128, -192 and -256 all at or above 128-bit strength | AES-256 for all classification levels | AES-128, -192 or -256, preferably AES-256 (ISM-1769); AES-128 and AES-192 *"will not be approved beyond 2030"* |
| Approved post-quantum algorithms | None (§2.4.8) | ML-KEM, ML-DSA, SLH-DSA (FIPS 203, 204, 205) | CRYSTALS-Kyber and CRYSTALS-Dilithium at their highest (Level V) parameters, the algorithms later standardised as ML-KEM and ML-DSA | ML-KEM-768 or -1024 and ML-DSA-65 or -87, preferably the larger (ISM-1995, ISM-1991) |
| Dates for classical public-key cryptography | None | 112-bit strength *"Deprecated after 2030"*, everything *"Disallowed after 2035"* (IR 8547 ipd, Tables 2 and 4) | *"Exclusively use"* CNSA 2.0 by 2030 (software signing, networking equipment) or 2033 (web, cloud, operating systems, niche equipment) | DH, ECDH, ECDSA and RSA *"will not be approved beyond 2030"* |
| Dates for symmetric cryptography and hashing | None | Symmetric standards at the 112-bit level, such as three-key TDEA, *"will be disallowed in 2030"*; no date for AES at any key size (IR 8547 ipd §4.1.3) | AES-256, SHA-384 and SHA-512 from the outset | AES-128 and AES-192 (ISM-1769), and SHA-224 and SHA-256 (ISM-1766), *"will not be approved beyond 2030"*; new equipment to support AES-256, SHA-384 and SHA-512 *"by no later than 2030"* (ISM-1917) |

Three cautions travel with that table:

- **The NIST dates are from a draft.** IR 8547 is an initial public draft
  whose comment period closed on 10 January 2025. Its 2030 deprecation reaches
  the **112-bit** class only (RSA-2048, DH-2048, P-224). Curves and keys of 128
  bits and more, P-256 and Ed25519 included, have no 2030 row and are
  *"Disallowed after 2035"* (Tables 2 and 4). Applying a 2030 date to every
  classical signature misreads the draft.
- **The CNSA 2.0 years apply to US National Security Systems.** The advisory
  says *"Its direction applies to all NSS use of public cryptographic
  algorithms"*, and its timetable is one NSA *"anticipates"*. Its footnote 1
  defines *exclusively use*: hybrid solutions may still be allowed, but
  *"CNSA 2.0 algorithms will become mandatory to select at the given date"*.
- **"Implement" in the NZISM curve controls is open to two readings.** A
  system that *supports* P-384 alongside P-256 may meet `17.2.22.C.01` on one
  reading and fail it on the other, which requires P-384 to be *used*. A
  network probe sees the curve a server agreed to, and sometimes the full list
  it offered. takestock reports which of the two it observed, so the reader
  can apply either reading.

### Quantum attacks on symmetric primitives

Grover's algorithm searches an *n*-bit key in about 2^(n/2) steps. That is
often summarised as halving a cipher's strength, "AES-128 reduced to 64 bits",
and a reader told that will conclude AES-128 is broken. NIST does not draw
that conclusion. IR 8547 ipd §4.1.3:

> *"NIST's existing standards in symmetric cryptography — including hash
> functions, XOFs, block ciphers, KDFs, and DRBGs — are significantly less
> vulnerable to known quantum attacks than the public-key cryptography
> standards in SP 800-56A, SP 800-56B, and FIPS 186. In particular, all
> NIST-approved symmetric primitives that provide at least 128 bits of
> classical security are believed to meet the requirements of at least
> Category 1 security within the system of five security strength categories
> for evaluating parameter sets in the NIST PQC standardization process …
> NIST has a few symmetric cryptography standards at the 112-bit security
> level, which will be disallowed in 2030."*

The same document's Table 6 puts AES-128 in Category 1, AES-192 in Category 3
and AES-256 in Category 5. Category 1 is *defined* as key search on a block
cipher with a 128-bit key, so AES-128 is the yardstick the post-quantum
parameter sets are measured against, not a casualty of them; ML-KEM-512 sits
in the same category. AES-128 in use is therefore a question of how much
headroom to buy, and takestock records it as an informational reading
(`quantum-symmetric-margin:<bits>`), not as a weakness.

Other bodies set a higher bar by choice rather than by this reasoning: the
NZISM §17.2.13 summary table lists AES with a 256-bit minimum (see *Inside the
NZISM itself* below), CNSA 2.0 requires AES-256 for US National Security
Systems, and the ASD ISM withdraws approval of AES-128 and AES-192 after 2030
(table above).

### CNSA 2.0: the advisory and the FAQ

NSA has published CNSA 2.0 in two documents that are both current, and they
give different dates.

**The algorithms**, from the FAQ (Ver. 2.1, December 2024): AES-256 (FIPS
197); ML-KEM-1024 (FIPS 203); ML-DSA-87 (FIPS 204); SHA-384 or SHA-512 (FIPS
180-4); LMS or XMSS (SP 800-208) for software and firmware signing; and
SHA3-384 or SHA3-512 (FIPS 202) for internal hardware functions only, such as
integrity checks at start-up, not for general use.

**The per-category timetable** is in the 2022 advisory (Ver. 1.0, *Other
requirements for NSS*, page 6), which says *"NSA anticipates the following
timetable"*:

| Category | Support and prefer CNSA 2.0 by | Exclusively use CNSA 2.0 by |
|---|---|---|
| Software and firmware signing (begin transitioning immediately) | 2025 | 2030 |
| Web browsers and servers, cloud services | 2025 | 2033 |
| Traditional networking equipment (for example VPNs, routers) | 2026 | 2030 |
| Operating systems | 2027 | 2033 |
| Niche equipment (for example constrained devices, large PKI systems) | 2030 | 2033 |
| Custom applications and legacy equipment | — | update or replace by 2033 |

Its footnote 1 defines *exclusively use*: hybrid solutions may still be
allowed or required, but *"CNSA 2.0 algorithms will become mandatory to select
at the given date, and selecting CNSA 1.0 algorithms alone will no longer be
approved"*. It is a must-offer date, not a must-be-the-only-thing-on-the-wire
date.

**The FAQ carries no per-category timetable.** It reports the 2024 update to
CNSS Policy 15, the instrument NSA names as setting the dates for National
Security Systems: *"by January 1, 2027, all new acquisitions for NSS will be
required to be CNSA 2.0 compliant … by December 31, 2030, all equipment and
services that cannot support CNSA 2.0 must be phased out … and by December 31,
2031, CNSA 2.0 algorithms are mandated for use."* It also says no transition
is enforced before 31 December 2025 for products already validated against a
National Information Assurance Partnership or Commercial Solutions for
Classified profile. The policy itself, CNSSP 15 (dated 4 March 2025), is
published by the Committee on National Security Systems.

**Reading them together.** NSA has not withdrawn the advisory: it re-hosted
the file in May 2025 and its 2022 press release still links to it. For a US
National Security System the FAQ's 2027, 2030 and 2031 are the operative
track. For anyone else, neither track binds, and the advisory's per-category
split is the more useful calibration because it distinguishes kinds of
equipment. Cite the advisory's years as a timetable NSA anticipates for US
National Security Systems, name the FAQ's enforcement track beside them, and
call neither superseded nor binding. Anything that cites the FAQ for a 2033
date is citing a document that does not contain it.

### Other national post-quantum timetables

| Publisher | Plan or discover by | Begin, or migrate priority systems by | Complete by |
|---|---|---|---|
| UK National Cyber Security Centre (20 March 2025) | 2028: discovery done and an initial migration plan built | 2031 | 2035 |
| Australian Signals Directorate (updated 22 September 2025) | End of 2026: a refined transition plan | End of 2028: transition begun, starting with critical systems and data | End of 2030 |
| EU NIS Cooperation Group (23 June 2025) | 31 December 2026 | High-risk use cases by 31 December 2030 | 31 December 2035 |
| New Zealand | No dated milestone (see [`OBLIGATIONS.md`](OBLIGATIONS.md)) | — | — |

ASD's date is a flat cessation, not a strength-tiered deprecation: *"ASD
recommends ceasing the use of traditional asymmetric cryptography by the end
of 2030. This includes … RSA, Diffie-Hellman (DH), Elliptic Curve
Diffie-Hellman (ECDH) and Elliptic Curve Digital Signature Algorithm
(ECDSA)."* Unlike NIST, it makes no exception for keys of 128 bits and more.
ASD also describes the inventory this tool produces: *"A mature CBOM details
the cryptographic implementations in the context they are used, and captures
information on cryptographic products, software, libraries, algorithms,
protocols, parameters, versions and configurations."*

There is no joint Five Eyes post-quantum standard. Each country publishes its
own (the NZISM, the ASD ISM, the UK NCSC's timelines, NIST and CNSA 2.0 for
the United States, and Canada's ITSM.40.001), and "Five Eyes alignment" means
informal convergence on NIST's algorithms. New Zealand's NCSC (part of GCSB)
and the UK's NCSC (part of GCHQ) are unrelated organisations that share an
acronym, and searches for "NCSC guidance" routinely return the UK body's
material.

### A DKIM key sits under three different bars

A DKIM signing key is an RSA key used for digital signatures.

- The SGE DKIM Deployment Guide *"strongly recommend[s]"* 2048-bit keys and
  says *"You can revert to 1024-bit keys on legacy systems if needed"* (§4.2
  and Appendix 2). A 1024-bit DKIM key does **not** breach SGE.
- RFC 8301 §3.2: *"Signers MUST use RSA keys of at least 1024 bits for all
  keys. Signers SHOULD use RSA keys of at least 2048 bits."*
- On a plain reading, NZISM `17.2.24.C.01` (RSA for digital signatures, at
  least 3072 bits, MUST) reaches a DKIM key too. Neither the NZISM nor the SGE
  guides say so in terms, so takestock labels this as a reading.

A report should give the bar for each verdict, because the same key passes
one, falls short of a recommendation in another, and fails a MUST in the
third.

### Email transport: the NZISM and the SGE framework pull opposite ways

- NZISM `15.2.47.C.01` (MUST) requires *opportunistic* TLS, as defined in RFC
  3207, on servers exchanging mail over public infrastructure, and context
  paragraph §15.2.34 advises: *"You should support the case where TLS is not
  used at all, if you want to be confident you can receive emails from any
  entity."*
- The SGE framework says *"TLS1.1, 1.0, SSL, no-TLS, or sending unencrypted
  must not be used"*. Its TLS Deployment Guide then narrows the enforced
  version to mail between government organisations. See the companion
  document.

### DMARC `p=reject`: the New Zealand bar and the DMARC standard pull opposite ways

- NZISM `15.2.36.C.02` (MUST) asks for a DMARC policy of `p=reject`, and the
  SGE DMARC Deployment Guide says *"All domains must have a p=reject DMARC
  policy."*
- RFC 9989 §7.4, the DMARC standard itself, says *"domains that host users
  who might post messages to mailing lists SHOULD NOT publish Domain Owner
  Assessment Policies of "p=reject""*, and that a domain wishing to publish
  it *"SHOULD"* first publish `p=none` for at least a month and then
  `p=quarantine` for as long again. The same section says a domain that
  publishes `p=reject` *"MUST NOT rely solely on SPF"* and *"MUST apply valid
  DKIM signatures"*.

takestock grades the New Zealand requirement as written and cites the RFC
beside it. An organisation not bound by the NZISM control weighs the two.

An organisation that the NZISM control or the Secure Government Email
framework binds meets `p=reject`, because that is the requirement it is
assessed against, and records openly that the DMARC standard advises against
it for domains whose users post to mailing lists. It can reduce the cost that
RFC 9989 §7.4 describes:

- **DKIM-sign all mail.** §7.4 requires this of any domain that publishes
  `p=reject`, and notes that when mail is relayed by forwarders or role-based
  aliases, where SPF fails, *"DKIM signatures will generally remain valid"*.
  Alignment therefore survives forwarding that leaves the signed message
  intact. A mailing list that alters the signed parts of a message, such as
  the subject or body, invalidates the signature, so this does not solve the
  mailing-list case. The SGE framework already requires every outbound
  message to be DKIM signed.
- **Tell users, or set a rule.** §7.4 says domains that publish `p=reject`
  *"SHOULD implement policies that their users not post to Internet mailing
  lists and/or inform their users that their participation in mailing lists
  may be hindered"*. It also records that mailing-list software has adopted
  workarounds that rewrite the From: line of list mail so that it stays
  aligned.
- **A separate sub-domain for staff who post to external lists** is takestock's
  suggestion, not the RFC's. Given its own, lower policy, it would keep list
  posts from being rejected, but that is a departure, not an exemption: the
  NZISM control covers all email *"originating from or received by their
  domain(s)"* and the SGE guide says *"All domains"*. takestock grades a
  sub-domain it is given like any other, so the lower policy shows as short of
  `p=reject`, and under the NZISM it needs a dispensation (see *Deferring a
  MUST* above).

### Inbound DMARC handling: the SGE framework and the DMARC standard pull opposite ways

- The SGE framework (§8) says *"Inbound emails must be checked for DMARC
  compliance and acted on based on the sending domain's DMARC policy."* Under
  *Inbound messages and DMARC* in the same section it adds *"Where the sending
  domain policy rejects the email, the email should be rejected and
  dropped."* The SGE DMARC Deployment Guide (§3) puts the requirement as
  *"Inbound emails must be scanned by DMARC and acted on."*
- RFC 9989 §7.4 says *"Mail Receivers MUST NOT reject incoming messages solely
  on the basis of a "p=reject" policy by the sending domain"*. Receivers
  *"must use the DMARC policy as part of their disposition decision, along
  with other knowledge and analysis"*, and *"In the absence of other knowledge
  and analysis, Mail Receivers MUST treat such failing mail as if the policy
  were "p=quarantine" rather than "p=reject"."*

An organisation that the SGE framework binds meets the framework's
requirement, because that is the one it is assessed against, and states the
tension openly. Both texts can be served together. §7.4 forbids rejecting
*solely* on the sender's policy, so a rejection that also rests on *"other
knowledge and analysis"*, which the RFC says *"might refer to observed sending
patterns for properly authenticated mail using the sending domain, content
filtering, etc."*, remains open to a receiver. Mail that is not rejected
still stays out of users' mailboxes: the framework says mail failing DMARC
*"should never make it to the users' mailboxes"*, and sends quarantined mail
*"to the email platform quarantine for release only by administrators"*
(§8). The framework does not say whether quarantining mail from a
`p=reject` domain counts as acting on that policy. It does depart from the
framework's SHOULD to reject and drop that mail.

### Inside the NZISM itself

- **AES key size.** The §17.2.13 summary table lists AES with a minimum
  *"256-bit key"*. No control in the chapter states an AES key length: the
  approved list in §17.2.11 says only *"AES"*, and the only AES control is
  `17.2.28.C.01` on ECB mode. (`17.2.20.C.01` and `.C.02` deal with devices
  that cannot reach *"required key lengths"*, without saying where those
  lengths are set.) takestock treats the table as guidance, not a control.
  Every graded row that names a 128-bit or 192-bit AES key cites §17.2.13 in a
  note saying the key is shorter than the table's minimum: the AES-128 GCM and
  CCM rows and the AES-192 CBC row of the symmetric-cipher table (which grade
  TLS suites and the same ciphers reported by other collectors), the IKE
  AES-128 and AES-192 transforms, and the SSH `aes128-*` and `aes192-*`
  ciphers. None of these citations is marked as breaching a control, so none
  is counted among the MUST-level breaches that need a dispensation, and none
  changes a grade. A TLS CBC suite is graded on one row shared by every AES key
  size, so it carries no such note. The same table lists ECDSA against
  *"FIPS 186-3"*; the
  current version is FIPS 186-5 (NIST, 3 February 2023), which superseded
  FIPS 186-4.
- **MTA-STS described as key pinning.** §15.2.24 says that with MTA-STS *"you
  can specify that mail traffic sent to a domain is encrypted with a specific
  public encryption key"*. MTA-STS does not pin a key. It requires the
  receiving server to present a certificate that validates against trusted
  certificate authorities and matches a listed host (RFC 8461 §3.3 and §4).
- **A malformed example record.** §15.2.18 prints the DMARC record
  `V=DMARC1;p=reject;sp=reject;adkim-s;aspf=s;…`. `adkim-s` has a hyphen where
  the DMARC standard, RFC 9989 §4.7, defines the tag as `adkim=s`. Under RFC
  9989 §4.8, *"Syntax errors in the remainder of the record MUST be discarded
  in favor of default values (if any) or ignored outright"*, and §4.7 makes
  relaxed alignment the default, so copying the example leaves DKIM alignment
  relaxed. (RFC 9989 obsoletes RFC 7489, whose §6.3 said the same with
  SHOULD.) The SGE framework repeats the same example
  (see the companion document).

## Severity labels and remediation clocks

New Zealand's government guidance prescribes **no** severity label set for
security findings and no table mapping severity to a remediation deadline.

- The NZISM contains no CVSS reference. Its vulnerability section asks
  agencies to *"analyse and treat all vulnerabilities"* (`6.2.6.C.01`,
  SHOULD), without tiers.
- The one remediation clock in the NZISM is for patches: `12.4.4.C.01` (MUST,
  at CONFIDENTIAL, SECRET and TOP SECRET) requires critical security patches
  *"within two (2) days"*, and `12.4.4.C.04` is the same at All
  Classifications as a SHOULD (*"preferably within two (2) days"*). The
  manual does not define *critical*; the rating is the vendor's.
- The NCSC NZ *Minimum Cyber Security Standards* (2025) split the patch clock
  by exposure, under *Suggested actions*: critical patches *"within two days …
  on external-facing systems, or where working exploits exist, and within two
  weeks on internal systems"*. The requirement at the minimum maturity level,
  CS-CMM 2, is only that *"patch severity prioritisation criteria are in
  place"*: an organisation must have criteria, and the standard does not say
  what they are.
- The government risk guidance tells organisations to approve their own scales
  and offers examples; see [`RISK-SCALE.md`](RISK-SCALE.md).

So a severity ladder an organisation builds for its findings is not a
departure from a New Zealand standard. It is what the guidance asks it to do,
and its reasoning has to carry its own weight. For prioritising
quantum-vulnerable systems, `2.4.13.C.06` lists the factors (a high-value
asset, the sensitivity of what it protects, what depends on it, how long the
data must stay protected) and leaves algorithm strength out.

Some words already carry a fixed meaning in New Zealand government, and a
severity scale should avoid them:

| Word or set | Existing meaning |
|---|---|
| UNCLASSIFIED, IN-CONFIDENCE, SENSITIVE, RESTRICTED, CONFIDENTIAL, SECRET, TOP SECRET | Security classifications and protective markings, used throughout the NZISM (for example §1.1.4 and each control's classification scope) and the PSR |
| Critical, Serious, Low (as a set) | The incident categories NZISM §7.2.14 suggests |
| C1 to C6 | NCSC NZ's cyber incident categories |

*Critical* on its own is safe: both the NZISM and NCSC NZ use it for patch
severity. It is the set, and the classification words, that collide.

## Severity, risk and deadlines in other schemes

How other bodies tie a finding to a deadline, for anyone designing or
defending a remediation ladder.

**Severity words replaced by deadlines.** CISA Binding Operational Directive
26-04 (10 June 2026), binding on US federal civilian agencies, revoked BOD
19-02 and BOD 22-01 and removed severity labels from federal vulnerability
remediation: *"CVSS scores such as 'critical' or 'high' do not prescribe
specific actions. To eliminate ambiguity, CISA replaces these labels with
explicit timelines for required remediation under defined conditions."* Its
Table 1 maps four factual decision points (publicly exposed; listed in the
Known Exploited Vulnerabilities catalogue; automatable; technical impact) to
one of four outcomes: 3 days, 14 days, 60 days, or fix on system upgrade.

**A severity score is not a risk rating.** The CVSS v4.0 User Guide §2.2 is
headed *"CVSS Base Score (CVSS-B) Measures Severity, not Risk"* and says
*"CVSS Base (CVSS-B) scores are designed to measure the severity of a
vulnerability and should not be used alone to assess risk."* FIRST's consumer
implementation guidance supplies no mapping from score to deadline, and NIST
SP 800-40 Rev. 4 prescribes none. The common shape is that severity is
standardised and the deadline is the organisation's to own.

**Vocabularies that are not interchangeable:**

| Source | Labels | What it produces |
|---|---|---|
| CVSS v4.0 | None, Low, Medium, High, Critical (0.1–3.9, 4.0–6.9, 7.0–8.9, 9.0–10.0) | A severity score |
| NIST SP 800-30 Rev. 1 | Very High, High, **Moderate**, Low, Very Low | A risk rating |
| SSVC, CERT/CC deployer tree | Defer, Scheduled, Out-of-Cycle, Immediate | An action |
| SSVC, CISA's tree | Track, Track\*, Attend, Act | An action |
| CISA BOD 26-04 | None | A dated deadline |

NIST says *Moderate*, never *Medium*, and has no *Critical* tier, so "NIST
severity" and "CVSS severity" are different vocabularies. SSVC's outcomes
differ by stakeholder tree, and are often quoted as if they were one set.

**Deadlines that are tied to a severity.** The ASD *Essential Eight* asks for
patches within 48 hours where a vulnerability is *"assessed as critical by
vendors or when working exploits exist"* on internet-facing systems, two weeks
otherwise for internet-facing systems, and one month for workstations. PCI DSS
v4.0.1 §6.3.3 asks for critical patches within one month; v4.0.1 removed
"high" from that clause.

**Every scheme has a do-nothing outcome.** SSVC has *Defer* (*"Do not act at
present"*), BOD 26-04 has *fix on system upgrade*, and PCI DSS v4.0.1 leaves
lower-ranked vulnerabilities to the entity's own targeted risk analysis. A
ladder without such a rung has to give every asset a date, which manufactures
urgency for a long tail of benign findings and weakens the rungs above it.

**One scheme fails on strength alone.** The PCI Approved Scanning Vendor
programme guide fails a component *"if it supports SSL or early versions of
TLS"*, and fails any finding scored CVSS 4.0 or higher, whether or not it is
exploitable. Where part of an estate is in PCI scope, weak cryptography left
off the top of an exploitability-based ladder can still fail an external scan.
That is a compliance gate, not a severity rating.

**A minimum CBOM is due.** US Executive Order 14412 §5(d) (22 June 2026)
directs CISA to publish, within 270 days, *"the minimum elements for a
cryptographic bill of materials … to enable the automated assessment of the
cryptographic assets utilized by a hardware or software element"*.

## Drafts and revisions to watch

Cite a document's status beside its number: *IR 8547 ipd* (initial public
draft), never a bare *IR 8547*. A draft quoted as final reads exactly like a
verified fact once it has been copied into a report. The status and reading of
every document the grading policy cites is recorded in
`src/takestock/data/baseline.yaml`, under `authorities:`. These are the ones
in motion:

| Document | State | Why it matters |
|---|---|---|
| NIST IR 8547 | Initial public draft (12 November 2024); comments closed 10 January 2025; no final published | Its transition years are an expected approach, not a final standard |
| NIST SP 800-131A | Rev. 2 (2019) is final; Rev. 3 is an initial public draft (21 October 2024), comments closed December 2024 | Rev. 3 would raise the minimum classical security strength from 112 to 128 bits at the end of 2030 and retire SHA-1, SHA-224 and DSA |
| NIST SP 800-52 | Rev. 2 (2019) is final; NIST consulted until 10 July 2026 on revising it | The consultation includes whether to keep recommending support for TLS 1.2 |
| NIST SP 800-56A | Rev. 3 (2018) is final; NIST's planning note of 6 January 2026 says it has decided to update it | Pair-wise key establishment (DH, ECDH) |
| NIST SP 800-57 Part 1 | Rev. 5 (May 2020) is final; a Rev. 6 draft was open for comment until 5 February 2026 | Table 2, which maps key sizes to security strengths |
| NIST SP 800-107 Rev. 1 | Final; NIST has announced it will withdraw it once replacement implementation guidance is published | The authority for truncated HMAC output. Withdrawal is announced and conditional, which is not the same as withdrawn |
| FIPS 180-4, FIPS 202, SP 800-38A, 38C, 38D and 38E | Final; NIST has decided to revise each | No successor published |

## Sources read for this document

| Publisher | Document | Where |
|---|---|---|
| GCSB | NZISM v3.9, §1.1, §1.2, §2.4, Chapter 4, §6.2, §7.2, §12.4, Chapter 14, §15.2, §17.1, §17.2, §17.8, §17.9, §17.10, Chapter 20, Chapter 22 | <https://nzism.gcsb.govt.nz/ism-document> (the site also offers the full manual as XML and CSV) |
| NCSC NZ | *NZISM v3.9 Release*; NZISM release notes | <https://www.ncsc.govt.nz/news/nzism-v3-9-release/>, <https://www.ncsc.govt.nz/news/nzism/> |
| NCSC NZ | *Minimum Cyber Security Standards*, standards 4, 5 and 8; *Protect your organisation* guidance pages | <https://www.ncsc.govt.nz/protect-your-organisation/minimum-cyber-security-standards/>, <https://www.ncsc.govt.nz/sitemap.xml> |
| PSR | *INFOSEC* policy framework v2.0 | <https://www.protectivesecurity.govt.nz/assets/psr/INFOSEC-policy.pdf> |
| Government Chief Digital Officer | *Guide to managing updates on remote endpoints* | <https://www.digital.govt.nz/> |
| NIST | FIPS 203, FIPS 204, FIPS 205, FIPS 186-5 | <https://csrc.nist.gov/pubs/fips/203/final> (and `/204/final`, `/205/final`, `/186-5/final`) |
| NIST | SP 800-57 Part 1 Rev. 5, Table 2 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf> |
| NIST | SP 800-131A Rev. 2; SP 800-52 Rev. 2 | <https://csrc.nist.gov/pubs/sp/800/131/a/r2/final>, <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf>, <https://csrc.nist.gov/pubs/sp/800/52/r2/final> |
| NIST | IR 8547 ipd, Tables 2, 4 and 6, §4.1.3 | <https://csrc.nist.gov/pubs/ir/8547/ipd>, <https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf> |
| NIST | SP 800-30 Rev. 1; SP 800-40 Rev. 4; publication pages of the documents under *Drafts and revisions to watch* | <https://csrc.nist.gov/pubs/> |
| NSA | *Announcing the Commercial National Security Algorithm Suite 2.0*, Ver. 1.0, September 2022 | NSA press release and advisory PP-22-1338 |
| NSA | *CNSA 2.0 and Quantum Computing FAQ*, Ver. 2.1, December 2024 | <https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003071836/> |
| ASD | ISM, *Guidelines for cryptography*, September 2026 edition; post-quantum planning guidance (updated 22 September 2025); *Essential Eight* | Australian Cyber Security Centre website |
| UK National Cyber Security Centre | Post-quantum migration timelines (20 March 2025) | The UK NCSC website |
| EU NIS Cooperation Group | Coordinated implementation roadmap for the transition to post-quantum cryptography (23 June 2025) | The European Commission's website |
| CISA | Binding Operational Directive 26-04; the SSVC decision tree | The CISA website |
| FIRST | CVSS v4.0 User Guide, §2.2 | The FIRST website |
| CERT/CC | SSVC deployer decision tree | The CERT/CC SSVC documentation |
| PCI Security Standards Council | PCI DSS v4.0.1; Approved Scanning Vendor Program Guide | The PCI SSC document library |
| US Government | Executive Order 14412 §5(d) (22 June 2026) | The Federal Register |
| IETF | RFC 2119, RFC 8174, RFC 3207, RFC 7489, RFC 8301, RFC 8461, RFC 9989 | <https://www.rfc-editor.org/rfc/> |
