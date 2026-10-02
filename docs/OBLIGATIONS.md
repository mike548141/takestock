# Obligations: New Zealand public-sector levers on cryptography and data

[`STANDARDS.md`](STANDARDS.md) maps the *technical* standards takestock grades
against. This document maps the *legal and policy* instruments above them that
give a cryptographic finding its weight in New Zealand's public sector: which
ones are law, which are government policy, which are guidance, and what each
actually says. It ends with New Zealand's post-quantum position, stated as
precisely as the sources allow.

It is written for anyone preparing a board paper, an audit response or a
business case from takestock's findings. **It is not legal advice.** Whether a
particular instrument applies to a particular organisation depends on that
organisation's legal form and contracts, and a lawyer should confirm it before
anyone relies on it.

## The map

| Instrument | Kind | Whom it binds | What it says that bears on cryptography and data |
|---|---|---|---|
| Privacy Act 2020 | Law | Every *agency* that holds personal information; the Act's definition of a New Zealand agency covers public sector agencies and private sector bodies alike (s 8) | Reasonable security safeguards (IPP 5); care when a service provider holds the data (IPP 5(b), s 11); retention (IPP 9); offshore disclosure (IPP 12); breach notification (ss 112–115) |
| Public Records Act 2005 | Law | Public offices and local authorities, as defined in s 4 | Keep full and accurate records, including of contracted-out work (s 17); no disposal, including destruction, without the Chief Archivist's authority (s 18) |
| Protective Security Requirements (PSR), INFOSEC | Government policy | Agencies mandated by Cabinet; others are encouraged to adopt it | Security measures *"in line with"* the NZISM (paragraph 44); ICT systems, in house or cloud, *"MUST meet the NZISM minimum standards"* (paragraph 138); system assurance through NZISM certification and accreditation or continuous monitoring (paragraphs 184–186); compensating measures where a MUST cannot be met (paragraph 13) |
| New Zealand Information Security Manual (NZISM) | Technical standard | Departments and agencies it applies to (§1.2.3); compliance *"is not required as a matter of law"* (§1.2.6) | Chapter 17 algorithm and key-length controls; §2.4 post-quantum preparation |
| NCSC NZ Minimum Cyber Security Standards | Technical standard | GCISO-mandated agencies, who *"will be required to implement them"*; others may adopt them | Ten maturity standards mapped to NZISM controls |
| Government Procurement Rules (5th edition) | Government policy | The agencies listed by New Zealand Government Procurement as required to apply them; others are encouraged to have regard to them | Govern the procurement *process*, not technical content (see below) |

## Privacy Act 2020

### IPP 5: storage and security

Information privacy principle 5 (s 22) requires an agency that holds personal
information to ensure:

> *(a) that the information is protected, by such security safeguards as are
> reasonable in the circumstances to take, against— (i) loss; and (ii)
> access, use, modification, or disclosure that is not authorised by the
> agency; and (iii) other misuse; and (b) that, if it is necessary for the
> information to be given to a person in connection with the provision of a
> service to the agency, everything reasonably within the power of the agency
> is done to prevent unauthorised use or unauthorised disclosure of the
> information.*

IPP 5 names no algorithm, key size or protocol. It is a **reasonableness**
test. What it gives a cryptographic finding is a link to law: a weak cipher,
an expired certificate or plaintext transport on a system that holds personal
information is evidence on whether the safeguards were *"reasonable in the
circumstances"*. That question has a regulator, the Privacy Commissioner,
behind it. A report should keep the two claims apart: *"fails NZISM control
X"* is a technical finding; *"bears on IPP 5"* is a legal one, and only a
lawyer can say whether a safeguard was unreasonable.

IPP 5(b) reaches cryptography the organisation does not run itself. Where a
supplier or cloud service holds the data, the duty is *"everything reasonably
within the power of the agency"*, which in practice means contract terms,
assurance reports and the evidence takestock can gather about the supplier's
public endpoints.

### Section 11: information held by an agent

Section 11 treats personal information that one agency (A) holds *"for or on
behalf of"* another (B), *"for safe custody or processing"*, as held by B and
not A (s 11(1)–(2)), unless A uses or discloses it for its own purposes
(s 11(3)). It does not matter whether A is outside New Zealand (s 11(4)), and
passing the information to A is not a disclosure by B (s 11(5)). The practical
consequence is that the IPP 5 duty for data in a supplier's or cloud
provider's custody stays with the organisation that gave it to them.

### IPP 9: retention

*"An agency that holds personal information must not keep that information
for longer than is required for the purposes for which the information may
lawfully be used."* takestock's reading of why this matters for cryptography:
data captured in encrypted form today could be decrypted later by an attacker
with a sufficiently capable quantum computer, which is why NZISM
`2.4.13.C.02` asks for an inventory of datasets that must stay secure *"for
an extended amount of time"*. Data that is no longer held cannot be exposed
that way, so retention limits shrink the long-lived set.

### IPP 12: disclosure outside New Zealand

IPP 12(1) allows a disclosure to a foreign person or entity, in reliance on
listed IPP 11 grounds, only where one of six conditions holds, for example
that the recipient is subject to *"privacy laws that, overall, provide
comparable safeguards to those in this Act"* (IPP 12(1)(c)), or is otherwise
required to protect the information comparably, *"for example, pursuant to an
agreement"* (IPP 12(1)(f)). Read with s 11, a provider that only stores or
processes data on the agency's behalf is not receiving a disclosure.

### Part 6: notifiable privacy breaches

- A *privacy breach* includes *"unauthorised or accidental access to, or
  disclosure, alteration, loss, or destruction of"* personal information, and
  an action that prevents the agency from accessing it (s 112).
- A *notifiable* breach is one *"that it is reasonable to believe has caused
  serious harm … or is likely to do so"* (s 112).
- In assessing serious harm the agency **must** consider, among other things,
  *"whether the personal information is protected by a security measure"*
  (s 113(e)). Encryption with keys the attacker does not hold is the obvious
  example, which makes the state of an organisation's cryptography part of
  the breach assessment itself.
- The agency must notify the Privacy Commissioner (s 114), and affected
  individuals or the public (s 115), *"as soon as practicable"* after
  becoming aware of a notifiable breach.

## Public Records Act 2005

- **Records include data.** A *record* is information *"in its original form
  or otherwise"*, including *"data compiled, recorded, or stored"* in any
  medium (s 4).
- **Contracted-out work stays the office's record.** *"Every public office and
  local authority must create and maintain full and accurate records of its
  affairs … including the records of any matter that is contracted out to an
  independent contractor"* (s 17(1)).
- **Disposal needs authority.** *"No person may dispose of, or authorise the
  disposal of, public records or protected records except with the authority
  of the Chief Archivist"* (s 18(1)). *Disposal* includes *"the sale,
  alteration, destruction, or discharge of a record"* (s 4).

What this means for cryptography, as takestock reads it: losing or destroying
the only key that can decrypt a set of public records makes them unreadable,
which has the same effect as destroying them. Key escrow and recovery for
encrypted records are therefore records-management questions as well as
security ones. Whether a given practice counts as *disposal* is for Archives
New Zealand or a lawyer to say.

## Protective Security Requirements: INFOSEC

The PSR is the government's protective security policy framework; INFOSEC is
its information security part. Version 2.0 is dated 1 October 2026. It has
four mandatory requirements: INFOSEC 1 *understand what you need to protect*,
INFOSEC 2 *design your information security*, INFOSEC 3 *validate your
security measures* and INFOSEC 4 *keep your security up to date*.

- **Who it is for.** Organisations *"mandated to implement the PSR"* and those
  that do so *"on a voluntary basis"*; *"non-mandated organisations in the
  public and private sectors are encouraged to adopt the PSR as appropriate to
  their context"* (paragraphs 2–3).
- **It delegates the technical detail to the NZISM.** *"An organisation MUST
  design and implement the appropriate information security measures …
  proportionate to the risks it faces and in line with: a. The New Zealand
  Government Security Classification System b. The New Zealand Information
  Security Manual c. Any privacy, legal, and regulatory obligations that you
  operate under."* (paragraph 44).
- **Suppliers are in scope.** The Chief Information Security Officer *"is
  responsible for ensuring their systems and that of any supplier to
  government who holds organisation information comply with the NZISM"*
  (paragraph 136), and ICT systems *"may be hosted in house or in the cloud and
  MUST meet the NZISM minimum standards"* (paragraph 138).
- **An unmet MUST needs compensating measures.** An organisation *"must
  implement all mandatory measures unless it can demonstrate that a given
  measure is not relevant in its context"* (paragraph 12), and *"If a
  mandatory measure cannot be directly implemented, suitable compensating
  measures MUST be in place to manage identified risks"* (paragraph 13). As
  takestock reads it, a finding that an NZISM MUST control is unmet therefore
  raises two questions for an organisation that implements the PSR: whether a
  dispensation has been granted, and what compensating measures are in place.
- **ICT systems need system assurance.** INFOSEC 3.1, *"Ensure appropriate
  system assurance for ICT systems"*:
  - *"An organisation MUST conduct the appropriate system assurance activities
    required for the type of security measures being implemented as stated in
    the NZISM"* (paragraph 184).
  - *"Agencies MUST either: a. adopt the NZISM continuous monitoring model;
    and/or b. follow the certification and accreditation process defined in
    the NZISM"*, for all ICT systems (paragraph 185).
  - *"Organisations MUST plan for the certification and accreditation of
    physical buildings, security and equipment alongside ICT system
    assurance"* (paragraph 186), with physical security covered by the PSR's
    PHYSEC framework.

  NZISM v3.9, the version takestock grades against, sets out certification and
  accreditation in Chapter 4 (*System Certification and Accreditation*) and
  describes no continuous monitoring model. takestock performs neither; its
  inventory and grades are evidence that either process can use.

  The PSR points to an NZISM chapter titled *System Assurance* that is not
  yet published, and it numbers that chapter two ways: the change log says
  *"NZISM Chapter 7: System Assurance – Publish date October 2026"*, while
  paragraph 185's link reads *"NZISM 4. System Assurance"*. In v3.9, Chapter
  4 is *System Certification and Accreditation* and Chapter 7 is
  *Information Security Incidents*. Cite neither number as settled until the
  chapter appears. [`CONTINUOUS-ASSURANCE.md`](CONTINUOUS-ASSURANCE.md) sets
  out what peer frameworks mean by continuous monitoring in the meantime.
- **Security keeps pace.** *"An organisation MUST ensure that their security
  measures keep pace with this change to remain relevant and effective"*
  (paragraph 188). INFOSEC 4.2 (paragraph 193) carries the framework's only
  device-level MUSTs: protecting ICT equipment, *"including personal
  devices"*, from malware, and applying security patches and updates
  regularly.
- **Changes from version 1.0.** Version 1.0 (1 October 2025) required
  certification and accreditation, with physical security certified *before*
  the ICT system was accredited, and said compensating measures MUST be
  *"selected"* rather than in place. Version 2.0 changed those two passages
  and moved paragraph numbers by one to three (v1.0 paragraph 185 is v2.0
  paragraph 188; v1.0 paragraph 190 is v2.0 paragraph 193). The requirement
  numbers INFOSEC 1 to 4 and their sub-numbers did not change, and nothing
  else of substance moved. Check the version before quoting a paragraph
  number.
- **Legislation wins a conflict.** *"When legislation requires an organisation
  to manage protective security in a way that is different to the PSR, that
  legislation takes precedence"* (paragraph 19).

## NZISM and the Minimum Cyber Security Standards

The NZISM applies to information and systems operated *"by, or on behalf of"*
the government departments, agencies and organisations listed in Schedule 1 of
the Ombudsmen Act 1975 (Parts 1 and 2) and Schedule 1 of the Official
Information Act 1982, and to organisations with a formal agreement to access
classified information (§1.2.3). It is guidance until made binding: *"compliance
with the NZISM is not required as a matter of law. The controls in the NZISM
could be made binding on departments and agencies, either by legislation, or
Cabinet direction"* (§1.2.6). Crown entities, local government and the private
sector are *"encouraged"* to use it (§1.1.2).

The NCSC NZ *Minimum Cyber Security Standards* (published 30 October 2025) are
*"intended for GCISO-mandated agencies who will be required to implement them,
however non-mandated agencies wishing to adopt the Standards are also welcome
to do so"*. They map to NZISM controls and use a maturity scale.

## Government Procurement Rules

The Rules (5th edition, 47 rules) govern how a procurement is planned, taken
to market and awarded. New Zealand Government Procurement lists the agencies
that must apply them, and encourages the wider public sector to have regard to
them. They are not a cryptography standard. Their relevance to takestock is
procedural: requirements derived from findings can be written into any
procurement that an agency must run properly under the Rules.

## New Zealand's post-quantum position

**New Zealand has published no official deadline for migrating to
post-quantum cryptography.** The evidence, source by source:

| Source | What it says |
|---|---|
| NZISM v3.9 §2.4.8 | *"Currently there are no post-quantum cryptographic systems approved for use in the NZISM"* |
| NZISM v3.9 §2.4.9 | GCSB *"will review applicable standards and consider them for incorporation into the NZISM when they are published"* |
| NZISM v3.9 §2.4.10 | Agencies *"should therefore be prepared to transition away from these algorithms possibly in the next 2-3 years"*: a hedged expectation in an undated paragraph, not a date |
| NZISM v3.9 §2.4.13 | Seven controls, all SHOULD: awareness, inventories, risk marking, prioritisation, a transition plan. None sets a date |
| New Zealand's Cyber Security Strategy 2026–2030 (Department of the Prime Minister and Cabinet, February 2026) | *"Within the timeframe of this strategy, quantum computing has the potential to render current encryption methods obsolete"*, and *"The GCSB will also refresh its Cryptographic Products Management Infrastructure to ensure government ICT will be prepared for the emerging needs of a post-quantum world."* No migration date |
| NCSC NZ website | At the time of writing, no page listed in the site's own sitemap mentions quantum computing |

The dates that do exist belong to other jurisdictions and populations:

| Source | Date | Applies to |
|---|---|---|
| ASD ISM, *Guidelines for cryptography* (September 2026) | DH, ECDH, ECDSA and RSA *"will not be approved beyond 2030"*; new equipment to support ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512 and AES-256 *"by no later than 2030"* (ISM-1917) | Australian government systems |
| NSA, CNSA 2.0 advisory (Ver. 1.0, September 2022) | *"Exclusively use"* CNSA 2.0 by 2030 or 2033, by category of equipment | US National Security Systems |
| NIST IR 8547, initial public draft (12 November 2024) | 112-bit classical public-key algorithms *"Deprecated after 2030"*; classical public-key algorithms *"Disallowed after 2035"* | US federal systems; still a draft |

A New Zealand organisation can adopt any of these as its own target, and many
will. If it does, a report should present the date as **the organisation's
own risk decision**, calibrated against those sources, and never as
compliance with a New Zealand deadline, because there is none.

## What a finding gains from each lever

| Finding | Technical bar | Lever that gives it weight |
|---|---|---|
| Weak or obsolete cryptography on a system holding personal information | NZISM Chapter 17 | Privacy Act IPP 5 (reasonable safeguards); s 113(e) if a breach occurs |
| The same, at a supplier or cloud service | NZISM, through PSR INFOSEC paragraph 136 for mandated agencies | IPP 5(b) and s 11: the duty stays with the organisation |
| Encrypted records whose keys have no recovery path | NZISM key management (§17.1, §17.9) | Public Records Act ss 17–18, where the records are public records |
| Quantum-vulnerable public-key cryptography protecting long-lived data | NZISM §2.4 (SHOULD) | IPP 5 and IPP 9; no New Zealand deadline |
| A capability gap to close through a purchase | The derived requirement | Government Procurement Rules, as the process it is written into |

## Sources read for this document

| Publisher | Document | Where |
|---|---|---|
| New Zealand Parliament | Privacy Act 2020: s 8, s 11, s 22 (IPPs 5, 9, 12), ss 112–115 | <https://www.legislation.govt.nz/act/public/2020/0031/latest/LMS23342.html>, <https://www.legislation.govt.nz/act/public/2020/0031/latest/LMS23530.html> |
| New Zealand Parliament | Public Records Act 2005: ss 4, 17, 18 | <https://www.legislation.govt.nz/act/public/2005/0040/latest/whole.html> |
| PSR | *INFOSEC* policy framework v2.0, and v1.0 for comparison (v1.0 is no longer on the site; the Internet Archive holds a copy) | <https://www.protectivesecurity.govt.nz/assets/psr/INFOSEC-policy.pdf> |
| GCSB | NZISM v3.9, §1.1.2, §1.2, §2.4, Chapter 4 | <https://nzism.gcsb.govt.nz/ism-document> |
| NCSC NZ | *Minimum Cyber Security Standards*; site map | <https://www.ncsc.govt.nz/protect-your-organisation/minimum-cyber-security-standards/>, <https://www.ncsc.govt.nz/sitemap.xml> |
| Department of the Prime Minister and Cabinet | *New Zealand's Cyber Security Strategy 2026–2030* | Published on the Department's website |
| New Zealand Government Procurement | *Application of the Rules*; *Government Procurement Rules* overview | Published on the New Zealand Government Procurement website |
| ASD | ISM, *Guidelines for cryptography*, September 2026 | Australian Cyber Security Centre website |
| NSA | CNSA 2.0 advisory, Ver. 1.0 | NSA press release and advisory PP-22-1338 |
| NIST | IR 8547 ipd | <https://csrc.nist.gov/pubs/ir/8547/ipd> |
