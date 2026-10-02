# Continuous assurance: keeping a security authorisation current

Most security regimes start with a full assessment and a decision to let a
system operate. What differs is how that decision stays current. The older
model issues a certificate for a fixed term and repeats the assessment when it
lapses. The newer model, called *continuous monitoring*, *ongoing
authorisation* or *continuous assurance*, keeps the decision open for as long
as a standing flow of evidence shows the risk is still acceptable.

New Zealand is moving in this direction. The Protective Security Requirements
(PSR) INFOSEC policy framework v2.0 lets agencies *"adopt the NZISM continuous
monitoring model; and/or follow the certification and accreditation process"*
(paragraph 185), but the NZISM chapter that will describe that model is not
yet published (see [`OBLIGATIONS.md`](OBLIGATIONS.md)). This document records
what peer frameworks in the United States, Australia and the United Kingdom
require, what New Zealand's current material already says, and what an
organisation has to build for itself, so that a reader can plan before the New
Zealand text appears. It pays particular attention to cloud services, where the
provider changes the platform under the customer's authorisation.

Every quotation was read in the publisher's own text. Where a statement rests
on a search summary rather than a read source, it is marked **unverified**.
*Force* says whom a statement binds.

## Terms used here

- **Certification and accreditation (C&A)**: the NZISM's process. A
  certifier assesses a system's controls; the Accreditation Authority accepts
  the residual risk and authorises operation for a period.
- **Authorisation to operate (ATO)**: the equivalent decision in US federal
  practice, issued by an *authorising official* (AO). An *authorisation to
  use* is the same decision by a customer of a shared or cloud service.
- **Ongoing authorisation**: an authorisation with no termination date, kept
  current by continuous monitoring and reviewed on set triggers.
- **ISCM** (information security continuous monitoring): NIST's term for the
  monitoring programme behind ongoing authorisation.
- **POA&M** (plan of action and milestones): the tracked list of weaknesses
  and the dates by which each will be fixed.
- **Significant change**: a change large enough to require the authorising
  official to look again.
- **OSCAL** (Open Security Controls Assessment Language): NIST's
  machine-readable formats for control catalogues, system security plans and
  assessment results.

## The sources

| Key | Document | Version or date | Publisher | Force |
|---|---|---|---|---|
| NZISM | New Zealand Information Security Manual, <https://nzism.gcsb.govt.nz/ism-document> | v3.9 (footer *"Last updated on November-2025. Version 3.9"*) | GCSB | Required of agencies through the PSR; adopted by choice by others |
| NZISM-BST | NZISM baseline security templates page, <https://nzism.gcsb.govt.nz/resources/nzism-baseline-security-templates> | Undated web page | GCSB | Guidance |
| PSR-INFOSEC | PSR INFOSEC policy framework, <https://www.protectivesecurity.govt.nz/assets/psr/INFOSEC-policy.pdf> | v2.0, 1 October 2026 | New Zealand Government | Mandatory for agencies mandated to implement the PSR |
| NCSC-NZ-MCSS | *Minimum Cyber Security Standards*: *Secure Configuration of Software*, <https://www.ncsc.govt.nz/protect-your-organisation/secure-configuration-of-software/> | 30 October 2025 | NCSC NZ | Required of GCISO-mandated agencies; others welcome to adopt |
| DGNZ | Cloud services risk assessment pages, <https://www.digital.govt.nz/standards-and-guidance/technology-and-architecture/cloud-services/assess-the-risks/use-assessment> | Last updated 10 October 2022 | Government Chief Digital Officer | Guidance |
| SP800-37 | NIST SP 800-37 Rev. 2, *Risk Management Framework*, <https://csrc.nist.gov/pubs/sp/800/37/r2/final> | December 2018; no later revision listed | NIST | Mandatory for US federal agencies; voluntary elsewhere |
| CSWP3 | NIST *Supplemental Guidance on Ongoing Authorization* | 3 June 2014; **withdrawn 19 April 2019**, *"rolled into SP 800-37 Revision 2"* | NIST | Withdrawn; do not cite as current |
| SP800-137 | NIST SP 800-137, *Information Security Continuous Monitoring*, <https://csrc.nist.gov/pubs/sp/800/137/final> | September 2011; no revision listed | NIST | As SP800-37 |
| SP800-137A | NIST SP 800-137A, *Assessing ISCM programs* | May 2020 | NIST | Guidance |
| SP800-53 | NIST SP 800-53 Rev. 5.2.0, as the OSCAL catalogue at <https://github.com/usnistgov/oscal-content> | Catalogue last modified 11 May 2026 | NIST | As SP800-37 |
| SP800-207 | NIST SP 800-207, *Zero Trust Architecture*, <https://csrc.nist.gov/pubs/sp/800/207/final> | August 2020 | NIST | Guidance |
| FR-2026 | FedRAMP Consolidated Rules for 2026 (rulesets for certification, Key Security Indicators, collaborative continuous monitoring, significant change notification, vulnerability detection and response, certification data sharing, secure configuration guides, the security decision record, and agency use) | Launched 24 June 2026; each rule has its own effective date | FedRAMP (US General Services Administration) | Binding on FedRAMP-certified providers and the US agencies that use them |
| FR-20x | FedRAMP 20x programme page | As read at the time of writing | FedRAMP | Programme status |
| FR-ConMon | FedRAMP *Continuous Monitoring Playbook* (Rev5) | v1.0, 17 November 2025 | FedRAMP | The Rev5 path, being replaced by FR-2026 on the dates given |
| AU-ISM | Australian Government *Information Security Manual*, from ASD's official OSCAL repository, <https://github.com/AustralianCyberSecurityCentre/ism-oscal> | September 2026 release (tag v2026.09.4, published 3 September 2026) | Australian Signals Directorate | Mandatory for Australian non-corporate Commonwealth entities through their protective security policy; guidance otherwise |
| UK-CSP | NCSC UK *Cloud Security Principles* (principles 5, 13 and 14) | v2.1, 17 November 2018, reviewed 7 June 2023 | UK National Cyber Security Centre | Guidance |
| UK-CAF | NCSC UK *Cyber Assessment Framework* | v4.0, 18 April 2024, reviewed 6 August 2025 | UK National Cyber Security Centre | The basis of GovAssure for UK government |
| GovAssure | UK Government Security *GovAssure guidance* | Web page | UK Government Security Group | UK central government |
| CISA-ZTMM | CISA *Zero Trust Maturity Model* | v2.0, April 2023 | CISA | Guidance |
| CISA-BOD2501 | CISA BOD 25-01 *Implementing Secure Practices for Cloud Services* | Issue date **unverified**; its deadlines run from February to June 2025 | CISA | Binding on US federal civilian agencies |
| CISA-SCuBA, CDM | CISA SCuBA project and Continuous Diagnostics and Mitigation programme pages | Web pages | CISA | Programme descriptions |
| OIDF-SSF | OpenID Shared Signals Framework 1.0, CAEP 1.0 and RISC 1.0 | Final specifications, published 29 August 2025 | OpenID Foundation | Voluntary standard |
| OSCAL | NIST OSCAL, <https://pages.nist.gov/OSCAL/> | v1.2.3, 7 August 2026 | NIST | Voluntary standard; FedRAMP agencies must be able to ingest it (AGU-AGC-GRC) |
| OCSF | Open Cybersecurity Schema Framework | v1.9.0, 3 August 2026 | The OCSF project | Voluntary standard |
| CSA-STAR | Cloud Security Alliance STAR programme page | As read at the time of writing | Cloud Security Alliance | Voluntary scheme |

## What the frameworks share

Every framework read keeps a full first authorisation. None lets continuous
monitoring replace the *first* decision. What changes is what keeps that
decision current: a standing flow of evidence, and an accountable official who
reviews it on a set cadence and on defined triggers, in place of a fixed-term
certificate that lapses.

| What the organisation has to have | What the sources say (force) | Where |
|---|---|---|
| **1. A full first authorisation** | NIST: ongoing authorisation needs a system that *"has received an initial authorization based on a complete, zero-based review"* (US federal, binding). AU ISM: an authorisation package of system security plan, incident response plan, change and configuration management plan, continuous monitoring plan, security assessment report and POA&M, after which a system may be *"granted an ongoing authorisation to operate"* | SP800-37 App. F p. 149; AU-ISM *Authorise the system* |
| **2. A written continuous monitoring strategy or plan** | NIST: the strategy sets *"the minimum monitoring frequency for implemented controls"* and the *"ongoing control assessment approach"*, and the senior risk official approves it. AU ISM-1163: *"Systems have a continuous monitoring plan"*. SP 800-53 CA-7 requires metrics, frequencies, correlation, response and reporting | SP800-37 tasks P-7 and S-5; SP800-137 §2–3; AU-ISM ISM-1163; SP800-53 CA-7 |
| **3. Metrics and frequencies per control, by volatility and criticality** | SP 800-137: *"Volatile security controls are assessed more frequently"*; firewalls and log servers are named *"candidates for more frequent monitoring"* | SP800-137 pp. 25–26 |
| **4. Automation for most of the evidence** | SP 800-37: *"if a substantial portion of monitoring is not accomplished via automation, it will not be feasible or practical to move from the current static authorization approach"*. FedRAMP 20x: *"Continuous evidence of what is happening is stronger than a policy saying it should happen."* | SP800-37 App. F p. 151; FR-20x principle 05 |
| **5. Time-driven and event-driven triggers for the decision-maker** | NIST lists event triggers: new threat or vulnerability, more findings, a new authorising official, significant change, supply-chain change, a threshold exceeded. NZISM 4.4.12.R.03 and the AU ISM's *Monitor the system* list nearly the same events | SP800-37 App. F pp. 153–154; NZISM 4.4.12.R.03; AU-ISM |
| **6. A definition of significant change, and who decides** | NIST: *"a change that is likely to substantively affect the security or privacy posture of a system"*. NZISM 6.3.8.C.01 (MUST): reaccredit when a configuration change has *"changed the overall security risk"*. FedRAMP sorts provider changes into routine, adaptive and transformative classes, each with a notice period | SP800-37 App. F; NZISM 6.3.8.C.01; FR-2026 SCN |
| **7. A standing decision, reviewed on a cadence** | NIST: the authorising official *"acknowledges the ongoing acceptance of identified risks"*, and moving to ongoing authorisation is recorded as *"a new authorization decision"* with no termination date. AU ISM-1587: report status to the authorising officer *"at least annually"* | SP800-37 App. F pp. 149–150, fn. 152; AU-ISM ISM-1587 |
| **8. A loop from findings to fixes** | SP 800-37 tasks M-3 and M-4; FedRAMP Rev5 monthly POA&M; the AU ISM authorisation package includes a *"plan of action and milestones"* | SP800-37; FR-ConMon; AU-ISM |
| **9. Assessors independent of the people who run the system** | NIST: for moderate and high systems, the information is *"produced and analyzed by an entity that meets the independence requirements established by the organization"*. NZISM 6.1.8.C.01 (SHOULD): use independent reviewers | SP800-37 App. F p. 150; NZISM 6.1.8.C.01; SP800-53 CA-7(1) |
| **10. For cloud services, an evidence feed from the provider** | NIST: a cloud *"authorization to use does not require a termination date"*, but the customer must make sure the provider's monitoring *"is shared on an ongoing basis"* and that the provider *"notifies the customer organization when there are significant changes"*. FedRAMP 2026: quarterly ongoing certification reports, machine-readable change notices, persistent vulnerability detection. AU ISM-1794 and ISM-1572: contracted notice periods | SP800-37 App. F pp. 145–146; FR-2026; AU-ISM |
| **11. The provider's telemetry inside the customer's own monitoring** | NZISM 23.5.12.C.01 (MUST): cloud provider logs incorporated into enterprise logging *"in a timely manner"*. UK CSP 13: logs in a usable format, and alerts sent automatically | NZISM 23.5.12.C.01; UK-CSP 13 |
| **12. A way back to reauthorisation** | NIST: reauthorise where *"there is a breach/incident or failure of or significant problems with the continuous monitoring program"*; where monitoring is not comprehensive enough, *"a maximum authorization period can be specified"* | SP800-37 App. F p. 152 |

## New Zealand today

Until the System Assurance chapter is published, NZISM v3.9 still caps the time
between accreditations at three years (`4.4.12.C.01`, MUST) and asks for two
(`4.4.12.C.05`, SHOULD). The nearest New Zealand precedent for continuous
assurance is GCSB's baseline security templates for cloud platforms. GCSB says
they *"support and encourage agency adoption of continuous assurance
(certification) processes"*, with controls *"continually assessed by the cloud
provider"* and *"reported and presented to the agency in real-time, or near
real-time through a dashboard"*. A New Zealand model is therefore likely, though
not certain, to rest on automated assessment by the provider against a
baseline mapped to the NZISM, plus review by the agency.

## What each framework says

### NIST SP 800-37 Rev. 2: the Monitor step and ongoing authorisation

The 2014 white paper on ongoing authorisation was withdrawn on 19 April 2019,
and NIST says *"The information in this white paper has been rolled into SP
800-37 Revision 2."*

**The Monitor tasks** (Chapter 3):

- M-1: *"The information system and environment of operation are monitored in
  accordance with the continuous monitoring strategy."*
- M-2: *"Ongoing assessments of control effectiveness are conducted in
  accordance with the continuous monitoring strategy."*
- M-3: *"The output of continuous monitoring activities is analyzed and
  responded to appropriately."*
- M-4: *"Risk management documents are updated based on continuous monitoring
  activities."*
- M-5: *"A process is in place to report the security and privacy posture to
  the authorizing official and other senior leaders and executives."*
- M-6: *"Authorizing officials conduct ongoing authorizations using the results
  of continuous monitoring activities and communicate changes in risk
  determination and acceptance decisions."* The task text: *"Review the
  security and privacy posture of the system on an ongoing basis to determine
  whether the risk remains acceptable."*
- M-7: system disposal.

**The strategy** (task P-7): *"The continuous monitoring strategy identifies
the minimum monitoring frequency for implemented controls across the
organization; defines the ongoing control assessment approach; and describes
how ongoing assessments are to be conducted"*, including *"instructions for
ongoing assessment of controls for which monitoring cannot be automated"*. The
senior accountable official for risk management, or the risk executive
function, *"approves the continuous monitoring strategy including the minimum
frequency with which controls are to be monitored"*. Task S-5's output is a
*"Continuous monitoring strategy for the system including time-based trigger
for ongoing authorization."*

**Appendix F, ongoing authorisation** (pp. 149–154):

- *"Reauthorizations are unnecessary in situations where the continuous
  monitoring program provides authorizing officials with the information
  necessary to manage the risk arising from changes to the system or the
  environment in which the system operates."*
- Two conditions must hold before a system moves from point-in-time to ongoing
  authorisation: an initial authorisation *"based on a complete, zero-based
  review"*, and an organisational continuous monitoring programme *"that
  monitors implemented controls with the appropriate degree of rigor and at
  the required frequencies"*.
- The move is recorded by *"issuing a new authorization decision"*, which
  makes clear (footnote 152) that the system is *"no longer bound to the
  termination date specified in the initial authorization document"*.
- Independence, for moderate- and high-impact systems: the information *"is
  produced and analyzed by an entity that meets the independence requirements
  established by the organization"*.
- Triggers: *"time-driven authorization triggers refer to the frequency with
  which the organization determines that authorizing officials are to review
  security and privacy information"*; *"event-driven triggers necessitate an
  immediate review"*. The event list: *"New threat, vulnerability, privacy
  risk, or impact information; An increased number of findings or
  deficiencies from the continuous monitoring program; New missions/business
  requirements; Change in the authorizing official; Significant change in
  risk assessment findings; Significant changes to the system, common
  controls, or the environments of operation; Changes in the supply chain
  affecting security or privacy risks to operational systems; or Exceeding
  organizational thresholds."*
- Automation: *"if a substantial portion of monitoring is not accomplished via
  automation, it will not be feasible or practical to move from the current
  static authorization approach to an effective and efficient ongoing
  authorization approach."*
- The safety valve: *"if the continuous monitoring program is not sufficiently
  comprehensive to fully support ongoing authorization, a maximum
  authorization period can be specified by the authorizing official"*, and *"A
  reauthorization may be warranted, for example, if there is a breach/incident
  or failure of or significant problems with the continuous monitoring
  program."*
- Significant change: *"a change that is likely to substantively affect the
  security or privacy posture of a system"*. The examples include
  *"Modifications to system ports, protocols, or services"*, *"Modifications to
  cryptographic modules or services"* and *"Modifications to security and
  privacy controls"*. Most changes, NIST adds, *"can be handled through the
  continuous monitoring program and ongoing authorization."*
- Cloud and shared systems (pp. 145–146): *"The authorization to use does not
  require a termination date but remains in effect if the customer
  organization continues to accept the security and privacy risk … It is
  incumbent on the customer organization to ensure that information from the
  monitoring activities conducted by the provider organization is shared on an
  ongoing basis and that the provider organization notifies the customer
  organization when there are significant changes to the system, application,
  or service that may affect the security and privacy posture of the
  provider."*

**SP 800-53 Rev. 5.2.0 controls that carry this:**

- CA-7, *Continuous Monitoring*: a system-level strategy with metrics,
  frequencies for monitoring and for assessment, ongoing control assessments,
  correlation and analysis, response actions, and *"Reporting the security and
  privacy status of the system"* to named roles at a set frequency.
- CA-7(1): *"Employ independent assessors or assessment teams to monitor the
  controls in the system on an ongoing basis."* CA-7(4) adds risk monitoring
  of effectiveness, compliance and change.
- CA-6 e: *"Update the authorizations [frequency]."*
- SA-9 c: monitor *"control compliance by external service providers on an
  ongoing basis"*. SA-9(2): providers *"identify the functions, ports,
  protocols, and other services required for the use of such services"*.

### NIST SP 800-137 and SP 800-137A

SP 800-137 defines ISCM as *"maintaining ongoing awareness of information
security, vulnerabilities, and threats to support organizational risk
management decisions."* Its six steps: *"Define an ISCM strategy; Establish an
ISCM program; Implement an ISCM program; Analyze data and Report findings;
Respond to findings; and Review and Update the ISCM strategy and program."*
Establishing the programme means *"determining metrics, status monitoring
frequencies, control assessment frequencies, and an ISCM technical
architecture"*, and implementation should *"Automate collection, analysis, and
reporting of data where possible."*

On frequency (pp. 25–26): *"Volatile security controls are assessed more
frequently"*; configuration controls CM-6 and CM-8 *"may require more frequent
assessment and monitoring, preferably using automated, SCAP-validated tools"*;
and controls *"that provide critical security functions (e.g., log management
server, firewalls) are candidates for more frequent monitoring."* It foresees
that *"the question When did the system receive authorization to operate? will
become less meaningful than How resilient is the system?"*

Its Appendix D names eleven security automation domains: vulnerability, patch,
event, incident, malware detection, asset, configuration, network, licence and
information management, and software assurance.

SP 800-137A is a method for *assessing* a monitoring programme: it *"provides
organizational leadership with information on the effectiveness and
completeness of the organization's ISCM program"*. It audits the customer's own
regime, not the provider's.

### FedRAMP: Rev5 continuous monitoring, the 2026 rules and 20x

**Words.** The 2026 rules say *Certification* (FedRAMP Certification, Ongoing
Certification Report) where earlier FedRAMP material said *Authorization*. The
agency still issues its own Authorization to Operate (AGU-USE-ABU).

**Rev5 continuous monitoring** (FR-ConMon). *"Each month, the CSP uploads an
up-to-date POA&M and inventory, along with raw vulnerability scan files (when
required by agreements with agency customers) and reports to the secure
repository."* *"CSPs must scan operating systems, Web applications, and
databases monthly"*, with authenticated scans *"wherever possible"* for moderate
and high systems. Agency escalation triggers include *"Five or more unique
vulnerabilities or POA&M items aged greater than 30 days"* and *"Notification
received less than 30 days before the planned change"*. *"Each agency that
issues an ATO, or authority to use (ATU), for a cloud offering must review the
CSP's ConMon activities."*

**20x status**, as the programme page stood at the time of writing: Phase 3,
*"Wide-scale Adoption"*. Rules for Classes A, B and C are finalised; Class D
(high) is planned for Phase 4; and *"FedRAMP will stop accepting new Rev5
Certifications on 2027-06-11"*. The page says future dates *"are estimates …
not firm commitments"*. Lessons it records: *"Key Security Indicators can
demonstrate security posture in near real time, replacing static yearly manual
assessments while improving confidence and overall security"*; *"No
participants actively reused existing framework assessments such as SOC 2"*;
and fast reviews shared *"consistent machine-readable schemas, concise evidence
context, clear failure criteria"*. Principle 03: *"Security should be
continuously enforced, monitored, and reported—not staged for a point-in-time
audit."*

**Key Security Indicators** are outcome statements. Those most relevant to a
customer of a cloud service:

- KSI-CMT-LMC: *"Modifications to the cloud service offering are logged and
  monitored."*
- KSI-CMT-RMV: changes made *"through the redeployment of version controlled
  resources rather than direct modification wherever reasonable."*
- KSI-CMT-VTD: *"Persistent testing and validation of changes throughout
  deployment is automated."*
- KSI-CNA-EIS: *"Automated services are used to persistently assess the
  security of all machine-based information resources and automatically
  enforce their intended operational state."* (required for Class C)
- KSI-MLA-EVC: configuration, *"especially infrastructure as code, is
  persistently evaluated and tested."*
- KSI-MLA-OSM: a SIEM or similar, *"persistently reviewed for centralized,
  tamper-resistant logging of events, activities, and changes."*
- KSI-PIY-GIV: *"Authoritative sources are used to automatically generate
  real-time inventories of all information resources when needed."*
- KSI-SVC-ACM: configuration *"managed using automation and persistently
  reviewed for drift."*
- KSI-SCR-MON: third-party software *"automatically monitored for upstream
  vulnerabilities"*.
- KSI-IAM-APM and KSI-IAM-JIT: passwordless sign-in or *"strong passwords with
  phishing-resistant MFA"*; least privilege with just-in-time authorisation.

**Security Decision Record.** It *"replaced a traditional System Security Plan
with a persistently maintained, verified, and validated record"*, supplied *"in
both human-readable and JSON formats"*; Class B and C providers include a
30-day history of each metric.

**Collaborative continuous monitoring.** Providers *"MUST supply an Ongoing
Certification Report to all necessary parties every 3 months"*, summarising
changes, changes planned for the next three months, accepted vulnerabilities,
transformative changes, updated security recommendations, and reportable
incidents or an attestation that none occurred (CCM-OCR-AVL). *"Agencies MUST
review each Ongoing Certification Report"* against the risk tolerance in their
Authorization to Operate (CCM-AGM-ROR). Class C providers host a quarterly
review. The rule applies to 20x initial certification from 4 July 2026, to 20x
ongoing certification from 1 January 2027, and to Rev5 from 2 April 2027.

**Significant change notification.** Providers *"MUST evaluate all potential
significant changes"* and classify them:

- *Routine recurring* changes, such as signature updates, firewall rule
  updates and routine patching, need no notice.
- *Adaptive* changes, such as *"Changing cryptographic modules where the new
  module meets the same standards"*, need notice *"within 10 business days after
  finishing"*.
- *Transformative* changes, such as a data-centre migration or the
  *"addition, removal, or replacement of a critical third party service"*, need
  notice *"at least 30 business days before starting"*, again at least 10
  business days before, and within 5 business days after finishing and after
  verification.

Each notice includes a *"Summary of customer impact, including changes to
services and customer configuration responsibilities"* and the impact analysis;
twelve months of notices are kept, in human-readable and JSON form. Emergency
changes may go first, with notice afterwards.

**Vulnerability detection and response.** Providers *"MUST systematically,
persistently, and promptly discover and identify vulnerabilities"*, and *"MUST
treat problems or failures with their vulnerability detection and response
processes as vulnerabilities"*; *"An out-of-date control statement in the
Security Decision Record is a vulnerability"*. Drift-prone resources are checked
at least every three months, one month, fourteen days or seven days for
Classes A to D (SHOULD). Remediation times are keyed to a *Potential Agency
Impact N-rating*. The ruleset applies from 7 December 2026.

**Secure configuration guides.** These rules translate most directly into
what a customer can ask of a provider:

- A Secure Configuration Guide (MUST) covering top-level administrative
  accounts and *"Explanations of security-related settings … and their
  security implications"*.
- Settings at secure defaults *"when initially provisioned"* (SHOULD).
- The capability *"to compare all current settings for top-level
  administrative accounts and privileged accounts to the recommended secure
  defaults"*, *"to export all security settings in a machine-readable format"*,
  and *"to view and adjust security settings via an API"* (each SHOULD).
- The guide itself in machine-readable form, with *"versioning and a release
  history"* (SHOULD).
- *"Agencies MUST review the Secure Configuration Guides supplied by Providers
  and configure relevant security settings."*

**Certification data sharing.** A *"FedRAMP-compatible trust center"* with
*"documented programmatic access to all FedRAMP Certification Data"*;
automation to keep human-readable and machine-readable forms consistent;
snapshots aligned to each Ongoing Certification Report; and, for Classes B to
D, an availability service covering *"at least the past 30 days"* that stays up
*"even if the primary cloud service offering is unavailable"*.

**Agencies.** *"Agencies MUST ensure that internal governance, risk,
compliance, and inventory tools can produce and ingest machine-readable
artifacts using formats identified by FedRAMP, including at least: Open
Security Controls Assessment Language (OSCAL); JSON"* (AGU-AGC-GRC).

**SOC 2.** Class A accepts a recent alternative certification, including
*"SOC 2 Type II"* *"within the past 12 months"*, with the *"Complete report,
bridge or gap letter (if applicable), verified audit engagement documentation,
estimated schedule for upcoming report"*.

### Australia: the ISM and IRAP

The ISM text below is from ASD's OSCAL release v2026.09.4 and the PDF published
with it.

**Authorise and monitor.** The authorisation package *"includes the system's
system security plan, cyber security incident response plan, change and
configuration management plan, continuous monitoring plan, security assessment
report, and plan of action and milestones."* *"In some cases, the security
risks associated with a system's operation will be acceptable and it will be
granted an ongoing authorisation to operate"*; otherwise the authorising
officer may set constraints, *"such as limiting the system's functionality or
specifying an expiration date"*. *"For commercial providers providing services
to an organisation, the authorising officer is the CISO of the supported
organisation (or their delegate)."* Monitoring is *"Real-time monitoring of
cyber threats, security risks and security controls … as outlined in a
continuous monitoring plan"*, and a change in policy, a new threat, controls
found less effective than planned, a major incident or a major architectural
change prompts another assessment and an updated package.

**Controls:**

- **ISM-1163** (revised June 2026): *"Systems have a continuous monitoring plan
  that includes: conducting security assessment activities to identify
  vulnerabilities; analysing identified vulnerabilities to determine their
  potential impact; implementing mitigations based on risk, effectiveness and
  cost."* The March 2026 wording carried fortnightly vulnerability scans and
  annual assessments and penetration tests; those cadences have left this
  control.
- **ISM-2118** (new in September 2026): *"Vulnerability assessments and
  penetration tests are conducted for systems prior to their deployment,
  including prior to the deployment of significant changes, and at least every
  six months thereafter."*
- **ISM-1526**: *"System owners continuously monitor the security of each
  system, and manage associated cyber threats, security risks and security
  controls."*
- **ISM-1587**: *"System owners report the security status of each system to
  its authorising officer at least annually."*
- **ISM-0027**: an authorisation to operate for each system, from its
  authorising officer.
- **ISM-1636**: controls assessed by the organisation's own assessors or IRAP
  assessors. No fixed reauthorisation interval for an organisation's own
  systems was found in the text read.
- **ISM-1570**: outsourced cloud service providers and their services undergo
  an IRAP assessment *"at least every 24 months"*; ISM-1793 says the same for
  managed service providers. ISM-1637 and ISM-1638 keep a register with the
  *"due date for the next security control assessment"*.
- **Contracts.** Security requirements in contracts *"regularly reviewed"*
  (ISM-0072); *"The right to verify compliance with security requirements is
  documented in contractual arrangements"* (ISM-1571) and *"is regularly
  exercised"* (ISM-1738); break clauses (ISM-1804); provider incident reporting
  *"as soon as possible"* (ISM-0141); *"A minimum notification period of one
  month by service providers for significant changes to their own service
  provider arrangements"* (ISM-1794); *"The regions or availability zones where
  data will be processed, stored and communicated, as well as a minimum
  notification period for any configuration changes"* (ISM-1572); *"Access to
  all logs relating to an organisation's data and services"* (ISM-1573); and
  portable data for *"backups, service migration and service
  decommissioning"* (ISM-1574).
- **Provider access** (new or revised in September 2026): restricted to
  approved tools, source addresses and time windows (ISM-2124); *"All access to
  an organisation's systems by a service provider is independently logged by
  the organisation in a manner that the service provider cannot modify or
  delete, and analysed in a timely manner"* (ISM-2125); unauthorised provider
  access *"treated as a cyber security incident"* (ISM-1576).
- **Change management** (ISM-0912): a plan including *"the establishment and
  maintenance of authorised baseline configurations for systems"*.
- **Scanning**: at least daily for online services (ISM-1698) and for
  internet-facing servers and network devices (ISM-1701); automated asset
  discovery at least fortnightly (ISM-1807).
- **Principle GOV-05**: residual risks, *"including inherited and shared
  security risks, are accepted before they are authorised for use and
  continuously monitored and managed throughout their operational life."*

**Hosting Certification Framework** (**unverified**: the framework's own site
could not be read). A search summary says certified providers report any
upcoming *"Relevant Change"*, complete a contract form twice a year and an
annual review, and that *"A Certification does not expire but it does require
ongoing maintenance"*.

### United Kingdom: the Cyber Assessment Framework, GovAssure and the Cloud Security Principles

**CAF v4.0, A2.c *Assurance*.** *Achieved* requires all of: *"You validate that
the security measures in place to protect the network and information systems
are effective and remain effective for the lifetime over which they are
needed"*; *"Your confidence in the security … can be justified to, and verified
by, a third party"*; deficiencies *"assessed, prioritised and remedied when
necessary in a timely and effective way"*; and *"The methods used for assurance
are reviewed to ensure they are working as intended"*. *Not achieved*
indicators include *"A particular product or service is seen as a 'silver
bullet' and vendor claims are taken at face value"* and *"Assurance is assumed
because there have been no known problems to date."* Principle C1, *Security
monitoring*, covers sources and tools, securing logs, alerts, triage, skills,
and behaviour and threat intelligence.

**GovAssure** is a five-stage cycle: scoping, choosing systems for the current
year, a self-assessment against the CAF, an independent assurance review, and
a targeted improvement plan. It is a periodic, organisation-level cycle, not
continuous authorisation of a system. The pages read state no frequency; a
search summary says departments are reviewed annually (**unverified**).

**Cloud Security Principles v2.1.** Each item is guidance, in the form *"you
should be confident that"* or *"prefer a provider that"*:

- **5.1 Vulnerability management.** Know the provider's timescales for
  deploying security updates; *"If there is evidence to suggest that a
  vulnerability is being actively exploited in the wild, you should expect
  your service provider to put mitigations in place immediately"*; a cloud
  provider *"should therefore be expected to apply mitigations and/or security
  updates to their service faster than would usually be expected in individual
  organisations"*; *"consider statistics of prior performance"*.
- **5.4 Configuration and change management.** *"unauthorised changes to the
  deployed service components and their configuration will be detected and
  prevented"*; the provider *"will give you appropriate notice before making
  changes that affect how you use the service"*; check that any
  certification's scope covered these processes.
- **13.1 Audit information.** Know what audit information is provided, how,
  when, in what format and for how long; the provider supplies audit
  information for actions its own staff take on your service; *"audit
  information cannot be deleted by the customer or the cloud provider during a
  defined retention period"*; prefer providers with *"APIs and tooling to query,
  process, and archive audit information"* and *"an RBAC role for auditors"*;
  log configuration changes, authentication events and data access.
- **13.2 Security alerts.** *"the provider will send their alerts promptly to a
  recipient of your choosing, through an automated means"*, in *"a structured
  machine-readable format"*, with *"a means for simulating alerts"*, and an
  alert when your own configuration creates a security issue.
- **14.1 Secure by design and by default.** The provider improves its default
  configuration as threats change; *"periodically review your service
  configuration against the platform's good practice guides"*.
- **14.2 Helping customers.** *"all service configuration can be set and
  audited using infrastructure as code, or via an API"*; *"there is a single
  place where you can see all of your deployed resources"*; an actionable alert
  when your configuration *"could weaken your security stance"*.

### CISA

- **Continuous Diagnostics and Mitigation** *"delivers cybersecurity tools,
  integration services, and dashboards"* to US federal civilian agencies.
- **Zero Trust Maturity Model v2.0**, cross-cutting capabilities at *Optimal*:
  *"comprehensive visibility enterprise-wide via centralized dynamic monitoring
  and advanced analysis of logs and events"*; orchestration that *"dynamically
  respond[s] to enterprise-wide changing requirements"*; governance that *"fully
  automates enterprise-wide policies"* with *"continuous enforcement and dynamic
  updates"*. For networks: environments *"defined using infrastructure-as-code
  managed by automated change management methods"*. For applications, agencies
  *"should explore options to shift their operations away from a focus on
  accreditation boundaries and updating ATOs"*.
- **SCuBA** publishes secure configuration baselines for Microsoft 365 and
  Google Workspace, with tools that *"evaluate an organization's current M365
  and GWS tenant controls against CISA's SCBs and generate clear, visual
  reports"*. It is the model for vendor-neutral, automated assessment of a
  software-as-a-service tenant against a baseline. No SCuBA baseline exists
  for other kinds of cloud service, on the pages read.
- **BOD 25-01** (binding on US federal civilian agencies): deploy the SCuBA
  assessment tools for in-scope tenants and *"begin continuous reporting"*,
  integrated with CISA's continuous monitoring or reported quarterly in a
  machine-readable format, and *"Implement all mandatory SCuBA Secure
  Configuration Baselines and begin continuous monitoring for new cloud
  tenants prior to granting an Authorization to Operate (ATO)"*. Authorising
  officials *"may accept risk for deviations"*.

### NIST SP 800-207: zero trust

- Tenet 5: *"The enterprise monitors and measures the integrity and security
  posture of all owned and associated assets"*, and *"should establish a
  continuous diagnostics and mitigation (CDM) or similar system to monitor the
  state of devices and applications"*.
- Tenet 6: *"Continual monitoring with possible reauthentication and
  reauthorization occurs throughout user transactions"*.
- Policy engine inputs (§3) include the CDM system's view of whether an asset
  *"is running the appropriate patched operating system"*, and *"Network and
  system activity logs"* giving *"real-time (or near-real-time) feedback on the
  security posture"*.

### Standards a provider can support

| Standard | What it is | Status | What a customer can reasonably ask for |
|---|---|---|---|
| **OSCAL** (NIST) | Machine-readable models for catalogues, profiles, component definitions, system security plans, assessment results and POA&Ms | v1.2.3 (August 2026). FedRAMP agencies must be able to ingest it; ASD publishes the ISM in it | An OSCAL *component definition* mapping the service's capabilities to controls, with the customer and provider responsibilities split, and assessment results in OSCAL or JSON. No NZISM OSCAL catalogue was found, so an NZISM mapping is a matter for negotiation |
| **OpenID Shared Signals, CAEP, RISC** | Push-based security event streams between cooperating parties. CAEP covers changes relevant to sessions and access; RISC covers account and credential risk | Final specifications (August 2025). CAEP events include session revoked, credential change, device compliance change, assurance level change, token claims change and risk level change | Receiving (and ideally sending) named CAEP events, shown working with the customer's identity provider during a trial |
| **OCSF** | An open, vendor-neutral schema for log events | v1.9.0 (August 2026) | Native OCSF output, or a published field-level mapping to it |
| **CSA STAR** | A cloud assurance registry | The current programme page offers Level 1 (self-assessment) and Level 2 (third-party: attestation through SOC 2, which *"expire[s] after one year unless updated"*, and certification through ISO 27001, which *"expire[s] after three years unless updated"*). A continuous level was announced in 2019, but the current page lists none. NZISM 5.8.37 still says *"As at March 2017, the STAR scheme is still to be fully implemented"* | A Level 2 listing that covers the services in scope. A continuous level cannot be asked for |
| **SOC 2 Type II** and bridge letters | An auditor's report on control design and operating effectiveness over a period | NZISM 5.8.27: a Type 2 report covers *"a period of at least six consecutive calendar months"*; 5.8.16: a Type 1 report *"is of limited use"*. FedRAMP Class A accepts a SOC 2 Type II within 12 months plus a *"bridge or gap letter"*. That a bridge letter is a management assertion carrying no auditor opinion is **unverified** | A current Type II whose system description names each service and the regions serving the customer; no more than about 12 months between period ends; a bridge letter for any gap; the next report date; exceptions disclosed with the provider's response |
| **ISO/IEC 27001:2022** | A certified information security management system | Certificates *"expire after three years unless updated"* (CSA). Surveillance audits at least annually within the cycle is **unverified** (the governing standard is paywalled) | The certificate and a Statement of Applicability whose scope includes the services and operating locations; the latest surveillance audit date |
| **FedRAMP, IRAP** | Government cloud assessments | FedRAMP's 2026 rules apply now; IRAP at least every 24 months (ISM-1570) | Where held, reuse the evidence: ongoing certification reports, change-notice history, the Secure Configuration Guide, the IRAP report. NZISM 5.8.46 notes that the AU ISM and the NZISM have *"detail differences"* |

### New Zealand material

**PSR INFOSEC v2.0.** Its change log: *"INFOSEC 3: Updated to include
continuous monitoring and options for system assurance in line with changes to
the NZISM Chapter 7: System Assurance – Publish date October 2026."* Paragraph
184: *"An organisation MUST conduct the appropriate system assurance activities
required for the type of security measures being implemented as stated in the
NZISM."* Paragraph 185: *"Agencies MUST either: a. adopt the NZISM continuous
monitoring model; and/or b. follow the certification and accreditation process
defined in the NZISM 4. System Assurance (nzism.gcsb.govt.nz) for all ICT
systems."* Paragraph 186 adds planning for physical certification and
accreditation. The chapter is numbered 7 in the change log and 4 in paragraph
185; in v3.9, Chapter 4 is *System Certification and Accreditation* and Chapter
7 is *Information Security Incidents*.

**NZISM v3.9, the points that bear on a continuous model:**

- `3.2.11.C.02` (SHOULD): *"The CISO SHOULD be responsible for ensuring agency
  compliance with the NZISM through facilitating a continuous program of
  certification and accreditation of all agency systems."* The manual already
  uses *continuous* of certification and accreditation.
- `4.4.12.C.01` (MUST): *"the period between accreditations of each of their
  systems does not exceed three years"*; `4.4.12.C.05` (SHOULD): two years;
  `4.4.12.C.04`: do not operate with a lapsed accreditation without a
  dispensation.
- `4.4.12.R.03`, the triggers for reaccreditation: *"changes in the agency's
  information security policies or security posture; detection of new or
  emerging threats …; the discovery that controls are not operating as
  effectively as planned; a major information security incident; and a
  significant change to systems, configuration or concept of operation"*.
- §4.5.14: the Accreditation Authority *"may choose to define a reduced
  timeframe before reaccreditation … or place restrictions on the use of the
  system"*.
- `6.1.7.C.01` and `6.1.8.C.01` (SHOULD): reviews *"at least annually"*, by
  independent reviewers; `6.1.9.C.01` lists what a review covers, including
  *"any third party assurance reports"*.
- `6.2.5.C.01` (SHOULD): vulnerability assessment *"after a significant change
  to the system"*.
- `6.3.6.C.02` (SHOULD): changes that *"could impact the security of a system
  or accreditation status"* go to the Accreditation Authority; `6.3.7.C.03`
  (SHOULD): test changes and update the risk management and security plans;
  **`6.3.8.C.01` (MUST)**: *"When a configuration change impacts the security
  of a system and is subsequently assessed as having changed the overall
  security risk for the system, the agency MUST reaccredit the system."*
- `12.7.14.C.02` (SHOULD): *"monitor supply chain risks on an ongoing basis"*.
- `16.6.13.C.04` (SHOULD): keep DNS, proxy and event logs *"for a minimum of 12
  months"*; `16.6.12.C.01` (MUST): protect event logs from modification;
  `16.6.15.C.01` and `.C.02` (SHOULD): detect events *"as they occur"* and
  correlate them *"in a near real-time manner"*.
- `23.1.56.C.01` (SHOULD): *"deploy and manage their cloud infrastructure using
  automation, version control, and infrastructure as code techniques where
  these are available"*, so a system can roll back to the last known good
  configuration.
- §23.2.13 (context): tenancy changes *"may trigger the commencement of the
  certification and accreditation process … However, this may not be the case
  in a cloud environment, as platform changes are made by the cloud service
  provider and may occur with minimal or no notice"*.
- `23.2.16.C.02` (MUST): a cloud risk assessment *"in line with the process
  outlined by the GCDO"*; `23.2.18.C.01` (SHOULD): *"regular assurance checks
  on cloud service providers, … by a suitably qualified assessor"*;
  **`23.2.19.C.01` (MUST)**: *"obtain assurance that cloud service providers
  undertake appropriate software and operating system patching and
  maintenance"*; **`23.2.20.C.01` (MUST)**: *"obtain assurance that technical
  protections exist to adequately isolate tenants"*.
- `23.2.21.C.01` (SHOULD): use GCSB-endorsed baseline security templates, which
  *"significantly reduce agency's assurance activities and focus then on moving
  towards continuous security posture assessments"* (`23.2.21.R.01`).
- **`23.5.10.C.01`**, **`23.5.11.C.01`** and **`23.5.12.C.01`** (all MUST):
  *"understand the range of logging capabilities provided by their cloud
  service providers and determine whether they are sufficient"*; logs
  *"collected, protected, and that their integrity can be confirmed"*; and
  *"cloud service provider logs are incorporated into overall enterprise
  logging and alerting systems or procedures in a timely manner"*.
- §23.2.5: *"an organisation can never outsource responsibility for
  governance"*.

**GCSB baseline security templates.** They *"validate agencies' cloud
environment configuration settings and report on potential areas of poor
security practice"*. The controls assessed are *"configured by the agency as
part of their tenant environment; continually assessed by the cloud provider;
reported and presented to the agency in real-time, or near real-time through a
dashboard; aligned to one or more controls in the NZISM"*. *"Agency security
activities can shift from manually determining and reporting on NZISM
compliance to focusing on the current security posture."* The templates listed
are for public cloud platforms; none was found for other kinds of cloud
service.

**NCSC NZ, *Secure Configuration of Software*.** The minimum for GCISO-mandated
agencies is CS-CMM 2. CS-CMM 4 reads: *"Configurations are locked and
proactively and continuously monitored for deviations from approved templates.
Changes or updates to a baseline security configuration triggers alerts across
all applicable systems."* Its outcomes include contractual commitments from
vendors to secure-by-default and secure-by-design practice, and *"An ongoing
programme of configuration review against approved configuration templates."*
The Standards align with the *"PSR Assurance Framework"*, which *"provides the
assurance mechanism for the NCSC to assess agency compliance"*.

**digital.govt.nz cloud risk assessment.** *"Risk assessment sign-offs are not
complete certification and accreditation processes"*; for ongoing use, *"set up
a regular schedule to monitor and review the risks and security controls for
your information in the public cloud service"*; reassess *"when there are any
significant changes or new risks"*; and a service whose risks are not monitored
becomes *"'shadow cloud'"*. The Government Chief Digital Officer's pages titled
*System Assurance* concern assurance of digital *investments*, not NZISM system
assurance; the two are easily confused.

**NCSC NZ edge devices page.** It points to the UK NCSC's specifications for
*"digital forensics and protective monitoring"* for producers of network
devices, which encourage *"standard, secure-by-default logging"*. The linked
specification was not read.

## What the organisation keeps for itself

A provider supplies evidence. The decision, and the regime that keeps it
current, stay with the customer: *"an organisation can never outsource
responsibility for governance"* (NZISM §23.2.5), and the UK CAF counts vendor
claims *"taken at face value"* as a failure. For a cloud service, the
organisation needs:

1. **A full first certification and accreditation** under the current NZISM
   Chapter 4. Every framework read requires one before ongoing authorisation
   (SP 800-37 Appendix F; the AU ISM's *Authorise the system*). It includes the
   cloud risk assessment the NZISM requires (`23.2.16.C.02`, MUST).
2. **A continuous monitoring strategy for the system**, covering metrics, the
   monitoring and assessment frequency of each control set by its volatility
   and criticality (SP 800-137 §3.2.2; SP 800-53 CA-7; ISM-1163), which
   controls are evidenced automatically by the provider's exports and
   interfaces and which by hand, and who reviews the evidence and how often.
   NIST has the senior risk official approve the strategy (SP 800-37 task P-7).
3. **An Accreditation Authority decision designed for ongoing operation**,
   recording that the system has moved to continuous monitoring, the
   time-driven review cadence (for example quarterly, aligned to the
   provider's report cycle), the event-driven triggers (NZISM `4.4.12.R.03`; SP
   800-37 Appendix F; the provider's transformative changes), and the risk
   thresholds that force a return to reaccreditation. While NZISM v3.9
   governs, the decision still needs a reaccreditation date no more than three
   years out (`4.4.12.C.01`), and the Authority may set a shorter one
   (§4.5.14).
4. **A significant-change procedure joined to the provider's change notices.**
   Each incoming notice and each internal policy change is classified; changes
   that *"could impact the security … or accreditation status"* go to the
   Accreditation Authority (`6.3.6.C.02`), and where overall risk changes the
   system is reaccredited (`6.3.8.C.01`, MUST). Define in advance which of the
   organisation's own policy changes count as routine. FedRAMP treats firewall
   rule and signature updates as routine, but that is the provider's view of its
   own service.
5. **A loop from findings to fixes**: configuration drift, provider reports and
   penetration test results become tracked actions with owners and dates (SP
   800-37 M-3 and M-4; the AU ISM authorisation package; digital.govt.nz's
   *monitor and review*).
6. **Ingestion and detection for the provider's telemetry, with someone
   accountable for watching it** (NZISM `23.5.12.C.01` and §16.6.15; UK CAF C1),
   and monitoring of that pipeline, so that lost evidence is itself noticed.
7. **A register of complementary controls.** For each attestation (the SOC 2
   complementary user-entity controls, a provider's secure configuration
   guide, its responsibility matrix), record the controls it assumes the
   customer operates, and evidence them. FedRAMP's AGU-USE-RSG is the US
   equivalent: agencies MUST configure services as the provider's guide sets
   out.
8. **A supplier assurance calendar**: a register of cloud and managed service
   providers with each one's next assessment date (ISM-1637 and ISM-1638 are
   the model), report periods and bridge-letter dates tracked, and a scheduled
   exercise of the right to verify (ISM-1738).
9. **Independent review** of the system at least annually (NZISM `6.1.7.C.01`,
   `6.1.8.C.01`), and an SP 800-137A-style assessment of the monitoring
   programme itself.
10. **Reporting upward**: system status to the Accreditation Authority on the
    set cadence (ISM-1587 sets *"at least annually"* as a floor), within a
    CISO-led *"continuous program of certification and accreditation"* (NZISM
    `3.2.11.C.02`).
11. **A declared configuration baseline for the tenancy**, mapped to the NZISM,
    against which drift is measured, and reviewed when the provider's secure
    configuration guide or the NZISM changes (NCSC NZ CS-CMM 3; NZISM
    `6.1.9.C.01`).

## Open questions until the NZISM chapter is published

1. **Which chapter, and what it is called.** The PSR change log says Chapter 7;
   paragraph 185 says Chapter 4. A renumbering, a new chapter and an error in
   the PSR are all possible.
2. **What "the NZISM continuous monitoring model" requires**: a strategy
   document, minimum metrics or frequencies, automated evidence, a decision
   cadence for the Accreditation Authority, rules on independence. None of it
   can be confirmed before the chapter appears.
3. **Whether the three-year cap survives** for systems under the continuous
   model, or gives way to an open-ended authorisation as NIST and the AU ISM
   allow.
4. **What "and/or" permits**: the continuous model for some systems, or some
   controls within one system, and certification and accreditation for the
   rest. NIST explicitly allows a phased, per-subsystem transition.
5. **Organisations that adopt the NZISM by choice.** Paragraph 185 binds
   *"Agencies"*; paragraph 184 binds *"An organisation"*. A non-mandated adopter
   chooses its own route; whether NCSC NZ will recognise that choice, for
   example through PSR self-assessment or Minimum Standards reporting, is not
   known.
6. **Overseas evidence**: whether New Zealand will accept FedRAMP Key Security
   Indicator data, IRAP, SOC 2 or ISO evidence, and with what mapping effort.
   NZISM 5.8.46 already notes differences between the AU ISM and the NZISM.
7. **Baseline templates beyond the hyperscale platforms**: whether GCSB will
   extend them to software-as-a-service and other cloud services. If
   not, the organisation's own baseline (item 11 above) carries the load.
8. **Significant-change thresholds**, for an organisation's own changes and for
   a provider's: whether the chapter will adopt FedRAMP-style classes and
   notice periods, or the AU ISM's one-month floor (ISM-1794).
9. **Evidence format**: whether New Zealand will name a machine-readable format
   such as OSCAL or JSON, as FedRAMP does. No NZISM OSCAL catalogue was found.
10. **The PSR Assurance Framework and Minimum Standards reporting**: whether
    continuous monitoring outputs will feed NCSC NZ's view of agency
    performance.

Evidence asked of a provider is useful under either route: it reduces the
effort of reaccreditation under certification and accreditation, and it is
what a continuous model would run on. Anything that depends on the open
questions, such as an NZISM control mapping or a GCSB template, is better asked
for as desirable than as mandatory.

## Retrieval notes

- The Australian Cyber Security Centre's site and the Hosting Certification
  Framework's site failed with HTTP/2 protocol errors in both a command-line
  client and a full browser. ASD's official OSCAL repository on GitHub carries
  the ISM catalogue and the PDF; comparing its March and September 2026
  releases shows how ISM-1163 changed.
- NIST's 2014 ongoing-authorisation white paper is withdrawn; its publication
  page records the withdrawal and the supersession by SP 800-37 Rev. 2.
- Several FedRAMP 20x pages linked from older material return HTTP 404; the
  current programme page and the 2026 Consolidated Rules replace them.
- digital.govt.nz serves a real *Page not found* page for a wrong address, and
  a short placeholder to non-browser clients for a right one. Its site search,
  in a browser, finds the current addresses.
- The Cloud Security Alliance's address for a continuous STAR level redirects
  to the main STAR page.
- ISO/IEC 17021-1 and 27006-1, which set certification audit cadences, are
  paywalled and were not read.
- NIST SP 1800-35 was not read.
