# Risk scale: the New Zealand government reference

takestock grades what it finds against standards: a primitive is weak or
strong, a control is met or unmet. A **risk rating** is a different thing. It
combines how likely a harm is with how bad it would be for a particular
organisation, and most of that is business context no scanner can see. This
document sets out the New Zealand government's published risk scale so that a
report built from takestock's findings can rate risks on a recognised
footing, and says which parts takestock can inform and which belong to the
business owner.

The source is the risk assessment guidance on digital.govt.nz, published by
the Government Chief Digital Officer (GCDO) for New Zealand government
organisations: *Risk assessments for government organisations*,
<https://www.digital.govt.nz/standards-and-guidance/privacy-security-and-risk/risk-management/risk-assessments>.
Each section below names the page it comes from. The pages read for this
document were last updated on 10 October 2022.

## What the guidance is, and its standing

- **It is guidance, not law.** It describes a method and offers example scales.
- **It is built on recognised standards.** *About risk assessments* says the
  process *"is aligned with and based on"* AS/NZS ISO 31000:2018 (*Risk
  management — Guidelines*) and AS/NZS ISO/IEC 27005:2018 (*Information
  security risk management*), and draws on the OCTAVE Allegro and SABSA
  methodologies.
- **It defers to the organisation's own approved scale first.** *Using risk
  scales and matrices for your organisation* opens: *"Use your
  organisation's approved risk scales and matrices — if they're in
  development or do not exist, use our examples to help in their development
  and approval."*
- **Senior management owns the scale.** The same page says senior management
  should be involved in developing scales and approving them *"by signing off
  on them"*, and *"must also identify and document who needs to be informed
  and has the authority to accept risk at each level of importance"*.
- **It warns against bare labels.** *"When using the categories of high, medium
  or low, they do not give enough information for the: stakeholders to
  accurately assign a rating; reader of a risk report to understand how and
  why a risk was given a specific rating."* Every level below therefore comes
  with its definition.

## Rate before controls, then after

Both impact and likelihood are first assessed **as if no controls were in
place**. *Assess the impacts of risks happening* says: *"Assume there are no
controls currently in place when you and the stakeholders are assessing the
impacts of risks happening"*, and *Assess the likelihood of risks happening*
says the same for likelihood. The result is the **initial** rating, *"also
called an overall or a gross rating"* (*Find the initial risk ratings*).

The existing controls are then listed and the same matrix is read again with
any adjusted ratings, giving the **final** rating, *"also called residual or
net ratings"* (*Find the final risk ratings*).

## Likelihood: five levels, each anchored twice

From *Assess the likelihood of risks happening*. Each level has two anchors,
and stakeholders may use *"either, or both"*: the skill and resources an
attacker needs, and the time in which the risk is expected to happen.

| Rating | Level | Skills and resources | Time |
|---|---|---|---|
| 5 | Almost certain | *"Without any specialist skills or resources, it's easy for the threat to exploit the information system's vulnerability."* | Within 1 to 6 months |
| 4 | Highly probable | *"With minimal skills or resources, it's highly likely for the threat to exploit the information system's vulnerability."* | Within 6 to 12 months |
| 3 | Possible | *"With moderate skills or resources, it's possible for the threat to exploit the information system's vulnerability."* | Within 12 to 36 months |
| 2 | Possible but unlikely | *"It requires significant skills and resources for the threat to exploit the information system's vulnerability."* | Within 3 to 5 years |
| 1 | Almost never | *"It's difficult for the threat to exploit the information system's vulnerability."* | Not within 5 years |

Two rules from the guidance matter for scanner evidence:

- **No data is not low likelihood.** *"If quantitative information about the
  risk frequency is not available, it does not mean that the likelihood of
  the risk happening is low."*
- **Match the horizon to the system's life.** *Using risk scales and
  matrices* says the likelihood scale *"should reflect your organisation's
  standard life cycle for its information systems"*. This matters for
  post-quantum risk, where the threat's horizon may be longer than the
  scale's top band but shorter than the life of the data.

## Impact: five levels

From *Assess the impacts of risks happening*. The guidance offers a **simple**
scale in general terms and a **detailed** scale across four categories:
reputation, health and safety, service delivery, and financial. *"The business
owner decides which is appropriate to use."* Both use the same five names.

| Rating | Level | Simple scale, in summary |
|---|---|---|
| 5 | Severe | Severely compromises multiple strategic objectives; severe ongoing impact on service delivery across multiple organisations; severe political or reputational damage; a serious breach of laws |
| 4 | Significant | The same, at *significant*; damage to the Minister's reputation is rated severe |
| 3 | Moderate | Moderately compromises a strategic objective; the Minister needs to be briefed; litigation against one or more organisations |
| 2 | Minor | Minor impact on delivery or an objective; handled by current resources with some changes to planning |
| 1 | Minimal | No real effect on outcomes or objectives; absorbed without affecting capacity |

The detailed scale anchors each level with figures. Two of its four
categories, as examples:

| Level | Service delivery | Financial |
|---|---|---|
| 5 Severe | Staff hours up by more than 50% (20 hours a week) for more than 30 days; turnover up 10% or more in six months | Cannot be managed without additional government funding; yearly operating costs up more than 12%; one-off cost above $100,000 |
| 4 Significant | Hours up by more than 38% (10 to 15 hours a week) for 30 days; turnover up 3% to 10% | Cannot be managed without re-prioritising work programmes; costs up 10% to 12%; one-off $50,000 to $100,000 |
| 3 Moderate | *"Prolonged service failure"*; hours up less than 25% (8 to 10 hours a week) for 2 to 4 weeks; turnover up 1% to 3% | Modest increases in resources; costs up 7% to 10%; one-off $20,000 to $50,000 |
| 2 Minor | *"A brief service failure"*; hours up less than 15% (6 hours a week) for under 2 weeks; turnover up less than 1% | Current resources with minor planning changes; costs up 5% to 7%; one-off $10,000 to $20,000 |
| 1 Minimal | Limited effect on a business unit; hours up less than 5% for under 2 weeks; no turnover change | Current resources, no re-planning; costs up less than 5%; one-off under $10,000 |

The reputation category runs from the Prime Minister losing confidence in the
Minister or the organisation's senior management, with media interest for
more than a week and an external investigation, at 5, to *"no media
attention"* at 1. Health and safety runs from *"Loss of life"* at 5 to *"No
loss or significant threat to the health or life of people"* at 1.

The dollar bands are fixed amounts, not proportions of a budget. An
organisation adopting the detailed scale should tailor them, which is what the
guidance asks senior management to do (*Using risk scales and matrices*:
*"senior management must define the impacts at each point on the scale"*).

## The matrix: 5 × 5, four zones

From *Find the initial risk ratings*, Table 1. Impact runs down, likelihood
across.

| Impact ↓ / Likelihood → | Almost never | Possible but unlikely | Possible | Highly probable | Almost certain |
|---|---|---|---|---|---|
| **Severe** | Zone 3 | Zone 3 | Zone 4 | Zone 4 | Zone 4 |
| **Significant** | Zone 2 | Zone 3 | Zone 3 | Zone 3 | Zone 4 |
| **Moderate** | Zone 2 | Zone 2 | Zone 2 | Zone 3 | Zone 3 |
| **Minor** | Zone 1 | Zone 2 | Zone 2 | Zone 2 | Zone 3 |
| **Minimal** | Zone 1 | Zone 1 | Zone 2 | Zone 2 | Zone 2 |

The guidance colours the zones *"red — zone 4; orange — zone 3; yellow — zone
2; green — zone 1"*, and says what to report: *"Sometimes, organisations have
different numbers assigned to each cell. Regardless, the most important
information is the zone where the risk is located."* takestock-based reports
should therefore state the **zone**, with the impact and likelihood levels
that produced it, rather than a cell number or a colour alone.

## Who may accept a risk

From *Evaluate the risks*, Table 2, an *example* escalation table:

| Zone | Escalation and reporting level |
|---|---|
| Zone 4 | Chief executive |
| Zone 3 | Senior leadership team |
| Zone 2 | Business owner |
| Zone 1 | Service manager or project manager |

*"If choosing to accept a risk, the business owner needs to make sure it's in
a zone where they have the authority to accept it. If it's not, they need to
inform the right reporting level and get their authorisation — only then can
a government organisation accept a risk in zones 3 and 4."*

For each risk the business owner chooses one of four actions: **Avoid**,
**Treat**, **Transfer** or **Accept**. Acceptance applies *"when risks are
assessed as being within the government organisation's risk tolerance
level"*, and also *"when it is not practical to avoid, treat or transfer
them"*.

Two further points from the same page:

- **A control has to move the rating.** The guidance's worked example: a risk
  rated *almost never* and *severe* sits in zone 3, and *"Recommending a
  control that reduces the likelihood of the risk happening will not reduce
  its final rating."* Only reducing impact moves it.
- **Controls are expected to match the NZISM.** *"Government organisations are
  required to use controls that match the guidance in the New Zealand
  Information Security Manual (NZISM)."* See [`STANDARDS.md`](STANDARDS.md)
  for the NZISM's own statement of its legal force.

## One tension inside the guidance

*Prioritise the risks* sets a threshold in numbers: *"Risks that are given a
final rating between 1 and 3 generally do not require further evaluation"*,
while those *"between 4 and 25 need to be prioritised and evaluated"*. The
example matrix carries no cell numbers, and the matrix page says the zone, not
the number, is what matters. The two instructions cannot both be applied
literally to the example matrix. One reading is that ratings 1 to 3 mean zone
1, which has exactly three cells in the example; another is that the threshold
belongs to an organisation's own numbered matrix. takestock-based reports
state the zone and leave the threshold to the organisation's approved scale.

## What takestock can inform, and what it cannot

| Part of the rating | takestock's evidence | Who decides |
|---|---|---|
| Likelihood, skills-and-resources anchor | Strong evidence: whether a weakness is reachable from the internet, whether the protocol or cipher has a known practical attack, whether a fix is a configuration change or a replacement | Stakeholders, using the evidence |
| Likelihood, time anchor | Weak evidence: the age of a configuration, the published retirement dates of an algorithm (see [`STANDARDS.md`](STANDARDS.md)) | Stakeholders |
| Impact | None directly. takestock can say what a system is and what protects it, not what the information is worth to the organisation | Business owner |
| Existing controls | Partial: controls visible on the wire (TLS settings, email authentication records); not policies, monitoring or procedures | Business owner and subject experts |
| Acceptance | None | The authority for the zone |

So a takestock finding is an input to a risk rating, not the rating itself.
A report that prints a zone should say who supplied the impact level.

## Vocabulary to keep separate

| Word | Means here | Do not confuse with |
|---|---|---|
| Grade | takestock's verdict on a primitive or control against a named standard | A risk rating |
| Zone | The risk matrix band, 1 to 4 | A severity label or a remediation deadline |
| Critical | In the NZISM, a class of security patch to apply within two days (`12.4.4.C.01`), and the top incident category suggested in §7.2.14 | Zone 4 |
| Classification words (IN-CONFIDENCE, RESTRICTED and the rest) | How sensitive information is, under the PSR | Any risk or severity level |

## Pages read for this document

All on digital.govt.nz under
`/standards-and-guidance/privacy-security-and-risk/risk-management/risk-assessments/`:

| Page | Path |
|---|---|
| Risk assessments for government organisations | (the section root) |
| About risk assessments | `about` |
| Using risk scales and matrices for your organisation | `analyse/using-risk-scales-and-matrices` |
| Assess the impacts of risks happening | `analyse/impact-assessments` |
| Assess the likelihood of risks happening | `analyse/likelihood-assessments` |
| Find the initial risk ratings | `analyse/initial-risk-ratings` |
| List the existing controls for each risk | `analyse/existing-controls` |
| Find the final risk ratings | `analyse/final-risk-ratings` |
| Prioritise the risks | `prioritise` |
| Evaluate the risks | `evaluate` |
