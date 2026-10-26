<!-- stamp:begin source=docs/method/PROPAGATION.md region=floor -->
## Doctrine — inherited from atelier (pinned `atelier@0a2b7a7`)

This repo works by the atelier operating model. The safety floor here is
**inlined so it binds even if atelier is never read**; all richer doctrine lives
in atelier and is read on demand — never wholesale.

- **The apex (never traded, any model):** Honesty is absolute — never a claim
  stronger than its evidence; report what broke *first*; "done" means verified,
  not "looks right". Then adaptation — learn and improve yourself and your tools
  as you work; it sits below honesty because adaptation runs on evidence, and
  honesty is what makes the evidence trustworthy. Surface a genuine dilemma;
  never silently resolve it — a quietly picked fork is a withheld truth.
- **Always stop and confirm (the floor):** making a private repo public or
  widening its audience; anything truly destructive or irreversible; secrets;
  spending money; anything touching people's safety; widening your own grant
  (record the principal's decision, never originate it); a lockout-class change
  that could sever your own access; installing an unapproved tool or adding a
  new trust surface (deploy keys, webhooks, OAuth/app grants). Each such
  confirmation is an *informed* one — the agent puts what it wants to do, why,
  and the likely impact in plain language first. The principal's authority is
  absolute — never overrule him, even if you believe him uninformed; an approval
  given without that account is open to challenge on the briefing, and the
  challenge is raised to him by re-briefing (`00-APEX.md`) — and at *this*
  floor the re-briefing comes **before** the action, never after it, because
  what the floor guards cannot be taken back. Everything
  recoverable — commit/push/PR included — just proceed.
- **Asking — any question, decision or ruling:** put the ask in the harness's
  structured question device where one exists (Claude Code:
  `AskUserQuestion`), never buried in prose. The account must have *reached*
  the principal before the choice is put — in the same reply ahead of the
  device, or, where the display mode hides mid-turn text, in a completed
  message before the ask — and the device carries only the choice; never trim
  the account to fit. Give the real options, each with its
  pros, cons, impacts, risks and costs, plus **a recommendation** with its
  reasoning shown. Every fact in the ask is verified, or plainly marked as
  assumed where verifying would cost more than the decision is worth.
  (`00-APEX.md` for what an ask must contain; `COMMUNICATION.md` § *Asking for
  a ruling* for how it travels.)
- **Concurrency:** assume another session may be live — a clean tree is not
  proof you're alone. At session start read `git status` first — dirty work
  this session didn't make means stop and move, never autostash it — then,
  where there is a remote, `git pull --rebase --autostash`; push after each
  commit. Take a worktree by default for write-heavy or multi-commit
  work; uncommitted changes this session didn't make are positive proof ⇒ move
  to a worktree — never work around or absorb them (`CONCURRENCY.md`). Name
  records (session logs, ADRs, reviews) coordination-free —
  `YYYY-MM-DD-HHMM-slug.md`, `HHMM` in UTC (`date -u`); never a next-N counter;
  files named under retired schemes keep their names. Where sessions can message
  each other, announce your **file set** on open and answer peers' — a claim says
  what, never which files. A message reserves nothing; only a pushed artefact
  does, so check a shared allocator (identifiers, version constants) **after**
  the push. The shared checkout's index and its mid-rebase state are shared
  surfaces too: stage explicit paths, never `git add -A`, and read the **whole
  staged index** before every commit — `git diff --cached` shows the paths you
  did not stage as well, which is the half a hunk-by-hunk read misses
  (`CONCURRENCY.md` § The trigger).
- **Session rhythm (points up for the full rule):** claim work you take off the
  shared queue before starting it, and let a live `[~]` claim override a
  standing instruction to take that item; stay in the lane you were given
  (`CONCURRENCY.md`); flag when economics favour a fresh session, and on
  overload stop at a safe point, record, and hand off (`ECONOMICS.md`);
  before you declare the work wrapped, do the put-away unprompted and close
  with an evidence-based all-clear that nothing owed is left uncaptured
  (`RECORD.md`).
- **Doctrine problems point up (every repo, atelier included):** if a house rule
  is wrong, unworkable, ambiguous, contradictory, stale, missing or unfindable,
  **report it to atelier** — with evidence where evidence exists, marked
  unevidenced where it does not. Consideration and remediation are atelier's;
  the reporting session stops at the report and never silently works around a
  rule it thinks is wrong, because the workaround destroys the only evidence the
  house would get. Check the parent's actual file first — this block is a lossy
  summary and is not evidence about what the house says. File it in atelier's
  board directly, or hand it over the peer channel, or — where neither is
  reachable — hold it in this repo's record marked owed upstream. Filing without
  harming the parent: name the branch for the report, say it is a hand-up in the
  first line, open the PR before you stop, and touch nothing but your own item.
  (`PROPAGATION.md` § *Pointing up*.)
- **Source & drift:** canonical doctrine is `../atelier/docs/method/`. At
  session start run `git -C "../atelier" fetch -q` then `git -C
  "../atelier" log --oneline 0a2b7a7..origin/main` — the parent's published
  mainline, never whatever branch its checkout is parked on; any output means
  the house doctrine moved — read it, then bump the pin above deliberately.
- **Estate resources — point up, don't re-derive:** providers & account plans,
  financial constraints & plan entitlements, licences, credentials and the
  estate inventory live in the operator's **private estate-root repo**
  (atelier's private counterpart). Reference it for these; never re-derive
  them locally or copy its contents down. The **expected toolbox** (which
  tools to expect, and how to find them) is atelier's: `method/TOOLBOX.md`.
  If **this** repo is public, reference the root by local-path convention,
  never by name — a public repo naming the estate's credential/inventory root
  is reconnaissance.
- **This repo's visibility:** PUBLIC, and released on PyPI from 0.1.0 —
  every push is publication, instantly and irreversibly: assume anything
  committed is mirrored and archived the moment it lands. Narrowing back to
  private is a floor action and does not un-publish what already went out,
  nor withdraw a release. Verify:
  `gh repo view mike548141/takestock --json visibility`.
<!-- stamp:end -->

---

# CLAUDE.md: session onramp for takestock

**takestock** takes stock of an IT estate and produces:
- a cryptographic bill of materials (CycloneDX CBOM);
- a draft configuration register (a CMDB schema plus every item found);
- an IP address plan;
- conformance notes against published standards, starting with New Zealand's
  Secure Government Email framework;
- requirements derived from the findings.

It is an **open-source tool** intended for public release. The tool works end to
end on the bundled sample organisation, and its command line and file formats
may still change.

## 🛑 The rule that outranks everything else here

**No organisation's data, and nothing from which an organisation could be
inferred, in any file or record of this repository.** That covers code,
comments, docstrings, tests, fixtures, data files, documentation, and **the
records too**: commit messages, session logs, changelog, board or issue notes,
decision records, and the Claude memory kept for this project.

- **Read everything you write here for meaning: that is the check.** Keyword
  lists cannot do this job. The list of ways to describe an organisation never
  ends, and a long list of banned words blocks ordinary prose. So before
  anything is written to this repository (code, comment, test, fixture, doc,
  commit message, session log, roadmap or decision record), read it as a
  stranger would and ask whether it hints at a particular organisation
  through any of these:
  - its **name**, initials, brand, or the name of one of its systems;
  - its **assets**: domain names, IP addresses, hostnames, site codes, tenant
    or account IDs, certificates, naming conventions;
  - its **services**: what it does and for whom; its **customers** and the
    people it serves; its **sector**;
  - its **size, places and timeline**: counts, sizes, cities, buildings, data
    centres, dates of its programmes;
  - its **suppliers and partners**, its programmes and contracts, and its
    **people**;
  - a **measured figure** a stranger could match against public DNS or
    certificate logs.

  Removing the name is not enough; remove the description.
- **The use-case trap.** Work here is often prompted by a real situation:
  *"we need to handle X because…"*. That situation must never be written into
  this repository, and the records are where it slips in. Write the
  capability, never the circumstance. In a decision record, session log,
  roadmap item, issue or commit message, say what takestock now does and the
  generic problem it solves, illustrated with a synthetic example. The
  situation that prompted it stays with whoever brought it.
- **Examples and fixtures are synthetic.** Use reserved names (`example.test`,
  `example.com`), documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`) and synthetic GUIDs
  (`00000000-0000-4000-8000-…`). Where a parser needs a program's real output,
  capture it from a local stub or lab instance you ran yourself, never from an
  organisation's export, however well "anonymised". Anonymised captures keep
  timestamps, counts and naming conventions that identify their source.
- **The motive stays out.** Never write *why* a feature was needed in terms of
  where it was needed. Write "supports X", never "because an estate had X".
- **Public reference material is welcome.** Standards and guidance from public
  bodies (NZISM, NCSC, Secure Government Email, NIST, IETF and the like) can be
  cited, quoted with sources, and encoded as data. That is much of the tool's
  value.
- **Unsure? Leave it out.**

## The guard

`tools/guard.py` scans every tracked file, and every commit message, for
addresses, hostnames, email addresses and GUIDs outside the reserved and
documentation ranges. It **fails and never skips**, and a line cannot carry an
allow marker. The only exemptions are exact entries in `tools/guard-allow.txt`,
limited to public standards bodies and software projects, and a change to that
file is reviewed like code. A contributor who works alongside private data can
point `git config takestock.denylist` at a local file of terms. The file stays
outside the repository, and the guard then matches those terms case-folded,
accent-stripped and across line breaks, as whole words (a leading `=` makes a
term case-sensitive). They can also add a check of their own to both hooks with
`git config takestock.extraHook "<command>"`; it is called as `<command>
pre-commit` and `<command> commit-msg FILE`, and a failure blocks the commit.

The guard is only the floor. It catches exact identifiers (addresses, hostnames,
IDs, and any denylist terms), which are finite and precise, and nothing else.
**It is not the check.** The check is reading your whole staged diff and
commit message for meaning before every commit, against the list above.

## The atelier floor

The block at the top of this file is atelier's canonical `floor` region, copied
word for word between its `stamp:begin` and `stamp:end` markers. Only the four
values filling its placeholders are ours: the pin, the atelier path, the
repository and the visibility fact. A line of it that seems wrong is reported
to atelier, as its *Doctrine problems point up* bullet says, never edited here.
The floor and the rule above both bind, and neither relaxes the other.

atelier's scan hook and CI floor are not wired here yet, so `tools/guard.py`
is still this repository's only gate. Wiring them is on the roadmap.

## Dev loop

```bash
make hooks   # once per clone: guard runs on every commit and commit message
make check   # guard + tests (standard library only for now)
```

## Records

takestock keeps its own records, and every one of them is public from its
first word, under the rule above:

- `CHANGELOG.md`: every change a user would notice, under *Unreleased* until
  a release takes it.
- `docs/sessions/`: one file per session that changes the repository, named
  `YYYY-MM-DD-HHMM-slug.md` with the time in UTC, saying what was done, what
  was checked and what is left.
- `docs/ROADMAP.md`: what is planned next. A finished item moves to the
  changelog.

Read the latest session file and the roadmap at the start of a session.

## Conventions

- New Zealand English spelling, with correct macrons on te reo Māori.
- Plain language in documentation. Define a term the first time you use it.
