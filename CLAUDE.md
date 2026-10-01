# CLAUDE.md: session onramp for takestock

**takestock** takes stock of an IT estate and produces:
- a cryptographic bill of materials (CycloneDX CBOM);
- a draft configuration register (a CMDB schema plus every item found);
- an IP address plan;
- conformance notes against published standards, starting with New Zealand's
  Secure Government Email framework;
- requirements derived from the findings.

It is an **open-source tool** intended for public release. The repository is in
its first stage: the skeleton and the guard exist, and the tool itself does not
yet.

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
accent-stripped and across line breaks.

The guard is only the floor. It catches exact identifiers (addresses, hostnames,
IDs, and any denylist terms), which are finite and precise, and nothing else.
**It is not the check.** The check is reading your whole staged diff and
commit message for meaning before every commit, against the list above.

## Dev loop

```bash
make hooks   # once per clone: guard runs on every commit and commit message
make check   # guard + tests (standard library only for now)
```

## Conventions

- New Zealand English spelling, with correct macrons on te reo Māori.
- Plain language in documentation. Define a term the first time you use it.
