# Roadmap

What is planned next for takestock. A finished item
moves to [`CHANGELOG.md`](../CHANGELOG.md). To propose an item, open an
issue.

## Now

- **Install from PyPI in the README's quick start.** 0.1.0 is on PyPI; the
  quick start still installs from a clone because it needs the sample in
  `examples/`.

## Next

- **Settle the command line and file formats.** The README says both may
  still change. Before 1.0, decide which output fields are stable, and record
  every change to them in the changelog until then.

- **Clear the floor's advisory checks by 2027-01-31.** `.atelier-floor.json`
  runs datescan, spellscan and wrapscan advisory while their findings are
  cleared: dates in the reference guides to write as YYYY-MM-DD, US spellings
  outside quoted titles and proper names, and long lines in the guides. Fix
  each, or mark the ones that must stay (a quoted title, a table row), then
  drop the advisory entry.

- **Grade SGE-DMARC-R04 behind a third-party MX on DMARC, not on the spoof
  action.** When a domain's MX points to a service in front of Exchange
  Online (for example `mx1.gateway.example.net`) and the platform does not
  apply DMARC on that route, a *Quarantine* spoof-intelligence action is read
  as *met*. On that route the platform never identifies a message as failing
  DMARC, so the row is graded on a different test from the one the
  requirement names, while SGE-DMARC-02 reads *not measured* on the same
  facts. The gateway's unknown handling is treated three ways today: a policy
  that ignores DMARC is *not met*, a platform failure is *not measured*, and a
  spoof-action pass is *met*. Decide one treatment (*not measured*, or a pass
  qualified as the spoof action's), then align `sge._eval_dmarc_quarantine`,
  `test_where_dmarc_is_not_applied_the_spoof_action_decides`,
  `docs/SGE-NOTE.md` and `docs/COLLECTORS.md`.

## Later

- **1.0**, once the formats are settled and a release has been used without
  a breaking change.

## Queued reviews

- [ ] 🎯 **Rule-4 cold pass queued: the floor block stamped at atelier
  `0a2b7a7`.** Refs only. Delta: the commit that adds this item (resolve with
  `git log -S'floor block stamped at atelier' -- docs/ROADMAP.md`). Intent
  record: `docs/sessions/*-adopt-atelier-floor.md`. Doctrine
  surface: atelier `PROPAGATION.md` § *The standard child doctrine block*
  (the `floor` region) at `0a2b7a7`, and its stamp rules. For a non-author to
  take. Tier at selection: Fable, so it waits for the maintainer's approval
  of Fable work. **Not takeable by session `8266042b`**, which authored the
  adoption. **Brief ready (2026-11-02):**
  `docs/reviews/2026-11-01-1204-atelier-floor-block-and-wiring-cold.md`,
  with a held-back sibling of six questions; it also takes in the wiring
  that followed (`8e1e83d`, `1f7254a`).
  **Claimed 2026-11-01T13:49Z** for the cold pass, run under the maintainer's
  approval of Fable work for the weekly budget (2026-11-02). Orchestrator:
  headless session `d9664696` on Opus, an off-tier orchestrator under rule 4 that
  holds the context partition and forms no finding; it was started by
  session `c87c4ee0`, which only launched it. Reviewer: Fable 5.1. The
  held-back sibling is held outside the repository until act 1 is committed.
  **PASS RAN 2026-11-01: PASS-WITH-FINDINGS, 1 MAJOR, 7 MINOR, 2 notes.**
  Act 1 in `f836875`, act 2 and the folded sibling in the review file.
  Standing MAJOR: F1, on the hook plane the guard reads the working tree,
  not the index, so a staged identifier can land with every check green.
  Rulings owed to the maintainer (rule 3: a gate and its config, so
  nothing is applied until the maintainer rules), each with the reviewer's
  recommendation:
  - F1: approve the guard reading cached paths from the index, pinned by
    a test that stages an offending blob behind a clean working copy.
    Recommended.
  - F2: MAC addresses are ungated with leakscan's rule off. Route: a MAC
    check in the guard that passes locally administered and RFC 7042
    values (recommended), or the leakscan rule back on with markers.
  - F3: `.secretscanignore` exempts three whole test modules. Route:
    per-line markers, with the line-length rule lifted per file where a
    marker will not fit (recommended), or keep the whole-file exemption.
  - F8: commit messages are scanned by the local hook only. Approve a
    `ci.yml` step running the guard over each pushed message.
    Recommended.
  Routing: F4 (`make hooks` exits 0 without atelier), F6 (stale dev-loop
  line, with N3's CI wording), F7 (a pointer to the copied-text ruling at
  the point of use) and N2 (stale paths in `docs/`) are fixes any session
  may apply; F5 is a process note for the next landing. F4, F6 and F7
  applied 2026-11-13, with N3 (the session index entry of that date); N2
  is open. Fixes to F1, F2, F3 and F8 change a gate, so under rule 4 each is
  reviewed before it is trusted.
