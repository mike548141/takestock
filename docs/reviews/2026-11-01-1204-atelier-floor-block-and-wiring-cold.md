# Cold review — the atelier floor block and its wiring

**Board item:** `docs/ROADMAP.md` § *Queued reviews*, the ⏳ *"Rule-4 cold
pass queued: the floor block stamped at atelier `0a2b7a7`"*.
**Status:** BRIEF ONLY — not run.

**Reviewer tier: Fable** (atelier `REVIEW.md` rule 4 and the maintainer's
standing rule that reviews run on Fable). 🛑 **This pass runs only on the
maintainer's explicit approval of Fable work.** It never moves to a lesser
model; it waits.

**Provenance (REVIEW.md rule 4).** This brief was written on 2026-11-02 NZDT
by a brief-writing session on Opus that authored none of the subject and
neither started nor instructed session `8266042b`, which did. The reviewer
must not be `8266042b`, a session it started or instructed, or this
brief-writer.

**Held back:** one sibling file,
`2026-11-01-1204-atelier-floor-block-and-wiring-cold.deferred.md`, with six
questions. Open it only after your own findings are written to this file
(REVIEW.md rule 1). Fold it in below the verdict and delete it when the
verdict lands.

## Subject

| Commit | What it is |
|---|---|
| `ddf9417` | *docs: adopt atelier's floor block, pinned at `0a2b7a7`* — `CLAUDE.md`'s stamped region, `docs/ROADMAP.md`, the session record |
| `8e1e83d` | *tools: wire atelier's floor beside the guard* — `.atelier-floor.json`, `.githooks/pre-commit`, `.github/workflows/floor.yml`, `.secretscanignore`, `.leakscanignore`, `tools/extra_hook.py`, `Makefile`, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, two guides, the roadmap, the session record |
| `1f7254a` | *docs: record the ruling on local checks refusing copied atelier text* — the session record only |

**Scope note, itself attackable.** The queued item names the stamped block
(`ddf9417`). This brief adds `8e1e83d` and `1f7254a` because they put into
force the floor the block describes, and the queue holds no other pass for
them. That widening is the brief-writer's call.

**What the subject claims** (extracted from its commits and records, not
evaluated):

1. `CLAUDE.md`'s `stamp:begin … stamp:end` region is atelier's canonical
   `floor` region at `0a2b7a7`, word for word, with only four placeholder
   values filled: the pin, the atelier path, the repository and the
   visibility fact.
2. `.githooks/pre-commit` is atelier's shim, byte for byte, with its one
   placeholder filled (`../atelier/tools`); it names no scanner and runs
   atelier's `tools/floor.py`.
3. `.atelier-floor.json` declares the licence (Apache-2.0) and two local
   checks: `guard` (`tools/guard.py`, hook and CI) and `extra-hook`
   (`tools/extra_hook.py`, hook only, passing when no
   `takestock.extraHook` is set).
4. datescan, spellscan and wrapscan run **advisory** until 2027-01-31, each
   with a reason, and the roadmap carries clearing them.
5. leakscan's `email`, `ipv6` and `mac-address` rules are **off**, because
   addresses are this tool's content and the guard gates email and IP
   addresses more strictly.
6. `.secretscanignore` and `.leakscanignore` exempt named paths, each with
   a reason; two example file names in the guides carry an allow marker.
7. `.github/workflows/floor.yml` is atelier's thin CI caller, unchanged,
   with read-only permissions; `sign-boundary` is empty because every
   commit in the history is signed.
8. `make hooks` sets `hooks.atelierTools` to an atelier clone's tools and
   fails if there is none; the hook fails closed without them.
9. The maintainer's ruling (2026-10-27): when a pin bump brings in atelier
   text that a contributor's own extra hook refuses, that contributor adds a
   narrow exception in their own check; the copied text is never reworded.
10. Recorded checks: the floor's CI plane passes with every blocking check
    clean; the hook plane passes on the change's staged files; the guard
    passes; the shim matches another public child's; `floor.yml` matches
    atelier's template; the stamp was checked by a direct diff against the
    canonical region, because stampscan cannot resolve a source in another
    repository.

## Why it earns a review

It is doctrine text (the floor every session here reads first) and a guard
surface whose green exit is read as *safe to publish*, in a repository where
every push is publication and cannot be recalled. The worst failure is a
check that is advisory, switched off or exempted in a way that lets an
identifying value reach a public commit with every hook green.

## Scope and the four lenses — run all four

Intent, decisions, assumptions, the stamped text, the configuration, the
hook and CI wiring, `tools/extra_hook.py`, the docs that describe them, and
real behaviour (exercise the hook and the CI plane; an impossibility claim
states its grounds). Approach and assumptions first: name the load-bearing
assumptions yourself as your first act. Then correctness and quality,
completeness, and security and privacy (what each exemption, advisory and
disabled rule lets through, checked against the repository's own rule in
`CLAUDE.md`).

## How to read it

- **Commits, body-free:** `python3 <atelier>/tools/coldsweep.py --commit
  <sha> [--path <p>]` from this repository's root (subject, stat and diff,
  never the body; plain `git show` prints the body first, and reading is
  atomic). `<atelier>` is a clone of atelier, `../atelier` beside a primary
  clone.
- **Canonical text at the pin:** `git -C <atelier> show
  0a2b7a7:docs/method/PROPAGATION.md` (the region between
  `<!-- floor:begin -->` and `<!-- floor:end -->`).
- **Intent record, read after your findings:**
  `docs/sessions/2026-10-26-1022-adopt-atelier-floor.md` and
  `docs/sessions/2026-10-26-1240-wire-atelier-floor.md`.

## Re-run before you trust it

Each was run once by the brief-writer on `f980bec`, 2026-11-02 NZDT, with
atelier's tools at `f985b69` (not the pin):

- The stamp against the canonical region (bash), exit 1, three hunks:

  ```bash
  diff <(git -C <atelier> show 0a2b7a7:docs/method/PROPAGATION.md | sed -n '/<!-- floor:begin -->/,/<!-- floor:end -->/p') <(sed -n '/<!-- stamp:begin/,/<!-- stamp:end -->/p' CLAUDE.md)
  ```

- The floor, CI plane, with no local leakscan term list, as CI runs it
  (`ATELIER_LEAKSCAN_TERMS` pointed at an empty file; on a machine that keeps
  a term list, the plain command loads it): exit 0, no blocking check red.

  ```bash
  ATELIER_LEAKSCAN_TERMS=/dev/null python3 <atelier>/tools/floor.py --plane ci --root .
  ```

- `make check` (from a worktree, `make check VENV=<path to a venv>`): guard
  clean, ruff and mypy clean, 2086 passed.

A recorded pass is a claim; re-run it. Run the standing checklist unasked
(REVIEW.md, V1–V7). Close with PASS, PASS-WITH-FINDINGS or FAIL below the
divider, findings numbered.

---
