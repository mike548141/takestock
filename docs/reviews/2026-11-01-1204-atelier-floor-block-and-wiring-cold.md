# Cold review — the atelier floor block and its wiring

**Board item:** `docs/ROADMAP.md` § *Queued reviews*, the ⏳ *"Rule-4 cold
pass queued: the floor block stamped at atelier `0a2b7a7`"*.
**Status:** act 1 and act 2 run 2026-11-01 (UTC). Final verdict
PASS-WITH-FINDINGS (1 MAJOR, 7 MINOR); decisions are the maintainer's.
Held-back sibling folded below the verdict.

**Reviewer tier: Fable** (atelier `REVIEW.md` rule 4 and the maintainer's
standing rule that reviews run on Fable). 🛑 **This pass runs only on the
maintainer's explicit approval of Fable work.** It never moves to a lesser
model; it waits.

**Provenance (REVIEW.md rule 4).** This brief was written on 2026-11-02 NZDT
by a brief-writing session on Opus that authored none of the subject and
neither started nor instructed session `8266042b`, which did. The reviewer
must not be `8266042b`, a session it started or instructed, or this
brief-writer.

**Held back:** one sibling file, with six questions, opened only after
the reviewer's own findings were written to this file (REVIEW.md rule 1).
It is folded in below the verdict, at *Deferred sibling, folded below the
verdict*, and the sibling file is deleted.

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

## Verdict — act 1 (own findings, before the held-back sibling)

**PASS-WITH-FINDINGS.** 1 MAJOR, 6 MINOR, 2 notes. The stamped block is the
canonical `floor` region at `0a2b7a7` with only its four placeholders filled;
the hook fails closed, the CI plane is green, and every recorded check
reproduces except one. The MAJOR is a gap in what the guard reads on the hook
plane: it lets a staged identifier reach a commit with every blocking check
green.

**Provenance (REVIEW.md rule 4, V7).** Reviewer: Fable 5.1, run 2026-11-01
UTC under the maintainer's approval of Fable work for the weekly budget ending
2026-11-02. Spawned by headless session `d9664696` (Opus), an off-tier
orchestrator that holds the context partition, formed no finding and wrote no
severity; it was started by session `c87c4ee0` (Opus), which only launched it.
Neither was started or instructed by session `8266042b`, the author, nor by
the brief-writer; the reviewer was started by neither. The held-back sibling
was removed from the worktree before this pass began and was not opened,
searched for, or read from history before this section was written. The two
intent records were opened only after these findings were written (see
*Reconcile*, below). atelier's tools ran at `f985b69` (the clone's tip), not
the pin; the canonical text was read at the pin with `git show`.

### Load-bearing assumptions, named first (lens 1)

- **A1 — "the pin pins the floor".** It pins the *text*. Enforcement floats:
  the hook runs whatever commit the sibling atelier clone is parked on, and
  CI runs atelier at `main` (`floor.yml` says so, by design). A doctrine pin
  and a floating floor are two different facts; the docs keep them apart.
  Holds.
- **A2 — "the guard gates everything the disabled leakscan rules would".**
  True for `email` and `ipv6` (probed: a ULA, a global and a link-local
  address, and a non-reserved mail domain, all refused). False for
  `mac-address`: the guard has no MAC check. F2.
- **A3 — "the guard reads what the commit will contain".** False. It reads
  the working tree. F1.
- **A4 — "`make hooks` fails without atelier".** False; the hook still fails
  closed. F4.
- **A5 — "the exempted files hold only synthetic values, and will".** True
  today; the exemptions are whole-file and forward-open. F3.
- **A6 — "the stamp is the canonical region word for word".** Holds (V2
  below).
- **A7 — "everything landed under the queued pointer".** The wiring did not.
  F5.

### Findings

**F1 — MAJOR — On the hook plane the guard scans the working tree, not the
index, so a staged identifier can land with every blocking check green.**
`tools/guard.py` lists paths with `git ls-files --cached --others` and reads
each from disk. atelier's boundary scanners read the staged diff. Probed in a
scratch clone with the hook wired: a line carrying a hostname outside the
reserved domains was staged, the working copy was then restored to clean
text, and `git commit` ran — the guard printed `clean`, the floor printed no
blocking line, and the commit landed with the hostname in it. The converse
also holds (an untracked scratch file with an address blocks a clean commit),
which is the safe direction. The defect predates the subject: the hook it
replaced ran the guard the same way. But the wiring is where it now matters:
`.atelier-floor.json` declares the guard with "FORBIDS THE ACT: a public
history cannot be recalled", the hook's green exit is what the repository's
rule rests on, and the CI backstop runs after push, which here is
publication. Any partial-stage workflow (`git add -p`, an edit after `git
add`, a stash applied mid-commit) opens it. **Recommendation:** make the
guard read every cached path from the index (`git show :<path>`, or
`git cat-file --batch` over `ls-files -s`) and only untracked paths from
disk; in CI the index is the tree, so the same code is right on both planes
and no `args` are needed. Pin it with a test that stages an offending blob
behind a clean working copy, the shape atelier's `test_precommit.py` uses.
Until then the local check's `why` overclaims. *Ruling owed to the
maintainer:* this is a change to a gate, so the fix is his to approve; the
recommendation above is the reviewer's.

**F2 — MINOR — Turning off leakscan's `mac-address` rule leaves MAC addresses
ungated.** The `flags.leakscan.why` says the guard "gates email and IP
addresses more strictly"; it does, and the probe above confirms it. It says
nothing about MACs because the guard has nothing for them. Probed: a staged
line carrying a MAC address with a vendor-assigned (globally administered)
prefix passed the hook and landed. The `why`'s
description of the tree is accurate (fourteen values in five files, all
locally administered `02:…` or `00:00:5e:00:53:01`, the RFC 7042
documentation range), so re-enabling the rule today would need fourteen
markers, and the example CSV cannot carry one. But a MAC names a hardware
vendor in its first three octets and a device in the rest — an asset and a
supplier, the classes the repository's rule lists. **Recommendation:** give
the guard a MAC check in the same shape as its address checks, passing
locally-administered values (bit 1 of the first octet set) and
`00:00:5e:00:53:00/24`, and say so in the `why`. *Ruling owed:* which fix —
the guard (recommended, one home for every address class) or the leakscan
rule with markers.

**F3 — MINOR — `.secretscanignore` lifts the secret gate from three whole
test modules on a reason that is partly untrue, and from a forward-open
glob.** Run over copies of the three modules with no ignore file, secretscan
reports eleven findings, all `medium/entropy`, on lines of 67 to 96
characters. A `# secretscan:allow:entropy: synthetic` marker fits inside the
110-column limit on the shorter half; for the rest, a `per-file-ignores`
entry for `E501` in `pyproject.toml`, or a wrapped literal, is a narrower hole
than the whole file. Probed: a GitHub-token-shaped string appended to
`tests/test_dnsevidence.py` passed the hook and landed; the same string in a
non-exempt test module blocked with two `high` findings. `tests/fixtures/
probes/*.txt` admits any future file placed there. The guard still reads all
of these files, so an address would be caught; a credential would not.
**Recommendation:** per-line markers in the three modules, with the lint rule
lifted per file where a marker will not fit; keep the probes glob, whose
reason (TLS transcripts from loopback stubs) is sound, and add one line to
`CONTRIBUTING.md` § *Tests and fixtures* saying a new file under that
directory is not secret-scanned.

**F4 — MINOR — `make hooks` does not fail without an atelier clone; it sets
`hooks.atelierTools` to an empty string and exits 0.** The recipe's `cd`
fails inside `$(…)`, the substitution is empty, and `git config` happily
stores it. The hook then falls back to `<repo>/tools`, finds no `floor.py`,
and blocks: fail-closed holds, so no commit escapes. But the recorded claim
("fails if there is none", subject claim 8) does not reproduce, and the
contributor is left in a misleading state: `git config --get
hooks.atelierTools` prints nothing, and CONTRIBUTING's "check the hook is
live" command expands to `python3 "/floor.py"`. **Recommendation:** in the
`hooks` recipe, `test -f '$(ATELIER)/tools/floor.py' || { echo "no atelier
clone at $(ATELIER); make hooks ATELIER=<path>"; exit 1; }` before either
`git config` line. `CONTRIBUTING.md`'s sentence "The hook fails closed" is
true as written and can stay.

**F5 — MINOR — The wiring commit landed doctrine by function without the
queued pointer naming it (REVIEW.md rule 4, landing = queuing).** `8e1e83d`
put the floor into force: `.atelier-floor.json` decides what is enforced,
`floor.yml` is a CI gate, and both govern every future session here. Its
roadmap hunk replaced the "Wire atelier's floor checks" item and left the ⏳
pointer's delta at `ddf9417` alone. The pointer was widened to the wiring by
the brief-writer on 2026-11-02 (NZDT), seven days later; this pass covers
it. Nothing to apply now. For the next landing: the pointer's delta list is
edited in the commit that completes the series, not left for the brief.

**F6 — MINOR — `CLAUDE.md`'s dev loop line contradicts the Makefile and
CONTRIBUTING (V5).** `CLAUDE.md` § *Dev loop* still says `make check   #
guard + tests (standard library only for now)`. The Makefile runs ruff, mypy
and pytest from the project virtualenv, and CONTRIBUTING says "the whole
gate: guard, lint, type checks and tests". The subject edited the line above
it and left this one. **Recommendation:** `make check   # guard, lint, type
checks and tests (the venv from make venv)`.

**F7 — MINOR — The 2026-10-27 ruling on copied atelier text has no home at
the point of use.** Subject claim 9: when a pin bump brings in atelier text
that a contributor's own extra hook refuses, the contributor adds a narrow
exception to their check and the copied text is never reworded. `1f7254a`
touches only the session record. A contributor who meets exactly this case
reads `CONTRIBUTING.md` § *The guard* (the `takestock.extraHook` paragraph)
or `CLAUDE.md` § *The atelier floor*, and neither says it. **Recommendation:**
one sentence in `CLAUDE.md` § *The atelier floor* — "A local check that
refuses a line of copied atelier text gets a narrow exception; the copied
text is never reworded (ruling, 2026-10-27)" — with the same sentence, or a
pointer, in CONTRIBUTING's extra-hook paragraph. One home for the ruling, as
now, plus the pointer where it is needed.

**N1 — note — CHANGELOG.** `make hooks` now needs a clone of atelier beside
the checkout; nothing under *Unreleased* says so. CONTRIBUTING's own rule
("a change a user would notice") reads as the tool's user, not a
contributor, so this is a judgement for the maintainer, not a finding.

**N2 — note, outside the subject — pathscan.** The floor's warn-only
`pathscan` reports 31 stale paths in `docs/` (`takestock/readers/…`,
`data/…`, `targets/…`, all missing the `src/takestock/` or `examples/`
prefix). Pre-existing, not the subject's, and never blocking; a roadmap
item would clear it.

### Checks run (V2 — every recorded claim re-run)

| Claim | Re-run | Result |
|---|---|---|
| 1, stamp = canonical region at the pin | the brief's `diff` command | exit 1, three hunks: the begin marker and pin; the atelier path and pin in *Source & drift*; the visibility fact and repository. All placeholder fills. The floor region at atelier `origin/main` is unchanged from the pin (20 commits ahead, `diff` exit 0). |
| 2, shim byte for byte | `diff` against `tools/pre-commit.sample` at the pin and at `f985b69` | one line differs, the `<atelier-path>` hint filled with `../atelier`. Identical otherwise at both commits. |
| 3–5, config | `floor.py --list` on both planes; `_load_local` read | parses; `guard` enforced on both planes, `extra-hook` enforced on hook, `skipped · local (not declared on the ci plane)` on CI; three advisories with reasons and `review-by 2027-01-31`; leakscan runs with `disabled: email, ipv6, mac-address` and says so in its output. A passed `review-by` goes red but never blocks (floor.py, by design). |
| 6, ignore files | read; secretscan over copies without the ignore | eleven medium findings silenced (F3). The two guide markers are on a file name, as stated. |
| 7, `floor.yml` and signing | `diff` against `docs/build/templates/workflows/floor.yml` at the pin and at tip; `git cat-file` over every commit in the history | identical at both; every commit carries a `gpgsig` header. GitHub's floor workflow is green on `8e1e83d`, `1f7254a` and every push since (read from the run list, nothing exercised). |
| 8, `make hooks` fails without atelier | scratch clone with no sibling atelier | does not fail (F4). |
| 9, the ruling | `coldsweep --commit 1f7254a` | no change in scope; the record only (F7). |
| 10, CI plane | `ATELIER_LEAKSCAN_TERMS=/dev/null floor.py --plane ci --root .` on `9c10668` | exit 0; no blocking check red; secretscan 46 advisory, leakscan partial cover as CI always is. |
| 10, hook plane on the change's staged files | scratch clone at `ddf9417` with `8e1e83d`'s tree staged, `floor.py --plane hook` | exit 0, 14 staged paths, every enforced line green. |
| 10, `make check` | fresh venv built from the worktree (`pip install -e '.[dev]'`), `make check VENV=<that venv>` | guard clean, ruff and mypy clean, 2086 passed and 36 subtests. |
| hook behaviour | scratch clone, `core.hooksPath` and `hooks.atelierTools` set by hand, an empty term list for leakscan | without tools: blocks with the remedy printed. With tools: a clean commit lands; a staged hostname outside the reserved domains blocks on `guard`; an extra hook that exits 1 blocks on `extra-hook` and is called as `<command> pre-commit` from the repo top; a passing one is called again as `<command> commit-msg .git/COMMIT_EDITMSG`. The clone inherited neither `takestock.extraHook` nor `hooks.atelierTools` from the machine, as expected. |
| stampscan | `stampscan.py --root . CLAUDE.md` | `missing-source`: it resolves `source=` inside `--root` only (source confinement), so it cannot check this stamp. The claim is right; the drift check here is the floor block's own `git log <pin>..origin/main` line, by hand. |

### The standing checklist

- **V1** — three claims stronger than their evidence: the local check's
  "FORBIDS THE ACT" (F1), the `.secretscanignore` reason (F3), "make hooks
  fails" (F4).
- **V2** — table above.
- **V3** — `CLAUDE.md`, `CONTRIBUTING.md`, `README.md` (§ *Contributing*),
  the Makefile comment and `.githooks/commit-msg` agree on `make hooks` and
  the extra hook; the one stale mirror is F6.
- **V4** — the ruling has one home; it lacks a pointer at the point of use
  (F7). The stamp is the one sanctioned copy of the floor and is marked.
- **V5** — F6; F4's recipe against CONTRIBUTING's "needs a clone".
- **V6** — run, below.
- **V7** — provenance in the brief and repeated above.

### Security and privacy (lens 4, V6)

`/security-review` was not run, with grounds: this is a landed-delta review,
the scanner reads pending changes, and the only pending change in this
worktree was the removed deferred sibling and then this brief — the SL2
case REVIEW.md warns of. The lens is discharged by hand instead.

Threats enumerated for this surface: (a) *code the commit path executes* —
atelier's tools directory, chosen per clone by `hooks.atelierTools` or
`ATELIER_TOOLS` (the shim's trust note covers it; the scratch clone inherited
neither); the repository's own `tools/guard.py` and `tools/extra_hook.py`,
run by the floor directly and not through a shell, the same trust as the
repository itself; the contributor's own command, run through `sh -c` by
`extra_hook.py` on their own authority, from their own config, never from a
tracked file. (b) *CI supply chain* — the caller floats at `atelier@main`
with `contents: read` and no write permission; atelier's reusable workflow
SHA-pins its third-party actions and resolves the signing trust list at this
repository's own pin, never at `main`. Accepted by atelier's doctrine; the
template comment states the trade. A fork's pull request runs the floor over
the fork's tree with a read-only token. (c) *what reaches a public commit
with the floor green* — F1 (any identifier the guard checks, via the index/
tree split), F2 (a MAC address), F3 (a credential in three test modules or
under `tests/fixtures/probes/`). (d) *over-collection* — none: the config
holds counts, dates and public product names; the ignore files hold reasons;
the `why` strings were read against the repository's rule and name nothing
that points at an organisation.

### Reconcile (the two intent records, opened after the findings above)

`docs/sessions/2026-10-26-1022-adopt-atelier-floor.md` and
`docs/sessions/2026-10-26-1240-wire-atelier-floor.md` were read after F1–F7
and N1–N2 were written. Nothing in them steered a finding, and nothing in
them changes one:

- The stamping record's account of the four values and of why `stampscan`
  cannot check the stamp matches what was re-run above. One of its checks
  was not re-run here — that the block matches, line for line, another
  public child's at the same pin — because this repository names no such
  child and the diff against the canonical region already answers the
  question it asks.
- The wiring record states claim 8 in its own words ("fails if there is
  none"); F4 stands on that sentence.
- The wiring record carries the 2026-10-27 ruling under *Decision after
  close* and nowhere else; F7 stands, and its wording ("one word for one
  file, each time it happens") is the sentence worth pointing at from the
  point of use.
- **N1 closes.** The wiring record decided the changelog question and gave
  its reason ("a contributor will notice `make hooks` now needs an atelier
  clone, and `CONTRIBUTING.md` says so"). A decision taken and recorded is
  what the note asked for.
- The record's "passes when none is set" for the extra hook, and "the two
  local checks run" on the hook plane, both reproduced.

**Tally after reconcile: 1 MAJOR (F1), 6 MINOR (F2–F7), 1 note (N2).
PASS-WITH-FINDINGS.** Under REVIEW.md rule 3 these findings are on
self-authored doctrine by function (a gate and the config that decides what
it enforces), so the decisions are the maintainer's; the recommendations
above are the reviewer's counsel, and nothing here has been applied.

## Act 2 — the held-back sibling's questions

Opened after act 1 was committed (`f836875`), as the brief and REVIEW.md
rule 1 require. Six questions, all the brief-writer's; the authoring session
seeded none. Act 1 stands as committed; what changes is below, as an
addendum.

**Q1 — what each advisory and each disabled leakscan rule lets through, and
whether the guard covers each class.** The three advisories (datescan,
spellscan, wrapscan) let through relative-time words and non-ISO dates in
`docs/`, US spellings, and prose lines over the column budget. None is an
identifier class; the repository's rule is not weakened by them, and none
was ever a gate for meaning (a date that is an organisation's programme date
is invisible to datescan and the guard alike — the reading-for-meaning
check is the only cover there, as `CLAUDE.md` says). The disabled rules, one
by one: **email** — covered, and more strictly: leakscan flags any address,
the guard passes only reserved domains; probed with a non-reserved mail
domain, refused. **ipv6** — covered: the guard refuses anything outside
`2001:db8::/32`, loopback and unspecified; probed with a unique-local, a
global and a link-local address, all refused. **mac-address** — not
covered: the guard has no MAC check, and the probe landed (F2). So "the
guard gates email and IP addresses more strictly" is true for the two
classes it names and silent about the third it switched off.

**Q2 — are the path exemptions whole-file, and does a later value pass.**
Yes and yes. Both ignore files are read by the shared loader as path globs:
a matching file is skipped whole, line by line is not an option. Probed in
act 1 for secretscan (F3: a token-shaped string appended to an exempt test
module landed). Probed in act 2 for leakscan: the documentation IBAN from
the ISO example, appended to a copy of `tests/fixtures/probes/
tls-handshakes.json` under a copy of `.leakscanignore`, passes clean; with
the ignore file removed it is a `high` finding. The guard still reads every
one of these files, so an address, host name, email address or GUID would be
refused; a credential or a personal-data shape would not. F3's
recommendation stands; the JSON exemption is sound for its reason (JSON
cannot carry a marker) and the gap it leaves is personal-data shapes in one
fixture file, acceptable if named.

**Q3 — what `extra-hook` protects on CI and on a fresh clone, and whether
the docs describe it.** On CI: nothing, and visibly so — the board prints
`skipped · local (not declared on the ci plane)`; it could not run there,
because the command lives in a clone's own config. On a fresh clone:
nothing until `make hooks` runs (no hook at all) and then nothing until the
contributor sets `takestock.extraHook`; "passes when none is set" is the
design, and the check prints `nothing to run` on every such run. The docs
describe the calling convention as it behaves (both halves verified in act
1, with the arguments and working directory as documented). Neither
`CLAUDE.md` nor `CONTRIBUTING.md` says the check is hook-only, and both say
CI runs "the same floor"; see Q5. One thing neither plane does is scan the
commit message in CI: addendum F8 below.

**Q4 — what trace a narrow exception leaves, and what enforces "narrow".**
In this repository, none: the exception lives in the contributor's own
check, outside every repo; `tools/extra_hook.py` relays an exit code and
nothing else; the floor board shows a tick or a cross. The only repo-side
record is the ruling itself, in the session record (F7). What a later pin
bump finds is the loud half of the mechanism: a bump that trips the
contributor's check blocks, and the block is the trace; an exception made
stale by atelier rewording the line simply stops mattering, silently, which
is harmless because it then excuses nothing. Nothing enforces "narrow": the
floor cannot read a check it does not ship, and "one word for one file" is a
convention the contributor keeps. That is the right shape for a check whose
contents must never enter the repository. Addition to F7's recommended
sentence: say the exception is keyed to the file and to the atelier pin it
was added for, so that a bump is a deliberate re-test rather than an
accident. No severity change.

**Q5 — do the docs and records agree with what runs, plane by plane.** On
*what* runs, yes: `guard` on both planes and `extra-hook` on the hook only
(`.atelier-floor.json` and the wiring record say so); the three advisories
on both planes with the same reasons; the shim and `floor.yml` unchanged
from atelier's. On *how much it covers*, the prose overstates CI twice:
`CLAUDE.md` ("runs the same floor on every push and pull request") and
`CONTRIBUTING.md` ("The same floor runs in continuous integration"). CI runs
the same registry with two declared differences: the extra hook is skipped,
and leakscan runs structural-only with no term list (the board renders it
🟡 partial, by atelier's design). And one surface runs on no CI plane at
all: the commit message (F8). The records agree with the files except where
act 1 already said (F4's "fails if there is none"); `CLAUDE.md`'s dev-loop
line is F6. Note **N3**: when F6's line is edited, change the two "same
floor" sentences to "the same checks, with leakscan structural-only and the
extra hook skipped".

**Q6 — the drift check's layout, and which stamp is the subject.** The
check assumes atelier at `../atelier` relative to the repository root. It
does not resolve from a worktree (this pass ran in one, and `../atelier`
there is not a clone), and in CI there is no sibling clone at all; the
reusable workflow checks atelier out itself and never runs a stamp check.
So the drift check works from a primary clone beside atelier and nowhere
else. The hook already knows where atelier is (`hooks.atelierTools`) and the
Makefile has `ATELIER`; a `make drift` target running the block's two
commands from `$(ATELIER)` would make the check layout-independent while
leaving the stamped text verbatim, which the floor rules require. A note,
not a finding on the subject: the placeholder and its relative-path
convention are atelier's, and the value is the one the brief names. On the
second half: the subject is the stamp as made at `0a2b7a7`, and it is also
the stamp as it should now read — atelier's `origin/main` has moved past
the pin, and the `floor` region is byte-identical at both (act 1, V2). No
bump is owed for the floor text. Whether the pin should bump for the rest of
what moved is a session-start act under the block's own *Source & drift*
bullet, and outside this pass.

### Addendum

**F8 — MINOR — commit messages are scanned by the local `commit-msg` hook
and by nothing in CI.** `CLAUDE.md`'s rule names commit messages as records
that must carry no organisation's data, and says the guard scans "every
commit message". It does, on the hook. `.github/workflows/ci.yml` runs `make
check` (the guard over the tree) and `floor.yml` runs tree scanners; neither
reads a message. A hook-less clone (which `CONTRIBUTING.md` admits commits
unscanned), a `--no-verify`, or a web edit lands a message in the public
history with every CI check green. **Recommendation:** a step in `ci.yml`
that runs `tools/guard.py --msg` over each message in the pushed range
(`git log --format=%B` per commit; `github.event.before` to the pushed SHA
on push, base to head on a pull request) and fails on a hit; `ci.yml` is
this repository's own, so it is the right home, not the thin floor caller.
Found while answering Q3 and Q5; no act 1 finding changes.

**Final verdict: PASS-WITH-FINDINGS.** Tally: 1 MAJOR (F1), 7 MINOR
(F2–F8), 2 notes (N2, N3); N1 closed on reconcile. The decisions on every
finding are the maintainer's (REVIEW.md rule 3); nothing has been applied.

## Deferred sibling, folded below the verdict (orchestrator, 2026-11-01)

The text below is the held-back sibling, copied verbatim by the
orchestrating session `d9664696` once act 2 was saved. It was removed from
the worktree before the reviewer started, held outside the repository
through act 1, and released to the reviewer only after act 1 was committed
(`f836875`). The orchestrator formed no finding and changed
no word of it; its questions are answered in *Act 2* above. The sibling
file itself is deleted in the same commit as this fold.

<!-- folded verbatim: begin -->

# Deferred — the atelier floor block and its wiring, cold review

🛑 **Open only after your own findings are written** to
`2026-11-01-1204-atelier-floor-block-and-wiring-cold.md` (REVIEW.md rule 1).
A floor, never a fence: answer each, then fold this file in below your
verdict and delete it.

All six are the brief-writer's; the authoring session seeded none.

Q1. For each advisory scanner and each leakscan rule switched off: what
class of value can now reach a commit with every blocking check green, and
does the guard really cover each class the disabled rules covered (email
addresses, IPv6 addresses and MAC addresses each, not only "addresses")?

Q2. The path exemptions in `.secretscanignore` and `.leakscanignore`: are
they whole-file, and would a value added to an exempt file later pass with
nothing red?

Q3. `extra-hook` passes when no command is set, and runs on the hook plane
only. On CI and on a fresh clone, what does that check protect, and do
`CLAUDE.md` and `CONTRIBUTING.md` describe it as it behaves?

Q4. The 2026-10-27 ruling: when a contributor adds a narrow exception in
their own check, what leaves a trace a later pin bump can find, and does
anything enforce "narrow"?

Q5. Do `CLAUDE.md`'s account of the wiring, `CONTRIBUTING.md` and the
session records agree with what `.atelier-floor.json`, the shim and
`floor.yml` actually run, plane by plane?

Q6. The stamped block's drift check assumes atelier at `../atelier`. Does it
work in another layout (a worktree, CI), and with atelier's mainline now past
`0a2b7a7`, what is the subject: the stamp as made, or the stamp as it should
now read?

<!-- folded verbatim: end -->
