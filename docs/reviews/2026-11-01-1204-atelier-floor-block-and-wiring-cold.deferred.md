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
