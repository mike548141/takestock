# 2026-11-01 — Brief the queued review of the atelier floor

## What was done

- **A brief for the queued rule-4 pass**, in a new `docs/reviews/`:
  `2026-11-01-1204-atelier-floor-block-and-wiring-cold.md`, with its held-back
  sibling (`.deferred.md`, six questions) for the reviewer to open only after
  writing its own findings. The brief names the subject and the claims it
  makes, and no verdict.
- **Scope.** The queued item named the stamped floor block (`ddf9417`). The
  brief also takes in the wiring that put that floor into force (`8e1e83d`)
  and the ruling recorded after it (`1f7254a`), because no other pass covers
  them. The brief says the widening is the brief-writer's call.
- **Roadmap:** the queued item now names the brief. It still waits for the
  maintainer's approval of Fable work; the review was not run.

## Checks

Each re-run line the brief gives was run once before it was written down, on
`f980bec`: the stamp against atelier's canonical `floor` region at `0a2b7a7`,
atelier's floor on the CI plane, and `make check`. The results are in the
brief.

## What is left

- The review itself, on the maintainer's approval.
- No changelog entry: nothing a user of the tool would notice changed.

## Identifiers

- Worktree: one, removed at close
- Pin: `atelier@0a2b7a7`, unchanged
