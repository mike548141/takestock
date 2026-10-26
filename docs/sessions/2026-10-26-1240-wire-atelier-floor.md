# 2026-10-26 — Wire atelier's floor

Continues the earlier session record `*-adopt-atelier-floor.md`, which
stamped the floor block and left the wiring to the maintainer. The maintainer
chose to wire it the way atelier's other public children do.

## What was done

- **`.githooks/pre-commit` is atelier's shim**, copied from atelier at
  `0a2b7a7` with its one placeholder filled (`../atelier/tools`). It names no
  scanner; it runs atelier's `tools/floor.py`. It is byte for byte the shim
  another public child carries.
- **takestock's own pre-commit checks run inside it** as `local` checks in
  `.atelier-floor.json`: `guard` (`tools/guard.py`, on the hook and in CI) and
  `extra-hook` (new `tools/extra_hook.py`, on the hook only), which runs a
  contributor's `takestock.extraHook` command as `<command> pre-commit` and
  passes when none is set. `.githooks/commit-msg` is unchanged.
- **`.atelier-floor.json`** declares the licence (Apache-2.0, so licenscan
  runs), and:
  - datescan, spellscan and wrapscan **advisory** until 2027-01-31, each with
    its reason; the roadmap carries clearing them;
  - leakscan's `email`, `ipv6` and `mac-address` rules **off**, because
    addresses are this tool's content and the `guard` check gates email and IP
    addresses more strictly (reserved names and documentation ranges only).
- **Path exemptions with reasons**: `.secretscanignore` names the loopback
  stub transcripts in `tests/fixtures/probes/` and three test modules whose
  synthetic values read as high-entropy (a line marker would break the lint
  limit there); `.leakscanignore` names one JSON record of stub handshakes.
  Two example file names in the guides carry a `secretscan:allow:` marker.
- **One broken link fixed**: the README's anchor into `docs/ARCHITECTURE.md`
  had lost its `-carrypy` suffix.
- **`.github/workflows/floor.yml`** is atelier's thin CI caller, unchanged from
  atelier's template: every push and pull request runs the floor through
  atelier's reusable workflow, with read-only permissions. `sign-boundary` is
  empty, because every commit in the history is signed.
- **`make hooks`** now also sets `hooks.atelierTools` to the tools of an
  atelier clone (`ATELIER`, by default `../atelier`), and fails if there is
  none. `CONTRIBUTING.md` says what the hook runs, how to set it up, and how
  to prove it is live; `CLAUDE.md` describes the wiring.

## Checks

- atelier's floor, CI plane, with no personal-data terms (as CI runs it):
  passes. Every blocking check is clean; the three advisories and the
  warn-only pathscan report.
- The hook plane, on this change's staged files: every atelier check passes,
  and the two local checks run.
- `tools/guard.py` passes.
- The shim matches the one another public child carries, and `floor.yml`
  matches atelier's template.

## What is left

- Clearing the three advisory checks (roadmap).
- The queued review of the floor block.
- No changelog entry: nothing a user of the tool would notice changed. A
  contributor will notice `make hooks` now needs an atelier clone, and
  `CONTRIBUTING.md` says so.

## Identifiers

- Session: `8266042b`
- Worktree: `adopt-atelier-floor`, removed at close
- Pin: `atelier@0a2b7a7`, unchanged
- Board: roadmap *Next* item "Clear the floor's advisory checks by
  2027-01-31"
