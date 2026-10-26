# 2026-10-26 — Adopt atelier's floor block

## What was done

- **`CLAUDE.md` now opens with atelier's floor block**, pinned at
  `atelier@0a2b7a7` (atelier's `origin/main` today). It is the canonical
  `floor` region of atelier's `docs/method/PROPAGATION.md`, copied word for
  word between `stamp:begin` / `stamp:end` markers. The four placeholders are
  filled: `../atelier` as the atelier path, `0a2b7a7` as the pin,
  `mike548141/takestock` as the repository, and a visibility fact saying the
  repository is public and released on PyPI. The block carries its own drift
  check (its *Source & drift* bullet), so a session that opens here learns when
  atelier's doctrine has moved past the pin.
- **The existing onramp is kept whole**, below the block. A short new section,
  *The atelier floor*, says the block is copied verbatim and reported upward
  rather than edited, that it and takestock's own rule both bind, and that
  atelier's scan hook and CI floor are not wired yet.
- **Roadmap**: a *Next* item to wire atelier's floor checks, with the size of
  the first red, and a queued `⏳` review of the stamped block.

This is an adoption, not a pin bump: takestock had no pin before, so there was
no earlier pin to diff from. What it now inherits was read at `0a2b7a7`: the
`floor` region and its stamp rules in `PROPAGATION.md`, the repository standard
(`docs/build/REPO-STANDARD.md`) and atelier's `create-repo` skill, which sets
out what a child carries.

## Checks

- The stamped block, with its four values put back as placeholders, is
  identical to the canonical region at `0a2b7a7`, checked by a direct diff.
  It also matches, line for line, the block another public child carries at
  the same pin, apart from the visibility fact. atelier's `stampscan` cannot
  make this check from a child: it resolves the stamp's source inside this
  repository, finds no `docs/method/` here, and stops with a configuration
  error.
- No placeholder is left unfilled anywhere in the tree.
- `tools/guard.py` passes over the tree and over the commit message.
- atelier's floor, CI plane, over the tree: six checks block (secretscan,
  leakscan, linkscan, datescan, wrapscan, spellscan) and pathscan warns. All
  of them were red before this change, and this change adds no finding to any
  of them.

## What is left

- **Wiring atelier's scan hook, CI floor and `.atelier-floor.json`.** Not done:
  the tracked hooks and CI are what every contributor and every push meets, and
  how atelier's checks join the guard is the maintainer's decision. On the
  roadmap.
- **The queued review** of the stamped block, for a session that did not
  author it.
- No changelog entry: nothing a user of the tool would notice changed.

## Identifiers

- Session: `8266042b`
- Worktree: `adopt-atelier-floor`, removed at close
- Pin: none → `atelier@0a2b7a7`
- Board: roadmap *Next* item "Wire atelier's floor checks"; queued review
  "the floor block stamped at atelier `0a2b7a7`"
