# Roadmap: the board

What is planned next for takestock. A finished item
is marked `[x]` in its own file, and the change it made is recorded in
[`CHANGELOG.md`](../../CHANGELOG.md). To propose an item, open an
issue.

One file per item, in `<NNN>-<section>/<NNN>-<slug>.md`: the item's state line
first, its detail beneath, and its own `git log` as its history. Each
section's `README.md` holds that section's heading and narrative.
[`../ROADMAP.md`](../ROADMAP.md) is the index, generated from these files by
atelier's `tools/board.py --rebuild`; edit the item, never the index, and
rebuild the index in the same commit.

State lines:

- `[ ]` work is still owed. A 🎯 on the line marks a decision that is the
  maintainer's to make.
- `[x]` no more work is owed: delivered, superseded or declined, with the
  outcome said in the item's own text.
- `[~]` claimed by a session working on it now; take another item.
- `⏳` a review is queued and has not yet returned a verdict.
