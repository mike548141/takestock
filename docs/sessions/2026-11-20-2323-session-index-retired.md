# 2026-11-20 — The session index is retired; the folder is the log

**Done.** `docs/SESSIONS.md` is retired into this folder by atelier's
`tools/archivecut.py`, following atelier's own change the same day. Each of
its 41 entries now sits word for word near the top of the session file it
linked, with its link re-pointed for the folder; its preamble is kept word
for word in `docs/sessions/README.md`. `CLAUDE.md` now says the folder is the
index and a session starts by reading the newest few files
(`ls docs/sessions | sort | tail -5`).

**Checked.** `archivecut.py --verify` rebuilds the retired file byte for byte
from the README and the 41 session files. The roadmap index was already
current. Older roadmap items and changelog lines that name `docs/SESSIONS.md`
are records and keep their words.

**Left.** Nothing from this change.
