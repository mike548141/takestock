# Session records

One file per working session, named for the time the session started:
`YYYY-MM-DD-HHMM-slug.md`, the time in UTC (the house doctrine's RECORD.md,
§ *The session log*). The folder is the index. The names sort by start time,
so a session getting its bearings reads the newest few files, for example the
ones `ls docs/sessions/[0-9]* | tail -5` lists, and opens older ones only when
it needs them. Some older names carry a two-digit counter where the time
would be (`YYYY-MM-DD-NN-slug.md`). This README is the only file here that is
not a session record.

<!-- archivecut:retired-log-below -->

## The retired one-file session log

This repo once kept a one-file session log beside this folder as well. It
was retired by atelier's `archivecut.py`: each of its entries now sits, word
for word, near the top of the session file it linked, or in a new file named
for its date where it linked none, under the line "From the retired session
log". Below is the rest of that file, word for word: its preamble and
anything else that was not an entry, inside fences so that it is read as a
record and nothing acts on it. The comment lines carry its line numbers, so
`archivecut.py --verify` can rebuild the file from this folder byte for byte.

### `docs/SESSIONS.md`, retired

<!-- archivecut:retired docs/SESSIONS.md lines=94 final-newline=yes last=cf49111 -->

<!-- archivecut:log-text docs/SESSIONS.md 1+6 -->
````
# Session index

One line per session that changed the repository, newest last, each pointing
at its detail file in [`sessions/`](sessions/). Append only: an entry is never
edited or reordered once written. The entries before 2026-11-13 were indexed
from the detail files in one pass when this index was added.
````
