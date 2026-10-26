# 2026-10-26 — The register's Read me sheet, and one citation's wording

## What was done

- **The Read me sheet's date line.** It said *"Observation <stamp>, recorded
  <date>. Schema <version> (<maturity>)."* For a derived observation
  (`takestock rerun`) the stamp is the derived observation's and the
  recording date is the full observation's, so the line read as though the
  data had been recorded before the observation it named. It now says when
  the data was read, in a sentence: *"The data was read on 2030-01-10; 1 of
  its sources was read again on 2030-01-25."*, or a range when sources were
  read again on several days, or just the date for an ordinary observation.
  The register carries the dates as `register.read_on` and
  `register.read_again` (each plug-in read again, with the date it last
  was), built from the same derived-observation record that already dates
  each fact. A recording date given to the build does not change the read
  date of a derived observation or of one named by a time stamp; for any
  other, the read date is the recording date. The time stamp, the
  recording date and the schema version stay in the JSON.
- **The counts line** carries thousands separators, and calls the items
  what `item_noun` says: a new `cmdb:` profile key and a keyword to
  `build_register` and `register_payload`, in the plural. The default is
  still *configuration items*, the CMDB term; a profile can use the word its
  readers use. A blank or non-text value in a profile is refused.
- **The commentary on RSA 2048-bit against NZISM 17.2.24.C.01 and
  17.2.25.C.01** is reworded in plainer language. The substance, and every
  control cited, is unchanged.
- `docs/CMDB.md`, `docs/TARGET-PROFILE.md` and the changelog say so.

## Checks

- New tests on synthetic observations of the invented Example Widgets Ltd:
  the date sentence for a derived observation with one source read again,
  with sources read again on two days, and for an ordinary observation; the
  read date unchanged by a given recording date; the default and a caller's
  noun; a profile's noun, and blank or non-text values refused; thousands
  separators on large counts. All thirteen fail against the code before
  this change and pass with it.
- `make check`: guard, ruff, mypy and the whole test suite.

## Left

- Nothing owed from this change.
