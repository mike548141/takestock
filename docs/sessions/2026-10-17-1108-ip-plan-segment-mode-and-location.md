# 2026-10-17 — IP plan: segment mode, VLAN from an older source, segment locations, headed summary

## What was done

- **Segment mode.** `ipam.Segment` has two new optional fields: `mode`
  (`access`, `trunk`, or empty when the source does not say) and
  `trunk_vlans` (the VLANs a trunk carries, as the source writes them). Both
  are written to the segment's row when set. Any other mode, or trunk VLANs
  on a segment that is not a trunk, stops the build with the source and
  segment named.
- **A VLAN from an older source.** A segment's row still comes from the
  newest source that reports it. Where that source gives no VLAN and the
  segment is not a trunk, the row keeps the VLAN the newest older source
  stated, and `vlan_source` names that source. A stated VLAN is never
  replaced, a trunk is never given an older single VLAN, and a VLAN an older
  source gave a trunk is never kept. The kept VLAN counts like any other:
  in the subnet's `vlans`, the VLAN count and the VLAN check.
- **Segment locations.** A new plan-file key, `segment_location: {separator,
  names}`. With a separator set, the text before its first occurrence in a
  segment's name is the segment's `location`, and only the rest is read
  with `segment_codes`. So a leading cluster or switch-stack name is never
  read as a purpose, even when it shares its letters with a code
  (with codes `ops: operations` and `prd: production`, `ops.ops-web-prd`
  reads *operations, web, production* in location `ops`).
  `names` says what each location is (matched ignoring case) and is written
  as `location_meaning`. `ipam.split_location(name, separator)` does the
  split. A subnet a segment declares takes its purpose reading from the rest
  of the name only; the purpose still names the whole segment.
- **Headed summary items.** A `summary` item may be `{heading, text}`. It is
  written to the JSON as `{"heading", "text"}` (heading empty when absent)
  and shown on the page as a heading over its paragraph. Unknown keys, a
  missing `text`, or a list stop the build. Plain text items are unchanged.
- **The page.** The VLANs and segments table has a *Mode and notes* column
  (the mode with any trunk VLANs, and, for a kept VLAN, the source that
  stated it and its date), and a segment's name shows its location.
- **Docs**: `IPAM.md` (the summary key, a *Segment locations* section, the
  two `Segment` fields, how a kept VLAN is chosen, the page), the changelog.

## Checks

- New tests: a kept VLAN, a stated VLAN left alone, a trunk left without
  one, and an older trunk's VLAN not kept; mode and trunk VLANs written,
  and the two refusals; a location read apart from the codes, with and
  without codes, and the four refusals; `split_location` edge cases;
  headed summary items and their three refusals; the page's new column,
  location and heading.
- Twenty mutations, one at a time with `__pycache__` cleared, each turned
  its named tests red, and each file was restored byte for byte.
- `make check`: guard, ruff, mypy and the full test suite.

## Left

- The page does not yet show an access VLAN that changed between an older
  and a newer source.
- Segment names are still split at spaces as well as hyphens, underscores
  and dots.
