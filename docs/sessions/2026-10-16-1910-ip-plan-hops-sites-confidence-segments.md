# 2026-10-16 — IP plan: network hops, site precedence, confidence, retired segments

## What was done

Four changes to the IP address plan (`takestock.ipam`), each a rule that read
a plan more weakly or less exactly than its evidence allows:

- **An exposure-chain hop may be a network.** A hop's `address` can be a
  network in CIDR form, for a group of machines a request may reach any one
  of (the workers behind a load balancer). It is written as `network` and the
  page shows it as a network. A network with host bits set, a malformed
  prefix and anything that is not an address are still refused, and a `/32`
  or `/128` is read as its one address.
- **A declared site range outranks a source's site.** A subnet a source
  declares now goes to the site whose plan-file range holds it most
  specifically, even when the source names another site. The source's site is
  used only when no range holds the subnet. This is what `docs/IPAM.md`
  already said for declared subnets; the code took the source's site first
  whenever one was given.
- **A source-declared subnet is as strong as its source.** It reads
  `confidence: measured` when its source is of class `observed`, the class
  already trusted to have seen addresses in use, and `declared` otherwise. A
  source whose subnets come from typed names can set `evidence: named`.
- **A segment only replaced sources list is retired.** When a source that
  lists segments supersedes another, a segment only the older source lists
  is marked `superseded_by`, kept with its subnet and date, and left out of
  the segment and VLAN counts and the VLAN check. `Segment` takes an optional
  `detail`, so a newer source's `cannot_see` can say which segments it would
  never list. A newer source that lists no segments retires none.

One rule was examined and kept: a `record` source (a public record such as a
certificate-transparency log entry) still counts as a document for the
"subnets known only from documents" check. Such an entry shows a certificate
was issued for a name, not that anything answers at the address, so it
documents a subnet without confirming it. `docs/IPAM.md` now says why.

`docs/IPAM.md` states each rule and its reason, and the changelog records
each change.

## What was checked

- Each change has a test on a synthetic plan and reader. With the source
  changes taken out, all five new or extended tests failed; with them back,
  they passed.
- The sample organisation's plan was built before and after. Its CSV and
  page are byte-identical, and its JSON differs only by the new
  `counts.segments_superseded` (0), since the sample has no segments.
- `make check` (guard, ruff, mypy, tests) passed.

## What is left

- A reader has to put a segment's type in `detail`, and the plan has to name
  it in `cannot_see`, for a newer source that cannot see some kinds of
  segment. Nothing infers that blindness.
- A retired segment's subnet keeps the older source as its evidence. The
  plan does not yet say that the subnet may have gone with the segment.
