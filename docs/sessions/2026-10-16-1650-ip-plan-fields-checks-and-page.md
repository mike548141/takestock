# 2026-10-16 — IP address plan: new fields, two check rules, and the page

## What was done

Five changes to the IP address plan (`takestock.ipam`, `takestock.ipam_view`),
one commit each:

- **A `history` kind of name.** A source can set `name_is: history` for an
  export that lists every address a device has held. Its names stay on each
  address but never make a name conflict or become previous names.
- **How an address was given out, and its VLANs.** Each address carries
  `assignment` (`static`, `dynamic`, or `disputed` when sources disagree) and
  `assignment_basis` (each statement, naming its source), read from an
  `allocation` or `dhcp` value a reader puts in a sighting's detail, and
  `vlans` from a `vlan` value there. The `csv` reader takes optional
  `assignment` and `vlan` columns.
- **Segment codes, exposure chains and an audience line.** A plan file can
  declare `segment_codes` (what the parts of segment names mean, with an
  optional environment), `exposure_chains` (the hops from the internet to a
  service, resting on a declared source) and `audience`.
- **Two check rules.** A subnet's `addressing` value the plan does not know is
  listed as a check, *Unknown addressing values*, and treated as `static`,
  rather than silently changing which name conflicts count. A superseding
  source can name with `cannot_see` the sightings it would never list, so an
  address the older source reports with one of those values is not flagged as
  only in the older source. A subnet vouched for only by a `record` source
  stays *documented only*, now pinned by a test.
- **The page.** The address finder takes a MAC address as well as an IP
  address; the view (section, address search, subnet filter) is kept in the
  page's address so a copied link reopens it; a plan file's `part` and
  `author` give a label above the title and a line under it, through new
  optional `eyebrow` and `byline` arguments to `htmlpage.page`.

`docs/IPAM.md` and the changelog describe each change.

## What was checked

- Each change has a test on a small synthetic plan (documentation addresses,
  invented names) that fails with the change taken out and passes with it.
- The page was driven in a headless browser twice: opened directly, and inside
  a sandboxed `srcdoc` frame with a null origin, the way some document
  previews show a page. In the frame, `history.replaceState` throws a
  `SecurityError`. With the guard, both runs raised no script errors, every
  tab, the address finder (IPv4, IPv6, MAC, an unknown MAC, nonsense) and the
  subnet filter worked, and links carrying `#find=`, `#filter=` and a section
  opened on that view when opened directly. With the guard removed, the
  framed run raised 19 errors and the address finder stopped answering. That
  probe found one defect, fixed before the commit: the page applied the
  address's view before the controls were listening, so `#find=` and
  `#filter=` links opened the right section with an empty result.
- `make check` passed after every change.

## What is left

- The browser probe is not part of `make check`, which needs no browser. The
  test suite checks the shape of the script instead: every change to the
  address sits inside a `try` block, and the view is opened after the last
  listener is attached.
