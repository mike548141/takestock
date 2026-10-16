# 2026-10-16 — Register: names against machines, and when a port makes a service

## What was done

Five rules of the configuration register (`takestock.cmdb`) about names,
machines and services were examined on synthetic rows. Two were changed, and
three were kept with their reasons written down:

- **Changed: a DNS probe of a port is about a machine.** A row whose protocol
  is `dns` or `dnssec` was always read as being about a name. A probe of a
  machine answering DNS on a port, such as `53/udp`, therefore made a DNS
  Name carrying the machine's name, and no Network Service. Such a row now
  counts as a machine row when it names a port; a DNS or DNSSEC reading
  with no port is still a DNS Name, and a discovery or mail-authentication
  row stays a name row even when it names a port.
- **Changed: one `contains` edge per machine and service.** Every row naming
  a listener drew its own edge, so a listener that a TLS scan and an HSTS
  reading both named had two. The edge is now drawn once, with the strongest
  evidence among those rows, then the most recent.
- **Kept: a DNS-layer reading is a DNS Name, never a Host.** A zone's top
  read for DNSSEC and a service-record name from a zone file describe what a
  name publishes, not a machine.
- **Kept: a name and a machine spelled alike are two items.** Names and
  machines are keyed on different alias kinds, so the order of the rows
  cannot fold one into the other, and the register does not join them
  because `resolves-to` is not drawn.
- **Kept: a port alone makes a Network Service**, including on a Host
  labelled with an address when the probe named only an address. A probe
  that got an answer on a port has measured a listener, whichever field
  holds the port.

`docs/CMDB.md` ("How rows become items" and "Relationships") describes all
five rules; the module docstring and the changelog describe the two changes.

A second change makes the list of machines a software row is installed on
robust to the readers that write it:

- **The list is read from `extra.installed_on`**: a list of names, or names
  separated by commas. A name holding a space is refused, because it cannot
  be one host name, and the build stops naming the row's source.
- **`extra.hosts` stands in only as a list of names.** Before, any
  `extra.hosts` string was split on commas, so a count of machines such as
  `"3"` became a machine called `3`, and a string of names joined by spaces
  became one machine whose name was the whole string. A `hosts` string is
  now not read at all.
- The software inventory's rows carry `installed_on`, a list, beside their
  `hosts`, which is unchanged.

The installed-on list had not been released, so the rename changes nothing
for any user; the changelog says so.

## What was checked

- Four new tests on synthetic rows: DNS readings and a DNS listener, a name
  and a machine spelled alike in both row orders, a probe of an address, and
  three rows naming one listener.
- Two more for the installed-on list: a `hosts` count, a space-joined
  `hosts` string and a `hosts` list holding a space-joined entry make no
  machine; an `installed_on` that is space-joined, holds an entry with a
  space, or is a number is refused. The inventory test checks the new list.
- Each rule was taken out in turn, with the compiled-file cache cleared, and
  a new test went red each time: reading every `dns` row as a name; never
  reading one as a name; keying names as host names; reading no `port`;
  drawing an edge per row; keeping the first row's evidence rather than the
  strongest. The file was then restored and compared byte for byte.
- The same was done for the installed-on list, and a test went red each
  time: reading `hosts` in any shape; reading a `hosts` list whatever its
  entries hold; accepting an entry with a space; accepting a value that is
  neither a list nor a string; ignoring `installed_on`; the inventory not
  writing it.
- `make check` (guard, ruff, mypy, tests) passed.

## What is left

- A machine row whose host is an address is keyed on the `hostname` alias
  kind, and records the address as its `hostname`. The schema's `address`
  alias kind fits it better, but changing it would give those items new keys
  for anyone holding a `keys.jsonl` from an earlier build, so it is left for
  a decision.
- A `hosts` list whose entries hold no space is read as names, so a list
  holding a bare number still makes a machine of it. A reader that means a count
  should not put it in a list.
