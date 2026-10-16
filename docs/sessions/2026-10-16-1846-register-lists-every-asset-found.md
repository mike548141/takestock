# 2026-10-16 — The configuration register lists every asset found

## What was done

Five changes to the configuration register (`takestock.cmdb`) and the
collectors that feed it, one commit each:

- **Software with no host.** A row that names software and no machine, such
  as a software inventory's row for one product at one version, now makes its
  Software Product and Software Release. The release is installed on each
  machine the row names in `extra.hosts`, and a machine only that list names
  becomes a Host, counted under the inventory in the population rows. A row
  flagged `version-spread:` counts versions and makes no release.
- **Every product an inventory names.** The software inventory's scope row
  lists every product the export names, cryptographic or not, in
  `extra.software_products`, and the register makes a Software Product for
  each. A product outside the cryptographic software register is still not
  graded.
- **Network devices typed by their category.** With no host type on a row, a
  network device export's equipment category decides the class: a switch,
  router, firewall, wireless device or VPN gateway is a Network Device. A
  WAN link, an out-of-band management processor, storage and "other" stay a
  Host.
- **Every name a zone file publishes.** The zone file reader's "names nobody
  measured" row lists every published name in `extra.dns_names`, and the
  register makes a DNS Name for each. The observation gains no rows.
- **Machines from an IP address plan, when asked.** `takestock cmdb
  --ip-plan <plan>.json` (and `ip_plan=` in Python) makes an item for each
  machine the plan names at an address, with the plan's addresses for it. It
  is off unless given. Aliases, labels, past holders and addresses only a
  superseded source lists are left out.

`docs/CMDB.md`, `docs/COLLECTORS.md`, `docs/PLUGINS.md`, `docs/IPAM.md`, the
schema's `built_from` wording and the changelog describe each change.

## What was checked

- Each change has a test on synthetic rows, and a second test that feeds the
  real collector's output (software inventory, network device export, zone
  files, the sample IP plan) into the register, so the row shape the
  collector writes and the shape the register reads are tested together.
  Each new line was taken out in turn and the tests that depend on it went
  red, then it was restored.
- The sample organisation was observed offline and its register built after
  each change: the inventory's providers and its non-cryptographic product,
  the three network devices, the zone names and, with `--ip-plan`, the plan's
  machines all appear. The observation's row count did not change.
- `make check` passed after every change.

## What is left

- A machine is matched on its name exactly as each source spells it, so a
  short name from one source and a full name from another make two items.
- For a product outside the cryptographic software register, only its name
  is kept: not its versions or the machines carrying it.
- A zone file's names become DNS Names without their addresses: the reader
  keeps one record per name, which would be a partial address.
