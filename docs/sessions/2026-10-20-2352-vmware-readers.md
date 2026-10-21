# 2026-10-20 — VMware readers

## What was done

- **`vmware`**, in `readers/vmware.py`, kind `general`: a CSV of vSphere VM
  Encryption and vSAN encryption state, one row per virtual machine or vSAN
  cluster, in columns documented in `COLLECTORS.md` with a PowerCLI script
  that writes them. A vSAN cluster with encryption off is `weak`; a machine
  with it off is flagged `vm-encryption-off` and not graded, because the
  storage beneath may encrypt its files. Encryption on is graded as
  `aes256_xts`, the one cipher vSphere uses (Broadcom's vSphere 8.0
  documentation). Key custody is flagged by key provider type.
- **`rvtools`**, in `readers/rvtools.py`: RVTools workbooks, one or a folder.
  Firmware and secure-boot rows over machines powered on, ESXi version rows,
  configured guest type rows and a scope row reconciling `vInfo` rows to
  machines (templates and Site Recovery Manager placeholders left out). The
  workbooks have no encryption columns, and the scope row says so.
- **`vsphere_lists`**, in `readers/vsphere_lists.py`: the vSphere Client's
  exported lists of virtual machines, hosts and datastores, one site per file
  label. Per site: VM encryption, virtual TPM and virtualisation-based
  security; across sites: guest types and ESXi versions with vendor support
  status from a lifecycle table (bundled, or named with `settings:
  {lifecycle: …}`); per host: certificate expiry as at the export date; per
  site: datastores by what backs them, from the IEEE maker prefix in each
  device's NAA identifier, with datastores on disks inside hosts as a
  coverage gap.
- `vmware` and `rvtools` take `settings: {vsphere_lists: <folder>}`. When that
  folder holds a virtual-machine list, `vmware` raises no gap for a missing
  export and `rvtools` writes only its firmware rows, since the lists carry
  the rest.
- **Roles** for the new rows; the three readers in the library's table and
  their own sections in `COLLECTORS.md`; the changelog.
- **Guard allow-list**: `techdocs.broadcom.com`, Broadcom's documentation
  site, cited for vSphere's cipher and for the virtual TPM's precondition.

## Checks

- Fixtures written by hand: `tests/fixtures/vmware/example-vm-encryption.csv`
  (the reader's columns) and `tests/fixtures/vsphere_lists/` (the Export
  action's shape: a byte-order mark, every value quoted, a heading with a
  line break). RVTools workbooks are built in the tests with openpyxl. All
  names are synthetic, and the hosts are under `example.test`.
- New tests cover every graded state and flag, placeholders and templates,
  the site and date taken from file names, the lifecycle setting and the
  bundled default, certificate expiry from the export date, datastore
  placement, the `vsphere_lists` setting of the other two readers, the ways
  nothing is read, and the declarations. Seventeen changes to the readers'
  behaviour were each made in a scratch copy, and each turned a test red.
- `make check`: guard, ruff, mypy and the full test suite.
- The PowerCLI script was written from VMware's API and PowerCLI
  documentation and has not been run against a vCenter.

## Left to do

- More readers for the library, one product or format at a time.
