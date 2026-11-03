# 2026-11-03 — A Windows drive encryption and recovery-key escrow reader in the readers library

## What was done

- **`takestock.readers.m365_bitlocker`** (`general`, no default input): reads
  a CSV of Intune-managed Windows devices joined to the BitLocker recovery
  keys held in Microsoft Entra ID and grades each device on encryption and
  key custody together. Only Microsoft Entra ID is read: a copy kept in
  Active Directory Domain Services, a file, on paper or by a data recovery
  agent is not, and the rows and docs say so. Further exports are optional settings:
  `encryption_report` (the Intune encryption report), `managed_devices`
  (Intune's device list), `directory_devices` (Microsoft Entra ID's device
  objects, counts only), `escrow_missing` (a no-key subset, checked against
  the main file) and `cross_check` (another product's drive-encryption
  export, with its name, label, `extra` key, columns and "encrypted" values
  as settings). Rows: one per device, a scope row reconciling the registers,
  a TPM row and a row for enrolled devices that are not Windows.
  `escrowed_devices(path)` gives another reader of the same devices the names
  this one covers.
- `roles.py`: four role phrases for the new rows.
- `docs/COLLECTORS.md`: the library table row and a section, with Microsoft
  Graph PowerShell for the main CSV and the directory devices, written from
  Microsoft's documentation and not run.
- Changelog.

Sources read on 3 November 2026 (UTC), all on learn.microsoft.com: *BitLocker
recovery overview* (events that start BitLocker recovery, among them clearing
the TPM and a new motherboard with a new TPM; where else a recovery password
may be kept; data recovery agents); *View
report details for encryption status of devices managed with Microsoft
Intune* (the report's fields, "Encryption status" as whether the OS drive is
encrypted, the profile state summary as the least favourable condition, the
Windows status detail "The encryption method of the OS volume doesn't match
the BitLocker policy.", and CSV export); the Microsoft Graph pages *device
resource type* (`trustType` `Workplace` indicates bring-your-own personal
devices), *managedDevice resource type* (`isEncrypted` and the other columns
the script writes), *List managedDevices*
(`DeviceManagementManagedDevices.Read.All`), *List devices*
(`Device.Read.All`), *bitlockerRecoveryKey resource type* (`createdDateTime` is when the key was
originally backed up to Microsoft Entra ID; `volumeType` 1 is the
operating-system volume) and *List recoveryKeys* (does not return the key;
`BitlockerKey.ReadBasic.All` least privileged; with delegated sign-in the
caller must own the device or hold one of six listed roles).

## Checks

- 27 tests on fixtures composed in the test file (made-up device names,
  column headings, models and serials, dates in 2030).
- Thirty-six changes to the new code, each made in a scratch copy of the
  source, were run against those tests: all turned a test red (one only after
  an assertion was added for it), and the unchanged copy stayed green.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the PowerShell in `docs/COLLECTORS.md` against a test tenant.
- Microsoft's documentation lists the encryption report's fields but not the
  CSV headings of its export, nor those of the Intune device list export;
  the reader names the headings it reads.
- The `RiskState` label is the script's own; only the label meaning "not
  encrypted or unknown" changes a flag, and only its wording.
