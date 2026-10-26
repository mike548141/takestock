# Exporting Exchange Online settings

takestock's `exchange_online` reader ([`COLLECTORS.md`](COLLECTORS.md#exchange_online))
reads an export of an Exchange Online organisation's settings: accepted
domains, DKIM signing, anti-phishing policies and rules, preset security
policy rules, inbound and outbound connectors, and quarantine policies. The
script below writes that export. It is **read-only**: every command it runs
is a `Get-*` cmdlet, so nothing is created, changed or removed, no mail is
sent, and no mailbox content is read.

## Running it

1. Save the script below as `export-exchange-online-settings.ps1`.
2. In PowerShell with the ExchangeOnlineManagement module installed, run
   `./export-exchange-online-settings.ps1`. It signs in with
   `Connect-ExchangeOnline` if no session is open, using an account that can
   read Exchange Online configuration.
3. It writes a folder named `exchange-online-settings-<UTC time>` in your
   home folder, and a zip of it beside it, and prints the zip's path.
4. Name the folder or the zip as the reader's input in the target profile:

   ```yaml
   plugins:
     - name: exchange_online
       input: inbox/exchange-online-settings-2030-01-31T0900Z.zip  # secretscan:allow: a file name
   ```

The folder holds one `<cmdlet>.json` per cmdlet, each object exported whole,
and a `manifest.json` recording each cmdlet's count, or its error when it
failed. A cmdlet the account cannot run is recorded and the rest still run.

`-IncludeDlp` also exports the mail flow rules and Microsoft Purview's data
loss prevention policies and sensitivity labels. **takestock does not read
those yet.** The Purview half needs `Connect-IPPSSession`, which Microsoft
documents as unavailable in PowerShell 7 on Linux and macOS, so run it from
Windows for that half.

The script has not been run by takestock's own tests: the reader's test
fixture is written by hand in the shape the script writes. Each cmdlet is
documented on Microsoft Learn under the Exchange PowerShell module
reference, at the cmdlet's name in lower case.

## The script

```powershell
<#
.SYNOPSIS
    Export the Exchange Online settings that takestock's exchange_online reader
    reads. Read-only.

.DESCRIPTION
    Runs nine Exchange Online PowerShell Get-* cmdlets and writes each one's
    objects, whole, to <cmdlet>.json in a new folder, with a manifest.json
    recording, for each cmdlet, whether it ran, how many objects it returned and
    any error. The folder is then zipped. Nothing is created, changed or removed,
    no mail is sent, and no mailbox content is read: every command is a Get-*.

    The cmdlets, and the Secure Government Email requirements takestock grades
    from them (takestock's docs/COLLECTORS.md, exchange_online):

      Get-AcceptedDomain, Get-DkimSigningConfig, Get-OutboundConnector
          SGE-DKIM-01, outbound mail DKIM signed
      Get-AntiPhishPolicy, Get-AntiPhishRule, Get-EOPProtectionPolicyRule,
      Get-ATPProtectionPolicyRule, Get-InboundConnector
          SGE-DMARC-02, inbound mail checked for DMARC and acted on
      Get-QuarantinePolicy (with the anti-phishing policies)
          SGE-DMARC-R04, mail failing DMARC kept in a quarantine only an
          administrator releases from

    Each cmdlet is documented at
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/<cmdlet>,
    the cmdlet's name in lower case.

    OPTIONAL, AND NOT YET READ BY TAKESTOCK: -IncludeDlp adds the settings for
    the framework's data loss prevention requirements: Get-TransportRule from
    Exchange Online, and Get-DlpCompliancePolicy, Get-DlpComplianceRule,
    Get-Label and Get-LabelPolicy from Security & Compliance PowerShell, which
    needs Connect-IPPSSession. Microsoft's page "About the Exchange Online
    PowerShell V3 module" says: "Currently, Connect-IPPSSession and therefore Security & Compliance
    PowerShell isn't available in PowerShell 7 on Linux clients", and the same
    for macOS. Run the script from Windows for that half. A failure to connect
    is recorded in the manifest and the Exchange half is still written.

.PARAMETER OutputDirectory
    The folder to write. By default, exchange-online-settings-<UTC time> in
    your home folder. The zip is written beside it, with the same name.

.PARAMETER IncludeDlp
    Also export the data loss prevention settings described above.

.EXAMPLE
    ./export-exchange-online-settings.ps1

    Signs in with Connect-ExchangeOnline if no session is open, then writes the
    folder and zip and prints the zip's path.

.NOTES
    Needs the ExchangeOnlineManagement module and a sign-in that can read
    Exchange Online configuration. A cmdlet the account cannot run is
    recorded in the manifest, and the rest still run.
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $HOME ('exchange-online-settings-' +
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ'))),
    [switch] $IncludeDlp
)

$ErrorActionPreference = 'Stop'
$taken = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ')
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$readings = [System.Collections.Generic.List[object]]::new()

function Export-Reading {
    param([string] $Part, [string] $Cmdlet, [hashtable] $Arguments = @{})
    $file = "$Cmdlet.json"
    try {
        $objects = @(& $Cmdlet @Arguments | Select-Object -Property *)
        ConvertTo-Json -InputObject $objects -Depth 4 -WarningAction SilentlyContinue |
            Set-Content -Path (Join-Path $OutputDirectory $file) -Encoding utf8
        $readings.Add([ordered]@{ part = $Part; command = $Cmdlet; ok = $true
                                   count = $objects.Count; file = $file })
        Write-Host ('  {0,-30} {1,5} object(s)' -f $Cmdlet, $objects.Count)
    }
    catch {
        $message = ($_.Exception.Message -split "`r?`n")[0]
        $readings.Add([ordered]@{ part = $Part; command = $Cmdlet; ok = $false
                                   count = 0; error = $message })
        Write-Warning "$Cmdlet failed: $message"
    }
}

function Add-Failure {
    param([string] $Part, [string] $Cmdlet, [string] $Message)
    $readings.Add([ordered]@{ part = $Part; command = $Cmdlet; ok = $false
                               count = 0; error = $Message })
    Write-Warning "$Cmdlet failed: $Message"
}

# ---------------------------------------------------------------- Exchange Online
Write-Host 'Exchange Online'
$exchange = $true
if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
    try { Connect-ExchangeOnline -ShowBanner:$false }
    catch {
        $exchange = $false
        Add-Failure 'exchange' 'Connect-ExchangeOnline' (($_.Exception.Message -split "`r?`n")[0])
    }
}
if ($exchange) {
    Export-Reading 'exchange' 'Get-AcceptedDomain'
    Export-Reading 'exchange' 'Get-DkimSigningConfig'
    Export-Reading 'exchange' 'Get-OutboundConnector'
    Export-Reading 'exchange' 'Get-InboundConnector'
    Export-Reading 'exchange' 'Get-AntiPhishPolicy'
    Export-Reading 'exchange' 'Get-AntiPhishRule'
    Export-Reading 'exchange' 'Get-EOPProtectionPolicyRule'
    # Fails in an organisation without Defender for Office 365; recorded, not fatal.
    Export-Reading 'exchange' 'Get-ATPProtectionPolicyRule'
    Export-Reading 'exchange' 'Get-QuarantinePolicy'
    if ($IncludeDlp) {
        Export-Reading 'exchange' 'Get-TransportRule' @{ ResultSize = 'Unlimited' }
    }
}

# ------------------------------------------- Security & Compliance (optional)
if ($IncludeDlp) {
    Write-Host 'Security & Compliance (data loss prevention; not yet read by takestock)'
    $compliance = $true
    if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
        try { Connect-IPPSSession -ShowBanner:$false }
        catch {
            $compliance = $false
            $why = ($_.Exception.Message -split "`r?`n")[0]
            if ($IsLinux -or $IsMacOS) {
                $why += ' (Microsoft documents Connect-IPPSSession as unavailable in PowerShell 7 on Linux and macOS)'
            }
            Add-Failure 'compliance' 'Connect-IPPSSession' $why
        }
    }
    if ($compliance) {
        Export-Reading 'compliance' 'Get-DlpCompliancePolicy'
        Export-Reading 'compliance' 'Get-DlpComplianceRule'
        Export-Reading 'compliance' 'Get-Label'
        Export-Reading 'compliance' 'Get-LabelPolicy'
    }
}

# ---------------------------------------------------------------- manifest
$module = Get-Module ExchangeOnlineManagement | Select-Object -First 1
[ordered]@{
    pulled_utc      = $taken
    script          = 'export-exchange-online-settings.ps1'
    powershell      = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    exchange_module = $(if ($module) { "$($module.Version)" } else { $null })
    readings        = $readings
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8

$zip = "$OutputDirectory.zip"
Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $zip -Force
$failed = @($readings | Where-Object { -not $_.ok }).Count
Write-Host ''
Write-Host "Wrote $($readings.Count) reading(s), $failed failed (each failure is in manifest.json):"
Write-Host "  $zip"
```
