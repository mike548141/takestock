<#
.SYNOPSIS
    Export how mail flows through a Microsoft 365 organisation, for takestock's
    mailpath reader (takestock.mailpath.m365). Read-only.

.DESCRIPTION
    WHAT IT READS. Exchange Online PowerShell Get-* cmdlets only:

      Get-AcceptedDomain              the domains the organisation receives mail for
      Get-InboundConnector            who may hand mail in, and the TLS and certificate asked of them
      Get-OutboundConnector           where mail is handed out (smart hosts), and the TLS demanded
      Get-DkimSigningConfig           which domains are DKIM signed, key sizes, selectors
      Get-TransportRule               each mail flow rule's name, state, mode, priority, and the NAMES
                                      of the conditions and actions it sets (values only for routing
                                      and TLS actions; never the words, addresses or patterns it matches)
      Get-RemoteDomain                per-destination settings (auto-forwarding, formats)
      Get-ArcConfig                   the ARC sealers the organisation trusts
      Get-HostedContentFilterPolicy   the authentication-failure actions of the anti-spam policies
      Get-MailFlowStatusReport        message counts by day, direction and event type
      Get-MessageTraceV2              one row per message and recipient: when, sender and recipient,
                                      status, the sending and receiving addresses, size and IDs

    With -EmailEvents, and only then, it also runs one advanced hunting query
    against Microsoft Defender for Office 365's EmailEvents table through
    Microsoft Graph (POST /security/runHuntingQuery, delegated permission
    ThreatHunting.Read.All). A tenant without Defender for Office 365, or an
    account without that permission, is recorded in the manifest and the rest
    of the export is still written.

    IT CHANGES NOTHING. Every Exchange command is a Get-*; the Graph call runs a
    read-only query. Nothing is created, changed or removed and no mail is sent.
    The only state it leaves is the sign-in sessions it opens.

    WHAT IT NEVER EXPORTS: message subjects, bodies or attachments; the words,
    patterns or addresses a mail flow rule matches on; a connector's comment or
    validation recipients (Enhanced Filtering's recipients are written as
    "*@<domain>"); allowed and blocked sender lists. The Defender query
    keeps the recipient's domain, never the address, and never the subject.

    WHAT IT DOES EXPORT THAT NAMES PEOPLE: the message trace has the sender's
    and recipient's address on every row. Run with -DomainsOnly to write
    "*@<domain>" in their place; takestock reads only the domain. Keep the
    output out of any repository either way.

    LIMITS, as Microsoft documents them:
      Get-MessageTraceV2 (learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2):
        "search message data for the last 90 days", "only return 10 days worth of data per
        query", "a maximum of 5000 results", "A maximum of 100 query requests are accepted
        within a 5 minute running window", and, for more than one page, "use the
        StartingRecipientAddress and EndDate parameters with the values from the Recipient
        address and Received Time properties respectively of the previous result".
        So: 10-day windows, 5000 rows a query, paged that way, at most 95 queries in any
        five minutes.
      Get-MailFlowStatusReport: "for the last 90 days"; no range limit is documented, so it is
        asked in the same 10-day windows.
      Advanced hunting (learn.microsoft.com/defender-xdr/api-advanced-hunting): "Queries
        explore and return data from the past 30 days", "Results can return up to 100,000
        rows", "up to at least 45 calls per minute per tenant". So: one-day windows, an
        hour at a time for a day that reaches the row limit, and a pause between calls.

.PARAMETER OutputDirectory
    The folder to write. By default, m365-mail-flow-<UTC time> in your home
    folder. The zip is written beside it, with the same name.

.PARAMETER TraceDays
    How many days of message trace to read, up to 90 (the default).

.PARAMETER DomainsOnly
    Write "*@<domain>" for every address in the message trace.

.PARAMETER SkipTrace
    Do not read the message trace.

.PARAMETER EmailEvents
    Also read Defender for Office 365's EmailEvents through Microsoft Graph.
    Needs the Microsoft.Graph.Authentication module and consent to
    ThreatHunting.Read.All.

.PARAMETER EmailEventsDays
    How many days of EmailEvents to read, up to 30 (the default).

.EXAMPLE
    ./export-m365-mail-flow.ps1 -DomainsOnly

.EXAMPLE
    ./export-m365-mail-flow.ps1 -DomainsOnly -EmailEvents

.NOTES
    Written for Azure Cloud Shell (PowerShell 7, ExchangeOnlineManagement
    installed). It needs an account that can read Exchange Online
    configuration and run message trace, such as one holding the View-Only
    Configuration and Message Tracking roles.
    A command the account cannot run is recorded in manifest.json, and the
    rest still run. Each cmdlet is documented at
    https://learn.microsoft.com/powershell/module/exchangepowershell/<cmdlet>,
    the cmdlet's name in lower case.
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $HOME ('m365-mail-flow-' +
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ'))),
    [ValidateRange(1, 90)] [int] $TraceDays = 90,
    [switch] $DomainsOnly,
    [switch] $SkipTrace,
    [switch] $EmailEvents,
    [ValidateRange(1, 30)] [int] $EmailEventsDays = 30
)

$ErrorActionPreference = 'Stop'
$taken = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ')
$now = [datetime]::UtcNow
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$readings = [System.Collections.Generic.List[object]]::new()
$jsonArgs = @{ Depth = 5; WarningAction = 'SilentlyContinue' }
if ($PSVersionTable.PSVersion.Major -ge 7) { $jsonArgs.EnumsAsStrings = $true }

function Get-FirstLine($ErrorRecord) { ($ErrorRecord.Exception.Message -split "`r?`n")[0] }

function Format-Utc($Value) {
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $d = $Value
        if ($d.Kind -eq [System.DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
        return $d.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [cultureinfo]::InvariantCulture)
    }
    return "$Value"
}

function Get-Address([string] $Address) {
    if (-not $DomainsOnly) { return $Address }
    $at = $Address.LastIndexOf('@')
    if ($at -lt 0) { return '' }
    return '*' + $Address.Substring($at)
}

function Add-Failure([string] $Part, [string] $Command, [string] $Message) {
    $readings.Add([ordered]@{ part = $Part; command = $Command; ok = $false; count = 0; error = $Message })
    Write-Warning "$Command failed: $Message"
}

function Export-Reading {
    param([string] $Cmdlet, [hashtable] $Arguments = @{}, [string[]] $Property = @('*'),
          [string[]] $Exclude = @(), [scriptblock] $Shape)
    $file = "$Cmdlet.json"
    try {
        $raw = @(& $Cmdlet @Arguments)
        if ($Shape) { $objects = @($raw | ForEach-Object -Process $Shape) }
        else { $objects = @($raw | Select-Object -Property $Property -ExcludeProperty $Exclude) }
        ConvertTo-Json -InputObject $objects @jsonArgs |
            Set-Content -Path (Join-Path $OutputDirectory $file) -Encoding utf8
        $readings.Add([ordered]@{ part = 'exchange'; command = $Cmdlet; ok = $true
                                   count = $objects.Count; file = $file })
        Write-Host ('  {0,-32} {1,6} object(s)' -f $Cmdlet, $objects.Count)
    }
    catch { Add-Failure 'exchange' $Cmdlet (Get-FirstLine $_) }
}

# A mail flow rule is reduced to which conditions and actions it sets, by name.
# Values are kept only for the routing and transport settings below, which carry
# no message content; a rule's words, patterns and addresses are never written.
$ruleMeta = @('Name', 'Identity', 'Guid', 'DistinguishedName', 'ImmutableId', 'State', 'Mode',
    'Priority', 'Comments', 'Description', 'RuleVersion', 'WhenChanged', 'WhenChangedUTC',
    'WhenCreated', 'WhenCreatedUTC', 'ExchangeVersion', 'OrganizationId', 'IsValid', 'ObjectState',
    'RunspaceId', 'Conditions', 'Exceptions', 'Actions', 'ManuallyModified', 'RuleErrorAction',
    'RuleSubType', 'SenderAddressLocation', 'ExchangeObjectId', 'Id', 'OriginatingServer',
    'ActivationDate', 'ExpiryDate', 'UseLegacyRegex', 'IsRuleConfigurationSupported')
$ruleValues = @('RouteMessageOutboundConnector', 'RouteMessageOutboundRequireTls', 'SetSCL',
    'ApplyOME', 'RemoveOME', 'ApplyRightsProtectionTemplate', 'StopRuleProcessing', 'SetHeaderName',
    'RemoveHeader', 'FromScope', 'SentToScope', 'ExceptIfFromScope', 'ExceptIfSentToScope',
    'MessageTypeMatches')
$shapeRule = {
    $rule = $_
    $uses = [System.Collections.Generic.List[string]]::new()
    $values = [ordered]@{}
    foreach ($p in $rule.PSObject.Properties) {
        if ($ruleMeta -contains $p.Name -or $p.Name -like 'PS*') { continue }
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { if (-not $v) { continue } }
        elseif ($v -is [string]) { if ($v -eq '') { continue } }
        elseif ($v -is [System.Collections.IEnumerable]) { if (@($v).Count -eq 0) { continue } }
        $uses.Add($p.Name)
        if ($ruleValues -contains $p.Name) { $values[$p.Name] = "$v" }
    }
    [ordered]@{ Name = $rule.Name; State = "$($rule.State)"; Mode = "$($rule.Mode)"
                Priority = $rule.Priority; Uses = @($uses); Values = $values }
}

# An inbound connector's EFUsers lists the recipients Enhanced Filtering applies to; blank
# means everyone. Each is written as "*@<domain>", so "some recipients" survives without names.
$shapeInbound = {
    $c = $_ | Select-Object -Property * -ExcludeProperty Comment, ScanAndDropRecipients
    if ($c.PSObject.Properties['EFUsers']) {
        $c.EFUsers = @(@($c.EFUsers) | Where-Object { $_ } | ForEach-Object {
            $a = "$_"; $i = $a.LastIndexOf('@')
            if ($i -ge 0) { '*' + $a.Substring($i) } else { '*' }
        } | Select-Object -Unique)
    }
    $c
}

# ---------------------------------------------------------------- Exchange Online
Write-Host 'Exchange Online'
$exchange = $true
if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
    try { Connect-ExchangeOnline -ShowBanner:$false }
    catch { $exchange = $false; Add-Failure 'exchange' 'Connect-ExchangeOnline' (Get-FirstLine $_) }
}

if ($exchange) {
    Export-Reading 'Get-AcceptedDomain'
    Export-Reading 'Get-InboundConnector' -Shape $shapeInbound
    Export-Reading 'Get-OutboundConnector' -Exclude @('Comment', 'ValidationRecipients')
    Export-Reading 'Get-DkimSigningConfig'
    Export-Reading 'Get-TransportRule' @{ ResultSize = 'Unlimited' } -Shape $shapeRule
    Export-Reading 'Get-RemoteDomain'
    Export-Reading 'Get-ArcConfig'
    Export-Reading 'Get-HostedContentFilterPolicy' -Property @('Name', 'IsDefault',
        'MarkAsSpamSpfRecordHardFail', 'MarkAsSpamFromAddressAuthFail', 'MarkAsSpamNdrBackscatter',
        'SpamAction', 'HighConfidenceSpamAction', 'PhishSpamAction', 'HighConfidencePhishAction',
        'BulkThreshold')

    # Message counts by day, direction and event type, in the trace's 10-day windows.
    $from = $now.AddDays(-$TraceDays).AddMinutes(10)
    $status = [System.Collections.Generic.List[object]]::new()
    $statusErrors = [System.Collections.Generic.List[object]]::new()
    for ($s = $from; $s -lt $now; $s = $s.AddDays(10)) {
        $e = $s.AddDays(10); if ($e -gt $now) { $e = $now }
        try {
            foreach ($row in @(Get-MailFlowStatusReport -StartDate $s -EndDate $e)) {
                $status.Add(($row | Select-Object -Property * -ExcludeProperty RunspaceId, PS*))
            }
        }
        catch { $statusErrors.Add([ordered]@{ start = Format-Utc $s; end = Format-Utc $e; error = Get-FirstLine $_ }) }
    }
    if ($status.Count -gt 0 -or $statusErrors.Count -eq 0) {
        ConvertTo-Json -InputObject @($status) @jsonArgs |
            Set-Content -Path (Join-Path $OutputDirectory 'Get-MailFlowStatusReport.json') -Encoding utf8
        $readings.Add([ordered]@{ part = 'exchange'; command = 'Get-MailFlowStatusReport'; ok = $true
                                   count = $status.Count; file = 'Get-MailFlowStatusReport.json'
                                   failed_windows = @($statusErrors) })
        Write-Host ('  {0,-32} {1,6} row(s)' -f 'Get-MailFlowStatusReport', $status.Count)
    }
    else { Add-Failure 'exchange' 'Get-MailFlowStatusReport' $statusErrors[0].error }

    # ------------------------------------------------------------ message trace
    if (-not $SkipTrace) {
        $traceFile = Join-Path $OutputDirectory 'message-trace.csv'
        $pageSize = 5000
        $sent = [System.Collections.Generic.Queue[datetime]]::new()
        $rows = 0; $queries = 0
        $traceErrors = [System.Collections.Generic.List[object]]::new()
        for ($s = $from; $s -lt $now; $s = $s.AddDays(10)) {
            $windowEnd = $s.AddDays(10); if ($windowEnd -gt $now) { $windowEnd = $now }
            $end = $windowEnd; $startingRecipient = $null
            while ($true) {
                # At most 95 queries in any five minutes (Microsoft accepts 100).
                while ($sent.Count -gt 0 -and ([datetime]::UtcNow - $sent.Peek()).TotalSeconds -ge 300) {
                    [void] $sent.Dequeue()
                }
                if ($sent.Count -ge 95) {
                    Start-Sleep -Seconds ([math]::Ceiling(301 - ([datetime]::UtcNow - $sent.Peek()).TotalSeconds))
                    continue
                }
                $sent.Enqueue([datetime]::UtcNow)
                $query = @{ StartDate = $s; EndDate = $end; ResultSize = $pageSize }
                if ($startingRecipient) { $query.StartingRecipientAddress = $startingRecipient }
                try { $page = @(Get-MessageTraceV2 @query) }
                catch {
                    $traceErrors.Add([ordered]@{ start = Format-Utc $s; end = Format-Utc $end; error = Get-FirstLine $_ })
                    break
                }
                $queries++
                if ($page.Count -eq 0) { break }
                $page | Select-Object @{ n = 'Received'; e = { Format-Utc $_.Received } },
                    @{ n = 'SenderAddress'; e = { Get-Address $_.SenderAddress } },
                    @{ n = 'RecipientAddress'; e = { Get-Address $_.RecipientAddress } },
                    Status, FromIP, ToIP, Size, MessageId, MessageTraceId |
                    Export-Csv -Path $traceFile -Append -NoTypeInformation -Encoding utf8
                $rows += $page.Count
                if ($page.Count -lt $pageSize) { break }
                $last = $page[-1]
                if ($last.Received -eq $end -and $last.RecipientAddress -eq $startingRecipient) {
                    $traceErrors.Add([ordered]@{ start = Format-Utc $s; end = Format-Utc $end
                                                  error = 'paging made no progress; the rest of this window was not read' })
                    break
                }
                $end = $last.Received; $startingRecipient = $last.RecipientAddress
            }
            Write-Host ('  {0,-32} {1,6} row(s) to {2}' -f 'Get-MessageTraceV2', $rows, (Format-Utc $windowEnd))
        }
        if ($rows -gt 0 -or $traceErrors.Count -eq 0) {
            if (-not (Test-Path $traceFile)) { Set-Content -Path $traceFile -Value '' -Encoding utf8 }
            $readings.Add([ordered]@{ part = 'trace'; command = 'Get-MessageTraceV2'; ok = $true
                                       count = $rows; file = 'message-trace.csv'; queries = $queries
                                       start = Format-Utc $from; end = Format-Utc $now
                                       domains_only = [bool] $DomainsOnly; failed_windows = @($traceErrors) })
        }
        else { Add-Failure 'trace' 'Get-MessageTraceV2' $traceErrors[0].error }
    }
}

# ------------------------------------------- Defender for Office 365 (optional)
if ($EmailEvents) {
    Write-Host 'Defender for Office 365 EmailEvents (advanced hunting, through Microsoft Graph)'
    $graph = $true
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        $graph = $false
        Add-Failure 'defender' 'Connect-MgGraph' 'Microsoft Graph PowerShell is not installed (Microsoft.Graph.Authentication)'
    }
    else {
        try { Connect-MgGraph -Scopes 'ThreatHunting.Read.All' -NoWelcome }
        catch { $graph = $false; Add-Failure 'defender' 'Connect-MgGraph' (Get-FirstLine $_) }
    }
    if ($graph) {
        $eventsFile = Join-Path $OutputDirectory 'EmailEvents.csv'
        $columns = @('Timestamp', 'NetworkMessageId', 'EmailDirection', 'SenderFromDomain',
            'SenderMailFromDomain', 'RecipientDomain', 'DeliveryAction', 'DeliveryLocation', 'Connectors',
            'AuthenticationDetails', 'SenderIPv4', 'SenderIPv6', 'EmailSize', 'AttachmentCount')
        $limit = 100000
        function Invoke-EmailEvents([datetime] $Start, [datetime] $End) {
            # Never Subject, never an address: the recipient's domain is split from it here.
            $template = "EmailEvents | where Timestamp >= datetime({0}) and Timestamp < datetime({1}) " +
                "| project Timestamp, NetworkMessageId, EmailDirection, SenderFromDomain, " +
                "SenderMailFromDomain, RecipientDomain = tostring(split(RecipientEmailAddress, '@')[1]), " +
                "DeliveryAction, DeliveryLocation, Connectors, AuthenticationDetails, SenderIPv4, " +
                "SenderIPv6, EmailSize = column_ifexists('EmailSize', long(null)), AttachmentCount"
            $kql = $template -f (Format-Utc $Start), (Format-Utc $End)
            Start-Sleep -Milliseconds 1500
            $body = @{ Query = $kql } | ConvertTo-Json -Compress
            $response = Invoke-MgGraphRequest -Method POST -OutputType PSObject `
                -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
                -Body $body -ContentType 'application/json'
            return @($response.results)
        }
        $eventRows = 0; $windows = 0
        $eventErrors = [System.Collections.Generic.List[object]]::new()
        $truncated = [System.Collections.Generic.List[string]]::new()
        $evFrom = $now.AddDays(-$EmailEventsDays).AddMinutes(10)
        for ($s = $evFrom; $s -lt $now; $s = $s.AddDays(1)) {
            $e = $s.AddDays(1); if ($e -gt $now) { $e = $now }
            try {
                $result = Invoke-EmailEvents $s $e
                if ($result.Count -ge $limit) {
                    $result = @()
                    for ($h = $s; $h -lt $e; $h = $h.AddHours(1)) {
                        $he = $h.AddHours(1); if ($he -gt $e) { $he = $e }
                        $part = Invoke-EmailEvents $h $he
                        if ($part.Count -ge $limit) { $truncated.Add((Format-Utc $h)) }
                        $result += $part
                    }
                }
                $windows++
                if ($result.Count -gt 0) {
                    $result | Select-Object -Property $columns |
                        Export-Csv -Path $eventsFile -Append -NoTypeInformation -Encoding utf8
                }
                $eventRows += $result.Count
                Write-Host ('  {0,-32} {1,6} row(s) to {2}' -f 'EmailEvents', $eventRows, (Format-Utc $e))
            }
            catch {
                $eventErrors.Add([ordered]@{ start = Format-Utc $s; end = Format-Utc $e; error = Get-FirstLine $_ })
                # A first window that fails is the licence or the permission: stop asking.
                if ($windows -eq 0) { break }
            }
        }
        if ($windows -gt 0) {
            if (-not (Test-Path $eventsFile)) { Set-Content -Path $eventsFile -Value '' -Encoding utf8 }
            $readings.Add([ordered]@{ part = 'defender'; command = 'EmailEvents'; ok = $true
                                       count = $eventRows; file = 'EmailEvents.csv'
                                       start = Format-Utc $evFrom; end = Format-Utc $now
                                       truncated_hours = @($truncated); failed_windows = @($eventErrors) })
        }
        else { Add-Failure 'defender' 'EmailEvents' $eventErrors[0].error }
    }
}

# ---------------------------------------------------------------- manifest
$module = Get-Module ExchangeOnlineManagement | Select-Object -First 1
[ordered]@{
    pulled_utc      = $taken
    script          = 'export-m365-mail-flow.ps1'
    powershell      = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    exchange_module = $(if ($module) { "$($module.Version)" } else { $null })
    never_exported  = @('message subjects', 'message bodies', 'attachments',
                        'mail flow rule match words, patterns and addresses',
                        'connector comments and validation recipients',
                        'allowed and blocked sender lists', 'Defender recipient addresses')
    readings        = $readings
} | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8

$zip = "$OutputDirectory.zip"
Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $zip -Force
$failed = @($readings | Where-Object { -not $_.ok }).Count
Write-Host ''
Write-Host "Wrote $($readings.Count) reading(s), $failed failed (each failure is in manifest.json):"
Write-Host "  $zip"
