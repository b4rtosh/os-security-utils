#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manages Windows Defender Firewall rules (block ports/addresses), enforces them on profile change and audits changes.

.DESCRIPTION
    All rules created by this script are named "FWM-*" and belong to the group "FirewallManager".
    Features: block ports / IPs / ranges / CIDR (IPv4+IPv6), per-profile rules, idempotent add,
    modify / enable / disable / remove, JSON import, enforcement + drift repair (also as a SYSTEM
    scheduled task triggered at startup and on network-profile change), JSON-Lines audit log with
    rotation + Windows Event Log, detection of changes made outside the script, backup / restore.

    Direction semantics for ports: Inbound rules match the LOCAL port, Outbound rules match the REMOTE port.
    -RemoteAddress is always the remote side.

    Exit codes: 0 success, 1 unexpected error, 2 no admin rights, 3 invalid input,
    4 -Force required, 5 some operations failed, 6 object / file not found.

    JSON config example (-ConfigPath), "name" is required, the rest is optional
    (protocol: TCP|UDP|ICMPv4|ICMPv6|ICMP|Any, default TCP when ports are given else Any; "icmpType": ["8"] for ICMPv4/ICMPv6; direction: Inbound|Outbound|Any, default Any; profile default Any; enabled default true):
    {
      "rules": [
        { "name": "NoSMB",   "protocol": "TCP", "port": ["135", "139", "445"], "direction": "Inbound", "profile": ["Public"] },
        { "name": "NoRange", "protocol": "Any", "port": ["5000-5100"],          "direction": "Any" },
        { "name": "BadNet",  "remoteAddress": ["203.0.113.1-203.0.113.50", "10.0.0.0/8", "2001:db8::/32"], "direction": "Any", "enabled": true }
      ]
    }

.PARAMETER Action
    Block | List | Modify | Remove | Enable | Disable | Enforce | Status | History | Import | Backup | Restore | InstallTask | UninstallTask | Connections | Menu

.PARAMETER Name
    Block: base name of the rule(s) (optional, otherwise generated). Modify/Remove/Enable/Disable: rule name or wildcard, "FWM-" is added when missing.

.PARAMETER Protocol
    TCP, UDP, ICMPv4, ICMPv6, ICMP (= ICMPv4 + ICMPv6 rules) or Any. Any together with ports creates one TCP and one UDP rule. Default TCP (Any when no ports are given).

.PARAMETER Port
    Ports: single, list (135,139,445) or range (5000-5100); 1-65535. Not allowed with ICMP protocols.

.PARAMETER IcmpType
    ICMP type(s) for -Protocol ICMPv4/ICMPv6: type or type:code, e.g. 8 (echo request, v4) or 128 (echo request, v6). Without it all types are blocked; for ICMPv6 that needs -Force (breaks IPv6 neighbor discovery).

.PARAMETER RemoteAddress
    IPv4/IPv6 address, CIDR (10.0.0.0/8) or range (203.0.113.1-203.0.113.50).

.PARAMETER Direction
    Inbound, Outbound or Any (both directions, default).

.PARAMETER NetProfile
    Alias -Profile. Domain, Private, Public or Any (default). For Enable/Disable with -Scope Profile selects the firewall profile(s).

.PARAMETER Scope
    Enable/Disable target: Rule (default) or Profile (whole firewall profile on/off).

.PARAMETER ConfigPath
    JSON rules file used by Import / Enforce / InstallTask. Default: %ProgramData%\FirewallManager\rules.json

.PARAMETER LogPath
    Log directory. Default: %ProgramData%\FirewallManager\Logs

.PARAMETER BackupPath
    Backup: target .wfw file (default: timestamped file in %ProgramData%\FirewallManager\Backups). Restore: source .wfw file.

.PARAMETER Days
    History: how many days back to read (default 7).

.PARAMETER IncludeSecurity
    History: also read Security log events 4946/4947/4948/4950 (needs auditing, see EXAMPLE 8).

.PARAMETER Interactive
    Connections: after listing, asks which connection(s) to block and creates FWM-Conn-* rules (remote address, remote address + port, or local port).

.PARAMETER ConnectionState
    Connections: TCP state to list (default Established). -Port filters by local OR remote port, -RemoteAddress by remote address.

.PARAMETER ResolveDns
    Connections: add reverse-DNS host names (slower).

.PARAMETER Disconnect
    Connections -Interactive: also drop the selected IPv4 TCP connections (iphlpapi SetTcpEntry) after creating rules.

.PARAMETER Notify
    History/Enforce: log + Warning event for changes of FWM-* rules made outside this script.

.PARAMETER BackupFirst
    Export firewall policy before any modifying action.

.PARAMETER DryRun
    Shows what would be done without changing anything (nothing is applied or logged). Replaces -WhatIf in this script's documentation.

.PARAMETER Force
    Required for blocking critical ports (53, 443, 3389, 5985, 5986), loopback/local addresses, disabling a firewall profile and skipping Remove/Restore confirmation.

.EXAMPLE
    .\FirewallManager.ps1 -Action Block -Protocol TCP -Port 135,139,445 -Direction Inbound -Profile Public

.EXAMPLE
    .\FirewallManager.ps1 -Action Block -RemoteAddress 203.0.113.1-203.0.113.50,10.0.0.0/8 -Direction Any -Name BadNet

.EXAMPLE
    .\FirewallManager.ps1 -Action Block -Protocol Any -Port 5000-5100 -Direction Outbound -DryRun

.EXAMPLE
    .\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Name NoPing

.EXAMPLE
    .\FirewallManager.ps1 -Action Status; .\FirewallManager.ps1 -Action List

.EXAMPLE
    .\FirewallManager.ps1 -Action Disable -Name 'FWM-BadNet*'; .\FirewallManager.ps1 -Action Remove -Name BadNet* -Force

.EXAMPLE
    .\FirewallManager.ps1 -Action Import -ConfigPath C:\ProgramData\FirewallManager\rules.json -BackupFirst

.EXAMPLE
    .\FirewallManager.ps1 -Action InstallTask -ConfigPath C:\ProgramData\FirewallManager\rules.json

.EXAMPLE
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    .\FirewallManager.ps1 -Action History -Days 3 -IncludeSecurity -Notify

.EXAMPLE
    .\FirewallManager.ps1 -Action Disable -Scope Profile -Profile Public -Force

.EXAMPLE
    .\FirewallManager.ps1 -Action Backup; .\FirewallManager.ps1 -Action Restore -BackupPath C:\Backups\fw.wfw
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('Block', 'List', 'Modify', 'Remove', 'Enable', 'Disable', 'Enforce', 'Status', 'History', 'Import', 'Backup', 'Restore', 'InstallTask', 'UninstallTask', 'Connections', 'Menu')]
    [string]$Action,

    [ValidatePattern('^[\w\.\*\-\?]+$')]
    [string]$Name,

    [ValidateSet('TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'ICMP', 'Any')]
    [string]$Protocol = 'TCP',

    [string[]]$Port,

    [string[]]$IcmpType,

    [string[]]$RemoteAddress,

    [ValidateSet('Inbound', 'Outbound', 'Any')]
    [string]$Direction = 'Any',

    # Named NetProfile because $Profile is a PowerShell automatic variable.
    [Alias('Profile')]
    [ValidateSet('Domain', 'Private', 'Public', 'Any')]
    [string[]]$NetProfile = 'Any',

    [ValidateSet('Rule', 'Profile')]
    [string]$Scope = 'Rule',

    [string]$ConfigPath = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FirewallManager\rules.json'),

    [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FirewallManager\Logs'),

    [string]$BackupPath,

    [ValidateRange(1, 3650)]
    [int]$Days = 7,

    [switch]$IncludeSecurity,
    [switch]$Notify,
    [switch]$Interactive,
    [switch]$ResolveDns,
    [switch]$Disconnect,

    [ValidateSet('Established', 'Listen', 'TimeWait', 'CloseWait', 'All')]
    [string]$ConnectionState = 'Established',
    [switch]$BackupFirst,
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# -DryRun is the user-facing name of the dry-run mode; it drives the ShouldProcess machinery via $WhatIfPreference.
if ($DryRun) { $WhatIfPreference = $true }

#region Constants / state
$script:Bound = $PSBoundParameters
$script:ScriptPath = $PSCommandPath
$script:Prefix = 'FWM-'
$script:Group = 'FirewallManager'
$script:EventSource = 'FirewallManager'
$script:TaskName = 'Enforce'
$script:TaskPath = '\FirewallManager\'
$script:DataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FirewallManager'
$script:FwLog = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
$script:FailureCount = 0
$script:ExitCode = 0
$script:EventIds = @{ Add = 1001; Modify = 1002; Remove = 1003; Enable = 1004; Disable = 1005; Enforce = 1006; Backup = 1007; Restore = 1008; Disconnect = 1009; External = 1100; Error = 1900 }
$script:Critical = @{ 53 = 'DNS'; 443 = 'HTTPS'; 3389 = 'RDP'; 5985 = 'WinRM'; 5986 = 'WinRM' }
$script:AllProfiles = 'Domain', 'Private', 'Public'
#endregion

#region Helpers
function Write-Msg {
    <# .SYNOPSIS User-facing message (Polish). #>
    param([string]$Text, [ValidateSet('Info', 'Ok', 'Warn', 'Error')][string]$Level = 'Info')
    switch ($Level) {
        'Warn' { Write-Warning $Text }
        'Error' { Write-Information "[BŁĄD] $Text" -InformationAction Continue }
        'Ok' { Write-Information "[OK] $Text" -InformationAction Continue }
        default { Write-Information "[INFO] $Text" -InformationAction Continue }
    }
}

function Stop-Fwm {
    <# .SYNOPSIS Throws an exception carrying a script exit code. #>
    param([string]$Message, [int]$Code = 1)
    $ex = [System.InvalidOperationException]::new($Message)
    $ex.Data['ExitCode'] = $Code
    throw $ex
}

function Test-IsAdmin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-RuleName {
    param([string]$Pattern)
    if (-not $Pattern) { Stop-Fwm 'Podaj nazwę reguły (-Name), można użyć znaków wieloznacznych.' 3 }
    if ($Pattern -like "$script:Prefix*") { $Pattern } else { "$script:Prefix$Pattern" }
}
#endregion

#region Audit logging
function Initialize-Logging {
    <# .SYNOPSIS Creates log dir, Event Log source and prunes logs older than 30 days. #>
    if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force -WhatIf:$false | Out-Null }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($script:EventSource, 'Application')
        }
    }
    catch { Write-Msg "Nie można utworzyć źródła zdarzeń '$script:EventSource': $($_.Exception.Message)" Warn }
    Get-ChildItem -LiteralPath $LogPath -Filter 'firewall_*.log' -File |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) |
        Remove-Item -Force -WhatIf:$false
}

function Write-Audit {
    <# .SYNOPSIS Appends a JSON-Lines audit entry (rotated at 5 MB) and writes the same to the Application event log. #>
    param(
        [Parameter(Mandatory)][string]$Operation,
        [string]$Target,
        $Before,
        $After,
        [ValidateSet('Success', 'Failure')][string]$Result = 'Success',
        [string]$ErrorText,
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level
    )
    try {
        $json = [ordered]@{
            Timestamp = (Get-Date).ToString('o')
            User      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            Computer  = $env:COMPUTERNAME
            Operation = $Operation
            Target    = $Target
            Before    = $Before
            After     = $After
            Result    = $Result
            Error     = $ErrorText
            Message   = $Message
        } | ConvertTo-Json -Compress -Depth 5

        $file = Join-Path $LogPath ('firewall_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
        if ((Test-Path -LiteralPath $file) -and (Get-Item -LiteralPath $file).Length -ge 5MB) {
            [System.IO.File]::Move($file, ($file -replace '\.log$', ('_{0}.log' -f (Get-Date -Format 'HHmmss'))))
        }
        [System.IO.File]::AppendAllText($file, $json + "`n", [System.Text.UTF8Encoding]::new($false))

        if (-not $Level) { $Level = if ($Result -eq 'Failure') { 'Error' } else { 'Information' } }
        $id = if ($script:EventIds.ContainsKey($Operation)) { $script:EventIds[$Operation] } else { $script:EventIds.Error }
        if ($json.Length -gt 30000) { $json = $json.Substring(0, 30000) }
        [System.Diagnostics.EventLog]::WriteEntry($script:EventSource, $json, [System.Diagnostics.EventLogEntryType]$Level, $id)
    }
    catch { Write-Warning "Nie udało się zapisać wpisu audytu: $($_.Exception.Message)" }
}

function Invoke-Audited {
    <# .SYNOPSIS Runs a change under ShouldProcess and audits before/after state. Returns Done | Failed | Skipped. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$Target,
        $Before,
        [Parameter(Mandatory)][scriptblock]$Script,
        [scriptblock]$AfterScript,
        [switch]$Destructive,
        [switch]$Force
    )
    if ($Destructive -and -not $Force -and $ConfirmPreference -ne 'None') { $ConfirmPreference = 'Low' }
    if ($DryRun) { Write-Msg "DryRun: operacja '$Operation' na obiekcie '$Target' – nic nie zmieniono." Info; return 'Skipped' }
    if (-not $PSCmdlet.ShouldProcess($Target, $Operation)) { return 'Skipped' }
    $ConfirmPreference = 'None' # already confirmed; do not let inner cmdlets prompt again
    try {
        # NetSecurity cmdlets emit some failures as non-terminating errors; promote them so a failed change is never logged as success.
        $null = & $Script 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { throw $_.Exception } }
        $after = if ($AfterScript) { & $AfterScript }
        Write-Audit -Operation $Operation -Target $Target -Before $Before -After $after
        Write-Msg "$Operation : $Target" Ok
        'Done'
    }
    catch {
        $script:FailureCount++
        Write-Audit -Operation $Operation -Target $Target -Before $Before -Result Failure -ErrorText $_.Exception.Message
        Write-Msg "$Operation nieudane dla '$Target': $($_.Exception.Message)" Error
        'Failed'
    }
}
#endregion

#region Validation (ports, addresses)
function ConvertTo-PortList {
    <# .SYNOPSIS Validates ports/ranges (1-65535) and returns normalized unique tokens. #>
    param([string[]]$Ports)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($tok in (@($Ports) -split ',')) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if ($t -match '^(\d{1,5})$') { $lo = [int]$Matches[1]; $hi = $lo }
        elseif ($t -match '^(\d{1,5})-(\d{1,5})$') { $lo = [int]$Matches[1]; $hi = [int]$Matches[2] }
        else { Stop-Fwm "Nieprawidłowy port: '$t'" 3 }
        if ($lo -lt 1 -or $hi -gt 65535 -or $lo -gt $hi) { Stop-Fwm "Port poza zakresem 1-65535 lub odwrócony zakres: '$t'" 3 }
        $s = if ($lo -eq $hi) { "$lo" } else { "$lo-$hi" }
        if (-not $out.Contains($s)) { $out.Add($s) }
    }
    , $out.ToArray()
}

function ConvertTo-IpAddress {
    param([string]$Text)
    $ip = $null
    if ($Text -match '%' -or -not [ipaddress]::TryParse($Text, [ref]$ip)) { return $null }
    # TryParse accepts shorthand like "1" or "1.2"; require full dotted quad for IPv4.
    if ($ip.AddressFamily -eq 'InterNetwork' -and $Text -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    $ip
}

function Compare-Bytes {
    param([byte[]]$A, [byte[]]$B)
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return [Math]::Sign([int]$A[$i] - [int]$B[$i]) }
    }
    0
}

function ConvertTo-AddressRange {
    <# .SYNOPSIS Parses IP / CIDR / addr/mask / range to Lo,Hi bytes + canonical Key. Returns $null when invalid. #>
    param([string]$Text)
    $t = $Text.Trim()
    $lo = $null; $hi = $null
    if ($t -match '^(?<a>[^/]+)/(?<p>[^/]+)$') {
        $pfx = $Matches.p
        $base = ConvertTo-IpAddress $Matches.a
        if (-not $base) { return $null }
        $bytes = $base.GetAddressBytes()
        $bits = $bytes.Length * 8
        if ($pfx -match '^\d+$') { $len = [int]$pfx }
        else {
            $m = ConvertTo-IpAddress $pfx
            if (-not $m -or $bits -ne 32) { return $null }
            $len = 0
            foreach ($b in $m.GetAddressBytes()) { $len += [Convert]::ToString($b, 2).Replace('0', '').Length }
        }
        if ($len -gt $bits) { return $null }
        $lo = $bytes.Clone(); $hi = $bytes.Clone()
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $rem = $len - 8 * $i
            $mask = if ($rem -ge 8) { 255 } elseif ($rem -le 0) { 0 } else { (255 -shl (8 - $rem)) -band 255 }
            $lo[$i] = $bytes[$i] -band $mask
            $hi[$i] = $bytes[$i] -bor (255 -bxor $mask)
        }
    }
    elseif ($t -match '^(?<a>[^\-]+)-(?<b>[^\-]+)$') {
        $a = ConvertTo-IpAddress $Matches.a; $b = ConvertTo-IpAddress $Matches.b
        if (-not $a -or -not $b -or $a.AddressFamily -ne $b.AddressFamily) { return $null }
        $lo = $a.GetAddressBytes(); $hi = $b.GetAddressBytes()
        if ((Compare-Bytes $lo $hi) -gt 0) { return $null }
    }
    else {
        $a = ConvertTo-IpAddress $t
        if (-not $a) { return $null }
        $lo = $a.GetAddressBytes(); $hi = $lo
    }
    [pscustomobject]@{ Lo = $lo; Hi = $hi; Key = ('{0}-{1}' -f [ipaddress]::new($lo), [ipaddress]::new($hi)) }
}

function Assert-SafeTarget {
    <# .SYNOPSIS Requires -Force for critical ports and local/loopback addresses (lock-out protection). #>
    param([string[]]$Ports, [string[]]$Addresses, [switch]$Force)
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Ports) {
        $parts = $p -split '-'
        foreach ($c in $script:Critical.Keys) {
            if ($c -ge [int]$parts[0] -and $c -le [int]$parts[-1]) { $hits.Add("port $c ($($script:Critical[$c]))") }
        }
    }
    if ($Addresses) {
        $local = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-IpAddress ($_.IPAddress -replace '%.*$', '') }) + [ipaddress]::Loopback + [ipaddress]::IPv6Loopback
        foreach ($a in $Addresses) {
            $r = ConvertTo-AddressRange $a
            foreach ($ip in ($local | Where-Object { $_ })) {
                $b = $ip.GetAddressBytes()
                if ($b.Length -eq $r.Lo.Length -and (Compare-Bytes $r.Lo $b) -le 0 -and (Compare-Bytes $b $r.Hi) -le 0) {
                    $hits.Add("adres lokalny/loopback $ip (w '$a')"); break
                }
            }
        }
    }
    if ($hits.Count -eq 0) { return }
    $msg = 'Blokada może odciąć dostęp do systemu: ' + ($hits -join ', ')
    if (-not $Force) { Stop-Fwm "$msg. Użyj -Force, aby kontynuować." 4 }
    Write-Msg "$msg (kontynuacja dzięki -Force)" Warn
}
#endregion

#region Rule model
function New-RuleSpecs {
    <# .SYNOPSIS Validates input and expands it to concrete rule specs (per direction / protocol). #>
    param(
        [string]$BaseName, [string]$Protocol, [string[]]$Ports, [string[]]$Addresses, [string[]]$IcmpTypes,
        [string]$Direction, [string[]]$Profiles, [bool]$Enabled = $true, [switch]$Force, [switch]$SkipPortGuard
    )
    $portList = if ($Ports) { @(ConvertTo-PortList $Ports) } else { @() }
    $addrList = @()
    foreach ($a in (@($Addresses) -split ',')) {
        if (-not $a.Trim()) { continue }
        if (-not (ConvertTo-AddressRange $a)) { Stop-Fwm "Nieprawidłowy adres IP/CIDR/zakres: '$a'" 3 }
        $addrList += $a.Trim()
    }
    $isIcmp = $Protocol -in 'ICMPv4', 'ICMPv6', 'ICMP'
    $icmpList = @()
    foreach ($t in (@($IcmpTypes) -split ',')) {
        $t = $t.Trim()
        if (-not $t) { continue }
        if ($t -notmatch '^(\d{1,3})(:\d{1,3})?$' -or [int]$Matches[1] -gt 255) { Stop-Fwm "Nieprawidłowy typ ICMP: '$t' (oczekiwano typ lub typ:kod, 0-255)" 3 }
        $icmpList += $t
    }
    if (-not $portList -and -not $addrList -and -not $isIcmp) { Stop-Fwm 'Podaj -Port, -RemoteAddress lub protokół ICMP.' 3 }
    if ($Protocol -notin 'TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'ICMP', 'Any') { Stop-Fwm "Niedozwolony protokół: '$Protocol'" 3 }
    if ($isIcmp -and $portList) { Stop-Fwm 'Reguły ICMP nie obsługują portów – usuń -Port albo zmień protokół.' 3 }
    if ($icmpList -and -not $isIcmp) { Stop-Fwm '-IcmpType działa tylko z protokołem ICMPv4 lub ICMPv6.' 3 }
    if ($icmpList -and $Protocol -eq 'ICMP') { Stop-Fwm 'Typy ICMP różnią się między v4 i v6 – użyj -Protocol ICMPv4 albo ICMPv6 z -IcmpType.' 3 }
    if ($Direction -notin 'Inbound', 'Outbound', 'Any') { Stop-Fwm "Niedozwolony kierunek: '$Direction'" 3 }
    if ($BaseName -and $BaseName -notmatch '^[\w\.\-]+$') { Stop-Fwm "Niedozwolona nazwa: '$BaseName'" 3 }
    $profs = @($Profiles | Where-Object { $_ })
    foreach ($p in $profs) { if ($p -notin 'Domain', 'Private', 'Public', 'Any') { Stop-Fwm "Niedozwolony profil: '$p'" 3 } }
    $profs = if (-not $profs -or $profs -contains 'Any' -or @($profs | Select-Object -Unique).Count -ge 3) { @('Any') } else { @($profs | Select-Object -Unique | Sort-Object) }

    Assert-SafeTarget -Ports $(if ($SkipPortGuard) { @() } else { $portList }) -Addresses $addrList -Force:$Force
    # Blocking every ICMPv6 type breaks IPv6 neighbor discovery (NDP) and can cut the host off the network.
    if ($Protocol -in 'ICMPv6', 'ICMP' -and -not $icmpList) {
        if (-not $Force) { Stop-Fwm 'Blokada całego ICMPv6 psuje IPv6 (Neighbor Discovery). Podaj konkretny -IcmpType (np. 128 = echo request) albo użyj -Force.' 4 }
        Write-Msg 'Blokada całego ICMPv6 (kontynuacja dzięki -Force).' Warn
    }

    $protos = if ($Protocol -eq 'ICMP') { 'ICMPv4', 'ICMPv6' } elseif ($portList -and $Protocol -eq 'Any') { 'TCP', 'UDP' } else { , $Protocol }
    $dirs = if ($Direction -eq 'Any') { 'Inbound', 'Outbound' } else { , $Direction }
    foreach ($d in $dirs) {
        foreach ($pr in $protos) {
            $short = if ($d -eq 'Inbound') { 'In' } else { 'Out' }
            $ruleName = if ($BaseName) { "$script:Prefix$BaseName-$short-$pr" }
            else {
                $keys = ($addrList | ForEach-Object { (ConvertTo-AddressRange $_).Key } | Sort-Object) -join ','
                $bytes = [Text.Encoding]::UTF8.GetBytes("$d|$pr|$($portList -join ',')|$keys|$($icmpList -join ',')")
                $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').Substring(0, 8)
                "${script:Prefix}Block-$short-$pr-$hash"
            }
            [pscustomobject]@{
                Name = $ruleName; Direction = $d; Protocol = $pr; Port = [string[]]$portList
                RemoteAddress = [string[]]$addrList; Profile = [string[]]$profs; Enabled = $Enabled; IcmpType = [string[]]$icmpList
            }
        }
    }
}

function ConvertTo-KeyPart {
    param($Value, [switch]$Address)
    $items = @(@($Value) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'Any' })
    if ($Address) { $items = @($items | ForEach-Object { $r = ConvertTo-AddressRange $_; if ($r) { $r.Key } else { $_ } }) }
    ($items | Sort-Object) -join ';'
}

function Get-StateKey {
    <# .SYNOPSIS Canonical comparable string of a snapshot-shaped object (used for idempotency and drift detection). #>
    param($S)
    $prof = @(@($S.Profile) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $prof = if (-not $prof -or $prof -contains 'Any' -or $prof.Count -ge 3) { 'Any' } else { ($prof | Sort-Object) -join ';' }
    '{0}|{1}|{2}|{3}|L={4}|R={5}|A={6}|P={7}|I={8}' -f $S.Enabled, $S.Direction, $S.Action, $S.Protocol,
    (ConvertTo-KeyPart $S.LocalPort), (ConvertTo-KeyPart $S.RemotePort), (ConvertTo-KeyPart $S.RemoteAddress -Address), $prof, (ConvertTo-KeyPart $S.IcmpType)
}

function ConvertTo-StateShape {
    param($Spec)
    $in = $Spec.Direction -eq 'Inbound'
    [pscustomobject]@{
        Enabled = [string]$Spec.Enabled; Direction = $Spec.Direction; Action = 'Block'; Protocol = $Spec.Protocol
        LocalPort = if ($in) { $Spec.Port } else { @() }; RemotePort = if ($in) { @() } else { $Spec.Port }
        IcmpType = $Spec.IcmpType; RemoteAddress = $Spec.RemoteAddress; Profile = $Spec.Profile
    }
}

function Get-RuleSnapshot {
    <# .SYNOPSIS Concise state of a firewall rule object (for audit and comparison). #>
    param([Parameter(Mandatory)]$Rule)
    $pf = $Rule | Get-NetFirewallPortFilter
    $af = $Rule | Get-NetFirewallAddressFilter
    [pscustomobject]@{
        Name = $Rule.Name; Enabled = [string]$Rule.Enabled; Direction = [string]$Rule.Direction; Action = [string]$Rule.Action
        Protocol = [string]$pf.Protocol; LocalPort = (@($pf.LocalPort) -join ','); RemotePort = (@($pf.RemotePort) -join ','); IcmpType = (@($pf.IcmpType) -join ',')
        RemoteAddress = (@($af.RemoteAddress) -join ','); Profile = [string]$Rule.Profile
    }
}

function Get-RuleSnapshotByName {
    param([string]$RuleName)
    $r = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    if ($r) { Get-RuleSnapshot $r }
}

function Get-FwmRules {
    param([string]$Pattern = '*')
    Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue | Where-Object Name -Like $Pattern
}
#endregion

#region Rule operations
function Add-FwmRule {
    <# .SYNOPSIS Idempotent add: creates the rule, repairs it when different, skips when identical. Returns Done|Failed|Skipped|Unchanged. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Spec, [ValidateSet('Add', 'Enforce')][string]$Origin = 'Add')

    $in = $Spec.Direction -eq 'Inbound'
    # Filter nulls: an empty [string[]] stored in the spec can arrive as $null, and @($null) is a one-element array.
    $ports = @($Spec.Port | Where-Object { $_ })
    $addr = @($Spec.RemoteAddress | Where-Object { $_ })
    $types = @($Spec.IcmpType | Where-Object { $_ })
    $icmp = $Spec.Protocol -like 'ICMP*' # ports are not allowed on ICMP rules; type is used instead
    $p = @{ Direction = $Spec.Direction; Action = 'Block'; Protocol = $Spec.Protocol; Profile = @($Spec.Profile); Enabled = [string]$Spec.Enabled }
    $existing = Get-NetFirewallRule -Name $Spec.Name -ErrorAction SilentlyContinue

    if ($existing) {
        $before = Get-RuleSnapshot $existing
        if ((Get-StateKey $before) -eq (Get-StateKey (ConvertTo-StateShape $Spec))) {
            if ($Origin -eq 'Add') {
                Write-Msg "Reguła '$($Spec.Name)' już istnieje i jest zgodna – pominięto." Info
                Write-Audit -Operation 'Add' -Target $Spec.Name -Before $before -After $before -Message 'Unchanged (skipped)'
            }
            return 'Unchanged'
        }
        $op = if ($Origin -eq 'Enforce') { 'Enforce' } else { 'Modify' }
        # Explicit 'Any' so that stale ports/addresses are cleared.
        if ($icmp) { $p.IcmpType = if ($types.Count) { $types } else { 'Any' } }
        else {
            $p.LocalPort = if ($in -and $ports.Count) { $ports } else { 'Any' }
            $p.RemotePort = if (-not $in -and $ports.Count) { $ports } else { 'Any' }
        }
        $p.RemoteAddress = if ($addr.Count) { $addr } else { 'Any' }
        Invoke-Audited -Operation $op -Target $Spec.Name -Before $before `
            -Script { Set-NetFirewallRule -Name $Spec.Name @p } -AfterScript { Get-RuleSnapshotByName $Spec.Name }
    }
    else {
        $op = if ($Origin -eq 'Enforce') { 'Enforce' } else { 'Add' }
        if ($ports.Count) { if ($in) { $p.LocalPort = $ports } else { $p.RemotePort = $ports } }
        if ($addr.Count) { $p.RemoteAddress = $addr }
        if ($types.Count) { $p.IcmpType = $types }
        Invoke-Audited -Operation $op -Target $Spec.Name -Before $null `
            -Script { New-NetFirewallRule -Name $Spec.Name -DisplayName $Spec.Name -Group $script:Group -Description 'Managed by FirewallManager.ps1' @p } `
            -AfterScript { Get-RuleSnapshotByName $Spec.Name }
    }
}

function Get-FwmRuleView {
    param([string]$Pattern = '*')
    foreach ($r in @(Get-FwmRules $Pattern)) {
        $s = Get-RuleSnapshot $r
        [pscustomobject]@{ Name = $s.Name; Enabled = $s.Enabled; Direction = $s.Direction; Protocol = $s.Protocol; LocalPort = $s.LocalPort; RemotePort = $s.RemotePort; IcmpType = $s.IcmpType; RemoteAddress = $s.RemoteAddress; Profile = $s.Profile }
    }
}

function Update-FwmRule {
    <# .SYNOPSIS Modifies ports / addresses / protocol / profile of existing rules. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Pattern, [hashtable]$Changes)
    $rules = @(Get-FwmRules $Pattern)
    if (-not $rules) { Stop-Fwm "Nie znaleziono reguł pasujących do '$Pattern'." 6 }
    $ports = if ($Changes.Port) { @(ConvertTo-PortList $Changes.Port) }
    $addrs = @()
    foreach ($a in (@($Changes.RemoteAddress) -split ',')) {
        if (-not $a.Trim()) { continue }
        if (-not (ConvertTo-AddressRange $a)) { Stop-Fwm "Nieprawidłowy adres IP/CIDR/zakres: '$a'" 3 }
        $addrs += $a.Trim()
    }
    Assert-SafeTarget -Ports $ports -Addresses $addrs -Force:$Force
    foreach ($r in $rules) {
        $before = Get-RuleSnapshot $r
        $p = @{}
        if ($ports) { if ($before.Direction -eq 'Inbound') { $p.LocalPort = $ports } else { $p.RemotePort = $ports } }
        if ($addrs) { $p.RemoteAddress = $addrs }
        if ($Changes.Protocol) { $p.Protocol = $Changes.Protocol }
        if ($Changes.Profile) { $p.Profile = @($Changes.Profile) }
        if (-not $p.Count) { Stop-Fwm 'Modify: podaj -Port, -RemoteAddress, -Protocol i/lub -Profile.' 3 }
        $null = Invoke-Audited -Operation 'Modify' -Target $r.Name -Before $before `
            -Script { Set-NetFirewallRule -Name $r.Name @p } -AfterScript { Get-RuleSnapshotByName $r.Name }
    }
}

function Set-FwmRuleState {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Pattern, [bool]$Enabled)
    $op = if ($Enabled) { 'Enable' } else { 'Disable' }
    $rules = @(Get-FwmRules $Pattern)
    if (-not $rules) { Stop-Fwm "Nie znaleziono reguł pasujących do '$Pattern'." 6 }
    foreach ($r in $rules) {
        $before = Get-RuleSnapshot $r
        if ($before.Enabled -eq [string]$Enabled) { Write-Msg "Reguła '$($r.Name)' ma już Enabled=$Enabled." Info; continue }
        $null = Invoke-Audited -Operation $op -Target $r.Name -Before $before `
            -Script { Set-NetFirewallRule -Name $r.Name -Enabled ([string]$Enabled) } -AfterScript { Get-RuleSnapshotByName $r.Name }
    }
}

function Remove-FwmRule {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Pattern, [switch]$Force)
    $rules = @(Get-FwmRules $Pattern)
    if (-not $rules) { Stop-Fwm "Nie znaleziono reguł pasujących do '$Pattern'." 6 }
    # One confirmation for the whole set; per-rule prompts would make "Yes to All" apply to a single rule only.
    if (-not $DryRun) {
        if (-not $Force -and $ConfirmPreference -ne 'None') { $ConfirmPreference = 'Low' }
        if (-not $PSCmdlet.ShouldProcess(($rules.Name -join ', '), "Remove $($rules.Count) rule(s)")) { return }
        $ConfirmPreference = 'None' # already confirmed; Invoke-Audited must not prompt again
    }
    foreach ($r in $rules) {
        $null = Invoke-Audited -Operation 'Remove' -Target $r.Name -Before (Get-RuleSnapshot $r) `
            -Script { Remove-NetFirewallRule -Name $r.Name } -AfterScript { Get-RuleSnapshotByName $r.Name }
    }
}

function Import-FwmConfig {
    <# .SYNOPSIS Reads the JSON file and returns validated rule specs. #>
    param([string]$Path, [switch]$Force)
    if (-not (Test-Path -LiteralPath $Path)) { Stop-Fwm "Nie znaleziono pliku konfiguracyjnego: $Path" 6 }
    try { $cfg = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Stop-Fwm "Nieprawidłowy JSON w '$Path': $($_.Exception.Message)" 3 }
    if (-not $cfg.rules) { Stop-Fwm "Brak sekcji 'rules' w '$Path'." 3 }
    foreach ($r in @($cfg.rules)) {
        if (-not $r.name) { Stop-Fwm "Wpis konfiguracji bez pola 'name'." 3 }
        $ports = @($r.port | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        $proto = if ($r.protocol) { [string]$r.protocol } elseif ($ports) { 'TCP' } else { 'Any' }
        $dir = if ($r.direction) { [string]$r.direction } else { 'Any' }
        $enabled = if ($null -ne $r.enabled) { [bool]$r.enabled } else { $true }
        New-RuleSpecs -BaseName ([string]$r.name) -Protocol $proto -Ports $ports -Addresses @($r.remoteAddress | ForEach-Object { [string]$_ }) `
            -IcmpTypes @($r.icmpType | ForEach-Object { [string]$_ }) -Direction $dir -Profiles @($r.profile | ForEach-Object { [string]$_ }) -Enabled $enabled -Force:$Force
    }
}
#endregion

#region Profiles / status
function Get-ActiveProfiles {
    Get-NetConnectionProfile | ForEach-Object {
        $cat = [string]$_.NetworkCategory
        [pscustomobject]@{ Interface = $_.InterfaceAlias; Network = $_.Name; Profile = if ($cat -eq 'DomainAuthenticated') { 'Domain' } else { $cat } }
    }
}

function Get-FwmStatus {
    $active = @(Get-ActiveProfiles)
    $rules = @(Get-FwmRules)
    foreach ($pr in Get-NetFirewallProfile -Name $script:AllProfiles) {
        $n = @($rules | Where-Object { ([string]$_.Profile) -match "Any|$($pr.Name)" }).Count
        [pscustomobject]@{
            Profile = [string]$pr.Name; Enabled = [string]$pr.Enabled; DefaultInbound = [string]$pr.DefaultInboundAction
            DefaultOutbound = [string]$pr.DefaultOutboundAction; ScriptRules = $n; Active = [bool]($active | Where-Object Profile -eq ([string]$pr.Name))
        }
    }
}

function Set-FwmProfileState {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Profiles, [bool]$Enabled, [switch]$Force)
    if (-not $Enabled -and -not $Force) { Stop-Fwm 'Wyłączenie profilu zapory wymaga -Force.' 4 }
    $names = if (-not $Profiles -or $Profiles -contains 'Any') { $script:AllProfiles } else { $Profiles }
    $op = if ($Enabled) { 'Enable' } else { 'Disable' }
    foreach ($n in $names) {
        $get = { $x = Get-NetFirewallProfile -Name $n; [pscustomobject]@{ Name = [string]$x.Name; Enabled = [string]$x.Enabled; DefaultInboundAction = [string]$x.DefaultInboundAction; DefaultOutboundAction = [string]$x.DefaultOutboundAction } }
        $null = Invoke-Audited -Operation $op -Target "Profile:$n" -Before (& $get) `
            -Script { Set-NetFirewallProfile -Name $n -Enabled ([string]$Enabled) } -AfterScript $get
    }
}
#endregion

#region Enforcement + scheduled task
function Invoke-FwmEnforce {
    <# .SYNOPSIS Re-applies the config: creates missing, repairs drifted, re-enables disabled rules. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path)
    $active = @((Get-ActiveProfiles).Profile | Select-Object -Unique)
    Write-Msg ('Aktywny profil sieciowy: ' + $(if ($active) { $active -join ', ' } else { 'brak' }))
    # Config was reviewed at import time; do not block unattended enforcement on the lock-out guard.
    $specs = @(Import-FwmConfig -Path $Path -Force)
    $fixed = 0
    foreach ($s in $specs) {
        $r = Add-FwmRule -Spec $s -Origin Enforce
        if ($r -eq 'Done') { $fixed++ }
    }
    Write-Msg "Egzekwowanie zakończone: reguł w konfiguracji $($specs.Count), naprawionych/utworzonych $fixed."
    if ($fixed -gt 0) {
        Write-Audit -Operation 'Enforce' -Target ('Profile:' + ($active -join ',')) -Message "Enforcement pass: $fixed rule(s) created/repaired" -Level Warning
    }
    Get-FirewallChangeHistory -Since (Get-Date).AddDays(-1) -Notify | Out-Null
}

function Install-EnforcementTask {
    <# .SYNOPSIS Registers a SYSTEM scheduled task: at startup + on network profile change (NetworkProfile events 10000/10001). #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Config)
    $cfgFull = (Resolve-Path -LiteralPath $Config -ErrorAction SilentlyContinue).Path
    if (-not $cfgFull) { Stop-Fwm "Nie znaleziono pliku konfiguracyjnego: $Config" 6 }
    if ($script:ScriptPath -like "$env:SystemDrive\Users\*") {
        Write-Msg 'Skrypt leży w profilu użytkownika i będzie wykonywany jako SYSTEM – przenieś go do katalogu dostępnego tylko dla administratorów.' Warn
    }
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Enforce -ConfigPath "{1}" -LogPath "{2}"' -f $script:ScriptPath, $cfgFull, $LogPath.TrimEnd('\')
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
    $class = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'
    $evt = New-CimInstance -CimClass $class -ClientOnly
    $evt.Enabled = $true
    $evt.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000 or EventID=10001)]]</Select></Query></QueryList>'
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), $evt)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances Queue -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $null = Invoke-Audited -Operation 'Add' -Target "ScheduledTask:$script:TaskPath$script:TaskName" -Before $null `
        -Script { Register-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -Action $act -Trigger $triggers -Principal $principal -Settings $settings -Force } `
        -AfterScript { [pscustomobject]@{ State = [string](Get-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath).State } }
}

function Uninstall-EnforcementTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $t = Get-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
    if (-not $t) { Stop-Fwm 'Zadanie egzekwujące nie jest zainstalowane.' 6 }
    $null = Invoke-Audited -Operation 'Remove' -Target "ScheduledTask:$script:TaskPath$script:TaskName" -Before ([pscustomobject]@{ State = [string]$t.State }) `
        -Script { Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskPath -Confirm:$false }
}
#endregion

#region Change history (external change detection)
function Convert-SidToName {
    param([string]$Sid)
    try { ([Security.Principal.SecurityIdentifier]$Sid).Translate([Security.Principal.NTAccount]).Value } catch { $Sid }
}

function Get-EventData {
    param($EventRecord)
    $h = @{}
    foreach ($d in ([xml]$EventRecord.ToXml()).Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    $h
}

function Get-FirewallChangeHistory {
    <# .SYNOPSIS Reads firewall change events (Firewall log 2003-2006, optionally Security 4946-4950) and flags whether they came from this script (matched against the audit log within 30 s). #>
    [CmdletBinding()]
    param([datetime]$Since = (Get-Date).AddDays(-7), [switch]$IncludeSecurity, [switch]$Notify)

    $stateFile = Join-Path $LogPath 'lastcheck.txt'
    if ($Notify -and (Test-Path -LiteralPath $stateFile)) {
        $last = [datetime]::Parse((Get-Content -LiteralPath $stateFile -Raw).Trim(), [Globalization.CultureInfo]::InvariantCulture)
        if ($last -gt $Since) { $Since = $last }
    }
    $now = Get-Date

    $sources = @(
        @{ Log = 'Firewall'; Filter = @{ LogName = $script:FwLog; Id = 2003, 2004, 2005, 2006, 2097, 2099, 2052, 2082, 2059; StartTime = $Since } }
    )
    if ($IncludeSecurity) {
        Write-Msg 'Zdarzenia Security wymagają audytu: auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable'
        $sources += @{ Log = 'Security'; Filter = @{ LogName = 'Security'; Id = 4946, 4947, 4948, 4950; StartTime = $Since } }
    }
    # 2004-2006/2003: Vista-Win8 IDs; 2097/2099/2052/2082/2059: Windows 10/11 and Server 2016+ (verified against a Windows 11 log).
    $types = @{ 2003 = 'Zmiana ustawień/profilu'; 2004 = 'Dodanie reguły'; 2005 = 'Modyfikacja reguły'; 2006 = 'Usunięcie reguły'
        2097 = 'Dodanie reguły'; 2099 = 'Modyfikacja reguły'; 2052 = 'Usunięcie reguły'; 2082 = 'Zmiana ustawień/profilu'; 2059 = 'Usunięcie wszystkich reguł'
        4946 = 'Dodanie reguły'; 4947 = 'Modyfikacja reguły'; 4948 = 'Usunięcie reguły'; 4950 = 'Zmiana ustawień/profilu'
    }

    $audit = @()
    if (Test-Path -LiteralPath $LogPath) {
        $audit = @(Get-ChildItem -LiteralPath $LogPath -Filter 'firewall_*.log' -File | Where-Object LastWriteTime -ge $Since.AddMinutes(-1) |
                ForEach-Object { Get-Content -LiteralPath $_.FullName -Encoding UTF8 } | Where-Object { $_ } |
                ForEach-Object { $o = $_ | ConvertFrom-Json; [pscustomobject]@{ Time = [datetime]$o.Timestamp; Target = [string]$o.Target; Operation = $o.Operation; Result = $o.Result } } |
                Where-Object { $_.Result -eq 'Success' -and $_.Operation -ne 'External' })
    }

    $rows = foreach ($src in $sources) {
        try { $events = @(Get-WinEvent -FilterHashtable $src.Filter) }
        catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { Write-Msg "Nie można odczytać dziennika $($src.Log): $($_.Exception.Message)" Warn }
            $events = @()
        }
        foreach ($e in $events) {
            $d = Get-EventData $e
            $rule = [string]$d.RuleName
            $who = if ($d.ModifyingUser) { Convert-SidToName $d.ModifyingUser } elseif ($d.SubjectUserName) { "$($d.SubjectDomainName)\$($d.SubjectUserName)" } else { '' }
            $own = $audit | Where-Object { [Math]::Abs(($_.Time - $e.TimeCreated).TotalSeconds) -le 30 -and ($_.Target -eq $rule -or ($e.Id -in 2003, 2082, 4950 -and $_.Target -like 'Profile:*')) }
            [pscustomobject]@{
                Time = $e.TimeCreated; Log = $src.Log; Type = $types[[int]$e.Id]; Rule = $rule; User = $who
                Process = [string]$d.ModifyingApplication; Source = if ($own) { 'Skrypt' } else { 'Zewnętrzne' }
            }
        }
    }
    $rows = @($rows | Sort-Object Time -Descending)

    if ($Notify) {
        foreach ($x in ($rows | Where-Object { $_.Source -eq 'Zewnętrzne' -and $_.Rule -like "$script:Prefix*" })) {
            Write-Msg "Zmiana reguły '$($x.Rule)' poza skryptem ($($x.Type), $($x.User), $($x.Process))." Warn
            Write-Audit -Operation 'External' -Target $x.Rule -Message "$($x.Type) by '$($x.User)' via '$($x.Process)' at $($x.Time.ToString('o'))" -Level Warning
        }
        [System.IO.File]::WriteAllText($stateFile, $now.ToString('o'))
    }
    $rows
}
#endregion

#region Backup / restore
function Backup-FwmConfig {
    <# .SYNOPSIS Exports the whole firewall policy. netsh is used because no NetSecurity cmdlet exports/imports full policy (.wfw). #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$File)
    if (-not $File) { $File = Join-Path $script:DataRoot ('Backups\firewall_{0}.wfw' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    $dir = Split-Path -Parent $File
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    $st = Invoke-Audited -Operation 'Backup' -Target $File -Before $null `
        -Script { $o = & netsh advfirewall export $File 2>&1; if ($LASTEXITCODE -ne 0) { throw "netsh: $o" } } `
        -AfterScript { [pscustomobject]@{ File = $File; Bytes = (Get-Item -LiteralPath $File).Length } }
    if ($st -eq 'Done') { $File }
}

function Restore-FwmConfig {
    <# .SYNOPSIS Imports a .wfw backup (REPLACES the whole policy); a safety backup is taken first. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$File, [switch]$Force)
    if (-not $File -or -not (Test-Path -LiteralPath $File)) { Stop-Fwm 'Restore: podaj istniejący plik kopii w -BackupPath.' 6 }
    if (-not $DryRun -and $PSCmdlet.ShouldProcess($File, 'Safety backup')) { $null = Backup-FwmConfig }
    $null = Invoke-Audited -Operation 'Restore' -Target $File -Before $null -Destructive -Force:$Force `
        -Script { $o = & netsh advfirewall import $File 2>&1; if ($LASTEXITCODE -ne 0) { throw "netsh: $o" } }
}
#endregion

#region Connections
function Disconnect-FwmTcp {
    <# .SYNOPSIS Drops an established IPv4 TCP connection. No NetTCPIP cmdlet can do this, so iphlpapi!SetTcpEntry (MIB_TCP_STATE_DELETE_TCB) is used. Requires admin; IPv6 is not supported by this API. #>
    param([string]$LocalAddress, [int]$LocalPort, [string]$RemoteAddress, [int]$RemotePort)
    if (-not ('FwmTcp' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FwmTcp {
    [StructLayout(LayoutKind.Sequential)]
    struct MIB_TCPROW { public uint state; public uint localAddr; public uint localPort; public uint remoteAddr; public uint remotePort; }
    [DllImport("iphlpapi.dll")] static extern int SetTcpEntry(ref MIB_TCPROW row);
    static uint Port(int p) { return (uint)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF)); }
    public static int Drop(byte[] la, int lp, byte[] ra, int rp) {
        MIB_TCPROW r = new MIB_TCPROW();
        r.state = 12; // DELETE_TCB
        r.localAddr = BitConverter.ToUInt32(la, 0); r.localPort = Port(lp);
        r.remoteAddr = BitConverter.ToUInt32(ra, 0); r.remotePort = Port(rp);
        return SetTcpEntry(ref r);
    }
}
'@
    }
    $l = ConvertTo-IpAddress $LocalAddress; $r = ConvertTo-IpAddress $RemoteAddress
    if (-not $l -or -not $r -or $l.AddressFamily -ne 'InterNetwork' -or $r.AddressFamily -ne 'InterNetwork') { throw 'Zerwanie połączenia działa tylko dla IPv4.' }
    $rc = [FwmTcp]::Drop($l.GetAddressBytes(), $LocalPort, $r.GetAddressBytes(), $RemotePort)
    if ($rc -eq 317) { throw 'SetTcpEntry zwróciło 317 – zwykle oznacza brak uprawnień administratora albo połączenie już nie istnieje.' }
    if ($rc -ne 0) { throw "SetTcpEntry zwróciło kod $rc ($(([System.ComponentModel.Win32Exception]$rc).Message))" }
}

function Test-IpInRange {
    param([string]$Ip, $Range)
    $a = ConvertTo-IpAddress ($Ip -replace '%.*$', '')
    if (-not $a) { return $false }
    $b = $a.GetAddressBytes()
    $b.Length -eq $Range.Lo.Length -and (Compare-Bytes $Range.Lo $b) -le 0 -and (Compare-Bytes $b $Range.Hi) -le 0
}

function Get-FwmConnections {
    <# .SYNOPSIS Lists TCP connections with owning process and a per-run Id (valid only for this listing). UDP has no connection state and is not listed. #>
    [CmdletBinding()]
    param([string[]]$Ports, [string[]]$Addresses, [string]$State = 'Established', [switch]$ResolveDns)

    $portRanges = @()
    if ($Ports) { foreach ($t in (ConvertTo-PortList $Ports)) { $x = $t -split '-'; $portRanges += , @([int]$x[0], [int]$x[-1]) } }
    $addrRanges = @()
    foreach ($a in (@($Addresses) -split ',')) {
        if (-not $a.Trim()) { continue }
        $r = ConvertTo-AddressRange $a
        if (-not $r) { Stop-Fwm "Nieprawidłowy adres IP/CIDR/zakres: '$a'" 3 }
        $addrRanges += $r
    }

    $all = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $listening = @($all | Where-Object { [string]$_.State -eq 'Listen' } | ForEach-Object { $_.LocalPort } | Select-Object -Unique)
    $procs = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.Id] = $_ }
    $dns = @{}

    $rows = foreach ($c in $all) {
        if ($State -ne 'All' -and [string]$c.State -ne $State) { continue }
        if ($portRanges.Count -and -not @($portRanges | Where-Object { ($c.LocalPort -ge $_[0] -and $c.LocalPort -le $_[1]) -or ($c.RemotePort -ge $_[0] -and $c.RemotePort -le $_[1]) })) { continue }
        if ($addrRanges.Count -and -not @($addrRanges | Where-Object { Test-IpInRange $c.RemoteAddress $_ })) { continue }
        $proc = $procs[[int]$c.OwningProcess]
        $path = try { $proc.Path } catch { $null }
        $remote = $c.RemoteAddress -replace '%.*$', ''
        $hostName = ''
        if ($ResolveDns -and $remote -notin '0.0.0.0', '::') {
            if (-not $dns.ContainsKey($remote)) {
                $dns[$remote] = [string](Resolve-DnsName -Name $remote -Type PTR -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NameHost)
            }
            $hostName = $dns[$remote]
        }
        $fmt = { param($ip, $pt) if ($ip -match ':') { "[$ip]:$pt" } else { "${ip}:$pt" } }
        [pscustomobject]@{
            Proto = 'TCP'; Local = (& $fmt ($c.LocalAddress -replace '%.*$', '') $c.LocalPort); Remote = (& $fmt $remote $c.RemotePort)
            State = [string]$c.State; Direction = if ($listening -contains $c.LocalPort -and [string]$c.State -ne 'Listen') { 'In' } else { 'Out' }
            PID = [int]$c.OwningProcess; Process = if ($proc) { $proc.ProcessName } else { '' }; Host = $hostName; Path = $path
            LocalAddress = ($c.LocalAddress -replace '%.*$', ''); LocalPort = [int]$c.LocalPort; RemoteAddress = $remote; RemotePort = [int]$c.RemotePort
        }
    }
    $n = 0
    foreach ($r in ($rows | Sort-Object RemoteAddress, RemotePort, PID)) { $n++; $r | Add-Member -NotePropertyName Id -NotePropertyValue $n -PassThru }
}

function Show-FwmConnections {
    param([object[]]$Connections)
    if (-not $Connections) { Write-Msg 'Brak połączeń spełniających kryteria.'; return }
    $cols = 'Id', 'Proto', 'Local', 'Remote', 'State', 'Direction', 'PID', 'Process'
    if ($Connections | Where-Object Host) { $cols += 'Host' }
    $Connections | Format-Table -Property $cols -AutoSize | Out-Host
    Write-Msg 'Id jest ważne tylko dla tego wyświetlenia (numeracja zmienia się przy każdym odczycie).'
}

function Invoke-FwmConnectionBlock {
    <# .SYNOPSIS Interactively creates block rules from selected connections (via the normal idempotent Add path) and optionally drops them. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([object[]]$Connections, [switch]$Force, [switch]$Disconnect)
    if (-not $Connections) { return }

    $answer = (Read-Host 'Numery połączeń do zablokowania (np. 1,3-5; Enter = anuluj)').Trim()
    if (-not $answer) { Write-Msg 'Anulowano.'; return }
    $ids = foreach ($tok in ($answer -split '[,\s]+' | Where-Object { $_ })) {
        if ($tok -match '^(\d+)$') { [int]$Matches[1] }
        elseif ($tok -match '^(\d+)-(\d+)$') { [int]$Matches[1]..[int]$Matches[2] }
        else { Stop-Fwm "Nieprawidłowy numer: '$tok'" 3 }
    }
    $sel = @($Connections | Where-Object { $_.Id -in $ids })
    $missing = @($ids | Where-Object { $_ -notin $Connections.Id })
    if ($missing) { Stop-Fwm ('Brak połączeń o numerach: ' + ($missing -join ', ')) 3 }

    $scope = Read-Host 'Zakres: 1) zdalny adres  2) zdalny adres + port  3) port lokalny (tylko połączenia przychodzące) [1]'
    if (-not $scope) { $scope = '1' }
    if ($scope -notin '1', '2', '3') { Stop-Fwm "Nieprawidłowy zakres: '$scope'" 3 }
    $dir = 'Any'; $prof = 'Any'
    if ($scope -eq '1') {
        $dir = Read-Host 'Kierunek (Inbound/Outbound/Any) [Any]'; if (-not $dir) { $dir = 'Any' }
    }
    $profIn = Read-Host 'Profile (Domain,Private,Public lub Any) [Any]'; if ($profIn) { $prof = $profIn }

    # Validate everything before creating anything.
    $specs = @()
    foreach ($c in $sel) {
        $isIn = $c.Direction -eq 'In'
        if ($c.RemoteAddress -in '0.0.0.0', '::') { Write-Msg "Połączenie $($c.Id) nie ma zdalnego adresu (Listen) – pominięto." Warn; continue }
        if ($isIn -and $c.LocalPort -in 3389, 5985, 5986 -and -not $Force) {
            Stop-Fwm "Połączenie $($c.Id) ($($c.Remote) -> port $($c.LocalPort)) może obsługiwać Twoją sesję zdalną; blokada odetnie dostęp. Użyj -Force." 4
        }
        # Only the address is checked here: with a specific peer, critical ports (e.g. outbound 443) are not a lock-out risk.
        Assert-SafeTarget -Ports @() -Addresses @($c.RemoteAddress) -Force:$Force
        $label = $c.RemoteAddress -replace '[:.]', '-'
        switch ($scope) {
            '1' { $specs += New-RuleSpecs -BaseName "Conn-$label" -Protocol Any -Addresses $c.RemoteAddress -Direction $dir -Profiles ($prof -split ',') -Force }
            '2' {
                $p = if ($isIn) { $c.LocalPort } else { $c.RemotePort }
                $d = if ($isIn) { 'Inbound' } else { 'Outbound' }
                $specs += New-RuleSpecs -BaseName "Conn-$label-$p" -Protocol TCP -Ports "$p" -Addresses $c.RemoteAddress -Direction $d -Profiles ($prof -split ',') -Force -SkipPortGuard
            }
            '3' {
                if (-not $isIn) { Write-Msg "Połączenie $($c.Id) jest wychodzące – brak lokalnego portu usługi, pominięto." Warn; continue }
                # No -Force here: blocking a whole local port stays under the critical-port guard.
                $specs += New-RuleSpecs -BaseName "Conn-Port-$($c.LocalPort)" -Protocol TCP -Ports "$($c.LocalPort)" -Direction Inbound -Profiles ($prof -split ',') -Force:$Force
            }
        }
    }
    $specs = @($specs | Group-Object Name | ForEach-Object { $_.Group[0] })
    if (-not $specs) { Write-Msg 'Brak reguł do utworzenia.'; return }

    $specs | Format-Table Name, Direction, Protocol, @{ n = 'Port'; e = { $_.Port -join ',' } }, @{ n = 'RemoteAddress'; e = { $_.RemoteAddress -join ',' } }, @{ n = 'Profile'; e = { $_.Profile -join ',' } } -AutoSize | Out-Host
    if ((Read-Host "Utworzyć $($specs.Count) reguł(y)? [T/n]") -match '^[nN]') { Write-Msg 'Anulowano.'; return }
    foreach ($s in $specs) { $null = Add-FwmRule -Spec $s }

    if ($Disconnect -or (Read-Host 'Przerwać istniejące połączenia TCP? Zapora może nie zerwać już nawiązanych sesji [t/N]') -match '^[tTyY]') {
        foreach ($c in $sel) {
            if ($c.RemoteAddress -in '0.0.0.0', '::') { continue }
            $null = Invoke-Audited -Operation 'Disconnect' -Target "$($c.Local) -> $($c.Remote)" `
                -Before ([pscustomobject]@{ Local = $c.Local; Remote = $c.Remote; PID = $c.PID; Process = $c.Process }) `
                -Script { Disconnect-FwmTcp -LocalAddress $c.LocalAddress -LocalPort $c.LocalPort -RemoteAddress $c.RemoteAddress -RemotePort $c.RemotePort }
        }
    }
}
#endregion

#region Menu + main
function Show-FwmMenu {
    while ($true) {
        Write-Information @'

=== FirewallManager ===
 1) Status        2) Lista reguł      3) Zablokuj port/adres
 4) Włącz regułę  5) Wyłącz regułę    6) Usuń regułę
 7) Historia zmian  8) Kopia zapasowa  9) Egzekwuj konfigurację
10) Połączenia (blokowanie wybranego połączenia)
 0) Wyjście
'@ -InformationAction Continue
        $c = Read-Host 'Wybór'
        try {
            switch ($c) {
                '1' { Get-FwmStatus | Format-Table -AutoSize | Out-Host }
                '2' { Get-FwmRuleView | Format-Table -AutoSize | Out-Host }
                '3' {
                    $proto = Read-Host 'Protokół (TCP/UDP/Any) [TCP]'; if (-not $proto) { $proto = 'TCP' }
                    $ports = Read-Host 'Porty (np. 135,139,445 lub 5000-5100; puste = brak)'
                    $addr = Read-Host 'Adresy (IP/CIDR/zakres, oddzielone przecinkami; puste = brak)'
                    $dir = Read-Host 'Kierunek (Inbound/Outbound/Any) [Any]'; if (-not $dir) { $dir = 'Any' }
                    $prof = Read-Host 'Profile (Domain,Private,Public lub Any) [Any]'; if (-not $prof) { $prof = 'Any' }
                    $specs = New-RuleSpecs -Protocol $proto -Ports @($ports) -Addresses @($addr) -Direction $dir -Profiles ($prof -split ',') -Force:$Force
                    foreach ($s in $specs) { $null = Add-FwmRule -Spec $s }
                }
                '4' { Set-FwmRuleState -Pattern (Resolve-RuleName (Read-Host 'Nazwa reguły')) -Enabled $true }
                '5' { Set-FwmRuleState -Pattern (Resolve-RuleName (Read-Host 'Nazwa reguły')) -Enabled $false }
                '6' { Remove-FwmRule -Pattern (Resolve-RuleName (Read-Host 'Nazwa reguły')) -Force:$Force }
                '7' { Get-FirewallChangeHistory -Since (Get-Date).AddDays(-$Days) | Format-Table -AutoSize | Out-Host }
                '8' { Backup-FwmConfig -File $BackupPath | Out-Null }
                '9' { Invoke-FwmEnforce -Path $ConfigPath }
                '10' { $conns = @(Get-FwmConnections -State Established); Show-FwmConnections $conns; Invoke-FwmConnectionBlock -Connections $conns -Force:$Force -Disconnect:$Disconnect }
                '0' { return }
            }
        }
        catch { Write-Msg $_.Exception.Message Error }
    }
}

function Invoke-Main {
    try {
        if (-not (Test-IsAdmin)) { Stop-Fwm 'Skrypt wymaga uprawnień administratora. Uruchom PowerShell jako administrator.' 2 }
        Initialize-Logging
        $mutating = 'Block', 'Modify', 'Remove', 'Enable', 'Disable', 'Import', 'Enforce'
        if ($BackupFirst -and $Action -in $mutating -and -not $WhatIfPreference) { $null = Backup-FwmConfig -File $null }

        switch ($Action) {
            'Block' {
                # Only addresses given -> all protocols; ports given -> -Protocol (default TCP).
                $proto = if (-not $script:Bound.ContainsKey('Protocol') -and -not $Port) { 'Any' } else { $Protocol }
                $specs = @(New-RuleSpecs -BaseName $Name -Protocol $proto -Ports $Port -Addresses $RemoteAddress -IcmpTypes $IcmpType -Direction $Direction -Profiles $NetProfile -Force:$Force)
                foreach ($s in $specs) { $null = Add-FwmRule -Spec $s }
            }
            'List' { $p = if ($Name) { Resolve-RuleName $Name } else { '*' }; Get-FwmRuleView $p | Format-Table -AutoSize | Out-Host }
            'Modify' {
                $ch = @{ Port = $Port; RemoteAddress = $RemoteAddress }
                if ($script:Bound.ContainsKey('Protocol')) { $ch.Protocol = $Protocol }
                if ($script:Bound.ContainsKey('NetProfile')) { $ch.Profile = $NetProfile }
                Update-FwmRule -Pattern (Resolve-RuleName $Name) -Changes $ch
            }
            'Remove' { Remove-FwmRule -Pattern (Resolve-RuleName $Name) -Force:$Force }
            'Enable' { if ($Scope -eq 'Profile') { Set-FwmProfileState -Profiles $NetProfile -Enabled $true } else { Set-FwmRuleState -Pattern (Resolve-RuleName $Name) -Enabled $true } }
            'Disable' { if ($Scope -eq 'Profile') { Set-FwmProfileState -Profiles $NetProfile -Enabled $false -Force:$Force } else { Set-FwmRuleState -Pattern (Resolve-RuleName $Name) -Enabled $false } }
            'Status' {
                Get-FwmStatus | Format-Table -AutoSize | Out-Host
                Get-ActiveProfiles | Format-Table -AutoSize | Out-Host
            }
            'Import' {
                $specs = @(Import-FwmConfig -Path $ConfigPath -Force:$Force) # validate everything before applying anything
                foreach ($s in $specs) { $null = Add-FwmRule -Spec $s }
            }
            'Enforce' { Invoke-FwmEnforce -Path $ConfigPath }
            'History' {
                $h = @(Get-FirewallChangeHistory -Since (Get-Date).AddDays(-$Days) -IncludeSecurity:$IncludeSecurity -Notify:$Notify)
                if ($h) { $h | Format-Table -AutoSize | Out-Host } else { Write-Msg "Brak zmian reguł zapory w ostatnich $Days dniach (lub dziennik zdarzeń zapory jest wyłączony)." }
            }
            'Backup' { $f = Backup-FwmConfig -File $BackupPath; if ($f) { Write-Msg "Kopia zapasowa: $f" Ok } }
            'Restore' { Restore-FwmConfig -File $BackupPath -Force:$Force }
            'InstallTask' { Install-EnforcementTask -Config $ConfigPath }
            'UninstallTask' { Uninstall-EnforcementTask }
            'Menu' { Show-FwmMenu }
            'Connections' {
                $conns = @(Get-FwmConnections -Ports $Port -Addresses $RemoteAddress -State $ConnectionState -ResolveDns:$ResolveDns)
                Show-FwmConnections $conns
                if ($Interactive) { Invoke-FwmConnectionBlock -Connections $conns -Force:$Force -Disconnect:$Disconnect }
            }
        }
        if ($script:FailureCount -gt 0) { $script:ExitCode = 5 }
    }
    catch {
        $script:ExitCode = if ($_.Exception.Data.Contains('ExitCode')) { [int]$_.Exception.Data['ExitCode'] } else { 1 }
        Write-Msg $_.Exception.Message Error
        if ($script:ExitCode -eq 1) { Write-Audit -Operation 'Error' -Target $Action -Result Failure -ErrorText $_.Exception.ToString() }
    }
    finally {
        Write-Verbose "Zakończono (kod wyjścia $script:ExitCode)."
    }
}
#endregion

# Skip execution when dot-sourced (e.g. for testing functions).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Main
    exit $script:ExitCode
}
