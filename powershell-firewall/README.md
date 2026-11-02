# FirewallManager.ps1

Single-file manager for Windows Defender Firewall rules (PowerShell 5.1 / 7+, admin required).
All managed rules: name `FWM-*`, group `FirewallManager`. Full help: `Get-Help .\FirewallManager.ps1 -Full`.
Save the file as **UTF-8 with BOM** (Polish messages, PS 5.1).

## Architecture
Sections: constants -> helpers -> audit (`Write-Audit`, `Invoke-Audited`: ShouldProcess + before/after JSONL + Event Log) ->
validation (`ConvertTo-PortList`, `ConvertTo-AddressRange`, `Assert-SafeTarget`) -> rule model (`New-RuleSpecs`, `Get-StateKey`) ->
operations (`Add-FwmRule`, `Update-FwmRule`, `Set-FwmRuleState`, `Remove-FwmRule`, `Import-FwmConfig`) ->
profiles (`Get-FwmStatus`, `Set-FwmProfileState`, `Get-ActiveProfiles`) ->
enforcement (`Invoke-FwmEnforce`, `Install-/Uninstall-EnforcementTask`) ->
history (`Get-FirewallChangeHistory`) -> `Backup-/Restore-FwmConfig` -> `Show-FwmMenu`, `Invoke-Main`.

## Examples
```powershell
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 135,139,445 -Direction Inbound -Profile Public
.\FirewallManager.ps1 -Action Block -RemoteAddress 203.0.113.1-203.0.113.50,10.0.0.0/8 -Name BadNet
.\FirewallManager.ps1 -Action Block -Protocol Any -Port 5000-5100 -Direction Outbound -DryRun
.\FirewallManager.ps1 -Action Status
.\FirewallManager.ps1 -Action Disable -Name 'BadNet*'
.\FirewallManager.ps1 -Action Import -ConfigPath .\rules.example.json -BackupFirst
.\FirewallManager.ps1 -Action InstallTask -ConfigPath C:\ProgramData\FirewallManager\rules.json
.\FirewallManager.ps1 -Action History -Days 3 -IncludeSecurity -Notify
```
Security-log events need: `auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable`
(on non-English Windows use the subcategory GUID `{0CCE9232-69AE-11D9-BED3-505054503030}`).

Exit codes: 0 ok, 1 unexpected, 2 not admin, 3 invalid input, 4 `-Force` required, 5 some operations failed, 6 not found.

## Test checklist
- **Blocking:** `-Action Block ... -DryRun` prints, changes nothing; real run -> `-Action List` shows rule; second run reports "pominięto" (idempotent); `-Port 443` / `-RemoteAddress 127.0.0.1` without `-Force` -> exit 4.
- **Enforcement:** `Import`, then `Set-NetFirewallRule -Name FWM-... -Enabled False` (or change its port), run `-Action Enforce` -> rule repaired, `Enforce` entry in log. After `InstallTask`: `Start-ScheduledTask -TaskPath \FirewallManager\ -TaskName Enforce`, then switch network profile (e.g. change network category) and confirm a new Enforce run in Task History / log.
- **Logging:** `%ProgramData%\FirewallManager\Logs\firewall_YYYYMMDD.log` has JSON lines (Timestamp, User, Computer, Operation, Target, Before, After, Result); Event Viewer -> Application, source `FirewallManager`, IDs 1001-1008, 1100, 1900.
- **External changes:** `netsh advfirewall firewall add rule name="FWM-test" dir=in action=block protocol=tcp localport=9999` (or the wf.msc GUI), then `-Action History -Days 1 -Notify` -> row with Source `Zewnętrzne` + Warning event 1100; a rule added by the script shows `Skrypt`.
- **Backup:** `-Action Backup`, change something, `-Action Restore -BackupPath <file>`.

## Limits
- GPO / MDM rules can override or hide local rules; the script manages the local persistent store only.
- Firewall log (*Windows Firewall With Advanced Security/Firewall*, must be enabled): Windows 10/11 and Server 2016+ use IDs 2097 (rule added), 2099 (modified), 2052 (deleted), 2082 (setting changed), 2059 (all rules deleted); the older IDs 2003-2006 are read too. Modifying application/user are not always present.
- "Script vs external" is decided by matching an audit-log entry for the same rule within 30 s; a foreign change within that window of a script change is attributed to the script.
- Port semantics: Inbound = local port, Outbound = remote port.
- `InstallTask` runs the script as SYSTEM: keep it in an admin-only folder.
- Not run against a live firewall in development (non-elevated session): only syntax parse (PS 5.1) and validator functions were exercised. PSScriptAnalyzer was not available.
