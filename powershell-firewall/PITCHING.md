# Demo: co uruchomić

Wymagane: PowerShell 5.1 jako administrator, w katalogu ze skryptem; sesja SSH do `192.168.100.89` otwarta w drugim oknie.

```powershell
# 0. przygotowanie
Set-ExecutionPolicy -Scope Process Bypass
.\FirewallManager.ps1 -Action Backup
.\FirewallManager.ps1 -Action Status

# 1. dry-run i blokada portów
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 135,139,445 -Direction Inbound -Profile Public -DryRun
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 135,139,445 -Direction Inbound -Profile Public
.\FirewallManager.ps1 -Action List

# 2. ochrona przed odcięciem (kod 4)
.\FirewallManager.ps1 -Action Block -Port 3389

# 3. GŁÓWNY PUNKT: odcięcie sesji SSH
.\FirewallManager.ps1 -Action Connections -Interactive -RemoteAddress 192.168.100.89 -Disconnect
#   w kreatorze: numer połączenia z portem 22, zakres 2, profil Enter, potwierdzenie T

# 4. naprawa dryfu
.\FirewallManager.ps1 -Action Import
Disable-NetFirewallRule -Name FWM-CfgSMB-In-TCP
.\FirewallManager.ps1 -Action Enforce

# 5. zmiany spoza skryptu
netsh advfirewall firewall add rule name="FWM-ExtTest" dir=in action=block protocol=tcp localport=9997
netsh advfirewall firewall delete rule name="FWM-ExtTest"
.\FirewallManager.ps1 -Action History -Days 1

# 6. sprzątanie
.\FirewallManager.ps1 -Action Remove -Name '*' -Force
```

Do kroku 4 potrzebny jest `C:\ProgramData\FirewallManager\rules.json` z regułą `CfgSMB` (port 9999, Inbound), np.:

```json
{ "rules": [ { "name": "CfgSMB", "protocol": "TCP", "port": ["9999"], "direction": "Inbound", "profile": ["Public", "Private"] } ] }
```

Ratunek: `.\FirewallManager.ps1 -Action Restore -BackupPath <plik .wfw z kroku 0>`. Nie blokuj na żywo portu 443, całego ICMPv6 ani połączeń na `127.0.0.1`.
