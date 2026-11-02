# Instrukcja testowania FirewallManager.ps1

Najlepiej testuj na maszynie wirtualnej lub komputerze testowym. Wszystkie polecenia uruchamiaj w **PowerShell 5.1 jako administrator**, w katalogu ze skryptem. Powtórz najważniejsze testy w PowerShell 7 (`pwsh`), jeśli go używasz.

Do testów używaj bezpiecznych wartości: port `9999`, adresy z puli dokumentacyjnej `203.0.113.0/24` (TEST-NET-3) i port `80` do testu realnego efektu. **Nie używaj** `rules.example.json` do testów: zawiera `10.0.0.0/8`, co może zablokować Twoją sieć lokalną.

W każdym kroku sprawdzaj kod wyjścia: `$LASTEXITCODE` zaraz po uruchomieniu skryptu.

## 0. Przygotowanie

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Unblock-File .\FirewallManager.ps1
.\FirewallManager.ps1 -Action Backup          # kopia całej zapory (zapamiętaj ścieżkę .wfw)
.\FirewallManager.ps1 -Action Status
```

Oczekiwane: kod `0`, plik `.wfw` w `C:\ProgramData\FirewallManager\Backups`. Jeśli dla aktywnego profilu `Enabled = False`, włącz go: `-Action Enable -Scope Profile -Profile Private` (bez tego reguły nie mają efektu).

Przydatne do podglądu logu w każdym kroku:

```powershell
Get-Content (Get-ChildItem C:\ProgramData\FirewallManager\Logs\firewall_*.log | Sort LastWriteTime | Select -Last 1) -Tail 5
```

## 1. Tryb próbny (`-DryRun`)

```powershell
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 9999 -Direction Inbound -DryRun
.\FirewallManager.ps1 -Action List
```

Oczekiwane: komunikat `DryRun: operacja 'Add' na obiekcie 'FWM-Block-In-TCP-...'`, lista pusta, **brak** nowego wpisu w logu.

## 2. Blokowanie i idempotencja

```powershell
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 9999 -Direction Inbound -Profile Public
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 9999 -Direction Inbound -Profile Public   # drugi raz
.\FirewallManager.ps1 -Action Block -Protocol Any -Port 5000-5100,9998 -Direction Any -Name TestPorts
.\FirewallManager.ps1 -Action Block -RemoteAddress 203.0.113.1-203.0.113.50,2001:db8::/32 -Direction Any -Name TestNet
.\FirewallManager.ps1 -Action List
```

Oczekiwane:
- pierwsze wywołanie: `Add` (kod `0`); drugie: „już istnieje i jest zgodna – pominięto”, **bez** duplikatu na liście,
- `TestPorts` tworzy 4 reguły (In/Out × TCP/UDP), `TestNet` 2 reguły (In/Out, protokół Any),
- zmiana profilu przy tej samej regule (`-Profile Private` zamiast `Public`) daje `Modify`, nie nową regułę.

## 3. Walidacja i ochrona przed odcięciem

| Polecenie | Oczekiwany kod |
|---|---|
| `-Action Block -Port 0` | 3 |
| `-Action Block -Port 70000` | 3 |
| `-Action Block -Port 9-5` | 3 |
| `-Action Block -RemoteAddress 300.1.1.1` | 3 |
| `-Action Block -RemoteAddress 10.0.0.0/33` | 3 |
| `-Action Block -RemoteAddress 1.1.1.1-::1` (mieszane rodziny) | 3 |
| `-Action Block -Protocol TCP` (brak portu i adresu) | 3 |
| `-Action Block -Port 3389` (bez `-Force`) | 4 |
| `-Action Block -Port 443 -Direction Outbound` (bez `-Force`) | 4 |
| `-Action Block -RemoteAddress 127.0.0.1` (bez `-Force`) | 4 |
| `-Action Block -RemoteAddress 0.0.0.0/0` (obejmuje Twój adres) | 4 |
| `-Action Remove -Name NieMaTakiej` | 6 |

Sprawdź też, że po kodzie 3/4 **nie powstała** żadna reguła. Test `-Force` wykonuj tylko z `-DryRun`, żeby się nie odciąć: `-Action Block -Port 3389 -Force -DryRun` powinno dać ostrzeżenie i komunikat DryRun.

## 4. Modyfikacja, włączanie, wyłączanie, usuwanie

```powershell
.\FirewallManager.ps1 -Action Modify -Name TestNet* -RemoteAddress 203.0.113.100
.\FirewallManager.ps1 -Action Disable -Name TestPorts*
.\FirewallManager.ps1 -Action List -Name TestPorts*      # Enabled = False
.\FirewallManager.ps1 -Action Enable  -Name TestPorts*
.\FirewallManager.ps1 -Action Remove -Name TestPorts*    # pyta o potwierdzenie
.\FirewallManager.ps1 -Action Remove -Name TestNet* -Force
.\FirewallManager.ps1 -Action List
```

Oczekiwane: po `Modify` adres to `203.0.113.100`; ponowne `Disable` już wyłączonej reguły pisze „ma już Enabled=False”; `Remove` bez `-Force` pyta `[Y/N]`; po usunięciu lista pusta (kod `0`).

## 5. Realny efekt blokady (sprawdza, że zapora naprawdę blokuje)

```powershell
Test-NetConnection example.com -Port 80                  # TcpTestSucceeded : True
.\FirewallManager.ps1 -Action Block -Protocol TCP -Port 80 -Direction Outbound -Name TestOut80
Test-NetConnection example.com -Port 80                  # TcpTestSucceeded : False
.\FirewallManager.ps1 -Action Disable -Name TestOut80*
Test-NetConnection example.com -Port 80                  # znów True
.\FirewallManager.ps1 -Action Remove -Name TestOut80* -Force
```

Dla ruchu przychodzącego: uruchom nasłuch (`$l=[Net.Sockets.TcpListener]9999; $l.Start()`), zablokuj Inbound TCP 9999 i spróbuj połączyć się z **innego** komputera (`Test-NetConnection <ip> -Port 9999`). Połączenie z tego samego komputera przez loopback nie sprawdza reguł.

## 6. Konfiguracja JSON, egzekwowanie i dryf

Zapisz `C:\ProgramData\FirewallManager\rules.json`:

```json
{ "rules": [
  { "name": "CfgSMB", "protocol": "TCP", "port": ["9999"], "direction": "Inbound", "profile": ["Public", "Private"] },
  { "name": "CfgNet", "remoteAddress": ["203.0.113.1-203.0.113.50"], "direction": "Any" }
] }
```

```powershell
.\FirewallManager.ps1 -Action Import -BackupFirst
.\FirewallManager.ps1 -Action Enforce                 # nic do naprawy: bez wpisów Enforce w logu
# Symulacja dryfu:
Disable-NetFirewallRule -Name FWM-CfgSMB-In-TCP
Set-NetFirewallRule     -Name FWM-CfgNet-Out-Any -RemoteAddress 198.51.100.1
Remove-NetFirewallRule  -Name FWM-CfgNet-In-Any
.\FirewallManager.ps1 -Action Enforce
.\FirewallManager.ps1 -Action List
```

Oczekiwane: `Enforce` po dryfie wypisuje 3 operacje (włączenie, naprawa adresu, odtworzenie), w logu są wpisy `Operation: Enforce` ze stanem `Before`/`After`, a lista wraca do stanu z pliku. Błędy konfiguracji: pusty plik / zły JSON → kod 3, brak pliku → kod 6, `"direction": "Both"` → kod 3.

## 7. Zadanie zaplanowane i zmiana profilu

```powershell
.\FirewallManager.ps1 -Action InstallTask
Get-ScheduledTask -TaskPath \FirewallManager\ | Get-ScheduledTaskInfo
Start-ScheduledTask -TaskPath \FirewallManager\ -TaskName Enforce
Start-Sleep 10; (Get-ScheduledTaskInfo -TaskPath \FirewallManager\ -TaskName Enforce).LastTaskResult   # 0
```

Następnie wywołaj dryf jak w kroku 6 (np. `Disable-NetFirewallRule -Name FWM-CfgSMB-In-TCP`) i **zmień kategorię sieci**:

```powershell
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Public   # a potem z powrotem Private
```

Oczekiwane: zdarzenie 10000/10001 w `Microsoft-Windows-NetworkProfile/Operational` uruchamia zadanie i reguła zostaje naprawiona sama, z wpisem `Enforce` w logu (użytkownik `NT AUTHORITY\SYSTEM`). Sprawdź też w Harmonogramie zadań, że zadanie ma wyzwalacze „Przy uruchomieniu” i zdarzeniowy oraz działa jako SYSTEM. Test uruchomienia przy starcie: restart komputera i sprawdzenie logu. Sprzątanie: `-Action UninstallTask`.

## 8. Logowanie (audyt)

1. Plik `C:\ProgramData\FirewallManager\Logs\firewall_YYYYMMDD.log`: każda linia to JSON z polami `Timestamp` (ISO 8601), `User` (`DOMENA\login`), `Computer`, `Operation`, `Target`, `Before`, `After`, `Result`, `Error`.
2. Dla `Add` pole `Before` jest `null`, dla `Remove` `After` jest `null`.
3. Wymuszony błąd: np. `-Action Modify -Name FWM-X -Protocol Any -Port 80` na regule z portem, dla której Windows odrzuci zmianę (jeśli nie uda się wywołać błędu, pomiń). Oczekiwane: `Result: Failure`, `Error` z treścią, kod wyjścia 5.
4. Dziennik zdarzeń: Podgląd zdarzeń → Dzienniki systemu Windows → Aplikacja, źródło `FirewallManager`; ID 1001 Add, 1002 Modify, 1003 Remove, 1004 Enable, 1005 Disable, 1006 Enforce, 1007 Backup, 1008 Restore, 1100 zmiana spoza skryptu, 1900 błąd. Poziomy: Information, Warning, Error.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='FirewallManager'} -MaxEvents 10 | ft TimeCreated, Id, LevelDisplayName
```

5. Rotacja: ustaw plik logu na ponad 5 MB (`fsutil file createnew` na kopii nie wystarczy; dopisz dane do dzisiejszego `firewall_*.log` do ~5 MB) i wykonaj dowolną operację. Powinien powstać plik `firewall_YYYYMMDD_HHmmss.log`. Wiek: ustaw `LastWriteTime` kopii `firewall_20200101.log` na 40 dni wstecz i uruchom skrypt; plik powinien zniknąć.

## 9. Wykrywanie zmian spoza skryptu

Najpierw sprawdź, czy dziennik zapory jest włączony:

```powershell
wevtutil gl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"   # enabled: true
```

```powershell
# zmiany spoza skryptu:
netsh advfirewall firewall add rule name="FWM-ExtTest" dir=in action=block protocol=tcp localport=9997
netsh advfirewall firewall set rule name="FWM-ExtTest" new localport=9996
netsh advfirewall firewall delete rule name="FWM-ExtTest"
# zmiana ze skryptu:
.\FirewallManager.ps1 -Action Block -Port 9995 -Direction Inbound -Name ScriptTest

.\FirewallManager.ps1 -Action History -Days 1
.\FirewallManager.ps1 -Action History -Days 1 -Notify
```

Oczekiwane: wiersze „Dodanie / Modyfikacja / Usunięcie reguły” dla `FWM-ExtTest` ze Source `Zewnętrzne`, a dla `FWM-ScriptTest-In-TCP` Source `Skrypt`. Z `-Notify`: ostrzeżenie, wpis `External` w logu i zdarzenie ID 1100 (Warning); ponowne `-Notify` nie powtarza starych zgłoszeń (plik `lastcheck.txt` w katalogu logów).

Security (opcjonalnie):

```powershell
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
.\FirewallManager.ps1 -Action History -Days 1 -IncludeSecurity
```

Wykonaj najpierw nową zmianę (po włączeniu audytu); powinny pojawić się wiersze z `Log = Security` (ID 4946/4947/4948). Jeśli nie ma ich w ogóle, sprawdź lokalizację systemu (na polskim Windows użyj GUID podkategorii z README).

## 10. Profile

```powershell
.\FirewallManager.ps1 -Action Status
.\FirewallManager.ps1 -Action Disable -Scope Profile -Profile Public            # kod 4 (brak -Force)
.\FirewallManager.ps1 -Action Disable -Scope Profile -Profile Public -Force -DryRun
.\FirewallManager.ps1 -Action Enable  -Scope Profile -Profile Public
```

Oczekiwane: kolumna `ScriptRules` zgadza się z liczbą reguł z profilem Any lub tym profilem, kolumna `Active` wskazuje profil z `Get-NetConnectionProfile`. Wyłączanie profilu naprawdę wykonuj tylko świadomie (i od razu włącz z powrotem); wpisy `Disable`/`Enable` z `Target: Profile:Public` są w logu.

## 11. Kopia zapasowa i przywracanie (tylko na maszynie testowej)

```powershell
.\FirewallManager.ps1 -Action Backup -BackupPath C:\Temp\fw-before.wfw
.\FirewallManager.ps1 -Action Block -Port 9994 -Direction Inbound -Name BeforeRestore
.\FirewallManager.ps1 -Action Restore -BackupPath C:\Temp\fw-before.wfw -DryRun
.\FirewallManager.ps1 -Action Restore -BackupPath C:\Temp\fw-before.wfw          # pyta o potwierdzenie
.\FirewallManager.ps1 -Action List
```

Oczekiwane: po przywróceniu reguły `BeforeRestore` już nie ma; w katalogu `Backups` jest dodatkowa kopia bezpieczeństwa zrobiona tuż przed importem; Restore z nieistniejącym plikiem daje kod 6. `Restore` **zastępuje całą politykę zapory**, więc nie rób tego na produkcji.

## 12. Menu i `-WhatIf`

`.\FirewallManager.ps1 -Action Menu`: przejdź opcje 1, 2, 3 (z błędnym portem: komunikat błędu, menu nie kończy się), 7, 0. Standardowy `-WhatIf` nadal działa i pokazuje angielskie „What if:”.

## 12a. ICMP (ping)

Ping testuj z **innego komputera** w tej samej sieci (`ping <ip-testowanego>`); ping z samego siebie nie przechodzi przez reguły przychodzące. Sprawdź najpierw, że ping działa przed testem. Zwykle na Windows odpowiedź na ping jest dozwolona regułą „File and Printer Sharing (Echo Request – ICMPv4-In)”; jeśli jest wyłączona, ping nie działa od początku i test blokady nic nie pokaże: włącz ją na czas testu (`Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"`) i po teście wyłącz.

**A. Blokada ping (ICMPv4 typ 8) i idempotencja**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Name NoPing
.\FirewallManager.ps1 -Action List -Name NoPing*                  # Protocol ICMPv4, IcmpType 8, porty Any
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Name NoPing   # "pominięto"
```
Oczekiwane: z innego komputera `ping` kończy się „Request timed out”; drugie `Block` nie tworzy duplikatu i nie pisze wpisu `Modify`.

**B. Selektywność typu**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 13 -Direction Inbound -Name NoTimestamp   # inny typ niż echo
```
Oczekiwane: ping nadal jest blokowany tylko przez `NoPing`; po `-Action Disable -Name NoPing*` ping znowu działa (reguła typu 13 go nie blokuje); po `-Action Enable -Name NoPing*` znów jest blokowany. Typ z kodem: `-IcmpType 3:1` tworzy regułę z `3:1` na liście.

**C. Blokada wszystkich typów ICMPv4 i kierunek wychodzący**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -Direction Any -Name NoIcmp4
ping 8.8.8.8                                                      # na tym komputerze: brak odpowiedzi (Outbound zablokowany)
```
Oczekiwane: powstają `FWM-NoIcmp4-In-ICMPv4` i `FWM-NoIcmp4-Out-ICMPv4`; ping wychodzący z tego komputera i przychodzący do niego nie działają. Po `Remove` oba wracają.

**D. Modyfikacja przez ponowne `Block` (zmiana typu)**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 8,0 -Direction Inbound -Name NoPing
.\FirewallManager.ps1 -Action List -Name NoPing*                  # IcmpType 8,0
```
Oczekiwane: komunikat `Modify`, wpis w logu ze stanem `Before` (typ `8`) i `After` (typ `8,0`). Nie powstaje druga reguła. (`-Action Modify` nie obsługuje `-IcmpType`.)

**E. ICMPv6 i ochrona przed odcięciem**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv6 -Direction Inbound                 # kod 4, brak reguły
.\FirewallManager.ps1 -Action Block -Protocol ICMP -Direction Inbound                   # kod 4, brak reguły
.\FirewallManager.ps1 -Action Block -Protocol ICMP -Direction Inbound -Force -DryRun    # ostrzeżenie + 2x "DryRun" (ICMPv4 i ICMPv6)
.\FirewallManager.ps1 -Action Block -Protocol ICMPv6 -IcmpType 128 -Direction Inbound -Name NoPing6   # echo request v6, bez -Force
```
Nigdy nie wykonuj blokady całego ICMPv6 bez `-DryRun`: psuje IPv6 (Neighbor Discovery). Przy `NoPing6` sprawdź z innego komputera `ping -6 <adres-IPv6>`.

**F. Walidacja ICMP** (po każdej komendzie sprawdź `$LASTEXITCODE`; reguła nie może powstać)

| Polecenie | Oczekiwany kod |
|---|---|
| `-Action Block -Protocol ICMPv4 -Port 80` | 3 |
| `-Action Block -Protocol TCP -Port 80 -IcmpType 8` | 3 |
| `-Action Block -Protocol ICMPv4 -IcmpType 300` | 3 |
| `-Action Block -Protocol ICMPv4 -IcmpType abc` | 3 |
| `-Action Block -Protocol ICMP -IcmpType 8` | 3 |
| `-Action Block -IcmpType 8` (bez protokołu ICMP) | 3 |

**G. ICMP z adresami**
```powershell
.\FirewallManager.ps1 -Action Block -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 203.0.113.1-203.0.113.50 -Direction Inbound -Name NoPingNet
```
Oczekiwane: reguła ma `IcmpType 8` i adres zdalny; ping z Twojego komputera (inny adres) nadal działa.

**H. Konfiguracja JSON i dryf (najważniejsze dla `Enforce`)**
```json
{ "rules": [
  { "name": "CfgNoPing", "protocol": "ICMPv4", "icmpType": ["8"], "direction": "Inbound" },
  { "name": "CfgNoTs",   "protocol": "ICMPv4", "icmpType": ["13"], "direction": "Any" }
] }
```
```powershell
.\FirewallManager.ps1 -Action Import
.\FirewallManager.ps1 -Action Enforce                              # 2 razy z rzędu
Disable-NetFirewallRule -Name FWM-CfgNoPing-In-ICMPv4
Set-NetFirewallRule -Name FWM-CfgNoTs-Out-ICMPv4 -IcmpType 8       # zepsucie typu
.\FirewallManager.ps1 -Action Enforce
```
Oczekiwane: dwa pierwsze `Enforce` nie zgłaszają **żadnych** napraw (log bez wpisów `Enforce`). Jeśli zgłaszają naprawę przy każdym uruchomieniu, zapora zwraca typ w innej postaci niż podany (np. `8` vs `8:*`): zapisz wynik `Get-NetFirewallRule -Name FWM-CfgNoPing-In-ICMPv4 | Get-NetFirewallPortFilter | fl IcmpType` i zgłoś. Po zepsuciu `Enforce` naprawia obie reguły (włączenie + przywrócenie typu 13) i zapisuje `Before`/`After`. Błędny wpis (`"icmpType": ["300"]`) -> kod 3, żadna reguła z pliku nie powstaje.

**I. Usuwanie i potwierdzenie (jedno pytanie dla wielu reguł)**
```powershell
.\FirewallManager.ps1 -Action Remove -Name NoIcmp4*                # jedno pytanie, lista obu reguł; odpowiedź Y usuwa obie
```
Oczekiwane: jedno okno potwierdzenia dla całego zestawu, `N` nie usuwa żadnej reguły, `-Force` pomija pytanie.

## 12b. Połączenia (`-Action Connections`)

```powershell
.\FirewallManager.ps1 -Action Connections                          # lista połączeń Established (TCP), kolumna Id jest ważna tylko dla tego wyświetlenia
.\FirewallManager.ps1 -Action Connections -Port 443 -ResolveDns   # filtr po porcie lokalnym lub zdalnym + nazwy DNS
.\FirewallManager.ps1 -Action Connections -RemoteAddress 140.82.0.0/16 -ConnectionState All
.\FirewallManager.ps1 -Action Connections -Interactive -DryRun     # przejście przez pytania bez zmian
.\FirewallManager.ps1 -Action Connections -Interactive             # prawdziwe utworzenie reguł
```
Oczekiwane:
- Lista zawiera Id, Proto, Local, Remote, State, Direction (In = lokalny port nasłuchuje, Out = pozostałe), PID, Process. UDP nie jest listowany (brak stanu połączenia).
- Interaktywnie: numery (`1,3-5`), zakres (1 = zdalny adres, 2 = adres + port, 3 = lokalny port tylko dla przychodzących), profil, podgląd reguł i potwierdzenie `[T/n]`. Reguły mają nazwy `FWM-Conn-<adres>-...`; ponowny wybór tego samego adresu daje „pominięto”. Reguły widać w `-Action List -Name Conn*`.
- Wybór połączenia na loopback (`127.0.0.1`) lub lokalny adres -> kod 4 bez `-Force`; połączenie przychodzące na port 3389/5985/5986 -> kod 4 bez `-Force` (odcięcie sesji). Nieistniejący numer -> kod 3.
- Po utworzeniu reguły skrypt pyta o przerwanie połączenia (`-Disconnect` robi to bez pytania; mechanizm: `SetTcpEntry` z iphlpapi.dll, tylko IPv4, wymaga administratora). Sprawdź w logu operację `Disconnect` (zdarzenie 1009). Zapora zwykle nie zrywa już nawiązanej sesji TCP, stąd ta opcja; po niej połączenie nie powinno wrócić, bo reguła je blokuje.
- Test realny: otwórz stronę w przeglądarce, wybierz jej połączenie (po PID/procesie), zakres 2, `-Disconnect`; strona powinna przestać się ładować. Usuń regułę: `-Action Remove -Name Conn* -Force`.

## 13. Sprzątanie

```powershell
.\FirewallManager.ps1 -Action Remove -Name '*' -Force
.\FirewallManager.ps1 -Action UninstallTask
Remove-Item C:\ProgramData\FirewallManager\rules.json
```

Logi i kopie zostają w `C:\ProgramData\FirewallManager`; usuń je ręcznie, jeśli nie są potrzebne. Na koniec porównaj z kopią z kroku 0 (`Status`, `Get-NetFirewallProfile`) lub w razie wątpliwości zrób `Restore`.

## Czego NIE sprawdza ta instrukcja

Zachowania pod GPO/MDM (zasady domenowe mogą nadpisać lub ukryć reguły lokalne), Windows Server 2016 i stanu po restarcie z zadaniem uruchamianym przy starcie. Przetestuj je osobno, jeśli są dla Ciebie istotne.
