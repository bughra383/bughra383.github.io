---
layout: post
title: Active Directory Enumeration
date: 2025-04-10 16:39 +0300
categories: [Network Security, Active Directory]
tags: [windows, active directory, enumeration]
---

## Introduction

Active Directory (AD) enumeration is a crucial phase during penetration testing that involves gathering information about the AD infrastructure, including domains, users, groups, computers, policies, and trusts. This cheatsheet provides commands and techniques for effective AD enumeration.

## Initial Access Methods

### From Windows Domain-Joined Machine

```powershell
# Check current domain and user context
whoami /all
echo %userdomain%
$env:USERDOMAIN
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### From Linux (With Credentials)

```bash
# Using rpcclient
rpcclient -U "DOMAIN\user%password" 10.10.10.100

# Using CrackMapExec
crackmapexec smb 10.10.10.100 -u user -p password --users
crackmapexec smb 10.10.10.100 -u user -p password --groups

# Using Impacket tools
python3 GetADUsers.py -all DOMAIN/user:password@10.10.10.100
python3 lookupsid.py DOMAIN/user:password@10.10.10.100
```

## Domain Information

### Basic Domain Information

```powershell
# Get domain information
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get domain controllers
Get-ADDomainController
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Get domain functional level
(Get-ADDomain).DomainMode

# Get domain password policy
Get-ADDefaultDomainPasswordPolicy

# Get domain SID
Get-ADDomain | Select-Object DomainSID
```

### Domain Trust Enumeration

```powershell
# Using PowerShell
Get-ADTrust -Filter *
nltest /domain_trusts

# From Linux
python3 getTrusts.py DOMAIN/user:password@10.10.10.100
```

## User Enumeration

### Local Enumeration (Windows)

```powershell
# List all domain users
Get-ADUser -Filter * -Properties * | Select-Object samaccountname, description, pwdlastset, lastlogon
Get-NetUser | Select-Object cn, description, pwdlastset, lastlogon

# List all users with specific property
Get-ADUser -Filter 'Description -like "*admin*"' -Properties Description | Select-Object Name, Description

# Find users with SPN set (Kerberoastable accounts)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Find admin users 
Get-ADGroupMember "Domain Admins" | Select-Object name

# List recently created users (last 14 days)
$date = (Get-Date).AddDays(-14)
Get-ADUser -Filter 'whenCreated -ge $date' -Properties whenCreated

# Find users with non-expiring passwords
Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object Name
```

### Remote Enumeration (Linux)

```bash
# Using Enum4Linux
enum4linux -a 10.10.10.100

# Using rpcclient
rpcclient -U "DOMAIN\user%password" 10.10.10.100 -c "enumdomusers"
rpcclient -U "DOMAIN\user%password" 10.10.10.100 -c "queryuser 0x457"

# Using ldapsearch
ldapsearch -x -h 10.10.10.100 -D "cn=user,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "(objectClass=user)"
```

## Group Enumeration

### Local Enumeration (Windows)

```powershell
# List all domain groups
Get-ADGroup -Filter * | Select-Object Name

# List all domain admin accounts
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object name

# Get groups of specific user
Get-ADPrincipalGroupMembership -Identity "username" | Select-Object Name

# Find nested group memberships
function Get-ADNestedGroups($group) {
    $groups = @($group.name)
    foreach($member in Get-ADGroupMember $group) {
        if ($member.objectClass -eq "group") {
            $groups += Get-ADNestedGroups $member
        }
    }
    return $groups | Select-Object -Unique
}
Get-ADNestedGroups (Get-ADGroup "GroupName")

# Find interesting groups
Get-ADGroup -Filter 'Name -like "*admin*"' | Select-Object Name
```

### Remote Enumeration (Linux)

```bash
# Using rpcclient
rpcclient -U "DOMAIN\user%password" 10.10.10.100 -c "enumdomgroups"
rpcclient -U "DOMAIN\user%password" 10.10.10.100 -c "querygroup 0x200"
rpcclient -U "DOMAIN\user%password" 10.10.10.100 -c "querygroupmem 0x200"

# Using CrackMapExec
crackmapexec smb 10.10.10.100 -u user -p password --groups
```

## Computer/Machine Enumeration

### Local Enumeration (Windows)

```powershell
# List all domain computers
Get-ADComputer -Filter * -Properties * | Select-Object Name, OperatingSystem, IPv4Address

# Find Windows servers
Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server*"' -Properties OperatingSystem | Select-Object Name, OperatingSystem

# Find domain controllers
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address

# List all inactive computers (not logged in for 3 months)
$date = (Get-Date).AddMonths(-3)
Get-ADComputer -Filter 'LastLogonTimeStamp -lt $date' -Properties LastLogonTimeStamp | Select-Object Name, @{Name="LastLogon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
```

### Remote Enumeration (Linux)

```bash
# Using CrackMapExec
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt
crackmapexec smb 10.10.10.0/24 -u user -p password --computers

# Using nmap
nmap -sV -p 389,636,88,3268,3269 10.10.10.0/24
nmap -Pn -sV -p 5985 10.10.10.0/24 --script "winrm-*"

# Using ldapsearch
ldapsearch -x -h 10.10.10.100 -D "cn=user,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "(objectClass=computer)"
```

## GPO Enumeration

### Local Enumeration (Windows)

```powershell
# List all GPOs
Get-GPO -All | Select-Object DisplayName, GPOStatus, ModificationTime

# Get GPO details
Get-GPOReport -Name "GPO Name" -ReportType HTML -Path C:\Temp\GPOReport.html

# List GPOs applied to specific OU
Get-GPO -All | Where-Object {$_.DisplayName -like "*Servers*"}

# Using PowerView
Get-NetGPO | Select-Object displayname, whenchanged
```

### Remote Enumeration (Linux)

```bash
# Using Impacket
python3 getPac.py DOMAIN/user:password@10.10.10.100

# Using CrackMapExec
crackmapexec smb 10.10.10.100 -u user -p password --gpo-names
```

## ACL Enumeration

```powershell
# Find interesting ACLs using PowerView
Find-InterestingDomainAcl | Where-Object {$_.IdentityReferenceName -match "username"}

# Check permissions on specific AD object
Get-Acl -Path "AD:\CN=Administrator,CN=Users,DC=domain,DC=local" | Format-List

# Find objects with specific ACL settings
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.Filter = "(objectClass=user)"
$Searcher.FindAll() | ForEach-Object {
    $entry = $_.GetDirectoryEntry()
    $acl = $entry.psbase.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    if ($acl | Where-Object {$_.IdentityReference -match "DOMAIN\\username"}) {
        Write-Output $entry.distinguishedName
        $acl | Where-Object {$_.IdentityReference -match "DOMAIN\\username"} | Select-Object IdentityReference, ActiveDirectoryRights
    }
}
```

## LDAP Queries

```powershell
# Basic LDAP query using PowerShell
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.Filter = "(objectClass=user)"
$Searcher.FindAll()

# Search for specific attributes
$Searcher.PropertiesToLoad.Add("samaccountname")
$Searcher.PropertiesToLoad.Add("description")
$Results = $Searcher.FindAll()
$Results | ForEach-Object {
    $_.Properties["samaccountname"]
    $_.Properties["description"]
}
```

```bash
# Using ldapsearch from Linux
ldapsearch -x -h 10.10.10.100 -D "cn=user,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "(objectClass=user)" samaccountname description

# Anonymous LDAP bind (if allowed)
ldapsearch -x -h 10.10.10.100 -b "dc=domain,dc=local" -s sub "(objectclass=*)"
```

## Specific Sensitive Information Hunting

### Service Accounts

```powershell
# Find service accounts (accounts with SPN)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Find accounts with Kerberos delegations
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Password Policy

```powershell
# Get domain password policy
Get-ADDefaultDomainPasswordPolicy

# Get fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *

# From Linux with crackmapexec
crackmapexec smb 10.10.10.100 -u user -p password --pass-pol
```

### Sensitive Files Search

```powershell
# Search for sensitive files on shares
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.txt,*.docx,*.xlsx,*.config

# Using keywords in file search
Find-InterestingDomainShareFile -Keywords "password","creds","confidential"
```

## Special Enumeration Techniques

### Bloodhound Collection

```powershell
# Import SharpHound module (on domain-joined machine)
Import-Module .\Sharphound.ps1

# Collect data
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp

# Stealth collection methods
Invoke-BloodHound -CollectionMethod Session,LoggedOn -Stealth
```

```bash
# From Linux using bloodhound-python
bloodhound-python -u user -p 'password' -ns 10.10.10.100 -d domain.local -c All
```

### ADIDNS Enumeration

```powershell
# Using PowerView
Get-DomainDNSRecord -ZoneName domain.local

# Using standard Windows commands
Get-DnsServerResourceRecord -ZoneName domain.local -ComputerName dc01.domain.local
```

## Kerberos-Based Enumeration

```bash
# Kerberos user enumeration (valid usernames don't return KDC_ERR_PREAUTH_REQUIRED)
python3 kerbrute.py -domain domain.local -users users.txt -dc-ip 10.10.10.100

# From Windows using Rubeus
.\Rubeus.exe brute /users:users.txt /domain:domain.local /outfile:valid_users.txt
```

```powershell
# Check for Kerberoastable accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Check for AS-REP Roastable accounts (don't require Kerberos pre-authentication)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

## Useful Tools

### Windows Tools
- PowerView / PowerSploit
- ADExplorer (Sysinternals)
- BloodHound & SharpHound
- PingCastle
- Rubeus
- ADRecon

### Linux Tools
- CrackMapExec
- Impacket Suite
- Bloodhound-python
- Enum4linux
- Kerbrute
- ldapdomaindump

## OPSEC Considerations

- Avoid excessive failed login attempts
- Use existing credentials when possible
- Limit enumeration to business hours
- Consider using stealth mode for BloodHound
- Use filtering to limit noise
- Log activities to prevent missing evidence
- Prefer passive enumeration when possible

## References

1. [ired.team - Active Directory Enumeration](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
2. [HackTricks - Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
3. [AD Security Blog](https://adsecurity.org/)
4. [BloodHound Documentation](https://bloodhound.readthedocs.io/)
5. [PayloadsAllTheThings - Active Directory Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)


