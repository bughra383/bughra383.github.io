---
layout: post
title: Content Discovery
date: 2025-04-10 16:33 +0300
categories: [Web Security, Enumeration]
tags: [ffuf, nikto, wpscan, dirbuster, gobuster, web, web security, enumeration, subdomain, vhost, waf]
---

## Information Gathering Tools

### WhatWeb

```bash
# Basic scan
whatweb target.com

# Aggressive scan with detailed output
whatweb -a 3 -v target.com

# Export results to JSON
whatweb -a 3 --log-json=results.json target.com
```
### Nikto

```bash
# Basic scan
nikto -h target.com

# Scan with SSL
nikto -h target.com -ssl

# Specify port
nikto -h target.com -port 8080

# Save output
nikto -h target.com -output nikto-results.txt
```

### WAFW00F (Web Application Firewall Detection)

```bash
# Detect WAF
wafw00f target.com

# List all WAFs that can be detected
wafw00f -l

# Scan multiple targets
wafw00f target1.com target2.com

# Verbose output
wafw00f -v target.com
```

## CMS Specific Tools

### WPScan (WordPress)

```bash
# Basic scan
wpscan --url target.com

# Enumerate users
wpscan --url target.com --enumerate u

# Enumerate vulnerable plugins
wpscan --url target.com --enumerate vp

# Enumerate all plugins
wpscan --url target.com --enumerate ap

# Password attack
wpscan --url target.com --passwords wordlist.txt --usernames admin
```

### JoomScan

```bash
# Basic scan
joomscan -u target.com

# Save output
joomscan -u target.com --ec

# Update database
joomscan --update
```

## Directory and File Discovery

### FFUF (Fast Web Fuzzer)

#### Directory Fuzzing

```bash
# Basic directory fuzzing
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ

# Filter by status code
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -fc 404

# Filter by response size
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -fs 42
```

#### Subdomain Fuzzing

```bash
# Basic subdomain fuzzing
ffuf -w /path/to/wordlist.txt -u https://FUZZ.target.com

# With custom DNS resolution
ffuf -w /path/to/wordlist.txt -u https://FUZZ.target.com -r
```

#### Recursive Scanning

```bash
# Recursively scan directories (depth 2)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2

# With file extension
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -recursion -e .php,.html,.txt
```

#### Parameter Fuzzing

```bash
# GET parameter fuzzing
ffuf -w /path/to/params.txt -u https://target.com/script.php?FUZZ=value

# POST parameter fuzzing
ffuf -w /path/to/params.txt -X POST -d "FUZZ=value" -u https://target.com/script.php

# Parameter value fuzzing (GET)
ffuf -w /path/to/values.txt -u https://target.com/script.php?param=FUZZ

# Parameter value fuzzing (POST)
ffuf -w /path/to/values.txt -X POST -d "param=FUZZ" -u https://target.com/script.php
```

#### Advanced FFUF Techniques

```bash
# Multiple parameters fuzzing
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://target.com/script.php?PARAM=VAL

# Match custom responses (using regex)
ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "admin|dashboard"

# Custom headers
ffuf -w wordlist.txt -u https://target.com/FUZZ -H "Cookie: session=1234567"

# Delay between requests
ffuf -w wordlist.txt -u https://target.com/FUZZ -p 0.5
```

## Additional Content Discovery Techniques

### Gobuster

```bash
# Directory mode
gobuster dir -u https://target.com -w /path/to/wordlist.txt

# DNS mode
gobuster dns -d target.com -w /path/to/wordlist.txt

# Virtual host discovery
gobuster vhost -u https://target.com -w /path/to/wordlist.txt
```

### Amass (Subdomain Enumeration)

```bash
# Basic enumeration
amass enum -d target.com

# Passive mode only
amass enum -passive -d target.com

# Output to text file
amass enum -d target.com -o results.txt
```

### Robots.txt and Sitemap.xml Analysis

```bash
# Download and examine
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml
```

### Common Backup Files
Check for: `.bak`, `.swp`, `.old`, `.backup`, `~`, `.tmp`, `.git`, `.svn`

```bash
# Using ffuf
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .bak,.old,.backup,~,.tmp
```

### Historical Content (Wayback Machine)

```bash
# Using waybackurls
waybackurls target.com | grep -v "\.js\|\.css\|\.png\|\.jpg" | sort -u
```

### JavaScript Files Analysis

```bash
# Download all JS files
wget -r -l1 -nd -A.js https://target.com

# Extract endpoints from JS
grep -r -E "(https?://|/)[^\"'> ]+" --include="*.js" .
```

### API Endpoint Discovery

```bash
# Common API paths
ffuf -w /path/to/api-wordlist.txt -u https://target.com/api/FUZZ

# Look for version patterns
ffuf -w /path/to/wordlist.txt -u https://target.com/api/v{1-3}/FUZZ
```

## WAF Bypass Techniques

### Detecting WAF Presence

```bash
# Using WAFw00f
wafw00f https://target.com

# Manual check with unusual requests
curl -I "https://target.com/<script>alert(1)</script>"
```

### Common Bypass Methods

```bash
# Use alternative HTTP methods
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -X HEAD
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -X TRACE

# Request header manipulation
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "X-Originating-IP: 127.0.0.1"
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "X-Forwarded-For: 127.0.0.1"
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "X-Remote-IP: 127.0.0.1"
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "X-Remote-Addr: 127.0.0.1"
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "X-Client-IP: 127.0.0.1"
```

### Path Obfuscation

```bash
# Case manipulation
curl https://target.com/AdMiN/
curl https://target.com/admin/

# URL encoding
curl https://target.com/%61%64%6d%69%6e/

# Double URL encoding
curl https://target.com/%2561%2564%256d%2569%256e/

# Unicode normalization
curl https://target.com/%u0061%u0064%u006d%u0069%u006e/

# Path traversal tricks
curl https://target.com/./admin/.//
curl https://target.com/admin;/
```

### Character Injection Techniques

```bash
# Null byte (before modern patches)
curl https://target.com/admin%00.jpg

# Using different delimiters
curl "https://target.com/index.php;param=value"

# Space obfuscation
curl https://target.com/admin%09/
curl https://target.com/admin%20/
curl https://target.com/admin%0d%0a/
```

### User-Agent Manipulation

```bash
# Changing user agents
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" https://target.com/admin/
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)" https://target.com/admin/

# With FFUF
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)"
```

## 403 Bypass Techniques

### Header Manipulation

```bash
# Add various headers 
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Rewrite-URL: /admin" https://target.com/
curl -H "Content-Length: 0" -X POST https://target.com/admin
curl -H "Referer: https://target.com/admin" https://target.com/admin
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com/admin
```

### Path Traversal Tricks

```bash
# Using path traversal to bypass restrictions
curl https://target.com/public/..;/admin
curl https://target.com/public/%2e%2e/admin
curl https://target.com/public/%252e%252e/admin

# Adding special characters to URLs
curl https://target.com//admin//
curl https://target.com/./admin/./
curl https://target.com/admin/something/../
```

### HTTP Method Switching

```bash
# Try different HTTP methods 
curl -X POST https://target.com/admin
curl -X PUT https://target.com/admin
curl -X PATCH https://target.com/admin
curl -X OPTIONS https://target.com/admin
curl -X TRACE https://target.com/admin

# FFUF for testing all methods
ffuf -w methods.txt:METHOD -u https://target.com/admin -X METHOD -fs 403
```

### Extension and Parameter Manipulation

```bash
# Adding file extensions
curl https://target.com/admin.json
curl https://target.com/admin.php
curl https://target.com/admin.html
curl https://target.com/admin.js

# Adding parameters
curl https://target.com/admin?param=1
curl https://target.com/admin?id=1
curl https://target.com/admin?admin=true
curl https://target.com/admin?debug=true
```

### URL and Port Manipulation

```bash
# URL case modifications
curl https://target.com/Admin
curl https://target.com/ADMIN
curl https://target.com/aDmIn

# Port specification
curl https://target.com:443/admin
curl https://target.com:80/admin

# Adding authentication information
curl https://user@target.com/admin
```

### Combination Techniques

```bash
# Using multiple techniques together
curl -H "X-Original-URL: /admin" -X POST -A "Googlebot" https://target.com/

# Using FFUF for testing combinations
ffuf -w headers.txt:HEADER -w values.txt:VALUE -u https://target.com/admin -H "HEADER: VALUE" -fc 403
```

## Tips for Effective Content Discovery

1. **Customize wordlists** based on the target application technology
2. **Combine tools** for better coverage
3. **Check HTTP response codes** beyond 200 (especially 301, 302, 401, 403)
4. **Analyze JavaScript** files for hidden endpoints and parameters
5. **Monitor network traffic** with tools like Burp Suite or OWASP ZAP
6. **Look for version control directories** (.git, .svn)
7. **Use multiple user-agents** when scanning
8. **Check for development/test endpoints** (dev, test, staging)
9. **Use custom extensions** based on the technology (.php, .aspx, .jsp, etc.)
10. **Review commented HTML code** for hidden information
11. **Try different IP spoofing headers** for 403 bypass
12. **Leverage HTTP protocol quirks** for bypassing restrictions
13. **Document all findings** thoroughly for later analysis
14. **Rotate IP addresses** when facing rate limiting
15. **Test WAF evasion techniques** systematically
