---
layout: post
title: Nmap Firewall & IDS Evasion
date: 2025-04-10 16:17 +0300
categories: [Network Security, Ports & Protocols]
tags: [nmap, firewall, ids, evasion, port scanning]
---

## TCP/UDP Port States and Firewall Responses

- **Open**: 
  - Response: SYN-ACK for TCP, application response for UDP
  - Firewall Behavior: Stateful firewalls track these as established connections
- **Closed**: 
  - Response: RST for TCP, ICMP port unreachable for UDP
  - Firewall Behavior: Next-generation firewalls may artificially generate RST responses
- **Filtered**:
  - Response: No response, ICMP errors, or artificial delays
  - Firewall Behavior: Adaptive firewalls intentionally delay responses to slow scanning
- **Unfiltered/Open\|Filtered/Closed\|Filtered**:
  - Often results of advanced firewall manipulation of returned packets

## Common Firewall Scenarios and Evasion Techniques

### Stateless Packet Filters

**Characteristics**: 
- Examines packets in isolation
- Typically filters based on simple header information (ports, flags)
- No tracking of connection state

**Effective Techniques**:
```bash
# NULL scan bypassing SYN filtering
nmap -sN -p 80,443,8080 192.168.1.0/24

# FIN scan against stateless filters
nmap -sF -Pn -f --data-length 25 192.168.1.1

# Fragment packets to bypass simple inspection
nmap -sS -f -p 1-1000 --randomize-hosts 192.168.1.0/24
```

### Stateful Firewalls

**Characteristics**:
- Tracks connection state 
- Validates packet sequences
- Enforces protocol conformance

**Effective Techniques**:
```bash
# ACK scan to map firewall ruleset
nmap -sA -p 1-1000 192.168.1.1

# Window scan for detecting subtle implementation differences
nmap -sW -p 22,80,443,3389 192.168.1.1

# Idle scan using third-party host to mask source
nmap -sI zombie.example.com:80 -p 22,80,443 192.168.1.1
```

### Next-Generation Firewalls (NGFW)

**Characteristics**:
- Deep packet inspection
- Application awareness
- User identification capabilities
- Integrated IDS/IPS functionality

**Effective Techniques**:
```bash
# Decoy scan to confuse attribution
nmap -D 10.0.0.1,10.0.0.2,RND,RND,ME -p 22,80,443 192.168.1.1

# Timing manipulation to evade rate-based detection
nmap -T2 --max-retries 1 --max-scan-delay 500ms 192.168.1.1

# Data payload manipulation with NSE scripts
nmap -sS -p 80,443 --script http-headers --data-length 15 192.168.1.1
```

## IDS/IPS Evasion Techniques

### Signature-Based Detection Systems

**Characteristics**:
- Match traffic against known attack patterns
- Often vulnerable to slight modifications of attack patterns

**Effective Techniques**:
```bash
# Manipulate TTL to defeat network sensors
nmap --ttl 17 -sS -p 80,443 192.168.1.1

# Use uncommon IP options
nmap --ip-options "L" 192.168.1.1

# Bad checksum testing (some IDS ignore packets with bad checksums)
nmap --badsum -sS -p 1-1000 192.168.1.1
```

### Anomaly-Based Detection Systems

**Characteristics**:
- Establish baseline of normal traffic
- Alert on deviations from normal patterns

**Effective Techniques**:
```bash
# Low and slow scanning to avoid rate triggers
nmap -T1 --max-parallelism 1 --max-rate 10 -p 1-1000 192.168.1.1

# Randomize scan attributes
nmap --randomize-hosts --scan-delay 3s 192.168.1.0/24

# Blend in with normal traffic using common source ports
nmap -g 53 -p- --source-port 53 192.168.1.1
```

## Advanced Firewall Evasion Command Examples

### Fragmentation and MTU Manipulation

```bash
# Double fragmentation with small fragments
nmap -ff --mtu 8 -sS -p 80,443,8080 192.168.1.1

# Fragmentation with decoys and random data length
nmap -f -D 10.0.0.1,10.0.0.2,ME --data-length 10-100 -p 1-1000 192.168.1.1

# Fragment scan with specific timing to defeat reassembly timeouts
nmap -f --scan-delay 2s -p 80,443,3306,3389 192.168.1.1
```

### Source Routing and IP Options

```bash
# Source routing manipulation (where supported)
nmap --ip-options "S 192.168.1.100 192.168.1.200" 192.168.1.1

# Record route option to analyze path
nmap --ip-options "R" 192.168.1.1
```

### Stealth Scanning Combinations

```bash
# Comprehensive stealth scan for firewall analysis
nmap -sS -sV -O -f --mtu 16 --data-length 40 --randomize-hosts -D 10.0.0.1,10.0.0.2,RND,ME -p 1-1000 --script firewall-bypass,intrusion-detection-system 192.168.1.1

# Low and slow comprehensive intelligence gathering
nmap -sS -sU -T2 --max-retries 1 -f --data-length 25 --scan-delay 5s -p T:22,80,443,445,3389,U:53,123,161 --script "default and safe" 192.168.1.1
```

### Evading Application-Layer Filtering

```bash
# HTTP traffic analysis with custom user agent
nmap -p 80,443 --script "http-* and not http-brute" --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 192.168.1.1

# Service version detection with increased intensity for firewall evasion
nmap -sV --version-intensity 9 --version-all -p 22,80,443 192.168.1.1
```

## Specific Firewall Vendor Evasion Techniques

### Cisco ASA Firewall

```bash
# Test for Cisco ASA specific behavior with ACK scan
nmap -sA -P0 -T2 --reason --open -p 80,443,8080 192.168.1.1

# Cisco ASA version detection attempt
nmap -sS -sV -p 443 --script ssl-enum-ciphers 192.168.1.1
```

### Palo Alto Networks

```bash
# Testing against app-ID capabilities
nmap -sS -sV --version-intensity 6 -p 80,443,8080 --script "http-headers,http-methods" 192.168.1.1

# Zone protection bypass attempt
nmap -sS --scan-delay 400ms --max-rate 15 -p 1-1000 192.168.1.1
```

### Fortinet FortiGate

```bash
# Testing Fortinet's fragmentation handling
nmap -f -f --mtu 8 -sS -p 1-1000 192.168.1.1

# FortiGate IPS evasion
nmap -sS --data-length 25 --randomize-hosts --source-port 53 -p 1-1000 192.168.1.1
```

## IDS/IPS Evasion Examples

### Snort Evasion

```bash
# Snort rule evasion with TTL manipulation
nmap --ttl 1 -sS -f -p 1-1000 192.168.1.1

# Snort preprocessor testing
nmap -sX -f --data-length 300 --scan-delay 50ms 192.168.1.1
```

### Suricata Evasion

```bash
# Suricata evasion with multiple techniques
nmap --ttl 10 -f -g 88 --data-length 100 --scan-delay 75ms -p 1-1000 192.168.1.1

# Suricata stream reassembly evasion
nmap -sS -f --mtu 16 --data-length 50 --badsum -p 1-1000 192.168.1.1
```

## Practical Combinations for Real-World Testing

```bash
# Comprehensive enterprise firewall bypass attempt
nmap -Pn -sS -sV -O -D 10.0.0.1,10.0.0.2,ME,RND,RND -f --mtu 16 --data-length 30-90 --randomize-hosts --source-port 53 -p 1-65535 --min-hostgroup 256 --min-rate 100 --script "default and safe" 192.168.1.0/24

# Low-visibility extended network reconnaissance
nmap -Pn -sT -T2 --scan-delay 1s -p 22,23,80,443,445,1433,3306,3389,8080 --script "discovery and safe" --max-retries 1 --host-timeout 30m 192.168.1.0/24

# Maximum evasion for critical targets
nmap -Pn -sI zombie.example.com:80 --ttl 9 -g 53 -f -f --data-length 100 --randomize-hosts --script firewall-bypass -p 80,443,8080,8443 192.168.1.1
```

