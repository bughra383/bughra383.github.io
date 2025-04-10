---
layout: post
title: Network Enumeration with Nmap
date: 2025-04-10 16:15 +0300
categories: [Network Security, Ports & Protocols]
tags: [networking, enumeration, port scanning]
---

## TCP/UDP Port States

- **Open**: Port actively accepting connections; service is listening. Nmap receives positive response (SYN-ACK for TCP scans, relevant UDP response for UDP scans).
- **Closed**: Port accessible but no service listening. For TCP, receives RST packet; for UDP, receives ICMP port unreachable message.
- **Filtered**: Firewall/filter blocks scan, no response received or ICMP error messages like type 3, code 13 (communication administratively prohibited). Timeouts typically indicate filtering.
- **Unfiltered**: Port accessible but unable to determine open/closed status. Common in ACK scans where RST responses come from both open and closed ports.
- **Open\|Filtered**: Cannot determine if port is open or filtered. Common in UDP scans where no response could mean either state.
- **Closed\|Filtered**: Cannot determine if port is closed or filtered. Seen in some cases where diagnostic techniques can't distinguish between them.

## TCP Flags

- **SYN**: Initiates connection. Firewalls often track SYN packets to prevent SYN flood attacks.
- **ACK**: Acknowledges received data. Stateful firewalls permit outbound ACKs for established connections only.
- **PSH**: Pushes buffered data. Some IDS/IPS systems flag unusual PSH usage patterns.
- **URG**: Marks data as urgent. Often blocked by firewalls as it's rarely used legitimately.
- **RST**: Resets connection. Firewalls generate RST packets to silently drop unauthorized connections.
- **FIN**: Ends connection. Many firewalls track connection state and only allow FIN on established connections.
- **NS/CWR/ECE**: Congestion control flags. Next-generation firewalls may monitor these for anomalies.

## Nmap Scan TCP and UDP Scan Parameters

- **TCP SYN Scan** (`-sS`): 
  - Sends SYN packet, receives SYN-ACK (open), RST (closed), or no response (filtered)
  - Firewalls: Packet filtering firewalls may block SYN packets to protected ports 
  - Stealthier than connect scans as it doesn't complete TCP handshake
  
- **TCP Connect Scan** (`-sT`): 
  - Completes full TCP handshake
  - Open: Full connection established
  - Closed: RST received after SYN
  - Filtered: No response or ICMP unreachable
  - Firewalls: More easily detected and logged by firewalls and IDS systems
  
- **UDP Scan** (`-sU`): 
  - Open\|Filtered: No response (common as open UDP ports often don't respond)
  - Closed: ICMP port unreachable message
  - Filtered: Other ICMP unreachable messages (type 3, codes 1,2,9,10,13)
  - Firewalls: May rate-limit ICMP responses, causing false positives

- **TCP ACK Scan** (`-sA`): 
  - Doesn't determine open ports but firewall rulesets
  - Unfiltered: RST response
  - Filtered: No response or ICMP error
  - Firewalls: Useful for mapping firewall rules as ACK packets are often treated differently than SYN

- **Version Detection** (`-sV`): 
  - Probes open ports with application-specific tests
  - Firewalls: Deep packet inspection firewalls may block based on payload signatures

## Nmap Fine-tuning Scope and Performance

- **Parallelism** (`--min-parallelism`, `--max-parallelism`):
  - Controls concurrent probes
  - High values may trigger firewall/IDS rate limiting or blocking
  - Low values avoid detection but slow scanning
  
- **Min-rate** (`--min-rate <rate>`): 
  - Forces minimum packet rate
  - Example: `--min-rate 1000` sends at least 1000 packets per second
  - Firewalls/IDS: High rates increase detection probability but overcome timeout-based defenses
  
- **Max-retries** (`--max-retries <num>`):
  - Affects accuracy vs. speed tradeoff
  - Lower values reduce timeout delays from filtered ports
  - Firewalls leveraging delayed responses may cause false negatives with low retries
  
- **Host timeout** (`--host-timeout <time>`):
  - Skips slow-responding hosts
  - Bypasses hosts implementing defensive delay tactics
  
- **Timing templates** (`-T0` to `-T5`):
  - T0/T1: Can evade IDS rate-based detection but extremely slow
  - T3: Default balance
  - T4/T5: Fast but easily detected by defensive systems

## Nmap Live Host Discovery

- **ARP Scan** (`-PR`):
  - Bypasses IP-based firewall rules on local networks
  - Not affected by software firewalls that filter IP traffic
  - Works only on local networks; most accurate for LAN scanning
  
- **ICMP Echo** (`-PE`):
  - Firewalls: Commonly blocked at network perimeters
  - Open/Up: Echo reply received
  - Filtered/Down: No response or prohibited ICMP messages
  
- **ICMP Timestamp/Address Mask** (`-PP`, `-PM`):
  - Alternative when echo requests are blocked
  - Many firewalls block echo but overlook these ICMP types
  - Response indicates host is up; no response suggests filtering
  
- **Skip host discovery** (`-Pn`):
  - Treats all hosts as online, bypassing firewall blocks on ping
  - Useful when firewalls block all ICMP but allow connections to services
  
- **List input** (`-iL file.txt`):
  - Scans pre-determined hosts regardless of discovery responses
  - Helpful when combining results from multiple reconnaissance methods

## Nmap Scanning Network Range

- **Single IP**: `nmap 192.168.1.1`
- **Multiple IPs**: `nmap 192.168.1.1 192.168.1.2`
- **CIDR notation**: `nmap 192.168.1.0/24`
  - Firewalls may detect sequential scanning; use randomization (`--randomize-hosts`)
- **Octet range**: `nmap 192.168.1.1-254`
- **Using wildcards**: `nmap 192.168.1.*`
- **Scan from file**: `nmap -iL targets.txt`
  - Can help evade pattern detection by scanning non-sequential addresses

## Nmap Advanced Port Scan

- **NULL Scan** (`-sN`):
  - Sends packets with no flags set
  - Open\|Filtered: No response
  - Closed: RST packet
  - Firewalls: May bypass stateless packet filters that only check for SYN flag
  - RFC-compliant systems should respond with RST to closed ports
  
- **FIN Scan** (`-sF`):
  - Only FIN flag set
  - Open\|Filtered: No response
  - Closed: RST packet
  - Firewalls: Often passes through firewalls that only watch for SYN packets
  - Can bypass simple firewall rulesets looking specifically for connection initiations
  
- **Xmas Scan** (`-sX`):
  - Sets FIN, PSH, URG flags simultaneously
  - Open\|Filtered: No response
  - Closed: RST packet
  - Firewalls: Abnormal flag combination often triggers IDS alerts but may bypass basic filters
  - More detectable than NULL or FIN scans due to distinctive flag pattern
  
- **Maimon Scan** (`-sM`):
  - FIN and ACK flags set
  - Responses vary by OS; some systems drop packet for open ports
  - Firewalls: May confuse firewalls as it appears as part of established connection
  
- **Window Scan** (`-sW`):
  - Examines TCP window size of RST packets
  - Open: Non-zero window size in RST (on some systems)
  - Closed: Zero window size in RST
  - Firewalls: Useful against systems where packet filtering handles RST responses differently
  
- **Custom Scan** (`--scanflags`):
  - Define specific flag combinations
  - Allows crafting packets to test specific firewall rule behaviors
  - Example: `--scanflags SYNFIN` to test for improper handling of invalid flag combinations

## Nmap Spoofing and Decoys

- **IP Spoofing** (`-S <IP>`):
  - Makes scan appear from different source
  - Firewalls: Can bypass source IP filtering but responses go to spoofed host
  - Requires privileged access and often network proximity
  
- **Decoys** (`-D decoy1,decoy2,...`):
  - Mixes real scan with additional spoofed source scans
  - Firewalls/IDS: Makes attribution difficult as multiple scan sources appear
  - Example: `-D 10.0.0.1,10.0.0.2,ME,10.0.0.3` (ME represents your actual IP)
  
- **Interface** (`-e <interface>`):
  - Specifies which network interface to use
  - Useful for multi-homed systems to select network path
  
- **Source port** (`-g/-source-port <port>`):
  - Uses specific source port number
  - Firewalls: May bypass misconfigured firewalls that allow all traffic from specific ports (e.g., 53/DNS, 80/HTTP)

## Nmap Fragmented Packets

- **Fragment packets** (`-f`):
  - Splits headers across multiple IP packets
  - Open/Closed/Filtered determined as per scan type, but packets arrive fragmented
  - Firewalls: May bypass inspection systems that don't properly reassemble fragments
  - Double fragmentation possible with `-ff`
  
- **Specific fragment sizes** (`--mtu <size>`):
  - Custom fragment size (must be multiple of 8)
  - Firewalls: Different fragmentation patterns may evade signature-based detection
  
- **Behavior**: Some firewalls/IDS fail to properly reassemble fragments for inspection, allowing malicious content to pass

## Nmap Idle/Zombie Scan

- **Idle scan** (`-sI <zombie host[:probeport]>`):
  - Uses side-channel attack via IP ID sequence numbers
  - Open port: Zombie's IP ID increments by 2 (target response to zombie + your probe to zombie)
  - Closed/Filtered: Zombie's IP ID increments by 1 (only your probe to zombie)
  - Firewalls: Extremely stealthy as scan appears to come from zombie host
  - Requirements: Zombie must have predictable IP ID sequence and low traffic
  - Advanced firewall detection requires correlation between multiple traffic sources

```
Attacker                 Zombie Machine               Target System
    |                          |                          |
    |-- IPID query ----------->|                          |
    |<-- IPID=X response ------|                          |
    |                          |                          |
    |-- Spoofed SYN (Source: Zombie IP) ----------------->|
    |                          |                          |
    |                          |<- SYN-ACK (port is open) |
    |                          |--  RST ----------------->|
    |                          |   (IPID increased)       |
    |                          |                          |
    |-- IPID query ------==--->|                          |
    |<-- IPID=X+1 response ----|                          |
```


