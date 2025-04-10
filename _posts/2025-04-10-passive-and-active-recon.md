---
layout: post
title: Passive and Active Reconnaissance
date: 2025-04-10 16:11 +0300
categories: [Information Gathering]
tags: [information gathering, osint]
---

## Overview

Reconnaissance (recon) is the first phase in a penetration test and involves collecting information about the target systems, networks, and organizations. This phase is critical as the quality and quantity of information gathered directly impacts the effectiveness of subsequent phases in the penetration testing process.

## Passive Reconnaissance

Passive reconnaissance involves gathering information about the target without directly interacting with the target systems. This approach is non-intrusive and doesn't leave traces or logs on the target systems.

### Key Characteristics

- No direct contact with the target systems
- Undetectable by the target organization
- Lower risk of disrupting services
- Legal in most cases without explicit permission

### Common Passive Recon Techniques

1. **OSINT (Open Source Intelligence)**
   - Examining public records and databases
   - Researching company websites and documentation
   - Reviewing job postings for technology stack information
   - Analyzing social media profiles of employees

2. **WHOIS Lookups**
   - Gathering domain registration information
   - Identifying administrative and technical contacts
   - Determining domain registrars and expiration dates
   - `whois bughra.dev`

3. **DNS Information**
   - Analyzing DNS records (A, MX, NS, CNAME, TXT)
   - Zone transfers (when available)
   - Subdomain enumeration via public records
   - `dig any bughra.dev`
   - `nslookup bughra.dev`

4. **Search Engine Research**
   - Google dorking (using advanced search operators)
   - Finding cached content and historical data
   - Locating exposed documents and files

5. **Web Archives**
   - Reviewing historical versions of websites
   - Identifying removed content and old infrastructure
   - [archive.org](https://archive.org)

6. **Certificate Transparency**
   - Analyzing SSL/TLS certificates
   - Discovering subdomains through certificate logs
   - [crt.sh](https://crt.sh)

### Passive Recon Tools

- theHarvester - Email and subdomain gathering
- Shodan - Internet-connected device search engine
- Maltego - Data mining and link analysis
- Recon-ng - Web reconnaissance framework
- OSINT Framework - Collection of OSINT resources
- SpiderFoot - OSINT automation tool

## Active Reconnaissance

Active reconnaissance involves direct interaction with the target systems to gather more detailed information. This approach is more intrusive and can potentially leave traces in system logs.

### Key Characteristics

- Direct interaction with target systems
- Detectable by the target organization
- Higher risk of triggering alerts or disrupting services
- Typically requires explicit permission

### Common Active Recon Techniques

1. **Network Scanning**
   - Port scanning to identify open services
   - Service version identification
   - Operating system fingerprinting
   - Network topology mapping

2. **Vulnerability Scanning**
   - Automated identification of potential vulnerabilities
   - Service misconfiguration detection
   - Patch level assessment

3. **Banner Grabbing**
   - Collecting service banners to identify software versions
   - Protocol-specific probing
   - `nc $IP $PORT`
   - `telnet $IP $PORT`

4. **Web Application Enumeration**
   - Directory and file discovery
   - Parameter discovery and analysis
   - Technology stack identification
   - CMS version detection

5. **Active DNS Techniques**
   - DNS zone transfer attempts
   - Brute forcing subdomains
   - DNS cache snooping

6. **Social Engineering Reconnaissance**
   - Phishing campaigns for information gathering
   - Pretexting calls to help desk or employees

### Active Recon Tools

- Nmap - Network scanning and enumeration
- Nikto - Web server scanner
- Burp Suite - Web application assessment
- OWASP ZAP - Web vulnerability scanner
- Dirb/Dirbuster - Web content discovery
- Metasploit - Vulnerability verification
- WPScan - WordPress vulnerability scanner

## The Reconnaissance Process Flow

A systematic approach to reconnaissance typically follows this pattern:

1. **Define Scope and Objectives**
   - Determine target systems and boundaries
   - Establish goals for information gathering

2. **Passive Reconnaissance**
   - Gather publicly available information
   - Build target profile without detection

3. **Initial Analysis and Mapping**
   - Organize collected information
   - Identify potential entry points

4. **Active Reconnaissance**
   - Verify findings from passive recon
   - Discover additional technical details

5. **Documentation and Analysis**
   - Organize all gathered information
   - Identify patterns, vulnerabilities, and attack vectors
