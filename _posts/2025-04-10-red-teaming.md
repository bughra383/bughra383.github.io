---
layout: post
title: Red Team Fundamentals and Methodologies
date: 2025-04-10 17:39 +0300
categories: [Exploitation, Red Teaming]
---

## Introduction to Red Teaming

Red teaming is an advanced form of security assessment that simulates real-world attacks against an organization's people, processes, and technology to identify vulnerabilities and test defensive capabilities. Unlike traditional penetration testing, red teaming adopts an adversarial approach, emulating threat actors' tactics, techniques, and procedures (TTPs) to provide a realistic evaluation of security posture.

### Core Principles

- **Adversary Emulation**: Mimicking the behavior of specific threat actors relevant to the target organization
- **Stealth & Persistence**: Operating with minimal detection for extended periods
- **Comprehensive Scope**: Testing across technical infrastructure, physical security, and human factors
- **Realistic Scenarios**: Using plausible attack chains that reflect actual threats
- **Objective-Driven**: Focusing on specific high-value targets and business impacts

### Red Team vs Penetration Testing

| Aspect | Red Team | Penetration Testing |
|--------|----------|---------------------|
| **Goal** | Assess detection & response capabilities | Find and exploit vulnerabilities |
| **Scope** | Broad, often includes multiple attack vectors | Typically limited to specific systems |
| **Knowledge** | Limited information (black box) | Often detailed information (white/grey box) |
| **Timeframe** | Extended (weeks/months) | Limited (days/weeks) |
| **Stealth** | Critical component | Not typically prioritized |
| **Target Awareness** | Limited or no prior notification | Usually announced and coordinated |

## Red Team Fundamentals

### Red Team Mindset

The red team mindset requires shifting perspective from defensive to offensive thinking:

- **Adaptive Problem Solving**: Overcoming obstacles through creative solutions
- **Persistence**: Continuing efforts despite setbacks and roadblocks
- **Situational Awareness**: Understanding the environment and adapting accordingly
- **Continuous Learning**: Staying current with evolving threats and techniques
- **Ethical Boundaries**: Operating within defined scope and rules of engagement

### Red Team Engagement Types

- **Full-Scope**: Comprehensive assessment including technical, physical, and social engineering
- **Targeted**: Focus on specific critical assets or systems
- **Assumed Breach**: Beginning with access already established to test post-compromise controls
- **Purple Team**: Collaborative approach with defenders actively involved
- **Tabletop Exercises**: Scenario-based discussions without actual system exploitation

## Red Team Methodologies and Frameworks

### The Cyber Kill Chain (Lockheed Martin)

Seven phases of a targeted attack:

1. **Reconnaissance**: Gathering information about the target
2. **Weaponization**: Preparing malware or exploit packages
3. **Delivery**: Transmitting the weapon to the target environment
4. **Exploitation**: Executing code on the target system
5. **Installation**: Establishing persistence
6. **Command & Control (C2)**: Creating a communication channel
7. **Actions on Objectives**: Accomplishing the attack goals

### MITRE ATT&CK Framework

A knowledge base of adversary tactics and techniques based on real-world observations:

- **Initial Access**: Techniques to gain entry into a network
- **Execution**: Techniques to run attacker-controlled code
- **Persistence**: Maintaining access across system restarts
- **Privilege Escalation**: Gaining higher-level permissions
- **Defense Evasion**: Avoiding detection
- **Credential Access**: Stealing account names and passwords
- **Discovery**: Learning about the environment
- **Lateral Movement**: Moving through the environment
- **Collection**: Gathering data of interest
- **Command and Control**: Communicating with compromised systems
- **Exfiltration**: Stealing data
- **Impact**: Manipulating, interrupting, or destroying systems and data

### Red Team Operations Framework

1. **Planning & Preparation**
   - Defining objectives and scope
   - Threat intelligence gathering
   - Team organization and resource allocation

2. **Intelligence Gathering**
   - Open-source intelligence (OSINT)
   - Target profiling
   - Network and infrastructure mapping

3. **Assessment & Analysis**
   - Vulnerability identification
   - Attack vector prioritization
   - Defense capability evaluation

4. **Execution**
   - Initial compromise
   - Persistence establishment
   - Privilege escalation
   - Lateral movement
   - Data exfiltration

5. **Reporting & Remediation**
   - Documentation of findings
   - Attack path visualization
   - Mitigation recommendations
   - Knowledge transfer

## Planning and Preparation

### Rules of Engagement (ROE)

A formal document defining:

- **Scope**: Systems and networks in-scope and out-of-scope
- **Timeframe**: Start and end dates for the assessment
- **Constraints**: Prohibited actions and techniques
- **Authorization**: Written approval from appropriate stakeholders
- **Communication Plan**: Points of contact and escalation procedures
- **Safe Harbor**: Protection for the red team from legal consequences

### Target Selection and Prioritization

- **Crown Jewels Analysis**: Identifying the organization's most valuable assets
- **Threat Modeling**: Understanding likely adversaries and their capabilities
- **Attack Surface Analysis**: Mapping potential entry points
- **Impact Assessment**: Evaluating potential damage from compromises

### Team Composition and Roles

- **Red Team Lead**: Overall management and client communication
- **Technical Lead**: Technical direction and tooling decisions
- **Operators**: Specialists in different attack vectors
- **Infrastructure Manager**: C2 infrastructure and operational security
- **White Cell/Exercise Control**: Independent observers ensuring adherence to ROE

## Intelligence Gathering Phase

### OSINT Collection

- **Digital Footprint Analysis**: Websites, domains, subdomains
- **Employee Information**: Professional profiles, organizational charts
- **Technology Stack**: Used applications, frameworks, infrastructure
- **Document Metadata**: Information leaked in public documents
- **Social Media Analysis**: Company and employee presence

### Technical Intelligence

- **Network Scanning**: Identifying active hosts and services
- **Service Enumeration**: Determining running applications
- **Vulnerability Scanning**: Identifying potential weaknesses
- **Cloud Resource Discovery**: Identifying cloud assets and configurations
- **Wireless Network Analysis**: Discovering and assessing wireless networks

### Physical Intelligence

- **Facility Reconnaissance**: Building layouts, entry points, security controls
- **Security Personnel Assessment**: Patterns, procedures, response capabilities
- **Physical Security Controls**: Badges, locks, cameras, sensors

## Execution Phase Techniques

### Initial Access Vectors

- **Phishing Campaigns**: Targeted emails with malicious attachments or links
- **Social Engineering**: Manipulating personnel to divulge information or perform actions
- **External Vulnerability Exploitation**: Leveraging vulnerabilities in external-facing systems
- **Physical Access**: Gaining unauthorized entry to facilities
- **Supply Chain Compromise**: Targeting third-party providers with access to the organization
- **Wireless Access**: Exploiting insecure Wi-Fi networks

### Persistence Mechanisms

- **Persistent Malware**: Implants that survive system reboots
- **Backdoor Accounts**: Creating or modifying user accounts
- **Scheduled Tasks/Jobs**: Executing code at regular intervals
- **Registry Modifications**: Altering Windows Registry for automatic execution
- **Boot/Logon Scripts**: Running code during system startup or user login
- **Legitimate Tool Abuse**: Using built-in features for malicious purposes

### Privilege Escalation

- **Vulnerability Exploitation**: Leveraging local security flaws
- **Credential Theft**: Capturing and reusing authentication credentials
- **Access Token Manipulation**: Impersonating other users or processe| Framework     | Language          | License     | Key Features                                        |
| ------------- | ----------------- | ----------- | --------------------------------------------------- |
| Cobalt Strike | Java              | Commercial  | Malleable C2, team server, extensive evasion        |
| Empire        | PowerShell/Python | Open Source | PowerShell-based, modular architecture              |
| Covenant      | .NET              | Open Source | Web interface, .NET payloads, task-based model      |
| Metasploit    | Ruby              | Open Source | Extensive exploit library, meterpreter              |
| Sliver        | Go                | Open Source | Cross-platform, multi-player, implant customization |
| Mythic        | Python/JavaScript | Open Source | Modular design, container-based, multi-C2           |
| Havoc         | C/C++             | Open Source | Modern evasion, Demon agent, extensible             |
| Merlin        | Go                | Open Source | HTTP/2 C2 communications                            |sers from compromised accounts
- **RDP/VNC/SSH Hijacking**: Taking over existing remote sessions
- **WMI/PowerShell Remoting**: Using administrative tools for remote execution

## Operational Security

### Infrastructure Management

- **Anonymous Infrastructure**: Using non-attributable servers and domains
- **Tiered Architecture**: Separating operational infrastructure from attribution
- **Domain Rotation**: Regularly changing C2 domains
- **Traffic Obfuscation**: Disguising malicious traffic as legitimate
- **Infrastructure Compartmentalization**: Limiting damage from infrastructure discovery

### Communication Security

- **Encrypted Channels**: Protecting data in transit
- **Out-of-Band Communication**: Using separate channels for team coordination
- **Secure Authentication**: Protecting access to team resources
- **Time-Based Operations**: Conducting activities during optimal timeframes
- **Minimal Command Execution**: Limiting actions to reduce detection chances

## Documentation and Reporting

### Engagement Documentation

- **Activity Logs**: Detailed record of all actions taken
- **Evidence Collection**: Screenshots, data captures, and artifacts
- **Timeline Reconstruction**: Chronological sequence of events
- **Attack Path Mapping**: Visual representation of compromise routes
- **Tool and Command Usage**: Documentation of all tools employed

### Report Components

- **Executive Summary**: High-level overview for leadership
- **Methodology**: Detailed approach and framework
- **Findings**: Vulnerabilities and weaknesses discovered
- **Attack Narratives**: Storyline of successful compromises
- **Risk Assessment**: Impact and likelihood analysis
- **Strategic Recommendations**: Long-term security improvements
- **Tactical Recommendations**: Specific vulnerability fixes
- **Metrics and Statistics**: Quantitative analysis of the assessment

## Red Team Tradecraft

### Living Off The Land (LOL)

Using legitimate system tools to avoid introducing malicious software:

- **Built-in Utilities**: PowerShell, WMI, WMIC, Regsvr32
- **Administrative Tools**: PsExec, BITSAdmin, Certutil
- **Scripting Engines**: PowerShell, VBScript, JScript, BAT
- **System Resources**: DLLs, Scheduled Tasks, Services

### Defense Evasion Through Observation

- **Process Analysis**: Understanding normal vs. abnormal behavior
- **Network Traffic Patterns**: Blending in with legitimate traffic
- **Timing Operations**: Acting during periods of high activity
- **Minimum Footprint**: Reducing artifacts and evidence
- **Counter-forensics**: Removing evidence of activities

## Red Team Infrastructure

### Command and Control (C2) Infrastructure

- **Redirectors**: Intermediate servers that forward traffic
- **Domain Fronting**: Hiding C2 traffic within legitimate domains
- **Fast Flux DNS**: Rapidly changing IP addresses
- **TOR/I2P Integration**: Routing through anonymous networks
- **Domain Categorization**: Using domains with favorable reputations

### Payload Delivery Systems

- **Staged Payloads**: Multi-phase execution to minimize detection
- **In-Memory Execution**: Operating without writing to disk
- **Custom Droppers**: Specialized delivery mechanisms
- **Fileless Techniques**: Executing without persistent files
- **Application Whitelisting Bypass**: Evading application controls

## Red Team Tools

### Categories of Tools

- **Reconnaissance Tools**: Maltego, Recon-ng, SpiderFoot
- **Exploitation Frameworks**: Metasploit, Cobalt Strike, Empire
- **Post-Exploitation**: PowerSploit, Mimikatz, BloodHound
- **Command & Control**: Covenant, Mythic, Havoc
- **Social Engineering**: Gophish, SET, BeEF
- **Custom Tools**: Bespoke utilities for specific operations

### Tool Selection Criteria

- **Detection Signature**: How easily detected by security controls
- **Stability**: Reliability in operational environments
- **Capability**: Feature set relevant to objectives
- **Interoperability**: Compatibility with other tools
- **Operational Security**: Risk of attribution or detection

## Measuring Red Team Effectiveness

### Success Metrics

- **Time to Detection**: How quickly defenders identify attacks
- **Time to Containment**: Speed of response after detection
- **Coverage**: Percentage of tested controls that were effective
- **Objective Achievement**: Success rate in reaching defined goals
- **Security Control Validation**: Effectiveness of specific controls
- **Mean Time to Compromise**: Average time required to achieve objectives

### Continuous Improvement

- **Lessons Learned**: Documenting and applying insights from operations
- **TTPs Refinement**: Updating techniques based on effectiveness
- **Threat Intelligence Integration**: Incorporating new adversary behaviors
- **Tool Enhancement**: Developing and improving custom tools
- **Team Development**: Enhancing operator skills and knowledge

## Purple Team Integration

### Collaborative Defense Improvement

- **Joint Planning**: Developing scenarios with defensive input
- **Real-time Feedback**: Immediate defender observations during exercises
- **Knowledge Transfer**: Sharing offensive techniques with defenders
- **Control Validation**: Testing specific security controls
- **Detection Tuning**: Adjusting detection capabilities based on findings

### Purple Team Exercises

- **Focused Scenarios**: Testing specific TTPs or controls
- **Attack/Defend**: Simultaneous offensive and defensive operations
- **Tabletop Exercises**: Discussion-based scenario walkthroughs
- **Assumption Validation**: Testing assumed security capabilities
- **Tool/Technique Demonstrations**: Showcasing specific attack methods

## Ethical and Legal Considerations

### Ethical Guidelines

- **Authorized Access**: Only accessing systems with proper approval
- **Data Protection**: Safeguarding sensitive information encountered
- **Responsible Disclosure**: Following established protocols for vulnerabilities
- **Proportional Impact**: Minimizing operational disruption
- **Professional Conduct**: Maintaining professional behavior throughout

### Legal Framework

- **Clear Authorization**: Formal written approval for all activities
- **Scope Boundaries**: Strict adherence to defined scope
- **Data Handling**: Compliance with privacy regulations
- **International Considerations**: Awareness of cross-border legal issues
- **Documentation**: Maintaining records of authorization and activities


