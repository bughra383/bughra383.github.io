---
layout: post
title: Active Directory Basics
date: 2025-04-10 16:37 +0300
categories: [Network Security, Active Directory]
tags: [windows, active directory, domain, domain controller, group, domain admin, administrator]
---

## Core Concepts

### What is Active Directory?
Active Directory (AD) is Microsoft's directory service for Windows domain networks. It stores information about network objects (like users, computers, printers) and manages their interactions. AD provides authentication, authorization, and a centralized management framework for Windows-based networks.

### Domain Controller (DC)
A domain controller is a server running Active Directory Domain Services (AD DS) that authenticates users, stores directory data, and enforces security policies for a Windows domain. DCs replicate data between each other to ensure consistency across the network.

### Users
AD users are security principals representing people who access network resources. Each user account contains attributes like username, password hash, group memberships, and permissions. Users authenticate to AD to gain access to network resources based on their assigned permissions.

### Machines
Computer accounts in AD represent devices joined to the domain. Each machine gets a unique computer account with attributes and permissions. Machines authenticate to the domain using machine accounts, enabling features like Group Policy application and SSO (Single Sign-On).

### Organizational Units (OU)
OUs are container objects used to organize and manage AD objects (users, groups, computers). They provide a hierarchical structure for applying Group Policy Objects (GPOs) and delegating administrative control. OUs help create logical administrative boundaries within a domain.

### Security Groups
AD security groups are collections of users, computers, and other groups used to simplify permission management. Instead of assigning permissions to individual users, permissions are assigned to groups, and users are made members of appropriate groups. Key built-in groups include Domain Admins, Enterprise Admins, and Schema Admins.

### Domain Admin
Domain Admins is a highly privileged security group that has complete control over the domain. Members can manage all aspects of the domain including users, computers, and domain controllers. Domain Admin accounts are prime targets for attackers due to their elevated privileges.

## Administrative Concepts

### Delegation
Delegation in AD refers to assigning specific administrative permissions to users or groups for managing subsets of objects. This implements the principle of least privilege by granting administrators only the permissions they need for their specific tasks rather than full domain admin rights.

### Group Policy
Group Policy provides centralized management and configuration of operating systems, applications, and user settings in an AD environment. Policies are created as Group Policy Objects (GPOs) and linked to sites, domains, or OUs to control settings for users and computers.

## Authentication Mechanisms

### Kerberos
Kerberos is the primary authentication protocol used in Active Directory. It uses tickets issued by the Key Distribution Center (KDC) to verify identities without sending passwords over the network. The protocol involves:
- Authentication Service (AS) Exchange: Initial authentication
- Ticket-Granting Service (TGS) Exchange: Service access
- Client/Server (CS) Exchange: Service authentication

### NTLM (NT LAN Manager)
NTLM is an older authentication protocol still supported in Windows environments for backward compatibility. It uses a challenge-response mechanism between clients and servers. While less secure than Kerberos, it's still used when Kerberos isn't available (like with IP addresses or non-domain joined systems).

## Advanced Structures

### Trees and Forests
- **Tree**: A collection of domains that share a contiguous namespace (e.g., root.com, sub.root.com)
- **Forest**: A collection of one or more trees that share a common schema, configuration, and global catalog. Trees in a forest can have different namespaces but trust each other.

### Trust Relationships
Trusts enable users in one domain to access resources in another domain. Key concepts:
- **Trust Direction**: Determines the flow of authentication:
  - One-way trust: Users in Domain A can access resources in Domain B, but not vice versa
  - Two-way trust: Users in both domains can access resources in the other domain
- **Transitive vs. Non-transitive**: Transitive trusts extend to other trusted domains, while non-transitive trusts don't

### Access Direction
In a trust relationship, the "access direction" is often confused with trust direction. Access flows in the opposite direction of trust:
- If Domain A trusts Domain B, users from Domain B can access resources in Domain A (access flows from B to A)
- The trust direction specifies which domain does the trusting, while access direction indicates where users can go

## Security Considerations

### Privilege Escalation Paths
Active Directory environments often contain complex permission chains that can be exploited to escalate privileges. Common paths include:
- Service account privileges
- Group Policy vulnerabilities
- Group membership exploitation
- Delegation abuse

### Common Attacks
- Kerberoasting: Requesting service tickets for cracking service account passwords
- Pass-the-Hash: Reusing password hashes without knowing the actual password
- Golden Ticket: Forging Kerberos tickets using the KRBTGT account hash
- Silver Ticket: Creating forged service tickets without contacting the KDC

## Best Practices

1. Follow the principle of least privilege
2. Implement proper account tiering
3. Use Protected Users security group for privileged accounts
4. Enable Advanced Audit Policy settings
5. Monitor for suspicious authentication patterns
6. Regularly review trust relationships
7. Implement time-based group membership for administrative access


