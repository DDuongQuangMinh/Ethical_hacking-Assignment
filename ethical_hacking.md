---
title: "Ethical Hacking Assignment"
author: [HAN23080181, HAN23080514, HAN23100188, HAN23100107, HAN23080227]
date: '2025-03-30'
toc: true
toc-own-page: true
lang: "en"
titlepage: true,
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "360049"
titlepage-rule-height: 0
titlepage-background: "background.pdf"
...

# **Title: Defensive Strategies Against the 5 Phases of Ethical Hacking: A Security Perspective**


# **1.Introduction**
Cybersecurity threats are one of the major problems in different countries including strong technological thriving countries such as United State, United Kingdom, and Russia, which target individual, businesses, and governments, causing financial losses, reputational damage, and operational disruptions. 
As organizations continue to store vast amounts of sensitive data, Ethical Hacking plays a crucial role in cybersecurity to protect the information of company and customers by simulating real-world attack to identify vulnerabilities within systems, networks, and applicators. The goal of Ethical Hacking is to understand mindset or tactic of attackers to strengthen security and implement effective countermeasures.

**Ethical Hacking is structured into five stage that mimic attack circuition:**
1. Reconnaissance: Collecting target data such as IP address, or network detail by scanning techniques.
2. Scanning and Enumeration: Analyzing vulnerabilities of target system using tool like Nmap and Nessus.
3. Gaining access: Gaining unauthorized access to target system through brute-force attack, SQL injection, misconfiguration.
4. Maintaining access: Enhancing access by deploying backdoor, rootkits, or others stealth techniques can avoid detection.
5. Cover track: Clearing track to evade detection.

# **2.Main body**
##  2.1 What is Ethical Hacking?
### 2.1.1 Introduction to Ethical Hacking
Ethical hacking or **penetration testing**, or **white-hat hacking**, or **offensive security testing**, is the name for the system security inspection process of an organization or government through emulating an actual attack on the system of that organization. This action is taken to examine and identify potential security weakness existing in the system that can be exploited by malicious actors.
Ethical hacking has become an essential cornerstones in modern cybersecurity framework due to the development of cyber threats is increasingly complicated and difficult to solve, providing organizations or governments to detect and overcome potential weakness.

### 2.1.2 Definition and Scope
Ethical hacking is the use of exploitation techniques by ethical hacker or friendly parties in an attempt to discover, identify, understand and repair security weakness in a network, computer system, or organization's system before threat actors can exploit them.

The practice encompasses the following scopes:
- Network infrastructure testing
- Web and mobile application penetration testing
- Wireless security assessments
- Cloud service configuration audits
- Physical and social engineering attacks (within red team exercises)

### 2.1.3 Objectives of Ethical Hacking
Objectives of Ethical Hacking:
- Identifying Security Vulnerabilities: Detect the security vulnerabilities existing in organization's system, network, and applications that may be exploited.
- Risk Assessment and Prioritization: Examine the system defence and impact of identified weakness based on industry standards.
- Compliance Assurance: Meet the requirements and regulations in the contract.
- Incident Response Readiness: Simulate the cyberattack to examine the efficiency of organization's detection and mitigation procedures.
- Security Posture Improvement: Give direction and enhance the effectiveness of the system resilience.

### 2.1.4 Ethical and Legal Considerations
Ethical hackers must obey the laws, consensus as well as organization policies. Any deviation from the term that have been signed between the two parties can constitute the law violation such as:
- Computer Fraud and Abuse Act (CFAA) – United States
- General Data Protection Regulation (GDPR) – European Union
- Computer Misuse Act 1990 – United Kingdom

Before the inspection was conducted, a contract also know as **Rules of Engagement (RoE) document** must be signed. This document outline:
- Testing scope and exclusions
- Authorized tools and techniques
- Testing schedule
- Notification and escalation protocols

In short, ethical hacker must comply with the principle to avoid leaked sensitive information, and the effects may occur when the information is leaked, ensuring data confidentiality, integrity and availability.

##  2.2 What is Active Directory(AD)?
### 2.2.1 Introduction to Active Directory (AD).
Active directory is a eraction of different hierarchies developed by Microsoft that serves as the backbone of identity and access management (IAM) in Windows-based enterprise networks, enabling administrators to manage information stored on the network such as user data, security, and distributed resources  more efficient.

### 2.2.2 Core Components of Active Directory.
#### 2.2.2.1 Active Directory Domain Services (AD DS).
A directory services knows as Active Directory Domain Services (AD DS), enabling directory data such as authentication(names, passwords, phone numbers), user logon processes, and directory searches can be stored and available across network users and administrators. In addition, AD DS improve the effectiveness in resources management and security policies.

#### 2.2.2.2 Domain Controllers (DCs).
Domain Controllers work as a brain controlling AD DS including security policies and directory data. Moreover, they approve and validate all clients and components in Windows domain network.

#### 2.2.2.3 Organizational Units (OUs).
Organizational Units (OUs) has the lowest rank in the decentralization system of AD and the smallest administrative units in Domain that function as a container to store directory objects such as users, group, computers, and other components. OUs are the smallest gear in the system but also the most important for the system to operate smoothly and effectively.

#### 2.2.2.4 Group Policy Objects (GPOs).
Group Policy Objects (GPOs) is a set of setting that implemented defence policies to Active Directory environment to manage thousands of users and devices across Directory domain. Thus, enforcing organizational standards and security compliance.

Purpose and Application:
- Centralized Configuration Management: Allow administrators to implement regular configurations to users have been created in the environment in a defined scope (site, domain, or OU).
- User Configuration Settings: Including guiding related to AD environment such as desktop environment, network connections, software installation, folder redirection, and logon/logoff scripts.
- Computer Configuration Settings: 
- Security Enforcement: Including policies for startup/shutdown scripts, Windows security settings, registry settings, and service control.
- Software Deployment: GPOs act function as crucial part in Directory domain helping automate the installation, update, or removal of software applications across multiple machines. 
- Loopback Processing: Useful in environments like kiosks or classrooms, where a user’s settings are overridden by the computer’s GPO regardless of who logs in.

GPO Processing Order (LSDOU):
When multiple GPOs are in place, they are applied in the following order:
1. Local GPO
2. Site-level GPOs
3. Domain-level GPOs
4. OU-level GPOs (from parent to child)

If settings conflict, those applied later in the sequence (e.g., at the OU level) take precedence.

### 2.2.3 Security and Authentication.
Active Directory (AD) own strong security and authentication through various network protocols, including the three most important protocols are Kerberos, LDAP, and NTML - collectively ensure that users and devices are authenticated securely and efficiently, enabling access control across an organization’s infrastructure.

#### 2.2.3.1 Kerberos Authentication Protocol.
Kerberos is the essential protocol of Active Directory in Domain environments, acting as a mediator for trusted hosts and untrusted network to secure communication between two parties such as authenticating service.

Key features:
- Ticket-Based Authentication: Key Distribution Center (KDC), which is a part of domain controller, providing ticket issued for Kerberos to operate.
- Mutual Authentication: Authentication is performed in parallel between client and server, in order to mitigate the risk of impersonation attacks.
- Time-Sensitive Tokens: Kerberos tickets have expiration timestamps, reducing the risk of token reuse or replay attacks.

#### 2.2.3.2 LDAP (Lightweight Directory Access Protocol).
LDAP or Lightweight Directory Access Protocol is an open and neutral protocol using in AD to manage directory services and become a central location for accessing, providing communication language that applications require to send and receive information from directory services.

Key Functions in AD:
- Directory Searches: LDAP is used to look up directory objects such as users, groups, or computers.
- Authentication and Authorization: LDAP can validate credentials and determine access rights based on user attributes.
- Directory Modification: Using LDAP to add, delete, or modify AD objects.

#### 2.2.3.3 NTLM (NT LAN Manager).
NTML is one of the old protocols applied before Kerboros. While the modern Active Directory environment is still priority Kerberos rather than NTML, they still use NTML to help old systems do not support Kerberos compatible with the environment.

NTLM Characteristics:
- Uses a challenge-response mechanism for authentication.
- Does not provide mutual authentication, making it vulnerable to relay attacks.
- Still used in workgroup environments, local logons, and when Kerberos is unavailable.

##  2.3 What is HoneyPot?

Honeypots are fake services designed to be decoys to attract, surveil and identify potential threat actors. These decoys are deliberately vulnerable and exposed by design. (Crowdstrike)

##  2.4 Reconnaissance
Reconnaissance is the first step of cyberattack where threat actors try to gather information of target's system without direct interaction. In defensive site, blue team will try to reduce exposure of sensitive data in documents or code by minimizing publicly available data and deploying early detection mechanisms such as Honeypots, Wazuh.

Honeypot function as a decoy in network to distract potential attacker from essential data and machine in Directory domain. Combining Wazuh with Honeypot to analyze, correlate, and respond to these early signals. When Honeypot is being triggered, Wazuh will automate IP blocking and send real-time alerts to defenders of unauthorized access attempts

This combination of deception and correlation allows defenders to detect reconnaissance activities early, manage external exposure, and engage proactively before attackers escalate their operations.

##  2.5 Scanning and Enumeration
Scanning is the next step of cyberattack. In this phase, attackers try to identify open ports, live hosts, and services of target's system by probing the network environment. 

##  2.6 Gaining access
##  2.7 Maintaining access
##  2.8 Cover Track

# **3.Malware Attacks and Remediation Plan**

# **4.Challenges in Securing Network**

# **5.Conclusion**

# **6.References**
- Stuttard, D., & Pinto, M. (2011). The Web Application Hacker’s Handbook: Finding and Exploiting Security Flaws (2nd ed.). Wiley Publishing.
- Weidman, G. (2014). Penetration Testing: A Hands-On Introduction to Hacking. No Starch Press.
- Microsoft (n.d.) Active Directory Domain Services overview. Microsoft Learn. Available at: https://learn.microsoft.com/vi-vn/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview (Accessed: 13 April 2025).
- CrowdStrike (n.d.) What is a honeypot in cybersecurity?, CrowdStrike. Available at: https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/honeypots/ (Accessed: 16 April 2025).
- Wikipedia. (2024). Honeypot (computing). [online] Available at: https://en.wikipedia.org/wiki/Honeypot_(computing) [Accessed 18 Apr. 2025].

# **7.Appendices**
