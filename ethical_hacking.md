title: "Ethical Hacking Assignment"
author: "HAN23080181
         HAN23080514
         HAN23100188
         HAN23100107
         HAN23080227"
date: "March 30, 2025"
wrap: preserve
geometry: a4paper
fontsize: 12pt
---

# **Title: Defensive Strategies Against the 5 Phases of Ethical Hacking: A Security Perspective**


# **1.Introduction**
Cybersecurity threats are one of the major problems in different countries including strong technologial thirving coutries such as United State, United Kingdom, and Russia, which target individual, businesses, and governments, causing financial losses, reputationl damage, and operational disruptions. 
As organizations continue to store vast amounts of sensitive data, Ethical Hacking plays a crucial role in cybersecurity to protect the information of company and customers by simulating real-world attack to identify vulnerabilities within systems, networks, and applicators. The goal of Ethical Hacking is to understand mindset or tatic of attackers to strengthen security and implement effective countermeasures.

**Ethical Hacking is structured into five stage that mimic attack circuition:**
1. Reconnaissance: Collecting target data such as IP address, or network detail by scanning techniques.
2. Scanning and Enumeration: Analyzing vulnerabilities of target system using tool like Nmap and Nessus.
3. Gaining access: Gaining unauthorized access to target system through brute-force attack, SQL injection, misconfiguration.
4. Maintaining access: Enhancing access by deploying backdoor, rootkits, or others stealth techiques can avoid detection.
5. Cover track: Clearing track to evade detection.

**Object of the report**
The object of this report to analyze these five phases from a defender's perspective. By examining each phase from a defensive standpoint, this report provides insights into effective cybersecurity strategies for protecting digital environments.

# **2.Main body**
##  2.1 What is Ethical Hacking?
### 2.1.1 Introduction to Ethical Hacking
Ethical hacking or **penetration testing**, or **white-hat hacking**, or **offensive security testing**, is the name for the system security inspection process of an organization or government through emulating an actual attack on the system of that oraganization. This action is taken to examine and identify potential security weakness existing in the system that can be exploited by malicious actors.
Ethical hacking has become an essential cornerstones in modern cybersecurity framework due to the development of cybeer threats is increaingly complicated and difficult to solve, providing organizations or governments to detect adn overcome potential weakness.

### 2.1.2 Definition and Scope
Ethical hacking is the use of exploitation techniques by ethical hacker or friendly parties in an attempt to discover, identify, understand and repair security weakness in a network, computer system, or organization's system before they can be exploited by threat actors.

The practice encompasses the following scopes:
- Network infrastructure testing
- Web and mobile application penetration testing
- Wireless security assessments
- Cloud service configuration audits
- Physical and social engineering attacks (within red team exercises)

### 2.1.3 Objectives of Ethical Hacking
Objectives of Ethical Hacking:
- Identifying Security Vulnerabilities: Detect the security vulnerabilities existing in organization's system, network, and applications that may be exploited.
- Risk Assessment and Prioritization: Examine the system defense and impact of identified weakness based on industry standards.
- Compliance Assurance: Meet the requirements and regulations in the contract.
- Incident Response Readiness: Simulate the cyberattack to examine the effeciency of organization's detection and mitigation procedures.
- Security Posture Improvement: Give direction and enhance the effectiveness of the system resilience.

### 2.1.4 Ethical and Legal Considerations
Ethical hackers must obey the laws, consnensus as well as organization policies. Any deviation from the term that have been signed between the two parties can constitute the law violation such as:
- Computer Fraud and Abuse Act (CFAA) – United States
- General Data Protection Regulation (GDPR) – European Union
- Computer Misuse Act 1990 – United Kingdom

Before the inspection was carried out, a contract also know as **Rules of Engagement (RoE) document** must be signed. This document ouline:
- Testing scope and exclusions
- Authorized tools and techniques
- Testing schedule
- Notification and escalation protocols

In short, ethical hacker must comply with the principle to avoid leaked sensitive information, and the effects may occure when the information is leaked, ensuring data confidentiality, integrity and avalability.

##  2.2 What is Active Directory(AD)?
### 2.2.1 Introduction to Active Directory (AD).
Active directory is a eraction of differient hierarchies developed by Microsoft that serves as the backbone of identity and access management (IAM) in Windows-based enterprise networks, enabling administrators to manage information stored on the network such as user data, security, and distributed resources  more efficient.
### 2.2.2 Core Components of ACtive Directory.
#### 2.2.2.1 Active Directory Domain Services (AD DS).
A directory services knows as Active Directory Domain Services (AD DS), enabling directory data such as authentication(names, passwords, phone numbers), user logon processes, and directory searches can be stored and available across network users and administrators. In addition, AD DS improve the effectiveness in resources management and security policies.
Function:
- Manages user accounts, credentials, and computer objects.
- Stores data in a hierarchical structure (domains, trees, forests).
- Facilitates Single Sign-On (SSO) within a Windows domain.

#### 2.2.2.2 Domain Controllers (DCs).
Domain Controllers work as a brain controlling AD DS including security policies and directory data. Moreover, they approve and validate all clients and components in Windows domain network. Domain Controllers also responsible for:
- Replication: Synchronizes directory data with other DCs to ensure consistency.
- FSMO Roles: A subset of DCs are assigned Flexible Single Master Operations (FSMO) roles, which are critical for certain operations (e.g., schema updates, RID assignment).

#### 2.2.2.3 Organizational Units (OUs).
Organizational Units (OUs) has the lowest rank in the decentrallization system of AD and the smallest administrative units in Domain that act as a container to store directory data such as 

#### 2.2.2.4 Group Policy Objects (GPOs).

### 2.2.3 Security and Authentication.

##  2.3 What is HoneyPot?
##  2.4 Reconnaissance
##  2.5 Scanning and Enumeration
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

# **7.Appendices**