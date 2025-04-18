# Ethical Hacking Assignment – Defensive Security Implementation Using Honeypot and Wazuh

## Introduction
This project presents a formal implementation of a defensive cybersecurity framework as part of an ethical hacking assignment. The solution integrates Honeypot technology with the Wazuh Security Information and Event Management (SIEM) platform to establish a proactive security monitoring and threat detection system. The primary objective is to simulate a real-world enterprise network under potential attack, observe and analyze adversarial behavior, and respond accordingly using defensive methodologies in line with industry best practices.

This assignment was conducted from a Blue Team perspective, focusing on prevention, detection, and response mechanisms rather than offensive tactics. The deployed environment offers insight into attacker techniques across the reconnaissance, scanning, and exploitation phases and provides forensic evidence through comprehensive monitoring and log analysis.

### Objectives
The specific objectives of this assignment are as follows:
- To implement a high-fidelity honeypot system to simulate vulnerable infrastructure and attract malicious actors.
- To integrate the honeypot with the Wazuh SIEM platform for real-time monitoring, log aggregation, and alert generation.
- To analyze unauthorized access attempts and suspicious behavior.
- To automate detection and response workflows using Wazuh’s built-in capabilities.
- To evaluate the effectiveness of defensive mechanisms in identifying and mitigating potential threats.

## Honeypot Deployment
The honeypot serves as a deliberately vulnerable system designed to deceive and monitor attackers. In this project, the Cowrie honeypot was utilized to simulate a Linux server accessible via SSH. The honeypot was configured to allow the logging of malicious activity without compromising any actual production systems.

Key features of the honeypot deployment include:
- Simulation of an exposed SSH environment with weak credentials.
- Emulation of common Linux file structures and command responses.
- Comprehensive session recording, including keystrokes, commands issued, and files downloaded.
- Logging of attacker IP addresses, timestamps, and geolocation data.
- Seamless integration with Wazuh via log forwarding for centralized analysis.

This setup enabled the system to attract a variety of attacks, including brute-force login attempts, port scans, and remote shell commands, thereby offering valuable insight into real-world threat behavior.

## Wazuh Integration
Wazuh, an open-source SIEM solution, was configured to collect, index, and analyze logs from both the honeypot and other monitored endpoints. It served as the primary platform for real-time threat detection, log correlation, rule-based alerting, and automated response.

Key functionalities of Wazuh in this assignment include:
- Real-Time Log Collection: Aggregation of system logs, authentication attempts, and honeypot activity.
- Threat Detection: Identification of unauthorized access, scanning activity, and command injection attempts through rule-based analysis.
- File Integrity Monitoring: Detection of unauthorized modifications to sensitive files and system binaries.
- Alert Management: Categorization and prioritization of security events based on severity levels.
- Active Response Mechanisms: Execution of predefined actions such as blocking IP addresses through firewall rules in response to detected threats.
- Visualization Dashboards: Use of Kibana dashboards to present detailed visual reports of attack sources, frequency, and patterns.

This integration significantly improved visibility into attack vectors and enabled efficient incident response.

## Attack Simulation and Detection
To validate the effectiveness of the deployed defense mechanisms, controlled attack scenarios were executed. These included:
- SSH brute-force attacks using tools such as Hydra.
- Port scanning and OS fingerprinting using Nmap.
- Remote code execution and reverse shell delivery using Metasploit.
- File transfer attempts using standard command-line utilities.

Wazuh successfully detected and logged all unauthorized activities. Alerts were generated in real time and included detailed information on the attack method, source IP, and attempted actions. The honeypot captured session data that provided forensic evidence of attacker intent and capabilities.

Additionally, Wazuh’s active response feature triggered firewall rules to automatically block the source IPs of malicious actors, thereby preventing further intrusion attempts without requiring manual intervention.

## Conclusion
This assignment demonstrates a comprehensive and practical application of defensive cybersecurity principles through the deployment of a honeypot and the use of Wazuh as a SIEM solution. The integration of deception technologies and real-time monitoring tools creates a robust defense-in-depth strategy capable of detecting, analyzing, and responding to various stages of a cyberattack.

The insights gained from this project emphasize the importance of proactive threat detection, behavioral analysis, and automated response systems in modern cybersecurity operations. Furthermore, it highlights how ethical hacking, when applied from a defensive standpoint, can effectively contribute to the development of secure infrastructures.