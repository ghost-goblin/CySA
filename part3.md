<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# ⚙️ Security Operations and Monitoring
[<<<](part2.md) | [>>>](part4.md)

 </div>

# Analyze data as part of security monitoring activities


## Heuristics
## Trend analysis
## Endpoint
- Malware
     - Reverse engineering
- Memory
- System and application behavior
     - Known-good behavior
     - Anomalous behavior
     - Exploit techniques
- File system
- User and entity behavior
 analytics (UEBA)
## Network
- Uniform Resource Locator (URL) and domain name system (DNS) analysis
     - Domain generation algorithm
- Flow analysis
 + **Flow collector** is a means of recording **metadata** and statistics about network traffic rather than recording each frame
- Packet and protocol analysis
 - Malware
 - **Fast Flux Network** is a method used by malware to hide the presence of C&C networks by continually changing the host IP addresses in domain resords using Domain Generation Algorithms
 - **Domain Generation Algorithm** (DGA) used by malware to evade blacklists by generating domain names for C&C networks dynamically

  1. Attacker sets up one or more dynamic DNS services
  2. Malware code implements a DGA to create a list of new domain names
  3. A parallel DGA is used to create name records on the DDNS service
  4. The malware tries a selection of the domains it has created to connect to the C2 server
  5. C&C server communicates with a new seed for the DGA to prevent from being blocked

## Log review
- Event logs
- Syslog
- Firewall logs
   + **ACL**s are processed from __top-to-bottom__ with the most specific rules on top
     1. Block incoming requests from internal or private, loopback and multicast IP addresses
     2. Block incoming protocols that should only be used locally i.e. ICMP, DHCP, OSPF, SMB etc.
     3. Configure IPv6 to either block all IPv6 traffic or allow it to authorised hosts and ports only
     4. Block outgoing ICMP status messages to prevent firewalking

- Web application firewall (WAF)
- Proxy
- Intrusion detection system (IDS)/ Intrusion prevention system (IPS)
## Impact analysis
- Organization impact vs. localized impact
- Immediate vs. total
## Security Information and Event Management (SIEM) review
- Rule writing
- Known-bad Internet protocol (IP)
- Dashboard
+ Host-centric log sources
    + Log removal
       - WinEventLog EventID `104`
           - `Get-WinEvent -FilterHashTable @{LogName='System';ID='104'}`
       - Codes `104` or `1102` indicate that the event log was cleared
       - Event code `1100` indicates an event log service shutdown
    + A user accessing a file
    + A user attempting to authenticate
    + Editing a registry key or value
    + PowerShell execution
+ Network-centric Lod
    + SSH

## Query writing
- String search
- Script
- Piping
## E-mail analysis
- Malicious payload
- Domain Keys Identified Mail (DKIM)
- Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- Sender Policy Framework (SPF)
- Phishing
- Forwarding
- Digital signature
- E-mail signature block
- Embedded links
- Impersonation
- Header
    + FTP, Network file sharing activity
    + Web/VPN traffic

# Implement configuration changesto existing controls to improve security
## Permissions
## Allow list (previously known as whitelisting)
## Blocklist (previously known as blacklisting)
## Firewall
## Intrusion prevention system (IPS) rules
## Data loss prevention (DLP)
## Endpoint detection and response (EDR)
## Network access control (NAC)
## Sinkholing
## Malware signatures
- Development/rule writing
## Sandboxing
## Port security

# Proactive threat hunting
## Establishing a hypothesis
## Profiling threat actors and activities
## Threat hunting tactics
- Executable process analysis
## Reducing the attack surface area
## Bundling critical assets
## Attack vectors
## Integrated intelligence
## Improving detection capabilities

# Automation concepts and technologies
## Workflow orchestration
- Security Orchestration, Automation, and Response (SOAR)
## Scripting
## Application programming interface (API) integration
## Automated malware signature creation
## Data enrichment
## Threat feed combination
## Machine learning
## Use of automation protocols and standards
- Security Content Automation Protocol (SCAP)
## Continuous integration
## Continuous deployment/delivery
