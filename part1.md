<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# 👻 Threat and Vulnerability Management
[<<<](part5.md) | [>>>](part2.md)

</div>

# 👀 Explain the importance of threat data and intelligence
## Intelligence Sources
- Cyber Threat Intelligence (CTI)
    + The process of investigating, collecting, analysing, and diseminating threat sources to provide data about the external threat landscape
      - Narrative report
      - Data Feeds

- CISP (Cyber Security Information Sharing Partnership) | ISAC (Information Sharing & Analysis Center)
    + A not-for-profit group set  up to share sector specific threat intelligence and security best practices amongst its members
- Open-Source Intelligence (OSINT)
    + Methods of obtaining information about a person or organisation through public records, websites, and social media
        + Search engines
           + [Shodan](https://www.shodan.io/)
              + Check out the [Shodan](https://tryhackme.com/room/shodan) room on TryHackMe
        + WHOIS lookups
           + IP Addresses
           + Domains
        + Social Media Analysis (SOCMINT)
        + Username / Email
        + Name, phone, public records
        + HTML Code
           + [The Wayback Machine](https://web.archive.org/) Internet Archive
           + [Urlscan.io](https://urlscan.io/) - website crawling
        + Metadata
           + Electronic document harvesting
           + `Exif` tag data from photos
- Proprietary-Source Intelligence
    + Threat intelligence is very widely provided as a commercial service offering, access to research and updates is subject to a subscription fee
- Closed-Source Intelligence
    + _Honeynet_ data that is derived from the providers oen research and analysis efforts & anonymised information mined from its customers systems
+ Social Engineering
    + [Creepy](https://www.geocreepy.com/) - social media geotagging
    + [Metasploit](https://docs.metasploit.com/)
    + Pretexting

1. **Timeliness**
2. **Relevancy**
3. **Accuracy**
4. **Confidence Levels**
    + Property of an intelligence source that ensures it produces qualified statements about reliability 
    
  
| **CIA** Triad       |
|---------------------|
| **C**onfidentiality |
| **I**ntegrity       |
| **A**vailability    |



## Indicator Management
1. Structured Threat Information eXpression (STIX)
   + JSON for security
     - Observed Data
     - Indicator
     - Attack Patterm
     - Campaign and Threat Actors


```json
  {
    "type": "threat-actor",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "spec_version": "2.1",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:23.000Z",
    "name": "Green Group Attacks Against Finance",
    "description": "Campaign by Green Group against targets in the financial services sector."
}
```

2. Trusted Automated eXchange of Indicator Information (TAXII)
   + A **protocol** for supplying codified information to automate incident detection and analysis
3. OpenIoC
   + A framework by Madiant that used XML-formatted files for supplying codied information to automate incident detection and analysis
   + **[Malware Information Sharing Project (MISP)](https://www.misp-project.org/)** provides a server platform for cyber threat intelligence sharing, a proprietary format, supports open IOC definitions, and can import and export STIX over TAXII
    + [CIRC.LU](https://www.circl.lu/doc/misp/feed-osint/)
    + [Botvrj](https://www.botvrij.eu/data/feed-osint/)
    + [Emerging Threats](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
    + [Feodo](https://feodotracker.abuse.ch/downloads/ipblocklist.csv)
    + [OpenPhish](https://openphish.com/feed.txt)
    + [Abuse CH](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
    + [Digital Side](https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/)
    + [FireHOL](https://iplists.firehol.org/)
    + [AlienVault OTX](https://otx.alienvault.com/)
    + [PhishHunt](https://phishunt.io/)
    + [Disposable Email Domains](https://github.com/ivolo/disposable-email-domains)
    + [FreeMail](https://github.com/dpup/freemail)
    + [AbuseIPDB](https://www.abuseipdb.com/)
    + [Stop Forum Spam](https://www.stopforumspam.com/)

## Threat Classification
+ Known threat vs. unknown threat
   + External/Removable Media
   + Attrition, an attack that employs brute-force methods
   + Web
   + Email
   + Impersonation
   + Improper usage
   + Loss or Theft of Equipment
+ Zero-day
   + Usually applied to the vulnerbility itself but can also refer to an attack of malware that exploits it
+ **Advanced Persistent Threat** (APT)
   + An attackers ability to obtain, maintain and diversify access to network systems using exploits and malware
   + Target large **PII data sets** 



## Threat Actors
+ Nation-state
+ Hacktivist
+ Organized crime
+ Insider threat
   - Intentional
       - Sabotage
       - Financial Gain
       - Business Advantage
   - Unintentional
       - Phishing Attack
       - **Shadow IT**
 
## Intelligence Cycle
+ `Requirements` (Direction & Planning) > 
+ `Collection & Processing` > 
+ `Analysis` > 
+ `Dissemination` (Create and share threat reports) >
+ `Feedback` >

## Information sharing and analysis communities
+ Healthcare
+ Financial
+ Aviation
+ Government
+ Critical infrastructure
  







# 🧠 Utilize threat intelligence to support organizational security
## Attack Frameworks
+ [MITRE ATT&CK](https://attack.mitre.org/) Framework | [attack.mitre.org](https://attack.mitre.org/)
  - An open-source knowledge base for listing and explaining specific adversary cyber tactics, techniques, and common knowleadge or precedures
  - **TTP**s - Tactics, Techniques & Procedures
  - **APT** - Advanced Persistent Threat
  - [Cyber Analytics Repository](https://car.mitre.org/) knowledge base
    + [Scheduled Task - FileAccess](https://car.mitre.org/analytics/CAR-2020-09-001/)
    + [Remote PowerShell Sessions](https://car.mitre.org/analytics/CAR-2014-11-004/)
+ 💎 The Diamond Model of Intrusion Analysis

```sh
                       Adversary
                   __________________
                 .-'  \ _.-''-._ /  '-.
               .-/\   .'.      .'.   /\-.
              _'/  \.'   '.  .'   './  \'_
Infrastucture:======:======::======:======: Capability (TTPs)
              '. '.  \     ''     /  .' .'
                '. .  \   :  :   /  . .'
                  '.'  \  '  '  /  '.'
                    ':  \:    :/  :'
                      '. \    / .'
                        '.\  /.'    
                          '\/'
                         Victim

```

+ Lockhead Martin **Kill Chain**
  1. `Reconnaissance`
      + The attacker determines what methods to use to complete the phases of the atttack
  2. `Weaponisation`
      + The payload code that exploit a vulnerability on the target system
  3. `Delivery` 
  4. `Exploitation`
  5. `Installation`
  6. `Command & Control` (C2)
  7. `Actions on Objectives`

## Threat Research
+ **Indicator of Compromise**
   + A residual sign that an asset or network has been successfully attacked or in being attacked
      - Unauthorised software and files
      - Suspicious emails
      - Suspicious registry and file system changes
      - Unknown port and protocol usage
      - Rogue hardware
      - Service disruption & disfacement
      - Suspicious or unauthorised account usage

```sh
# The Pyramid of Pain shows that some Indicators of Compromise are more challenging to attackers than others
          ,/`.TOUGH!        TTPs (Tactics, Techniques & Procedures)
        ,'/ __`.            Tools
      ,'_/_  _ _`.          Network / Host Artifacts
    ,'__/_ ___ _  `.        Domain Names
  ,'_  /___ __ _ __ `.      IP Addresses
 '-.._/___...-"-.-..__`.    Hash values
```

- TTPs (Tactics, Techniques, and Procedures) is how the attacker goes about their mission from reconnaissance down to data exfiltration
  + [CISA's (Cybersecurity & Infrastructure Security Agency)](https://www.cisa.gov/uscert/ncas/alerts)
  + [MITRE ATT&CK](https://attack.mitre.org/) Framework | [attack.mitre.org](https://attack.mitre.org/)

+ **Common Vulnerability Scoring System** (CVSSv3.1)
   + CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
       + Prioritise response actions
       + **Attack Vector** (AV)
           + Network (N), indicates that the attacker may exploit the vulnerbility remotely over the network
           + Adjacent (A)
           + Local (L)
           + Physical (P)
        + **Attack Complexity** (AC)
           + Low (L)
           + High (H)
## Threat Modeling Methodologies
  + A risk assessment that models organizational strengths and weaknesses
  + Adversary capability
  + Total attack surface
      + Points at which a network or application receives external connections or inputs/outputs that are potential vectors to be exploited
           + The holistic network
           + Websites or cloud services
           + Custom software apllications
  + Attack vector
      + A specific path by which a threat actor gains access to a system
         + Cyber
         + Human (Social Engineering)
         + Physical
  + Impact
  + Likelihood
     - High
     - Medium 
     - Low

## Threat Intelligence Sharing with Supported Functions
- Threat Intelligence information is commonly shared with:
    + _Incident Response_
    + _Vulnerbility Management_
    + _Risk Management_
    + _Security Engineering_
    + _Detection & Monitoring_
       + Analyse network Traffic
       + Analyse the executable process list
       + Analyse other infected hosts
       + Identify how the malicious process was executed
















# 🩹 Vulnerability management activities  
## Vulnerability identification
- Asset criticality
- Active vs. passive scanning

| Active   | Passive                                 |
|----------|-----------------------------------------|
| Nmap     | DNS reconnaissance                      |
| Gobuster | Simple packet monitoring and inspection |
| Burp     | Using open-source intelligence (OSINT)  |
       

- Mapping/Enumeration
    + SSL & TLS:
        + HTTP over TLS (1.3)
        + Use **TLS 1.2** or newer
        + Vulnerable protocols:
           + SSL 2.0, SSL 2.1, TLS 1.0
        + Must use current, secure ciphers
        + Certificates must remain valid and uncompromised
    + Ceritficate Management (PKI):
       + Use of an untrusted CA
       + Expiration of a certificate
       + Mismatch in certificate name
    + Domain Name Server:
       + Harvesting data with `whois` and `nslookup`
            + [BGP Looking Glasses](https://www.bgp4.as/looking-glasses)
            + `nslookup microsoft.com 8.8.8.8`
            + `nslookup -query=mx microsoft.com`
       + [MX Lookup Tool](https://mxtoolbox.com/)
            + Used to specify the email server(s) responsible for a domain name
       + **DNS Zone transfers**: 
            + Easiest way to gather complete DNS information:
               + Domain servers
               + Hostnames
               + MX and CNAME records
               + TTL records
            + `host -t axfr domain.name dns-server`
            + `dig axfr example.com @ns1.example.com`
       + DNS Brute Forcing:
            + Scripted query for each IP address that an organisation uses
            + Bypass IDS and IPS systems
       + DNS Antiharvesting Techniques:
            + Blacklisting systems and/or networks that abuse the service
            + Use CAPTCHAs to prevent bots
            + Privacy services that use third-party DNS registration information
            + Implement **rate limiting** to ensure that lookups are not done at high speeds
            + Not publishing zone files
    + Internal IP Disclosure:
       + Bad packet headers revealing information that should be hidden by NAT
       + HTTP version 1.0 request to the server without the Host header set, the server will refer to itself by its internal IP address
       + HTTP 1.0 protocol doesn't require the Host header to be set by the client as part of a request
       + `ncat -ssl owa.mymailserver.net 443 GET / HTTP/1.0`
    + Microsoft SQL Server:
       + TCP port 1433
       + HTTPS connection through a URL: TCP port 443
    + MySQL:
       + TCP port 3306
    + VPN:
       + Protocols, encryption tunnels can be vulnerable (PPTP)
    + Virtualisation:
       + VM Escape
       + Management Interface Acess
       + Virtual Host Patching
       + Virtual Guest issues
       + Virtual Network Issues
    + Use of vulnerable, down-level of protocols:
       + NTLM v1
       + LANMAN
       + NetBIOS
          + `nbtstat` displays NetBIOS over TCP/IP protocol statistics
          + `nbtstat -c` shows the contents of the NetBIOS name cache and a list of name-to-IP address mapping
       + Unsigned LDAP
       + SMB
          + Accessing SMB Shares using `smbclient`: `smbclient \\\\{target_IP}\\{SHARE_NAME}`
    + Printers:
        + Line Printer Requester, **LPR/LPD** TCP port 515
        + **IPP** TCP port 631
    + **Oracle Database** Net Listener:
        + TCP 1521

## Validation
- True positive
    + A legitimate attack which triggers to produce an alarm
- False positive
    + An event signalling to produce an alarm when no attack has taken place
- True negative
    + When no alarm is raised when an attack has taken place
- False negative
    + An event when no attack has occurred, and no detection is made

## Remediation/Mitigation
- Configuration baseline
   + Run the Microsoft Baseline Security Analyser (MBSA)
- Patching
- Hardening
- Compensating controls
- Risk acceptance
- Verification of mitigation

## Scanning parameters and criteria
- Risks associated with scanning activities
- Vulnerability feed
- Scope
- Credentialed vs. non-credentialed
- Server-based vs. agent-based
- Internal vs. external
- Special considerations
 - Types of data
 - Technical constraints
 - Workflow
 - Sensitivity levels
 - Regulatory requirements
 - Segmentation
 - Intrusion prevention system (IPS), intrusion detection system (IDS), and firewall settings

## Inhibitors to remediation
- Memorandum of understanding (MOU)
- Service-level agreement (SLA)
- Organizational governance
- Business process interruption
- Degrading functionality
- Legacy systems
- Proprietary systems




















# 📡 Analyze the output from common vulnerability assessment tools
## OWASP Zed Attack Proxy (ZAP)
+ [OWASP ZAP](https://www.zaproxy.org/) is an open-source web application security scanner that detects common threats to web applications
   + Check out the [OWASP Top 10](https://tryhackme.com/room/owasptop10) on TryHackMe
   + SQL injection 
   + XSS (Cross-site scripting) 
   + CSRF (Cross-site request forgery) 
   + Misconfigurations 
   + Data leakage
- [Burpsuite](https://www.kali.org/tools/burpsuite)
   + A set of tools used for the penetration testing of _web applications_
      + Check out the [Burp Suite: The Basics](https://tryhackme.com/room/burpsuitebasics) room on TryHackMe
      + Contains an **intercepting proxy** to see and modify the content of requests and responses in transit
      + **Intruder fuzzer** for brute-force enumeration and dictionary attacks on password forms
      + **Repeater** to modify requests and responses
- [Nikto](https://www.kali.org/tools/nikto)
   + An open-source web server and web apllication scanner
      + Find SQL injection and XXS vulnerabilities
      + Report on unusual headers
      + Identify installed software
- [Arachni](https://www.arachni-scanner.com)
   + Open-source penetration testing framework for web applications
+ HTTP Methods
   + GET
   + POST
   + PUT
   + HEAD
   + DELETE
   + PATCH
   + OPTIONS
   + CONNECT
   + TRACE
## Infrastructure vulnerability scanner
+ Common Vulnerabilities and Exposures (CVE)
   + [CVE-2020-1472](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
- Nessus
- OpenVAS
- Qualys _(cloud-based SaaS)_
## Software assessment tools and techniques
- Static analysis
   + Source code analysis is done by reviewing the code for an application
- Dynamic analysis
   + Relies on the execution of the code while providing it input to test the softwre
- Reverse engineering
   + Use a compiler to convert the source code into binary (machine) code that the computer can read
   + Use a decompiler to convert the binary code back into source code
- Fuzzing
  + Sending invalid or random data to application to test it's ability to handle unexpected data
## Enumeration
- **Nmap**
   + **Common Platform Enumeration** (CPE) is a scheme for identifying hardware devices, operating systems and applications developed by MITRE
   + By default, Nmap uses a **TCP SYN** scan
   + Nmap supports `HTTP` and `SOCKS 4` proxies, allowing the attacker to configure a remote host as a reverse HTTP proxy and bounce their scans through it or you can use _proxychains_:
      + `proxychains nmap -sT -Pn -n -p445,139,88,80 10.10.226.53`
    + **Target Specification**
       + `nmap 10.129.86.241/24`
    + **Service Version Detection**
       + `nmap -sV 10.129.86.241`
    + **Operating System Detection**
       + `nmap -O 10.129.86.241`
    + **Host Discovery**
       + `nmap -sn 10.129.86.241`
       + _Disable host discovery, port scan only_:
          + `nmap -Pn 10.10.226.53`
    + **Timing & Performance**
       + _Paranoid (0) Intrusion Detection System evasion_:
          + `nmap 10.10.226.53 -T0`
    + **Firewall / IDS Evasion and Spoofing**
       + _Use tiny fragmented IP packets_:
          + `nmap 10.10.226.53 -f`
       + _Relay connections through HTTP/SOCKS4 proxies_:
          + `nmap –proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1`
       + _Set offset size_:
          + `nmap 10.10.226.53 –mtu 32`
       + _Appends random data to sent packets_:
          + `nmap –data-length 200 10.10.226.53`
    + **Port Scans**
       + `-sS` TCP SYN packet
       + `-sU` UDP Scan
       + `-sT` TCP connect; conducts a three-way handshake scan
       + `-N` Null scan sends a packet with the header bit set to 0
       + `-sF` send an unexpected FIN packet
       + `-sX` sends a packet with the FIN, PSH and URG flags set to 1
       + `-p` Port Range

- hping / hping3
    + TCP/IP packet assembler and analyzer
        + `sudo hping3 -S --flood -p 80 www.wisetut.com`
        + `sudo hping3 -S 192.168.200.15`, send SYN packets to the target IP address
        + `sudo hping3 -0 192.168.200.15`, send a raw IP through the network

- Active vs. passive
    + Active:
       + Pinging hosts
       + Angry IP Scanner
       + Port scanning and service discovery (Nmap)
       + DNS forward or reverse lookup
       + DNS Zone Transfer
       +  🚩 Banner Grabbing
          + Telnet
          + Wget
          + `echo " " | nc -v 10.10.226.5 80`

    + Passive Footprinting:
       + DNS Registrar checks
       + WHOIS lookups
       + BGP looking glass
       + Log data and configuration analysis
       + Capturing network traffic by using a sniffing tool
          + Wireshark
          + Zeek or Bro
          + pof
          + **Netflow** is a Cisco network protocol that collects IP traffic information
       + `netstat` shows active TCP and UDP connection filtered by protocol
          + Windows, Linux & macOS
       + _Disable promiscuous mode for all NICs_ to mitigate attackers from analysing system traffic

- [Responder](https://github.com/SpiderLabs/Responder)

```sh
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

sudo apt install responder
responder-Icmp-Redirect -h

```


+ A python script whisch is a hybrid between active and passive information gathering
+ Passivley monitors the network, waiting for system to send out broadcasts intended for other devices running network services
+ Actively attempts to the hijack the session onces passively identifying these requests

## Wireless assessment tools
- Aircrack-ng
   + Capture packets from wireless networks
   + Conduct packet injection attacks
   + Crack preshared keys used on **WEP**, **WPA**, and **WPA2** nerworks
- Reaver
   + Find WPA and WPA2 passphrases on networks that support the WiFi Protected Setup (WPS) features
- oclHashcat
   + Multi-hash cracker used for brute force and dictionary attacks
## Cloud infrastructure assessment tools
- ScoutSuite
   + A multicloud auditing tool into user's accounts of cloud service providers and retrieves configuration information using their service API
- Prowler / Inspector
   + An AWS-specific security configuration testing tool
- Pacu
  + An AWS-specific exploitation framework used for cloud service penetration tests










# 📱 Threats and vulnerabilities associated with specialized technology
## Mobile
+ Vulnerable Legitimate Apps
+ Jailbreaking
+ Outdated OS
+ Malware and Malicious Apps
+ Compromised Wi-Fi Hotspots
+ Phishing
## Internet of Things (IoT)
+ Weak default passwords
+ Lack of security updates
+ Lack of encryption _(in transit and at rest)_
## Embedded
+ Computer intergrated into the operations of another device, such as a vehicle
## Real-time operating system (RTOS)
+ Slimmed-down operating systems packed onto a single chip
## System-on-Chip (SoC)
+ An integrated circuit that combines many elements of a computer system into a single chip
## Field programmable gate array (FPGA)
+ Computer chips that allow the end user to reprogam their function
+ FPFAs are easily cloned, increasing the risk of intellectual property theft
+ _For your interest: [How to Protect Intellectual Property in FPGAs Devices–Part 1](https://www.eetimes.com/how-to-protect-intellectual-property-in-fpgas-devices-part-1/)_
## Physical access control
+ Access point
+ Personal credentials
+ Readers and/or keypads
+ Control panel
+ Access control server
## Building automation systems
+ BAS is an intelligent system of both hardware and software, connecting heating, venting and air conditioning system (HVAC), lighting, security, and other systems to communicate on a single platform
   + HVAC systems
   + Electrical systems, including lighting
   + Security systems, including surveillance cameras and alarms
   + Plumbing systems
   + Fire alarms, and other emergency systems
   + Elevators
## Vehicles and drones
- Controller Area Network (CAN) bus
    + Specialised networks designed to facilitate the communication the communication between embedded systems without the TCP/IP network
## Workflow and process automation systems
## Industrial control system
## Supervisory control and data acquisition (SCADA)
- Modbus
   + An industrial protocol for communication possible between automation devices over TCP/IP (UDP)











# ☁️ Threats and vulnerabilities operating in the cloud
## Cloud service models
- Software as a Service (SaaS)
- Platform as a Service (PaaS)
- Infrastructure as a Service (IaaS)
## Cloud deployment models
- Public
- Private
- Community
- Hybrid
## Function as a Service (FaaS)/ serverless architecture
+ AWS Lambda
+ Google Cloud Functions
+ Microsoft Azure Functions
## Infrastructure as code (IaC)
+ DevOps
+ Azure Resource Manager (ARM) templates
## Insecure application programming interface (API)
  + Limit exposure of the API keys to the smallest set of individuals possible
  + Use different API keys for differnt user, applications and services
  + Restrict the rights associated with each API key
  + Never transmit API keys over unencrypted channels
  + Never store API key in unencrypted form
  + Ensure API keys are removed from any public code repository like Github
## Improper key management
  + Unauthorised diclosure of a key
  + Non-rotation of keys
  + Inapproriate key storage
## Unprotected storage
## Logging and monitoring
- Insufficient logging and monitoring
- Inability to access









# 🌱 Implement controls to mitigate attacks and software vulnerabilities
## Attack types
- Extensible markup
 language (XML) attack
- Structured query language (SQL) injection
- Overflow attack
   - Buffer
      + Overflowing a memory location by placing a string longer than a program expects into a variable
      + Enable ASLR (Address Space Location Randomisation) and DEP (Data Execution Prevention) in Windows
   - Integer
   - Heap
      + `malloc()`
- Remote code execution
- 📁 Directory traversal
    + Insert filesystem path values into a query string
    + `http://10.10.226.146/policy?document='aup.pdf'`
    + Enumerate web server on port 80 with `gobuster`
        ```sh
        gobuster dir -u http://10.10.226.146/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o gobuster_scan.txt
        ```
- Privilege escalation
+ Password Reuse:
    - Password spraying
       + Brute-force attacks resulting in thousands or millions of username attempts
    - Credential stuffing
       + Stolen username and password wordlists from another site
- Impersonation
    + OAuth open redirects
- On-path attack (previously known as man-in-the-middle attack)
   + Interfere in the communication flow between two systems
- Session hijacking
  + Session key or cookie exploitation causing the session to pass through a system under the attacker's control
- Rootkit
     + Combined multiple malicious software tools to provide continued access to a system while hiding their own existence
- Cross-site scripting (XSS)
     + An attacker embeds scripting commands on the website which can be executed by an unsuspecting user
     ```js
     // Inside of input field the following command will help find XSS by creating a simple alert
     <script>alert(1)</script>
     ```
     + Add the payload in the URL
     ```sh
     # Exploiting a vulnerable URL parameter and alerting the users cookie
     http://10.10.226.56/vulnerabilities/xss_r/?name=<script>alert(document.cookie)</script>
     ```
     + Enable **Output Encoding** to prevent this type of attack
        + Translates special characters so that it won't be interpreted as part of the script
 - Reflected
     + The attacker tricks the user in sending the attack to the server disguised as a ligitimate query string or other content
     + The server sends (reflects) the attack back to the user, causing it to execute
 - Persistent
     + The attacker is able to store the attack code on a server, waiting for the user to request the infected content
 - Document object model (DOM)
     + see _JavaScript_
     + Attacks occur within a database maintained by the user's web browser
## Vulnerabilities
- Improper error handling
- Dereferencing
- Insecure object reference
- Race condition
   + Rely on timing
- Broken authentication
- Sensitive data exposure
- Insecure components
- Insufficient logging and monitoring
- Weak or default configurations
    + A vulnerable FTP server which allows anonymous access:
      ```sh
      User:  anonymous
      Password:  anonymous@domain.com
      ```
- Use of insecure functions
 - strcpy
    + Used to copy the source string to the destination string
    + A stack overflow is caused if the buffer size of the destination string is smaller than the size of the source string
