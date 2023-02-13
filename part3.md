<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# ⚙️ Security Operations and Monitoring
[<<<](part2.md) | [>>>](part4.md)

 </div>

# 📊 Analyze data as part of security monitoring activities
## Heuristics
+  Focusses on behaviours instead of looking for a specific package
 
## Trend analysis
+ Identitfy large-scale changes from the norm
+ Processor Monitoring
+ Drive Capacity Monitoring
+ Application and service anomaly detection
+ Unexpected Traffic
+ Bandwidth consumption

## Endpoint
- Malware
     - **Reverse engineering** is the process of analysing the structure of hardware or software to reveal more about how it functions
     + Masquerading
     + DLL Injection
        + Manipulates the execution of a running process to load a desired library
           + `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
           + `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs` are loaded into every process that call the Win32 API functions
           + `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` are loaded into every process that runs `User32.dll`
     + DLL sideloading
        + [Hijack Execution](https://attack.mitre.org/techniques/T1574/002/)
        + Planting then invoking a legitimate application that executes the payload that tricks the application into loading a malicious DLL
     + Process hollowing
        + [Process Injection](https://attack.mitre.org/techniques/T1055/012/)
        + Inject malicious code into a suspended or hollowed process to evade process-based defenses
     + **Dropper** Malware is designed to install or run other types of malware embedded in a payload on an infected host
     + **Downloader** is a piece of code that connects to the Internet to retrieve additional tools after the initial infection by a dropper
     + Shellcode is any lightweight code designed to run an exploit on the target, which may include any type of code format from scripting to binary code
   + [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/):
     + A suite of tools to assist with Windows troubleshooting
     + [autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) - perform baseline system scans
        + Currently configured auto-start applications
        + Registry and file system locations
     + ProcDump
- Memory
   + Windows Resource Monitor: `resmon.exe`
      + Identify typical behaviour (Memory, CPU, Disk Utilisation) in real-time and over a period of time
   + Linuc / Unix: `top`, `ps`
- System and application behavior


   - Known-good behavior
      + Download [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) for process analysis
      + Check out [Intro to Endpoint Security](https://tryhackme.com/room/introtoendpointsecurity) Room on TryHackMe
      + System Idle `PID 0` and System `PID4` a kernel-level binary that is the parent of the first user-mode process (Session Manager Subsystem - `smss.exe`)
      + `csrss.exe` (Client Server Runtime SubSystem) manages low-level Windows functions, running from `%SystemRoot%\System32` and has no parent process
      + `wininit.exe` managed driver and services and should only have a single instance running as a process
      + `Services.exe` hosts nonboot drivers and background services, one instance running as a child of `winit.exe`, and other processes showing a child of `services.exe` or `svchost.exe`
         + Services will be started by `SYSTEM`, `LOCAL SERVICE` or `NETWORK SERVICE` accounts (if it is started by a `username`, it should be flagged)
      + `lsass.exe` (Local Security Authority SubSystem) handles authentication and authorisation services, single instance running as a child of `wininit.exe`
      + `winlogon.exe` managed access to the user desktop for each user session with Desktop Window Manager (`dwm.exe`) as a child process
      + `userinit.exe` sets up the shell (`explorer.exe`) and then quits
      + `explorer.exe` is the typical user shell launched with the user's account privileges and is the parent process for the logged-on user
   - Anomalous behavior
      1. Any process name that you do not recognise; `cmd.exe`, `schtasks.exe`, `wmic.exe`, `powershell.exe`, `reg.exe`, `sc.exe`
      2. Any process name that is similar to a legitimate system process (`svhost`)
      3. Processes that appear without an icon, version information, description or company name
      4. Processes that are unsigned
      5. Any process whose digital signiture doesn't match the identified publisher
      6. Any process that does not have a parent/child relationship with a principle Windows process
      7. Any process hosted by Windows utilities like Explorer, Notepad, Task Manager
      8. Any process that is packed or compressed _(highlighted purple)_ in process explorer
   - Exploit techniques
      + `wmic.exe` allows command-line access to the Windows Management Instrumentation
         + Delete Shadow Volume Copies: `wmic.exe shadowcopy delete /nointeractive`
         + `wmic /node:target-name process call create "cmd.exe /c task-name"`
      + Bypass Windows Applocker policy rules, `.exe`, `.dll`
      + Changes in keys in the Run Hive: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- File system
   + File monitoring and commerical Host Intrusion Detection Systems (HIDS)
   + Monitor and report on syetem file changes
      + Tripwire
      + OSSEC
- User and entity behavior analytics (UEBA)
   + Designed to monitor end user behaviour to prevent targeted attacks and insider threats
   + A system that can provide automated identification of suspicious activity by user accounts and computer hosts
       + **Microsoft Advanced Threat Analystics**
       + **Splunk**
           + ```sh
             process where subtype.create and
             (process_name == "wsmprovhost.exe" and parent_process_name == "svchost.exe")
              ```   

## Network
- Uniform Resource Locator (URL) and domain name system (DNS) analysis
   + **Percent encoding** allows a user-agaent to submit any safe or unsafe character (or binary data) to the server within the URL (encodeing unreserved characters)
      + Percent encoding can be misused to obfuscate the nature of a URL and submit input as a script or binary to perform directory transversal
   - **Fast Flux Network** is a method used by malware to hide the presence of C&C networks by continually changing the host IP addresses in domain records using _Domain Generation Algorithms_
   - **Domain Generation Algorithm** (DGA) used by malware to evade blacklists by generating domain names for C&C networks dynamically
   - **Fast Flux DNS** is a technique that rapidly changed the IP address with the associated domain
   - **Port Hopping** - An APT's C2 application might use any port to communicate and may jump betweeen different ports
- Flow analysis
   + **Flow collector** is a means of recording **metadata** and statistics about network traffic rather than recording each frame
   + Router-based monitoring:
     + NetFlow standard
     + RMON
     + SNMP
    + PRTG:
      + Packet sniffing which monitors the headers of packets
      + Flows
      + SNMP
      + WMI
- Packet and protocol analysis
 - Malware
     1. Attacker sets up one or more dynamic DNS services
     2. Malware code implements a DGA to create a list of new domain names
     3. A parallel DGA is used to create name records on the DDNS service
     4. The malware tries a selection of the domains it has created to connect to the C2 server
     5. C&C server communicates with a new seed for the DGA to prevent from being blocked

## Log review
- Event logs
   + Linux: 
      + `/var/log`
      + `/var/log/auth.log`, user login logs
      + `/var/log/faillog`, failed login attempts
   + Windows: `eventvwr. msc` / `%SystemRoot%\System32\Winevt\Logs\`
      1. Application
      2. Security
      3. System
      4. Setup
      5. Forwarded Events
- Syslog
   + A protocol enabling different appliances and software to transmit logs or event records to a central server
   + Port 514 (UDP) over TCP/IP, i.e. `10.1.0.248:514` (newer implemetations can use TLS 1.3)
- Firewall logs
   + **ACL**s are processed from __top-to-bottom__ with the most specific rules on top
     1. Block incoming requests from internal or private, loopback and multicast IP addresses
     2. Block incoming protocols that should only be used locally i.e. ICMP, DHCP, OSPF, SMB etc.
     3. Configure IPv6 to either block all IPv6 traffic or allow it to authorised hosts and ports only
     4. Block outgoing ICMP status messages to prevent _firewalking_
   + A **Black Hole** is a means of mitigating a DoS or intrusin attacks by silently dropping traffic

- Web application firewall (WAF)
  + Prevent web-based exploits and vulnerbilities like SQL injection, XML injection, and XSS attacks

- Proxy
   + Forward Proxy
   + Reverse Proxy
   + **Nontransparent Proxy** is a server that redirects requests and responses for clients configured with the proxy address and port

- Intrusion detection system (IDS) / Intrusion prevention system (IPS)
     1. **Network Intrusion Detection System** (NIDS) monitors the traffic flow from various areas of the network
     2. **Host-based Intrusion Detection System** (HIDS) monitors the traffic flow from a _single endpoint device_
  + An **IPS** is an IDS that can actively block an attack
     1. Network Intrusion Prevention System (NIPS)
     2. Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA)
     3. Wireless Intrusion Prevention System (WIPS)
     4. Host-based Intrusion Prevention System (HIPS)
  + Detection /Prevention Techniques
     + Signature-Based
     + Behaviour-Based
     + Policy-Based
  + 🐽 **Snort** (IDS / IPS), open-source for Windows and selected Linux distros
  + **Zeek** (Bro), open-source IDS for Unix/Linux distros
  + 🧅 **Security Onion**, open-source Linux-based platform for security monitoring, incident reesponse and threat hunting (bundles Snort, Suricata, Zeek, Wireshark, and NetworkMiner)

## Impact analysis
- Organization impact vs. localized impact
- Immediate vs. total
## Security Information and Event Management (SIEM) review
    1. Splunk
    2. ELK / Elastic Stack
    3. ArcSight
    4. QRadar
    5. Alien Vault and OSSIM
    6. Graylog
- Rule writing
  + Data sources with indicators
  + Query strings used to correlate indicators
  + Action to occur when event is triggered
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
+ Network-centric Log
    + SSH

## Query writing
- String search
   + `grep "cys[abc]" example.txt`
   + `grep cysa example.txt | more`
   + `grep -c "string" example.txt`
- Script
   + Linux
     + `df`, show a system's surrent disk utilization
     + `/etc/init.d/servicename status`
     + `service --status-all`
     + `chmod a+x my_script.sh`
     + `wget https://wordpress.org/latest.zip`
- Piping
   + `get-winevent -listlog * | where-object { $_.logname -like "*IIS*" } | format-list -property logname`
   + `reg query HKLM\Software /v QuietUninstallString /s | find "Wireshark"`
  

## E-mail analysis
- Malicious payload
  + An attachment or a clickable downloadable link
- Domain Keys Identified Mail (DKIM)
   + Validates that a a domain is associated with a message
- Domain-based Message Authentication, Reporting, and Conformance (DMARC)
   + A protocol that combines SPF and DKIM to prove that the sender is who they claim to be
- Sender Policy Framework (SPF)
   + Lists the servers that are authorised to send from your domain
- Phishing
   + Check out the [Phishing Page](https://attack.mitre.org/techniques/T1566/) on MITRE ATT&CK
- Forwarding
- Digital signature
- E-mail signature block
- Embedded links
- Impersonation
- Header
    + FTP, Network file sharing activity
    + Web/VPN traffic


# ⚙️ Implement configuration changes to existing controls to improve security
## Permissions
+ Layered security
+ Zero trust and least privilege access


## Allow list (previously known as whitelisting)
+ Whitelisting can be an effective fallback posture to use while conduting incident response
+ Access Control Lists
+ `access-list 100 permit tcp 192.168.1.0 0.0.0.255 host 10.10.64.1 eq 23`

## Blocklist (previously known as blacklisting)
+ `access-list 100 deny tcp any any eq 23 `
 
## Firewall
+ Rest at network boundary
+ Filter network connections based on **source**, **destination** and **port**
+ Packet Filtering
    + Check each packet against ACL rules for IP and Port
+ Stateful Inspection
    + Maintain information about the state of each connection
+ **NGFW**s - Next Generation Firewalls
    + Contextual information - recognizes users, apps, and processes to make decisions
    + Layer 7 of OSI model


## Intrusion prevention system (IPS) rules

## Data loss prevention (DLP)
+ A system that scans outbound traffic and prevents it from being transmitted if it contains specific contect types

## Endpoint detection and response (EDR)
+ Reduce false positives
+ [VirusTotal](https://www.virustotal.com/)
    + Or create custom signatures or detection rules
+ Yara


## Network access control (NAC)
+ 802.1X is a network authentication protocol that opens ports for network access when an organization authenticates a user's identity and authorizes them for access to the network
+ A standard for encapsulating **EAP** (Extensible Authentication Protocol) communications over a LAN or wireless LAN that provides port-based authentication
   + **Port-based NAC** is a switch (or router) that performs some sort of authentication of the attached device before activating the port
+ RADIUS carries authentication from a Network Access Server (NAS) to a AAA server
1. Agent-based vs agentless
2. In-band vs Out-of-Band



## Sinkholing
+ A technique to redirect malicious traffic to a server under the control of the defender
+ A DNS sinkhole _or black hole DNS_ is used to spoof DNS servers to prevent the resolving hostnames of specific URLS

## Malware signatures
- Development/rule writing
+ Most modern malware used _fileless_ techniques to avoid detection by a signature-based system


## Sandboxing
+ A computing environment that is isolated from the host system
   + Monitor system changes
   + Execute known malware


## Port security
+ A layer 2 switch security option that will allow only specific MAC addresses to access the port

 
# 🗡️ Proactive threat hunting
## Establishing a hypothesis
## Profiling threat actors and activities
## Threat hunting tactics
- Executable process analysis
## Reducing the attack surface area
+ Physical
+ Digital
## Bundling critical assets
## Attack vectors
## Integrated intelligence
+ Combines multiple intelligence sources to provide a better view of threats
## Improving detection capabilities


# 🤖 Automation concepts and technologies
## Workflow orchestration
- Security Orchestration, Automation, and Response (SOAR)
   + A technique to find previously unknown malware by observing behaviours common to malicious software
## Scripting
+ `touch /home/username/Documents/Web.html`
## Application programming interface (API) integration
## Automated malware signature creation
+ Malware repositories:
   + VirusTotal
   + Malpedia
   + MalShare
+ [YARA](https://yara.readthedocs.io/en/v4.1.1/index.html) can create malware signatures based on textual and binary patterns
## Data enrichment
+ Processes that improve/refine your original data
## Threat feed combination
## Machine learning
## Use of automation protocols and standards
- Security Content Automation Protocol (SCAP)
## Continuous integration / Continuous deployment/delivery
+ DevOps
