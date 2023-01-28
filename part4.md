<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# 🔥 Incident Response
[<<<](part3.md) | [>>>](part5.md)

 </div>

# Incident response process
## Communication plan
- Limiting communication to trusted parties
- Disclosing based on regulatory/ legislative requirements
- Preventing inadvertent release of information
- Using a secure method of communication
- Reporting requirements
## Response coordination with relevant entities
- Legal
- Human resources
- Public relations
- Internal and external
- Law enforcement
- Senior leadership
- Regulatory bodies
## Factors contributing to data criticality
- Personally identifiable information (PII)
- Personal health information (PHI)
- Sensitive personal information (SPI)
- High value asset
- Financial information
- Intellectual property
- Corporate information

# Apply the appropriate incident response procedure
## Preparation
- Training
- Testing
- Documentation of procedures
## Detection and analysis
- Characteristics contributing to severity level classification
- Downtime
- Recovery time
- Data integrity
- Economic
- System process criticality
- Reverse engineering
- Data correlation
## Containment
- Segmentation
- Isolation
## Eradication and recovery
- Vulnerability mitigation
- Sanitization
- Reconstruction/reimaging
- Secure disposal
- Patching
- Restoration of permissions
- Reconstitution of resources
- Restoration of capabilities and services
- Verification of logging/ communication to security monitoring
## Post-incident activities
- Evidence retention
- Lessons learned report
- Change control process
- Incident response plan update
- Incident summary report
- IoC generation


# Analyze potential indicators of compromise
## Network-related
- Bandwidth consumption
- Beaconing
- Irregular peer-to-peer communication
- Rogue device on the network
- Scan/sweep
- Unusual traffic spike
- Common protocol over non-standard port
## Host-related
- Processor consumption
- Memory consumption
- Drive capacity consumption
- Unauthorized software
- Malicious process
- Unauthorized change
- Unauthorized privilege
- Data exfiltration
- Abnormal OS process behavior
- File system change or anomaly
- Registry change or anomaly
- Unauthorized scheduled task
## Application-related
- Anomalous activity
- Introduction of new accounts
- Unexpected output
- Unexpected outbound communication
- Service interruption
- Application log


# Utilize basic digital forensics techniques
# Network
- Wireshark
    + Display filters
    ```sh
     tcp.port eq 25 or icmp
     ip.src == 152.106.6.125 and ip.dst == 192.168.0.1
     reg query HKLM\Software /v QuietUninstallString /s | find "Wireshark"
    ```
- `tcpdump`

```sh
tcpdump -e   # option includes the ethernet header during packet capture
tcpdump -n   # flag will show the IP addresses in numeric form
tcpdump -nn  # option shows IP addresses and ports in numeric format
tcpdump -X   # option will capture the packet's payload in hex and ASCII formats.
```

## Endpoint
- Disk
- Memory
## Mobile
## Cloud
## Virtualization
## Legal hold
## Procedures
## Hashing
- Changes to binaries
## Carving
## Data acquisition
