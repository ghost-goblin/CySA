<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# 🔥 Incident Response
[<<<](part3.md) | [>>>](part5.md)

 </div>

# 🎨 Incident response process
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

# 🖌️ Apply the appropriate incident response procedure
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


# 🔬 Analyze potential indicators of compromise (IOCs)
## Network-related
- Bandwidth consumption
  + Cause service disruption
- Beaconing
  + Activity sent to a C&C system as part of a botnet or malware remote system
  + Typically HTTTP / HTTPS traffic
  + Request commands, provide status, download additional malware
- Irregular peer-to-peer communication
- Rogue device on the network
- Scan/sweep
- Unusual traffic spike
  + Baseline or anomaly-cased detection
  + Heuristic or behaviour-based detected
  + Protocol analysis
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
  + [Wazuh](https://documentation.wazuh.com) monitors file integrity, permissions, ownership, and file attributes
  + Tripwire
  + Advanced Intrusion Detection Environment (AIDE)
  + Manual verification of digital signitures using checksums
- Registry change or anomaly
  + `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- Unauthorized scheduled task
  + Windows Task Scheduler, `schtasks.exe`
  + Linux:
     + `cat /etc/crontab`
     + `crontab -l`
## Application-related
- Anomalous activity
- Introduction of new accounts
- Unexpected output
- Unexpected outbound communication
- Service interruption
- Application log


# 🧪 Utilize basic digital forensics techniques
# Network
- Wireshark
    + Display filters
    ```sh
     tcp.port eq 25 or icmp
     ip.src == 152.106.6.125 and ip.dst == 192.168.0.1
    ```
- tcpdump

```sh
tcpdump -e   # option includes the ethernet header during packet capture
tcpdump -n   # flag will show the IP addresses in numeric form
tcpdump -nn  # option shows IP addresses and ports in numeric format
tcpdump -X   # option will capture the packet's payload in hex and ASCII formats.
```

## Endpoint
- Disk
   + `C:\Windows\AppCompat\Programs\Amcache.hve` - Windows programs that were recently run on the system
   + `C:\Windows\System32\Config`
   + `C:\Windows\System32\Config\RegBack`
   + NTUSER.DAT hive in the `C:\Users\<username>\` directory
- Memory
   + **System Memory Acquisition** is a process that creates an image file of the system memory that can be analysed to identify the processes that are running, the contents of the temporary file systems
   + While most of the Windows registry is stored on the disk, some keys (like `HKLM\Hardware`) are only stored in memory, so you should analyse the Registry via a memory dump
      + Registry data
      + Network connections
      + Cryptographic keys

## Mobile
## Cloud
## Virtualization
## Legal hold
## Procedures
## Hashing
+ Changes to binaries
+ A hash is not considered to be cryptographically secure if two files have the same hash value or digest
  + `Get-FileHash .\OpenVPN_2.5.1_I601_amd64.msi -Algorithm MD5`
  + Change the hash value: `echo "AppendTheHash" >> .\OpenVPN_2.5.1_I601_amd64.msi`
## Carving
+ Looks at data on a block-by-block basis, looking for information like file headers and other indicators of file structure and attempts to recover the files
   + Header and footer-based carving:
     + JPEG header: `xFF\xD8`
     + JPEG footer: `xFF\xD9`
   + Contect-based
   + File structure-based
 
## Data acquisition
+ CPU registers and cache memory
+ Contects of system memory (RAM), routing tables, ARP cache, process table, temporay swap files
   + `%SYSTEMROOT%\MEMORY.DMP`
+ Data on persistent mass storage (HSS/SDD/flash drive)
+ `dd` is used to clone drives in RAW format, the `bs` flag is used for setting the block size in bytes
+ `dd bs=64k if=/dev/disk/by-label/input-file of=/dev/disk/by-label/output-file`
+ `fdisk -l` or `lsblk` to list drives

```sh
mkdir ~/tmp
 # verify file authenticity and integrity
md5sum /dev/disk/by-label/[label of your drive] > ~/original.md5
# clone the drive
dd if=/dev/disk/by-label/[label of your drive] of=~/tmp/disk.img bs=64k
 # verify again
md5sum ~/tmp/disk.img > ~/clone.md5
```
 
+ Remove logging and monitoring data
+ Physical configuration and network topology
+ Archival media

