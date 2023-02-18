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
   + Chain of custody documentation
      + A second forensic examiner acting as a witness and countersigning all actions
- Human resources
   + Primary responsibility for employee relations and disciplinary policies
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
   + **NIST** evidence log:
      + Hostname
      + MAC Address
      + IP Address
## Containment
- Segmentation
- Isolation
   + Isolate the system before restoring from backups
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
   + Collect live forensics
   + Take photos of each system
   + Power them down
- Lessons learned report
- Change control process
- Incident response plan update
- Incident summary report
- IoC generation


# 🔬 Analyze potential indicators of compromise (IOCs)
## Network-related
- **Bandwidth consumption**
  + Cause service disruption
  + Brute-force methods to degrade networks or services as a form of **attrition**
- **Beaconing**
  + Activity sent to a C&C system as part of a botnet or malware remote system
  + Typically HTTTP / HTTPS traffic
  + Request commands, provide status, download additional malware
- **Irregular peer-to-peer communication**
  + A Botnet infection that uses a peer-to-peer command-and-control process
     + [BotScout.com](https://botscout.com/)
  + Use rapidly changing control nodes and don't rely on a consistent, identifiable control infrastructure
  + Traditional methods of detecting beaconing will fail
  + Morphing infection packages making signature-based detection unlikely to work 
     + Capture network flows for all host and use filters to remove normal traffic
- **Rogue device on the network**
   + Evil Twin Attack
      + Rogue AP configured to spoof the MAC address of a legitimate access point
- **Scan/sweep**
- **Unusual traffic spike**
   + Baseline or anomaly-cased detection
   + Heuristic or behaviour-based detected
   + Protocol analysis
- **Common protocol over non-standard port**
   + SSH on TCP port 1433


## Host-related
- Processor consumption
- Memory consumption
- Drive capacity consumption
- Unauthorized software
- Malicious process
   + Since most APTs send traffic in encrypted form, performing network forensics will only provide information about infected hosts
   + Endpoint forensics will find the actual exploit tools used on endpoint systems
   + Linux configuration settings which effect every service `/etc/xinetd.conf` / `systemctl`
- Unauthorized change
   + `/var/log/auth.log` contains information on successful and unsuccessful login attempts
- Unauthorized privilege
   + `C:\Windows\System32\config` is where Windows stores passwords for local Windows users
      + NTUSER.DAT hive in the `C:\Users\<username>\` directory
   + Check the `/etc/passed`, `/etc/sudoers` and/or `/etc/groups` directory for new Linux accounts
- Data exfiltration
   + Large data flows leaving the network using HTTPS to disguise the traffic
   + A **netcat** server _(listener)_
      + `nc -k -l 6667`, the `-k` flag makes it listen continuously rather than terminating after a client disconnects
      + `-l`determines the port that it is listening on
      + TCP port 6667 is a port typically associacted with _Internet Relay Chat_ (IRC)
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
   + Sysinternals [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) is used for monitoring CPU spikes in applications and generating crash dumps
- Introduction of new accounts
- Unexpected output
- Unexpected outbound communication
- Service interruption
- Application log
   + Pluggable Authentication Module (PAM)-aware applications have a file in the `/etc/pam.d` directory
      + List directives that define the module and what settings or controls are enabled
      + Multifactor Authentication settings


# 🧪 Utilize basic digital forensics techniques
# Network
- Wireshark
    + Display filters
    ```sh
     tcp.port eq 25 or icmp
     ip.src == 152.106.6.125 and ip.dst == 192.168.0.1
    ```

> `ifconfig` resets traffic counters at 4GB

- tcpdump

```sh
tcpdump -e   # option includes the ethernet header during packet capture
tcpdump -n   # flag will show the IP addresses in numeric form
tcpdump -nn  # option shows IP addresses and ports in numeric format
tcpdump -X   # option will capture the packet's payload in hex and ASCII formats.
```


 
## Endpoint

> Check out the [Introduction to Windows Registry Forensics](https://tryhackme.com/room/windowsforensics1) Room on TryHackME

- Disk
   + Sysinternals [DiskView](https://learn.microsoft.com/en-us/sysinternals/downloads/diskview) provides a GUI-based view of the disk with each cluster marked by the files and directories it contains
   + `C:\Windows\AppCompat\Programs\Amcache.hve` - Windows programs that were recently run on the system
   + `C:\Windows\System32\Config\RegBack`
   + The setupapi log file, `C:\Windows\INF\setupapi.dev.log`, records the first time a USB device is conneted to a Windows system
   + **Slack space** is the space left at the end of a file or end of a cluster that do not take the entire storage space allocated to them
      + Windows System Reserved and C: partitions
      + When clusters are overwritten, original data is left in the unused space between the end of a new file and the end of the cluster
   + The Windows command prompt does not store command history _(press `F7` with and open command prompt, you would be able to see the history)_
   + Boot into Safe Mode

> A **Jump Kit** is a common part of the incident response plan and includes a laptop with useful software, a sniffer and forensics tools, thumb drives, external hard drives and networking equipment

- Memory
   + Volatile Storage
   + **System Memory Acquisition** is a process that creates an image file of the system memory that can be analysed to identify the processes that are running, the contents of the temporary file systems
   + While most of the Windows registry is stored on the disk, some keys (like `HKLM\Hardware`) are only stored in memory, so you should analyse the Registry via a memory dump
      + Registry data
      + Network connections
      + Cryptographic keys

## Mobile
+ iPhone backups to local systems can be _full_ or _differential_
## Cloud
## Virtualization
+ `.log` files - log of activity for a virtual machine
+ `.VHD` -  virtual disk format Used by Microsoft Windows
+ `.VMDK` - VMWare’s virtual disk file format which may be either a dynamic or fixed virtual disk
   + _With dynamic disks, the disk will start small and grow to a predetermined limit_
   + _A fixed disk does not change size_
   + `.VMEM` - A backup of the virtual machine’s paging file which only exists of the VM is running or has crashed
   + `.VMSN` – VMware snapshot files, named by the name of the snapshot
      + A `.VMSN` file stores the state of the virtual machine when the snapshot as created
   + `.VMSD` - contains the metadata about the snapshot
   + `.NVRAM` - stores the BIOS information for the virtual machine
   + `.VMX` - configuration file for a virtual machine, such as the operating system, disk information, etc
      + A simple text file that can be easily edited
   + `.VMSS`- the "suspended state" file, storing the state of a suspended virtual machine
   + `.VMTM`- configuration file containing team data
   + `.VMXF` - If a virtual machine is removed from a team, this configuration file remains
+ Boot a Forensic Image to a Virtual Machine:
   + VMware DiskMount Utility:
   + `vmware-mount d: "C:\Documents and Settings\user\My Documents\My Virtual Machines\Windows 10 Professional\Windows 10 Professional.vmdk"`
## Legal hold
+ A legal hold (also known as a litigation hold) is a notification sent from an organization's legal team to employees instructing them not to delete electronically stored information (ESI) or discard paper documents that may be relevant to a new or imminent legal case
## Procedures
+ `secpol.msc` - Windows Local Security Policy
## Hashing
+ Changes to binaries
+ A hash is not considered to be cryptographically secure if two files have the same hash value or digest
+ **Windows**:
  + `Get-FileHash .\file.msi -Algorithm MD5`
  + Change the hash value: `echo "AppendTheHash" >> .\file.msi`
+ **Linux**:
  + `md5sum groups_list.txt`
  + Redirect the hash value of a file(s) into a text file:
     + `md5sum groups_list.txt groups.csv > myfiles.md5`
  + Read the mdsums and check them:
     + `md5sum -c myfiles.md5`
## Carving
+ Looks at data on a block-by-block basis, looking for information like file headers and other indicators of file structure and attempts to recover the files
   + Header and footer-based carving:
     + JPEG header: `xFF\xD8`
     + JPEG footer: `xFF\xD9`
   + Contect-based
   + File structure-based
+ Facebook _and other social media sites_ now strip metadata to help protect user privacy
+ ISO 8601 timestamps: `2022-09-27 18:00:00.000`
+ The timestamp format used in web browsers such as Apple Safari, Google Chrome and Opera
   + 64-bit value for microseconds since Jan 1, 1601 00:00 UTC
   + One microsecond is one-millionth of a second
   + `13321027248000000`

## Data acquisition
+ CPU registers and cache memory
+ Contects of system memory (RAM), routing tables, ARP cache, process table, temporay swap files
   + `%SYSTEMROOT%\MEMORY.DMP`
+ Data on persistent mass storage (HSS/SDD/flash drive)
+ `dd` is used to clone drives in RAW format, the `bs` flag is used for setting the block size in bytes
+ `dd bs=64k if=/dev/disk/by-label/input-file of=/dev/disk/by-label/output-file`
+ `fdisk -l` or `lsblk` to list drives
+ _Check your disk space:_
   + `du` - size of directories and subdirectories
   + `df` - checks disk usage on a mounted filesystem

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
   - Use [Eraser](https://eraser.heidi.ie), [DBAN](https://dban.org) _(Darik's Boot and Nuke)_ or encrypt the drive and then delete the key
+ Physical configuration and network topology
+ Archival media
+ Bitlocker-encrypted systems that mounted the encrypted volume before going to sleep can use Hibernation file analysis to retrieve the Bitlocker key

