<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# ⚙️ Security Operations and Monitoring
[<<<](part2.md) | [>>>](part4.md)

 </div>

# Analyze data as part of security monitoring activities

## Security Information and Event Management (SIEM)
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
    + FTP, Network file sharing activity
    + Web/VPN traffic
