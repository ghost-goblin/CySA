<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# ⚙️ Security Operations and Monitoring
[<<<](part2.md) | [>>>](part4.md)


## Security Information and Event Management (SIEM)
+ Host-centric log sources
    + Windows Event Logs
    + A user accessing a file
    + A user attempting to authenticate
    + Editing a registry key or valur
    + PowerShell execution
+ Network-centric Lod
    + SSH
    + FTP, Network file sharing activity
    + Web/VPN traffic

```ps1
 Get-WinEvent -FilterHashTable @{LogName='System';ID='104'}
```
