<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)


### 👪 Active Directory

</div>

- - -
+ Ways to breach Active Directory:
   + NTLM Authenticated Services 
     + Password Spraying 
   + LDAP Bind Credentials
     + Hosting a Rogue LDAP Server
     + Capturing LDAP Credentials
   + Authentication Relays
     + [Responder](https://github.com/lgandx/Responder)
     + Poison authentication requests 
   + Microsoft Deployment Toolkit
     + PXE Boot Image Retrieval
   + Configuration Files

- - -

+ Step 1: Gain AD credientials
   + OSINT
   + Phishing
+ Step 2: Windows binary allows us to inject credentials legitimately into memory
   + `runas.exe /netonly /user:<domain>\<username> cmd.exe`
   + `/netonly`
      + Commands are executed locally on the computer will run in the context of your standard Windows account, not against the DC

### NTLM (New Technology LAN Manager) and NetNTLM
+ Security protocols used to authenticate users' identities in AD
  + Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal
  + Remote Desktop Protocol (RDP) service of a server being exposed to the internet
  + Exposed VPN endpoints that were integrated with AD
  + Web applications that are internet-facing and make use of NetNTLM
+ Kerberos authentication uses hostnames embedded in the tickets
   + `dir \\domain.local\SYSVOL`
+ If we provide the IP instead, we can force the authentication type to be NTLM
   + `dir \\<DC IP>\SYSVOL`

###  SYSVOL
+ Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory
