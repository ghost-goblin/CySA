<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# 💾 Software and Systems Security
[<<<](part1.md) | [>>>](part3.md)

</div>

# 👮 Apply security solutions for infrastructure management
## Cloud vs. on-premises
## Asset management
- Asset tagging
  + Labeling or otherwise identifying systems, devices and other items
## Segmentation
- Physical
- Virtual
   + Virtual Desktop Infrastructure (VDI)
- Jumpbox
   + Can span 2 different security zones
   + Access into segmented networks from different security zones through a VPN
- System isolation
 - Air gap
   + Ensures that there is no connection at all between the infrastructures
## Network architecture
- Physical
- Software-defined
- Virtual private cloud (VPC)
- Virtual private network (VPN)
- Serverless
## Change management (CAB)
## Virtualization
- Virtual desktop infrastructure (VDI)
## Containerization
+ A technology that bundles together an application and their files, libraries and other dependencies, allowing the application to be deployed to multiple platforms or systems
## Identity and access management (IAM)
- Privilege management
   + Part of Authentication, Authorization and Accounting (AAA) framework
   + Identity and Access Management systems are built to create, store and manage permissions, groups and other information
   + Active Directory
       + Enabling and requiring TLS to keep LDAP queries and authentication secure which helps protect data in transit
       + Setting password storage to use a secure method
       + LDAP v2 defines three types of authentication: anonymous, simple (clear-text password) and Kerberos v4
       + LDAP ACLs can limit which accounts or users can access objects in the directory
       + Kerberos _(unlike RADIUS and TACACS+)_ is designed to operate on untrusted networks and uses encryption to protect its authentication traffic
           + [LDAP Injection](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) is used to improperly filter user input via web applications to send arbitary LDAP queries
   + **RADIUS**
   + **TACACS+**
       + TACACS+ should be run in an isolated environment to protect it from attackers
   + OAuth redirect exploits are a form of impersonation attack, allowing the attacker to pretend to be a legimate user
- Multifactor authentication (MFA)
- Single sign-on (SSO)
- Federation
   + Identity Providers (IDPs)
- Role-based (RBAC)
   + Subjects can only use permission if they have a role
   + The subject's role must be authorised for them to have
   + Subjects can use permissions only if the subject's role is authorised to use it
   + **Privilege Creep** occurs when a user changes roles but their permissions are not updated with their new respnsibilities
- Attribute-based (ABAC)
   + Based on policies
- Mandatory (MAC)
- Manual review
## Cloud access security broker (CASB)
+ Provide an additonal protection layer for accessing cloud-based applications
   + API-based CASB
   + Inline CASB solutions require either the **network configuration** or the use of a **software agent** to intercept requests from the users to the cloud provider to monitor and enforce policies
## Honeypot
## Monitoring and logging

## Encryption
+ Encryption at rest used at the host layer
+ Security keys and passwords must be secured
+ Hashing required to maintain integrity


## Certificate management

## Active defense



# 💾 Software assurance best practices
## Platforms
- Mobile
- Web application
- Client/server
- Embedded
- System-on-chip (SoC)
- Firmware
## Software development life cycle (SDLC) integration
## DevSecOps
## Software assessment methods
- User acceptance testing
- Stress test application
- Security regression testing
- Code review
## Secure coding best practices
- Input validation
- Output encoding
- Session management
- Authentication
- Data protection
- Parameterized queries
## Static analysis tools
## Dynamic analysis tools
## Formal methods for verification of critical software
## Service-oriented architecture
- Security Assertions Markup Language (SAML)
- Simple Object Access Protocol (SOAP)
- Representational State Transfer (REST)
- Microservices

# 💻 Hardware assurance best practices
## Hardware root of trust
- Trusted platform module (TPM)
- Hardware security module (HSM)
## eFuse
 + Firmware security
## Unified Extensible Firmware Interface (UEFI)
## Trusted foundry
## Secure processing
- Trusted execution
- Secure enclave
- Processor security extensions
- Atomic execution
## Anti-tamper
## Self-encrypting drive
## Trusted firmware updates
## Measured boot and attestation
## Bus encryption
