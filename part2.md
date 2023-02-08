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
       + Enable and require TLS to keep LDAP queries and authentication secure which helps protect data in transit
       + Set password storage to use a secure method
       + Use password-based authentication:
          + LDAP v2 defines three types of authentication: anonymous, unauthenticated (clear-text password) and Kerberos v4
          + Unauthenticated sessions should be turned off
       + Replicate of LDAP servers to prvent DDoS attacked and other service outages
       + LDAP ACLs can limit which accounts or users can access objects in the directory
       + Secure LDAPS over TCP port 636
       + Kerberos _(unlike RADIUS and TACACS+)_ is designed to operate on untrusted networks and uses encryption to protect its authentication traffic
          + Administrator account attacks
          + Kerberos Ticket Reuse (impersonation)
          + Ticket-granting ticket focussed attacks
       + Active Directory Attacks:
         + Malware-focussed (crediential capturing, exploit-based on systems or AD servers)
         + Credential theft via phishing etc.
         + Privilege escalation
         + Forgotton service accounts
         + Administrator rights that exist for more users than necessary
       + LDAP Attacks:
          + Attacks against insecure binding connection medtahod that target unencrypted LDAP traffic
          + Improper LDAP access controls allow attackers to harvest directory information and/or make modifacations to directory entries
          + [LDAP Injection](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) is used to improperly filter user input via web applications to send arbitary LDAP queries
          + Denial-of-service (DoS) attacks which disrupt authentication services
   + **RADIUS**
       + Operates via UDP / TCP in a client-server model
          + UDP 1812, **authentication** and **authorization** port
          + UDP 1813, the **accouting** port
       + Sends passwords that are obfusicated by a shared secret and MD5 hash
       + Traffic between the network access server is usually encrypted using IPSec tunnels
       + RADIUS Attacks:
           + Session replay attack of server responses
           + Targeting RADIUS fixed shared secret that can be compromised at the client level
           + DoS attacks aimed to prevent users from authenticating
           + Credential-based attacks to brute-force the RADIUS shared secret
   + **TACACS+**
       + Cisco-designed
       + TCP traffic
       + Should be run in an isolated environment to protect it from attackers from it's encryption flaws
   + OAuth
       + Authorisation standard used by Google, Microsoft, Facebook via Access Tokens
       + Enables users to share identity and account information while authenticating via the original identity provider
       + Redirect exploits are a form of impersonation attack, allowing the attacker to pretend to be a legimate user
    + OpenID
       + Open-sourced standard for decenralised authentication
     + OpenID Connect
       + An authentication layer built using the OAuth protocol
- Multifactor authentication (MFA)
    + Something you know
    + Something you have
    + Something you are (biometric)
    + Somewhere you are (location)
- Single sign-on (SSO)
- Federation
   + Move beyond the trust boundaries of your organisation
   + Linking an identity and it's attributes between multiple identity management systems
   + Identity Providers (IDPs) integrate with Service Providers (SP) or the relying party
       + ADFS
       + SAML
          + XML-based
       + OAuth
       + OpenID Connect
- Role-based (RBAC)
   + Subjects can only use permission if they have a role
   + The subject's role must be authorised for them to have
   + Subjects can use permissions only if the subject's role is authorised to use it
   + **Privilege Creep** occurs when a user changes roles but their permissions are not updated with their new respnsibilities
- Attribute-based (ABAC)
   + Based on policies
- Mandatory (MAC)
   + Mandatory Access Control systems rely on the operating system to control what subjects can access and what action they can perforn
- Manual review
## Cloud access security broker (CASB)
+ Provide an additonal protection layer for accessing cloud-based applications
   + API-based CASB
   + Inline CASB solutions require either the **network configuration** or the use of a **software agent** to intercept requests from the users to the cloud provider to monitor and enforce policies
## Honeypot
+ Systems that are designed to look like an attractive target to an attacker
+ Honeynet detection systems that are placed in segments of unused network space will detect scans that **blindly traverse IP ranges**
## Monitoring and logging

## Encryption
+ Encryption at rest used at the host layer
+ Security keys and passwords must be secured
+ Hashing required to maintain integrity


## Certificate management
+ Keep private keys and passphases secure
+ Ensure that systems use and respect certificate revocations
+ Manage certificate lifecycles
+ Responses to events like compromised keys or changes in the certificate root vendors

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
    + Ensures no unexpected input is sent the webserver
    + Blocks the use of the apostrophe `'` that is needed to break out of the SQL query
    + `orange tiger pillow'; SELECT CustomerName, CreditCardNumber FROM Orders; --`
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
