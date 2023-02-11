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
          + LDAP (TCP and UDP 389) v2 defines three types of authentication: anonymous, unauthenticated (clear-text password) and Kerberos v4
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
   + _Storing plaintext passwords is a bad idea!_
   + `bcrypt` is a strong passowrd-hashing algorithm that includes salts for stored values
   + `bcrypt` _(based on the Blowfish cipher)_ can mitigate a SQL injection vulnerability that lets an attacker dump password hashes
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
## Static analysis tools _(White-box testing)_
+ Tests the _source code_ for vulnerabilities by identifying common patterns
+ Language specific tools
## Dynamic analysis tools _(Black-box testing)_
+ Exploits a running application from the outside not dependent on the framework or progamming language used
+ Detects the vulnerabilities or threats that are too complex for a static code analyser like memory leaks, null pointer referencing and concurrency
## Formal methods for verification of critical software
+ Hash checking: `md5sum -c my_file.md5`
## Service-oriented architecture
- Security Assertions Markup Language (SAML)
   + An open standard that allows **Identity Providers** (IDP) to pass authorisation credentials to **Service Providers** (SP)
- Simple Object Access Protocol (SOAP)
   + A network protocol for exchaging structed data between nodes
   + XML-based on top of Applicaton Layer 7 protocols like HTTP, SMTP, IMAP and FTP
- Representational State Transfer (REST)
   + A standardised architectural style for stateless and cachable communictation between clients and servers
- Microservices

# 💻 Hardware assurance best practices
## Hardware root of trust
- Trusted platform module (TPM)
   + A microcontroller (chip) used to securley create, store and limit the use of cryprographic keys
   + Ensure platform integrity
- Hardware security module (HSM)
   + A physical computing device that protects digital key management and key exchange
   + Performs encryption operations for digital signitures and authentication
   + Cloud providers are making HSMs available _(Amazon's Cloud HSM, Azure's Dedicated HSM, Google's Cloud HSM)_ and provide the ability to host, manage and properly secure encryption keys
## eFuse (Electronic Fuse)
+ Change and modify functions or performance of a chip
+ Detect and react to irregular voltage and current influxes
## Unified Extensible Firmware Interface (UEFI)
+ Secure boot restricts the type of application that are used at boot to those who are signed
+ Digital signitues to validate authenticity, source and integrity of the code that is loaded
## Trusted foundry
+ Part of the Department of Defense's program that ensures all hardware components are trustworthy and have not been compromised by malicious actors
## Secure processing
- Trusted execution
- Secure enclave
   + CPU hardware-level isolation and memory encryption
   + Protects the data being processed by locked-down hardware in the CPU
   + Protects applications and data at runtime in an isolated memory environment
   + Can be used to run the appliation in a **Trusted Execution Environment** (TEE)
- Processor security extensions
- Atomic execution
## Anti-tamper
## Self-encrypting drive
## Trusted firmware updates
## Measured boot and attestation
+ Checks if the host machines are trustworthy before they're allowed to process data
   + Secure Boot and Secure Boot keys
      + The local system, which includes a TPM module, creates and signs a boot log to be validated by the remote server
   + Debug controls
   + Code integrity
## Bus encryption
+ Electronic systems that require high security
+ Encypted program instructions on a data bus that includes a _secure cryptoprocessor_
