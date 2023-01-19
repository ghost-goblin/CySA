<div align='center'>

# 🛡️ Cybersecurity Analyst

### 🏠 [HOME](README.md)
### ✏️ Download the study guide [here](https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-002-exam-objectives-(6-0).pdf?sfvrsn=86668f47_2)

# 👻 Threat and Vulnerability Management
[<<<](part5.md) | [>>>](part2.md)

</div>

## Intelligence Sources
#### Security Intelligence
+ The process through which data is collected, processed, analyzed, and disseminated to provide insights into the security status of systems, i.e. firewall logs
#### Cyber Threat Intelligence
+ The process of investigating, collecting, analysing, and diseminating threat sources to provide data about the external threat landscape
  - Narrative report
  - Data Feeds
#### CISP (Cyber Security Information Sharing Partnership) | ISAC (Information Sharing & Analysis Center)
+ A not-for-profit group set  up to share sector specific threat intelligence and security best practices amongst its members
#### Open-Source Intelligence (OSINT)
+ Methods of obtaining information about a person or organisation  through public records, websites, and social media
#### Proprietary-source intelligence
+ Threat intelligence is very widely provided as a commercial service offering, access to research and updates is subject to a subscription fee
#### Closed-source intelligence
+ Honeynet data that is derived from the providers oen research and analysis efforts & anonymised information mined from its customers systems

1. **Timeliness**
2. **Relevancy**
3. **Accuracy**
4. **Confidence Levels**
    + Property of an intelligence source that ensures it produces qualified statements about reliability 


## Indicator management
1. Structured Threat Information eXpression (STIX)
   + XML for security
2. Trusted Automated eXchange of Indicator Information (TAXII)
3. OpenIoC

## Threat classification
+ Known threat vs. unknown threat
+ Zero-day
   + Usually applied to the vulnerbility itself but can also refer to an attack of malware that exploits it
+ **Advanced Persistent Threat** (APT)
   + An attackers ability to obtain, maintain and diversify access to network systems using exploits and malware
   + Target large **PII data sets**


## Threat actors
+ Nation-state
+ Hacktivist
+ Organized crime
+ Insider threat
   - Intentional
       - Sabotage
       - Financial Gain
       - Business Advantage
   - Unintentional
       - Phishing Attack
       - **Shadow IT**
 
## Intelligence Cycle
+ `Requirements` (Direction & Planning) > `Collection & Processing` > `Analysis` > `Dissemination` > `Feedback` >

## Information sharing and analysis communities
+ Healthcare
+ Financial
+ Aviation
+ Government
+ Critical infrastructure
  
- - -

## Attack Frameworks
+ [MITRE ATT&CK](https://attack.mitre.org/) Framework
  - A knowledge base maintained by the MITRE Corp. for listing and explaining specific adversary tactics, techniques, and common knowleadge or precedures 
+ The Diamond Model of Intrusion Analysis
+ Lockhead Martin **Kill Chain**
  1. `Reconnaissance`
      + The attacker determines what methods to use to complete the phases of the atttack
  2. `Weaponisation`
      + The payload code that exploit a vulnerability on the target system
  3. `Delivery` 
  4. `Exploitation`
  5. `Installation`
  6. `Command & Control` (C2)
  7. `Actions on Objectives`

## Threat Research
+ Indicator of Compromise
   + A residual sign that an asset or network has been successfully attacked or in being attacked
      - Unauthorised software and files
      - Suspicious emails
      - Suspicious registry and file system changes
      - Unknown port and protocol usage
      - Rogue hardware
      - Service disruption & disfacement
      - Suspicious or unauthorised acoount usage
