---
layout: default
title: Methodology
parent: Plan & Develop
---

# Methodology
{: .no_toc }



DevSecOps methodology is an approach to software development that integrates security practices into the software development process from the beginning. The goal of DevSecOps is to make security an integral part of the software development process, rather than an afterthought.

Some common methodologies used in DevSecOps include:

1. Agile: Agile methodology focuses on iterative development and continuous delivery, with an emphasis on collaboration and communication between developers and other stakeholders. In DevSecOps, Agile is often used to facilitate a continuous feedback loop between developers and security teams, allowing security issues to be identified and addressed early in the development process.

2. Waterfall: Waterfall methodology is a traditional software development approach that involves a linear progression of steps, with each step building on the previous one. In DevSecOps, Waterfall can be used to ensure that security requirements are defined and addressed early in the development process, before moving on to later stages of development.

3. DevOps: DevOps methodology focuses on collaboration and automation between developers and IT operations teams. In DevSecOps, DevOps can be used to automate security testing and other security-related tasks, allowing security issues to be identified and addressed more quickly and efficiently.

4. Shift-Left: Shift-Left methodology involves moving security testing and other security-related tasks earlier in the development process, to catch and address security issues earlier. In DevSecOps, Shift-Left can be used to ensure that security is integrated into the development process from the very beginning.

5. Threat Modeling: Threat modeling is a methodology that involves identifying and analyzing potential threats to a software application, and then designing security controls to mitigate those threats. In DevSecOps, threat modeling can be used to identify and address potential security issues early in the development process, before they become more difficult and expensive to address.

These are just a few examples of the methodologies that can be used in DevSecOps. The key is to integrate security practices into the development process from the beginning, and to use a continuous feedback loop to identify and address security issues as early as possible.


## DoD

![DoD](../../../assets/images/dod-devsecops.png)


DoD Methodology in DevSecOps refers to the specific methodology and framework that the US Department of Defense (DoD) follows to implement DevSecOps practices in its software development lifecycle. The DoD has created its own set of guidelines and best practices for DevSecOps that align with its specific security requirements and regulations.

The DoD Methodology for DevSecOps is based on the following principles:

1. Continuous Integration/Continuous Delivery (CI/CD) pipeline: The CI/CD pipeline is an automated process for building, testing, and deploying software changes. The DoD Methodology emphasizes the importance of automating the pipeline to speed up the delivery process and ensure that all changes are tested thoroughly before they are deployed.

2. Security testing: The DoD Methodology requires that security testing is integrated throughout the entire software development lifecycle. This includes static code analysis, dynamic application security testing (DAST), and penetration testing.

3. Infrastructure as Code (IaC): The DoD Methodology promotes the use of IaC to automate the deployment and management of infrastructure. This approach ensures that infrastructure is consistent and repeatable, which helps to reduce the risk of misconfigurations and security vulnerabilities.

4. Risk management: The DoD Methodology requires that risk management is an integral part of the DevSecOps process. This involves identifying potential risks and vulnerabilities, prioritizing them based on their severity, and taking appropriate measures to mitigate them.

5. Collaboration: The DoD Methodology emphasizes the importance of collaboration between development, security, and operations teams. This includes regular communication, joint planning, and cross-functional training to ensure that all team members have a common understanding of the DevSecOps process.

Overall, the DoD Methodology for DevSecOps is designed to help the Department of Defense build secure, reliable, and resilient software systems that meet its unique security requirements and regulations.





## Microsoft


![Microsoft](../../../assets/images/microsoft-devsecops.png)


Microsoft has its own approach to DevSecOps, which is known as the Microsoft Secure Development Lifecycle (SDL). The SDL is a comprehensive methodology that integrates security practices and tools throughout the entire software development process, from planning and design to testing and release.

The key principles of the Microsoft SDL are:

1. Security by design: Security is considered from the beginning of the development process, and is integrated into the design of the application.

2. Continuous improvement: The SDL is an iterative process, with continuous improvement of security practices and tools based on feedback and lessons learned.

3. Risk management: Risks are identified and evaluated at each stage of the development process, and appropriate measures are taken to mitigate them.

4. Collaboration: Security is a shared responsibility, and collaboration between development, operations, and security teams is essential.

5. Automation: Automated tools and processes are used to ensure consistency and efficiency in security practices.

The Microsoft SDL includes specific practices and tools for each stage of the development process, such as threat modeling, code analysis, security testing, and incident response. Microsoft also provides guidance and training for developers, operations teams, and security professionals on how to implement the SDL in their organizations.




## Security guidelines and processes 

1- Security training:
Security awareness, Security certification program, Case study knowledge base, Top common issue, Penetration learning environment
OWASP top 10, CWE top 25, OWASP VWAD

2- Security maturity assessment
Microsoft SDL, OWASP SAMM self-assessment for maturity level
Microsoft SDL, OWASP SAMM

3- Secure design
Threat modeling templates (risks/mitigation knowledge base), Security requirements for release gate, Security design case study, Privacy protection 
OWASP ASVS, NIST, Privacy risk assessment

4- Secure coding
Coding guidelines (C++, Java, Python, PHP, Shell, Mobile), Secure coding scanning tools, Common secure coding case study 
CWE, Secure coding, CERT OWASP

5- Security testing
Secure compiling options such as Stack Canary, NX, Fortify Source, PIE, and RELRO, Security testing plans, Security testing cases, Known CVE testing, Known secure coding issues, API-level security testing tools, Automation testing tools, Fuzz testing, Mobile testing, Exploitation and penetration, Security compliance
Kali Linux tools, CIS

6- Secure deployment
Configuration checklist, Hardening guide, Communication ports/protocols, Code signing
CIS Benchmarks, CVE

7- Incident and vulnerability handling
Root cause analysis templates, Incident handling process and organization
NIST SP800-61

8- Security training
Security awareness by email, Case study newsletter, Toolkit usage hands-on training, Security certificate and exam 
NIST 800- 50, NIST 800- 16, SAFECode security engineering training



## Stage 1 – basic security control 

* Leverage third-party cloud service provider security mechanisms (for example, AWS provides IAM, KMS, security groups, WAF, Inspector, CloudWatch, and Config) 
* Secure configuration replies on external tools such as AWS Config and Inspector 
* Service or operation monitoring may apply to AWS Config, Inspector, CloudWatch, WAF, and AWS shield

Stage 2 – building a security testing team

Vulnerability assessment:
NMAP, OpenVAS

Static security analysis:
FindBugs for Java, Brakeman for Ruby on Rails, Infer for Java, C++, Objective C and C

Web security:
OWASP dependency check, OWASP ZAP, Archni-Scanner, Burp Suite, SQLMap, w3af

Communication:
Nmap, NCAT, Wireshark, SSLScan, sslyze

Infrastructure security:
OpenSCAP, InSpec

VM Toolset:
Pentest Box for Windows, Kali Linux, Mobile Security Testing Framework

Security monitoring:
ELK, MISP—Open source Threat Intelligence Platform, OSSCE—Open source HIDS Security, Facebook/osquery—performant endpoint visibility, AlienValut OSSIM—opensource SIEM

Stage 3 – SDL activities 

* Security shifts to the left and involves every stakeholder 
* Architect and design review is required to do threat modeling 
* Developers get secure design and secure coding training 
* Operation and development teams are as a closed-loop collaboration 
* Adoption of industry best practices such as OWASP SAMM and Microsoft SDL for security maturity assessment 

Stage 4 – self-build security services 

Take Salesforce as an example—the Salesforce Developer Center portal provides security training modules, coding, implementation guidelines, tools such as assessment tools, code scanning, testing or CAPTCHA modules, and also a developer forum. Whether you are building an application on top of salesforce or not, the Salesforce Developer Center is still a good reference not only for security knowledge but also for some open source tools you may consider applying.

Stage 5 – big data security analysis and automation

Key characteristics at this stage are: 

* Fully or mostly automated security testing through the whole development cycle
* Applying big data analysis and machine learning to identify abnormal behavior or unknown threats
* wProactive security action is taken automatically for security events, for example, the deployment of WAF rules or the deployment of a virtual patch

Typical open source technical components in big data analysis frameworks include the following:

* Flume, Log Logstash, and Rsyslog for log collection 
* Kafka, Storm, or Spark for log analysis 
* Redis, MySQL, HBase, and HDFS for data storage 
* Kibana, ElasticSearch, and Graylog for data indexing, searching, and presentation

The key stages in big data security analysis are explained in the table: 

Data collection:

Collects logs from various kinds of sources and systems such as firewalls, web services, Linux, networking gateways, endpoints, and so on. 

Data normalization:

Sanitizes or transforms data formats into JSON, especially, for critical information such as IP, hostname, email, port, and MAC.

Data enrich/label:

In terms of IP address data, it will further be associated with GeoIP and WhoIS information. Furthermore, it may also be labeled if it's a known black IP address. 

Correlation:

The correlation analyzes the relationship between some key characteristics such as IP, hostname, DNS domain, file hash, email address, and threat knowledge bases.

Storage:

There are different kinds of data that will be stored —the raw data from the source, the data with enriched information, the results of correlation, GeoIP mapping, and the threat knowledge base. 

Alerts:

Trigger alerts if threats were identified or based on specified alerting rules. 

Presentation/query:

Security dashboards for motoring and queries. ElasticSearch, RESTful API, or third-party SIEM.




## Role of a security team in an organization

1- Security office under a CTO 

![Security office under a CTO](../../../assets/images/model1.png)


* No dedicated Chief Security Officer (CSO) 
* The security team may not be big—for example, under 10 members 
* The security engineering team serves all projects based on their needs 
* The key responsibility of the security engineering team is to provide security guidelines, policies, checklists, templates, or training for all project teams
* It's possible the security engineering team members may be allocated to a different project to be subject matter experts based on the project's needs
* Security engineering provides the guidelines, toolkits, and training, but it's the project team that takes on the main responsibility for daily security activity execution




2-Dedicated security team  

![Dedicated security team](../../../assets/images/model2.png)


* **Security management:** The team defines the security guidelines, process, policies, templates, checklist, and requirements. The role of the security management team is the same as the one previously discussed in the Security office under a CTO section.
* **Security testing:** The team is performing in-house security testing before application release.
* **Security engineering:** The team provides a common security framework, architecture, SDK, and API for a development team to use
* **Security monitoring:** This is the security operation team, who monitor the security status for all online services.
* **Security services:** This is the team that develops security services such as WAF and intrusion deference services.



3- Security technical committee (taskforce)

![Security technical committee (taskforce)](../../../assets/images/model3.png)


The secure design taskforce will have a weekly meeting with all security representatives—from all project teams— and security experts from the security team to discuss the following topics (not an exhaustive list):

* Common secure design issues and mitigation (initiated by security team) 
* Secure design patterns for a project to follow (initiated by security team) 
* Secure design framework suggestions for projects (initiated by security team) 
Specific secure design issues raised by one project and looking for advice on other projects (initiated by project team)
* Secure design review assessment for one project (initiated by project team) 


