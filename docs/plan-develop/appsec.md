---
layout: default
title:  AppSec
parent: Plan & Develop
---

# AppSec
{: .no_toc }




Application security (AppSec) threats refer to the security risks and vulnerabilities that can be present in the software applications used by organizations. These threats can arise from various sources, such as software bugs, coding errors, design flaws, and inadequate security controls. AppSec threats can lead to data breaches, information theft, financial losses, reputational damage, and legal liabilities for organizations.

To address AppSec threats, various standards and frameworks have been developed. Here are some of the most important ones:

1. OWASP Top Ten: The Open Web Application Security Project (OWASP) Top Ten is a list of the most critical security risks to web applications. It is widely used by organizations as a guideline for identifying and addressing AppSec threats.

2. PCI DSS: The Payment Card Industry Data Security Standard (PCI DSS) is a set of security standards designed to protect credit card data. It requires merchants and service providers to implement various security controls to prevent unauthorized access to cardholder data.

3. ISO 27001: The International Organization for Standardization (ISO) 27001 is a standard for information security management systems. It provides a framework for implementing controls and processes to protect sensitive information, including software applications.

4. NIST Cybersecurity Framework: The National Institute of Standards and Technology (NIST) Cybersecurity Framework is a set of guidelines for managing and reducing cybersecurity risks. It provides a framework for organizations to identify, protect, detect, respond to, and recover from security incidents.

5. BSIMM: The Building Security In Maturity Model (BSIMM) is a software security framework that provides a measurement of an organization's software security program maturity. It identifies best practices and benchmarks for implementing a successful software security program.

6. CSA: The Cloud Security Alliance (CSA) provides guidance for secure cloud computing. Its Cloud Controls Matrix provides a framework for organizations to assess the security of cloud service providers.

7. CWE/SANS Top 25: A list of the top 25 most dangerous software errors, as identified by the Common Weakness Enumeration (CWE) and the SANS Institute.

8. NIST Cybersecurity Framework: A framework developed by the National Institute of Standards and Technology (NIST) to help organizations manage and reduce cybersecurity risk.


Cheatsheet with rules/policies for preventing OWASP Top 10 vulnerabilities


| Type    | Vulnerability   | Rule/Policy |
|:---------------|:---------------------|:---------------------|
| `A1: Injection` | 	SQL Injection	 | Use prepared statements and parameterized queries. Sanitize input and validate parameters. |
| `A1: Injection` | 	NoSQL Injection	 | Use parameterized queries with built-in protections. Sanitize input and validate parameters. |
| `A1: Injection` | 	LDAP Injection	 | Use parameterized queries and escape special characters. |
| `A1: Injection` | 	Command Injection	 | Use safe APIs or libraries that do not allow arbitrary command execution. Sanitize input and validate parameters. |
| `A2: Broken Authentication and Session Management` | 	Weak Passwords	 | Enforce strong password policies, including complexity requirements and regular password changes. Use multi-factor authentication. |
| `A2: Broken Authentication and Session Management` | 	Session Fixation	 | Regenerate session ID upon login and logout. Use secure cookies with HttpOnly and Secure flags. |
| `A3: Cross-Site Scripting (XSS)` | 	Reflected XSS	 | Sanitize all user input, especially from untrusted sources such as URLs, forms, and cookies. Use output encoding to prevent XSS attacks. |
| `A3: Cross-Site Scripting (XSS)` | 	Stored XSS	 | Filter user-generated content to prevent malicious scripts from being stored. Use output encoding to prevent XSS attacks. |
| `A4: Broken Access Control` | 	Insecure Direct Object Reference (IDOR)	 | Implement proper access controls and authorization checks to prevent direct object reference attacks. |
| `A5: Security Misconfiguration` | 	Improper Error Handling	 | Do not reveal sensitive information in error messages or logs. Use custom error pages. |
| `A6: Insecure Cryptographic Storage` | 	Weak Cryptography	 | Use strong, up-to-date encryption algorithms and keys. Implement proper key management and storage practices. |
| `A7: Insufficient Transport Layer Protection` | 	Unencrypted Communications	 | Use HTTPS with secure protocols and strong encryption. Disable insecure protocols such as SSLv2 and SSLv3. |
| `A8: Insecure Deserialization` | 	Insecure Deserialization	 | Validate and verify the integrity of serialized objects. Avoid accepting serialized objects from untrusted sources. |
| `A9: Using Components with Known Vulnerabilities` | 	Outdated Software	 | Keep all software and libraries up-to-date with the latest security patches. Monitor for vulnerabilities and apply patches as soon as possible. |
| `A10: Insufficient Logging and Monitoring` | 	Lack of Monitoring	 | Implement robust logging and monitoring practices to detect and respond to security events. Use SIEM tools and alerting systems. |


## DREAD:

![dread](../../../assets/images/dread.png)


* Damage potential: How much damage could be caused if the vulnerability is exploited?
* Reproducibility: How easy is it to reproduce the vulnerability?
* Exploitability: How easy is it to actually exploit the vulnerability?
* Affected users: How many users or systems are affected by the vulnerability?
* Discoverability: How easy is it for an attacker to discover the vulnerability?

By evaluating each of these factors, organizations can assign a score to a particular vulnerability and use that score to determine which vulnerabilities pose the greatest risk and should be addressed first.



## SDL (Security Development Lifecycle)

### Training:

* Core security training
* Requirements:
* Establish security requirements 
* Create quality gates/bug bars 
* Perform security and privacy risk assessments

### Design:

* Establish design requirements 
* Perform attack surface analysis reduction 
* Use threat modeling 

### Implementation:

* Use approved tools 
* Deprecate unsafe functions 
* Perform static analysis 

### Verification:

* Perform dynamic analysis 
* Perform fuzz testing 
* Conduct attack surface review

### Release:

* Create an incident response plan 
* Conduct final security review 
* Certify, release, and archive 

### Response:

1. Execute incident response plan 

## OWASP SAMM 

OWASP SAMM categorizes security practices into four key business 

### Governance:

* Strategy and metrics 
* Policy and compliance 
* Education and guidance 

### Construction:

* Threat assessment 
* Security requirements 
* Secure architecture 

### Verification:

* Design review 
* Implementation review 
* Security testing

### Operations:

* Issue management 
* Environment Hardening 
* Operational enablement
