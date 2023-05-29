---
layout: default
title:  Driver
parent: Plan & Develop
---

# Driver
{: .no_toc }



DevSecOps is a methodology that seeks to integrate security into the software development lifecycle, rather than treating it as a separate process that is bolted on at the end. The goal is to build secure, reliable software that meets the needs of the business, while also protecting sensitive data and critical infrastructure. There are several drivers and challenges associated with implementing DevSecOps, which are outlined below.

**Drivers:**

1. Security concerns: With the increasing frequency and severity of cyberattacks, security has become a top priority for organizations. DevSecOps provides a way to build security into the software development process, rather than relying on ad hoc security measures.

2. Compliance requirements: Many organizations are subject to regulatory requirements such as PCI-DSS, HIPAA, and GDPR. DevSecOps can help ensure compliance with these regulations by integrating security into the development process and providing visibility into the security posture of the application.

3. Agility and speed: DevSecOps can help organizations develop and deploy software more quickly and with greater agility. By integrating security into the development process, organizations can reduce the time and cost of remediation and avoid delays caused by security issues.

4. Collaboration: DevSecOps encourages collaboration between developers, security teams, and operations teams. By working together, these teams can build more secure and reliable software.

**Challenges:**

1. Cultural barriers: DevSecOps requires a cultural shift in the organization, with developers, security teams, and operations teams working together in a collaborative manner. This can be challenging, particularly in organizations with a siloed culture.

2. Lack of skills: DevSecOps requires a range of skills, including development, security, and operations. Finding individuals with these skills can be difficult, particularly in a competitive job market.

3. Tooling and automation: DevSecOps relies heavily on tooling and automation to integrate security into the development process. Implementing and maintaining these tools can be challenging, particularly for smaller organizations with limited resources.

4. Complexity: DevSecOps can be complex, particularly for organizations with large, complex applications. It can be difficult to integrate security into the development process without causing delays or creating additional complexity.


## Application Security Verification Standard (ASVS):

Authentication, Session Management, Access Control, Malicious Input handling, Output encoding/escaping, Cryptography, Error handling and logging , Data Protection, Communication Security, Http Security configuration, Security configuration, Malicious, Internal Security, Business logic, Files and resources, Mobile, Web services

### Design review 

* Security compliance checklist 
* Security requirement checklist (OWASP ASVS) 
* Top 10 security design issues 
* Security issues in the previous release 
* Customer or marketing feedback on security issues 


### Implementation review 

* Secure coding 
* Selection of reliable and secure third-party components 
* Secure configuration 


### Third-party components 

* A third-party software evaluation checklist: 
* Recommended third-party software and usage by projects: 
* CVE status of third-party components: 

### Code Review

* **Static Application Security Testing (SAST)** 

{: .highlight }
FindSecbugs, Fortify, Coverity, klocwork.

* **Dynamic Application Security Testing (DAST)**

{: .highlight }
OWASP ZAP, BurpSuite

* **Interactive Application Security Testing (IAST)** 

{: .highlight }
CheckMarks Varacode


* **Run-time Application Security Protection(RASP)** 

{: .highlight }
OpenRASP

* **SEI CERT Coding**

{: .highlight }
https://wiki.sei.cmu.edu/confluence/display/seccode/SEI+CERT+Coding+Standards

* **Software Assurance Marketplace (SWAMP)**

{: .highlight }
https://www.mir-swamp.org/

### Environment Hardening 

* Secure configuration baseline 
* Constant monitoring mechanism 

### Constant monitoring mechanism

* **Common vulnerabilities and exposures (CVEs)** 

{: .highlight }
OpenVAS, NMAP 

* **Integrity monitoring**

{: .highlight }
OSSEC

* **Secure configuration compliance**

{: .highlight }
OpenSCAP

* **Sensitive information exposure** 

{: .note }
No specific open source tool in this area. However, we may define specific regular expression patterns


## ENGAGE

https://engage.mitre.org/matrix/



## IACD


### Playbooks

Process Oriented

* Reflects organization's policies and procedures
* List activities that may require human interaction
* Organization-to-organization shareable



#### Playbooks

Process Oriented

* Reflects organization's policies and procedures
* List activities that may require human interaction
* Organization-to-organization shareable



#### Workflows

Technical Steps

* Focused on machine interaction
* Supports tailorable levels of automation
* Machine-to-machine shareable


#### Local Instance

Execution at the System Level

* Activity conducted is tailored to target system
* Describes specific decision logic and thresholds
* Machine-to-machine shareable in organization


### Example Playbook

To represent a general security process in a manner that:
1. Most organizations can associate with a process they are a
performing
2. Can be mapped to governance or regulatory
requirements (e.g., NIST 800-53)
3. Demonstrates a path to automation of the process over time
4. Identifies industry best practices for steps in the process

Playbook Content Types:

1. Initiating Condition
2. Process Steps
3. Best Practices and Local Policies
4. End State
5. Relationship to Governance or Regulatory Requirements



![IACD](../../../assets/images/iacd.png)


Steps to Build a Playbook:


1. Identify the initiating condition.

 Think About: What event or condition is going to start this playbook? This could be a time-based trigger,
the detection of an event, or the decision to act.

2. List all possible actions that could occur in response to this initiating condition.
 Think About: How could I respond to this condition? What steps would I take to mitigate this threat?
Don’t worry about order right now!

3. Iterate through the actions list from Step 2 and categorize the actions based on whether they are required
steps or whether they are optional.
 Think About: Is this step necessary to mitigate or investigate this event, or is it a best practice? Some
best practices have become standardized or widely implemented, while others may be considered extraneous.
It’s OK if it’s unclear whether some actions are required or optional; it’s up to you to categorize accordingly.

4. Use the required steps from Step 3 to build the playbook process steps diagram.
 Think About: Ordering. This is the time to think about the order in which you would perform these
actions.

5. Iterate through the optional actions and decide whether the actions can be grouped by activity or function.
For example: Monitoring, Enrichment, Response, Verification, or Mitigation.

6. Think About: Are there possible actions that can only take place in certain parts of the playbook?
This is how you would group the actions.

7. Modify the playbook process steps diagram from Step 4 to include the points where optional actions
would be selected.







