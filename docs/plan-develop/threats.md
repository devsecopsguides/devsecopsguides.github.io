---
layout: default
title:  Threats
parent: Plan & Develop
---

# Threats
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Threat Modeling




Threat modeling is a process that helps identify and prioritize potential security threats to a system or application. The goal of threat modeling is to identify security risks early in the development process and proactively mitigate them, rather than waiting for vulnerabilities to be discovered after deployment.

![stride](../../../assets/images/stride.png)


One popular method for conducting threat modeling is called STRIDE, which stands for Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, and Elevation of privilege. These are the six types of security threats that can affect a system, and by considering each of them in turn, a threat model can help identify potential vulnerabilities and attacks.

The STRIDE methodology is often used in combination with a diagram designer tool, such as Microsoft's Threat Modeling Tool or the open-source OWASP Threat Dragon. These tools allow you to create a visual representation of the system or application you are analyzing, and to map out potential threats and attack vectors.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Explains the six types of security threats in the STRIDE methodology:


| STRIDE Threat    | Description   | 
|:---------------|:---------------------|
| `Spoofing` | Impersonating a user, device, or system in order to gain unauthorized access or perform malicious actions. Examples include phishing attacks or using a fake SSL certificate to intercept data.	 | 
| `Tampering` | Modifying data or code in transit or at rest, in order to introduce errors, gain unauthorized access, or perform other malicious actions. Examples include modifying the source code of an application or altering data in a database.	 | 
| `Repudiation` | Denying or disavowing actions or events, in order to evade accountability or responsibility. Examples include denying that an action was taken, or that data was accessed.	 | 
| `Information Disclosure` | Revealing confidential or sensitive information to unauthorized parties, whether intentionally or accidentally. Examples include disclosing passwords or user data, or exposing private keys.	 | 
| `Denial of Service` | Disrupting or degrading the availability or functionality of a system or application, through network attacks, resource exhaustion, or other means. Examples include Distributed Denial of Service (DDoS) attacks or flooding a server with requests.	 | 
| `Elevation of Privilege` | Gaining additional access or privileges beyond those that were initially granted, in order to perform unauthorized actions or escalate an attack. Examples include exploiting a software vulnerability to gain administrative access or using a social engineering technique to obtain sensitive information.	 | 


### Implementation

Step 1: Define the Scope

Identify the application or system within the DevSecOps pipeline that you want to perform threat modeling for. For example, let's consider a microservices-based application deployed using containerization and managed by Kubernetes.

Step 2: Gather Information

Gather information about the application's architecture, design, and deployment. This includes understanding the components, their interactions, data flows, and external dependencies.

Step 3: Identify Threats and Assets

Identify the critical assets and sensitive data involved in the application. Consider both internal and external threats that could compromise the security of these assets. For example:
Unauthorized access to customer data stored in a database
Injection attacks on APIs or containers
Misconfiguration of Kubernetes resources leading to unauthorized access or privilege escalation

Step 4: Assess Vulnerabilities and Risks

Evaluate the architecture and design to identify potential vulnerabilities and risks associated with the identified threats. Consider the security implications at each stage of the DevSecOps pipeline, including development, testing, deployment, and operations. For example:
Insecure container images containing known vulnerabilities
Lack of proper access controls on Kubernetes resources
Weak or outdated authentication mechanisms

Step 5: Prioritize and Mitigate Risks

Prioritize the risks based on their potential impact and likelihood of occurrence. Develop mitigation strategies and recommendations to address each identified risk. Consider integrating security controls and best practices into the DevSecOps pipeline. For example:
Implementing automated vulnerability scanning and patch management for container images
Applying secure configuration practices for Kubernetes resources
Enforcing strong authentication and access controls at all stages of the pipeline

Step 6: Continuously Monitor and Improve

Incorporate threat modeling as an iterative process within the DevSecOps lifecycle. Regularly review and update the threat model as the application evolves or new risks emerge. Continuously monitor the system for potential threats and vulnerabilities.

Real-case Example:

In a DevSecOps context, consider a scenario where a development team is building a cloud-native application using microservices architecture and deploying it on a container platform. The threat modeling process could involve identifying risks such as:

* Insecure container images with vulnerabilities
* Weak authentication and authorization mechanisms
* Inadequate logging and monitoring for containerized applications
* Misconfiguration of cloud resources and access controls
* Insecure communication between microservices
* Injection attacks on API endpoints

Based on the identified risks, mitigation strategies could include:

* Implementing automated vulnerability scanning and image hardening for containers
* Applying strong authentication and authorization mechanisms, such as OAuth or JWT tokens
* Incorporating centralized logging and monitoring solutions for containerized applications
* Establishing proper cloud resource management and access control policies
* Encrypting communication channels between microservices
* Implementing input validation and security controls to prevent injection attacks




### Threat Matrix


This matrix provides a starting point for identifying potential threats and corresponding mitigations based on different categories.



| Threat Category    | Threat Description    |  Potential Mitigation |
|:---------------|:---------------------|:---------------------|
| `Authentication` | Weak or stolen credentials	 | Implement strong password policies, multi-factor authentication, and password hashing algorithms. |
| `Authentication` | Insecure authentication protocols		 | Use secure authentication protocols (e.g., TLS) and avoid transmitting credentials in plaintext. |
| `Authorization` | Insufficient access controls	 | Implement RBAC (Role-Based Access Control) and apply the principle of least privilege. |
| `Authorization` | Improper privilege escalation	 | Limit privilege escalation capabilities and regularly review user permissions. |
| `Data Protection` | Data leakage or unauthorized access	 | Encrypt sensitive data at rest and in transit, and implement proper access controls. |
| `Data Protection` | Insecure data storage		 | Follow secure coding practices for data storage, including encryption and secure key management. |
| `Network Security` | Inadequate network segmentation	 | Implement proper network segmentation using firewalls or network policies. |
| `Network Security` | Man-in-the-Middle attacks	 | Use encryption and certificate-based authentication for secure communication. |
| `Denial-of-Service (DoS)` | Resource exhaustion	 | Implement rate limiting, request validation, and monitoring for abnormal behavior. |
| `Denial-of-Service (DoS)` | Distributed DoS (DDoS) attacks		 | Employ DDoS mitigation techniques, such as traffic filtering and load balancing. |
| `System Configuration` | Misconfigured security settings	 | Apply secure configuration guidelines for all system components. |
| `System Configuration` | Insecure default configurations	 | Change default settings and remove or disable unnecessary services. |
| `Vulnerability Management` | Delayed patching of software	 | Establish a vulnerability management program with regular patching and updates. |
| `Vulnerability Management` | Lack of vulnerability scanning	 | Conduct regular vulnerability scans and prioritize remediation. |
| `Insider Threats` | Malicious or negligent insiders	 | Implement proper access controls, monitoring, and employee training programs. |
| `Insider Threats` | Unauthorized data access or theft	 | Monitor and log user activities and implement data loss prevention mechanisms. |
| `Physical Security` | Unauthorized physical access	 | Secure physical access to data centers, server rooms, and hardware components. |
| `Physical Security` | Theft or destruction of hardware	 | Implement physical security controls, such as locks, surveillance systems, and backups. |
| `Third-Party Dependencies` | Vulnerabilities in third-party components	 | Perform due diligence on third-party components, apply patches, and monitor security advisories. |
| `Third-Party Dependencies` | Lack of oversight on third-party activities	 | Establish strong vendor management practices, including audits and security assessments. |




### Tools




| Threat Category    | Threat Description     |
|:---------------|:---------------------|
| `Microsoft Threat Modeling Tool` | A free tool from Microsoft that helps in creating threat models for software systems. It provides a structured approach to identify, analyze, and mitigate potential threats.	 | 
| `OWASP Threat Dragon` | An open-source threat modeling tool that enables the creation of threat models using the STRIDE methodology. It provides an intuitive interface and supports collaboration among team members.	 | 
| `PyTM` |An open-source threat modeling tool specifically designed for web applications. It allows the modeling of various aspects of an application's architecture and helps in identifying potential threats.	 |
| `ThreatModeler` | A commercial tool that offers a comprehensive platform for threat modeling. It provides a visual modeling interface, automated threat analysis, and integration with other security tools and frameworks.	 | 
| `IriusRisK` | A commercial tool that combines threat modeling with risk management. It supports multiple threat modeling methodologies, provides risk assessment capabilities, and offers integration with other tools and platforms.	 | 
| `TMT (Threat Modeling Tool)` | An open-source command-line tool developed by OWASP for threat modeling. It supports the STRIDE methodology and allows for the automation of threat modeling processes.	 | 
| `Secure Code Warrior` | While not a traditional threat modeling tool, it offers interactive training modules and challenges that can help developers understand and identify potential threats during the development process.	 | 


## Threats 

### Weak or stolen credentials

This code creates a threat model using PyTM and represents the "Weak or Stolen Credentials" threat scenario. It includes actors such as "Attacker" and "Insider," a server representing the application server, and a datastore representing the user's data.

The threat model defines the "Weak or Stolen Credentials" threat and includes attack paths such as "Password Guessing/Brute Force Attack," "Credential Theft," and "Insider Threat." It also defines the impact of these threats, such as unauthorized access to user data and data breaches.

The code generates a threat model diagram in PNG format, named "weak_or_stolen_credentials_threat_model.png."

```
from pytm import TM, Server, Datastore, Actor

# Create a new threat model
tm = TM("Weak or Stolen Credentials Threat Model")

# Create actors
attacker = Actor("Attacker")
insider = Actor("Insider")

# Create server and datastore
server = Server("Application Server")
datastore = Datastore("User Datastore")

# Define weak or stolen credentials threat
tm.add_threat()
tm.threat.name("Weak or Stolen Credentials")
tm.threat.description("Threat of weak or stolen user credentials")

# Define attack paths
tm.attack_path(attacker, server, "Password Guessing/Brute Force Attack")
tm.attack_path(attacker, server, "Credential Theft")
tm.attack_path(insider, server, "Insider Threat")

# Define impact
tm.data_flow(server, datastore, "Unauthorized Access to User Data")
tm.data_flow(server, datastore, "Data Breach and Exposure of Sensitive Information")

# Generate the threat model diagram
tm.generate_diagram("weak_or_stolen_credentials_threat_model.png")
```


### Insecure authentication protocols

This code creates a threat model using PyTM and represents the "Insecure Authentication Protocols" threat scenario. It includes actors such as "Attacker" and "User," a server representing the application server, and a datastore representing the user's data.

The threat model defines the "Insecure Authentication Protocols" threat and includes attack paths such as "Eavesdropping" and "Man-in-the-Middle Attack." It also defines the impact of these threats, such as unauthorized access to user data and data breaches.

The code generates a threat model diagram in PNG format, named "insecure_authentication_protocols_threat_model.png."

```
from pytm import TM, Server, Datastore, Actor

# Create a new threat model
tm = TM("Insecure Authentication Protocols Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create server and datastore
server = Server("Application Server")
datastore = Datastore("User Datastore")

# Define insecure authentication protocols threat
tm.add_threat()
tm.threat.name("Insecure Authentication Protocols")
tm.threat.description("Threat of using insecure authentication protocols")

# Define attack paths
tm.attack_path(attacker, server, "Eavesdropping")
tm.attack_path(attacker, server, "Man-in-the-Middle Attack")

# Define impact
tm.data_flow(server, datastore, "Unauthorized Access to User Data")
tm.data_flow(server, datastore, "Data Breach and Exposure of Sensitive Information")

# Generate the threat model diagram
tm.generate_diagram("insecure_authentication_protocols_threat_model.png")
```


### Insufficient access controls	

This code creates a threat model using PyTM and represents the "Insufficient Access Controls" threat scenario. It includes actors such as "Attacker" and "User," a server representing the application server, and a datastore representing the sensitive data.

The threat model defines the "Insufficient Access Controls" threat and includes attack paths such as "Unauthorized Access" by the attacker and "Privilege Escalation" by the user. It also defines the impact of these threats, such as unauthorized access to sensitive data and data leakage.

The code generates a threat model diagram in PNG format, named "insufficient_access_controls_threat_model.png."


```
from pytm import TM, Actor, Server, Datastore

# Create a new threat model
tm = TM("Insufficient Access Controls Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create server and datastore
server = Server("Application Server")
datastore = Datastore("Sensitive Datastore")

# Define insufficient access controls threat
tm.add_threat()
tm.threat.name("Insufficient Access Controls")
tm.threat.description("Threat of insufficient access controls on sensitive data")

# Define attack paths
tm.attack_path(attacker, server, "Unauthorized Access")
tm.attack_path(user, server, "Privilege Escalation")

# Define impact
tm.data_flow(server, datastore, "Unauthorized Access to Sensitive Data")
tm.data_flow(server, datastore, "Data Leakage")

# Generate the threat model diagram
tm.generate_diagram("insufficient_access_controls_threat_model.png")
```


### Improper privilege escalation	

This code creates a threat model using PyTM and represents the "Improper Privilege Escalation" threat scenario. It includes actors such as "Attacker" and "User" and a server representing the application server.

The threat model defines the "Improper Privilege Escalation" threat and includes attack paths such as "Exploiting Vulnerability" by the attacker and "Abusing User Privileges" by the user.

The code generates a threat model diagram in PNG format, named "improper_privilege_escalation_threat_model.png."



```
from pytm import TM, Actor, Server

# Create a new threat model
tm = TM("Improper Privilege Escalation Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create server
server = Server("Application Server")

# Define improper privilege escalation threat
tm.add_threat()
tm.threat.name("Improper Privilege Escalation")
tm.threat.description("Threat of improper privilege escalation in the application")

# Define attack paths
tm.attack_path(attacker, server, "Exploiting Vulnerability")
tm.attack_path(user, server, "Abusing User Privileges")

# Generate the threat model diagram
tm.generate_diagram("improper_privilege_escalation_threat_model.png")
```


### Data leakage or unauthorized access

This code creates a threat model using PyTM and represents the "Data Leakage or Unauthorized Access" threat scenario. It includes actors such as "Attacker" and "User" and a datastore representing sensitive data.

The threat model defines the "Data Leakage or Unauthorized Access" threat and includes attack paths such as "Exploiting Vulnerability" by the attacker and "Unauthorized Access" by the user.

The code generates a threat model diagram in PNG format, named "data_leakage_unauthorized_access_threat_model.png."

```
from pytm import TM, Actor, Datastore

# Create a new threat model
tm = TM("Data Leakage or Unauthorized Access Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create datastore
datastore = Datastore("Sensitive Data")

# Define data leakage or unauthorized access threat
tm.add_threat()
tm.threat.name("Data Leakage or Unauthorized Access")
tm.threat.description("Threat of unauthorized access or leakage of sensitive data")

# Define attack paths
tm.attack_path(attacker, datastore, "Exploiting Vulnerability")
tm.attack_path(user, datastore, "Unauthorized Access")

# Generate the threat model diagram
tm.generate_diagram("data_leakage_unauthorized_access_threat_model.png")
```




### Insecure data storage

This code creates a threat model using PyTM and represents the "Insecure Data Storage" threat scenario. It includes actors such as "Attacker" and "User" and a datastore representing sensitive data.

The threat model defines the "Insecure Data Storage" threat and includes attack paths such as "Exploiting Storage Vulnerability" by the attacker and "Unauthorized Access to Stored Data" by the user.

The code generates a threat model diagram in PNG format, named "insecure_data_storage_threat_model.png."

```
from pytm import TM, Actor, Datastore

# Create a new threat model
tm = TM("Insecure Data Storage Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create datastore
datastore = Datastore("Sensitive Data")

# Define insecure data storage threat
tm.add_threat()
tm.threat.name("Insecure Data Storage")
tm.threat.description("Threat of insecure storage of sensitive data")

# Define attack paths
tm.attack_path(attacker, datastore, "Exploiting Storage Vulnerability")
tm.attack_path(user, datastore, "Unauthorized Access to Stored Data")

# Generate the threat model diagram
tm.generate_diagram("insecure_data_storage_threat_model.png")
```


### Inadequate network segmentation

This code creates a threat model using PyTM and represents the "Inadequate Network Segmentation" threat scenario. It includes actors such as "Attacker," "Internal User," and "External User," and defines boundaries for the internal and external networks.

The threat model defines the "Inadequate Network Segmentation" threat and includes dataflows representing the flow of sensitive data, unauthorized access, exfiltration of sensitive data, and command and control.

The code generates a threat model diagram in PNG format, named "inadequate_network_segmentation_threat_model.png."


```
from pytm import TM, Actor, Dataflow, Boundary

# Create a new threat model
tm = TM("Inadequate Network Segmentation Threat Model")

# Create actors
attacker = Actor("Attacker")
internalUser = Actor("Internal User")
externalUser = Actor("External User")

# Create boundaries
internalNetwork = Boundary("Internal Network")
externalNetwork = Boundary("External Network")

# Define dataflows
dataflow1 = Dataflow(internalUser, internalNetwork, "Sensitive Data Flow")
dataflow2 = Dataflow(externalUser, internalNetwork, "Unauthorized Access")
dataflow3 = Dataflow(internalNetwork, externalNetwork, "Exfiltration of Sensitive Data")
dataflow4 = Dataflow(internalNetwork, externalNetwork, "Command and Control")

# Define inadequate network segmentation threat
tm.add_threat()
tm.threat.name("Inadequate Network Segmentation")
tm.threat.description("Threat of inadequate segmentation between internal and external networks")

# Define attack paths
tm.attack_path(attacker, dataflow2, "Exploiting Insufficient Segmentation")
tm.attack_path(attacker, dataflow3, "Exfiltration of Sensitive Data")
tm.attack_path(attacker, dataflow4, "Command and Control")

# Generate the threat model diagram
tm.generate_diagram("inadequate_network_segmentation_threat_model.png")
```


### Man-in-the-Middle attacks

This code creates a threat model using PyTM and represents the "Man-in-the-Middle (MitM) Attacks" threat scenario. It includes actors such as "Attacker," "Client," and "Server," and defines boundaries for the client and server components.

The threat model defines the "Man-in-the-Middle Attacks" threat and includes a dataflow representing the flow of sensitive data between the client and server.

The code generates a threat model diagram in PNG format, named "man_in_the_middle_attacks_threat_model.png."



```
from pytm import TM, Actor, Dataflow, Boundary

# Create a new threat model
tm = TM("Man-in-the-Middle Attacks Threat Model")

# Create actors
attacker = Actor("Attacker")
client = Actor("Client")
server = Actor("Server")

# Create boundaries
clientBoundary = Boundary("Client Boundary")
serverBoundary = Boundary("Server Boundary")

# Define dataflows
dataflow1 = Dataflow(client, server, "Sensitive Data Flow")

# Define Man-in-the-Middle attack threat
tm.add_threat()
tm.threat.name("Man-in-the-Middle (MitM) Attacks")
tm.threat.description("Threat of an attacker intercepting and tampering with communication between client and server")

# Define attack paths
tm.attack_path(attacker, dataflow1, "Intercepting and Tampering with Communication")

# Generate the threat model diagram
tm.generate_diagram("man_in_the_middle_attacks_threat_model.png")
```


### Resource exhaustion	

This code creates a threat model using PyTM and represents the "Resource Exhaustion" threat scenario. It includes actors such as "Attacker" and "Service" and defines a dataflow between them.

The threat model defines the "Resource Exhaustion" threat and includes an attack path representing the attacker's ability to consume excessive resources, leading to service availability impact.

The code generates a threat model diagram in PNG format, named "resource_exhaustion_threat_model.png."


```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Resource Exhaustion Threat Model")

# Create actors
attacker = Actor("Attacker")
service = Actor("Service")

# Define dataflows
dataflow = Dataflow(attacker, service, "Data Flow")

# Define Resource Exhaustion threat
tm.add_threat()
tm.threat.name("Resource Exhaustion")
tm.threat.description("Threat of an attacker consuming excessive resources and impacting service availability")

# Define attack paths
tm.attack_path(attacker, dataflow, "Excessive Resource Consumption")

# Generate the threat model diagram
tm.generate_diagram("resource_exhaustion_threat_model.png")
```


### Distributed DoS (DDoS) attacks

This code creates a threat model using PyTM and represents the "Distributed Denial of Service (DDoS) Attacks" threat scenario. It includes actors such as "Attacker" and "Target" and defines a dataflow between them.

The threat model defines the "DDoS Attacks" threat and includes an attack path representing the attacker overwhelming the target system with a high volume of requests, causing denial of service.

The code generates a threat model diagram in PNG format, named "ddos_attacks_threat_model.png."

```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("DDoS Attacks Threat Model")

# Create actors
attacker = Actor("Attacker")
target = Actor("Target")

# Define dataflows
dataflow = Dataflow(attacker, target, "Data Flow")

# Define DDoS Attacks threat
tm.add_threat()
tm.threat.name("DDoS Attacks")
tm.threat.description("Threat of an attacker overwhelming the target system with a high volume of requests, causing denial of service")

# Define attack paths
tm.attack_path(attacker, dataflow, "DDoS Attack")

# Generate the threat model diagram
tm.generate_diagram("ddos_attacks_threat_model.png")
```


### Misconfigured security settings

This code creates a threat model using PyTM and represents the "Misconfigured Security Settings" threat scenario. It includes actors such as "Administrator" and "Attacker" and defines a dataflow between them.

The threat model defines the "Misconfigured Security Settings" threat and describes the threat arising from misconfigured security settings, leading to vulnerabilities and potential unauthorized access.

The code generates a threat model diagram in PNG format, named "misconfigured_security_settings_threat_model.png."

```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Misconfigured Security Settings Threat Model")

# Create actors
administrator = Actor("Administrator")
attacker = Actor("Attacker")

# Define dataflows
dataflow = Dataflow(administrator, attacker, "Data Flow")

# Define Misconfigured Security Settings threat
tm.add_threat()
tm.threat.name("Misconfigured Security Settings")
tm.threat.description("Threat arising from misconfigured security settings, leading to vulnerabilities and potential unauthorized access")

# Define attack paths
tm.attack_path(administrator, dataflow, "Misconfiguration Attack")

# Generate the threat model diagram
tm.generate_diagram("misconfigured_security_settings_threat_model.png")
```


### Insecure default configurations

This code creates a threat model using PyTM and represents the "Insecure Default Configurations" threat scenario. It includes actors such as "Administrator" and "Attacker" and defines a dataflow between them.

The threat model defines the "Insecure Default Configurations" threat and describes the threat arising from insecure default configurations, leading to vulnerabilities and potential unauthorized access.

The code generates a threat model diagram in PNG format, named "insecure_default_configurations_threat_model.png."

```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Insecure Default Configurations Threat Model")

# Create actors
administrator = Actor("Administrator")
attacker = Actor("Attacker")

# Define dataflows
dataflow = Dataflow(administrator, attacker, "Data Flow")

# Define Insecure Default Configurations threat
tm.add_threat()
tm.threat.name("Insecure Default Configurations")
tm.threat.description("Threat arising from insecure default configurations, leading to vulnerabilities and potential unauthorized access")

# Define attack paths
tm.attack_path(administrator, dataflow, "Insecure Default Configurations Attack")

# Generate the threat model diagram
tm.generate_diagram("insecure_default_configurations_threat_model.png")
```


### Delayed patching of software

This code creates a threat model using PyTM and represents the "Delayed Patching of Software" threat scenario. It includes actors such as "Administrator" and "Attacker" and defines a dataflow between them.

The threat model defines the "Delayed Patching of Software" threat and describes the threat arising from delayed or inadequate software patching, leaving systems vulnerable to known exploits.

The code generates a threat model diagram in PNG format, named "delayed_patching_threat_model.png."


```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Delayed Patching of Software Threat Model")

# Create actors
administrator = Actor("Administrator")
attacker = Actor("Attacker")

# Define dataflows
dataflow = Dataflow(administrator, attacker, "Data Flow")

# Define Delayed Patching of Software threat
tm.add_threat()
tm.threat.name("Delayed Patching of Software")
tm.threat.description("Threat arising from delayed or inadequate software patching, leaving systems vulnerable to known exploits")

# Define attack paths
tm.attack_path(administrator, dataflow, "Delayed Patching of Software Attack")

# Generate the threat model diagram
tm.generate_diagram("delayed_patching_threat_model.png")
```


### Lack of vulnerability scanning

This code creates a threat model using PyTM and represents the "Lack of Vulnerability Scanning" threat scenario. It includes actors such as "Administrator" and "Attacker" and defines a dataflow between them.

The threat model defines the "Lack of Vulnerability Scanning" threat and describes the threat arising from the lack of regular vulnerability scanning, which can result in undetected vulnerabilities and potential exploitation.

The code generates a threat model diagram in PNG format, named "lack_of_vulnerability_scanning_threat_model.png."


```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Lack of Vulnerability Scanning Threat Model")

# Create actors
administrator = Actor("Administrator")
attacker = Actor("Attacker")

# Define dataflows
dataflow = Dataflow(administrator, attacker, "Data Flow")

# Define Lack of Vulnerability Scanning threat
tm.add_threat()
tm.threat.name("Lack of Vulnerability Scanning")
tm.threat.description("Threat arising from the lack of regular vulnerability scanning, which can result in undetected vulnerabilities and potential exploitation")

# Define attack paths
tm.attack_path(administrator, dataflow, "Lack of Vulnerability Scanning Attack")

# Generate the threat model diagram
tm.generate_diagram("lack_of_vulnerability_scanning_threat_model.png")
```



### Malicious or negligent insiders

This code creates a threat model using PyTM and represents the "Malicious or Negligent Insiders" threat scenario. It includes actors such as "Insider" and "Attacker" and defines a dataflow between them.

The threat model defines the "Malicious or Negligent Insiders" threat and describes the threat arising from insiders with malicious intent or negligent behavior who may abuse their privileges, steal sensitive data, or cause damage to the system.

The code generates a threat model diagram in PNG format, named "malicious_or_negligent_insiders_threat_model.png."

```
from pytm import TM, Actor, Dataflow

# Create a new threat model
tm = TM("Malicious or Negligent Insiders Threat Model")

# Create actors
insider = Actor("Insider")
attacker = Actor("Attacker")

# Define dataflows
dataflow = Dataflow(insider, attacker, "Data Flow")

# Define Malicious or Negligent Insiders threat
tm.add_threat()
tm.threat.name("Malicious or Negligent Insiders")
tm.threat.description("Threat arising from insiders with malicious intent or negligent behavior who may abuse their privileges, steal sensitive data, or cause damage to the system")

# Define attack paths
tm.attack_path(insider, dataflow, "Malicious or Negligent Insiders Attack")

# Generate the threat model diagram
tm.generate_diagram("malicious_or_negligent_insiders_threat_model.png")
```




### Unauthorized data access or theft

This code creates a threat model using PyTM and represents the "Unauthorized Data Access or Theft" threat scenario. It includes actors such as "Attacker" and "User" and defines a dataflow between the user and a sensitive datastore.

The threat model defines the "Unauthorized Data Access or Theft" threat and describes the threat of unauthorized access or theft of sensitive data by attackers.

The code generates a threat model diagram in PNG format, named "unauthorized_data_access_theft_threat_model.png."


```
from pytm import TM, Actor, Datastore, Boundary, Dataflow

# Create a new threat model
tm = TM("Unauthorized Data Access or Theft Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create a boundary
boundary = Boundary("Internal Network")

# Create a datastore
datastore = Datastore("Sensitive Data")

# Define dataflows
dataflow = Dataflow(user, datastore, "Data Access")

# Define Unauthorized Data Access or Theft threat
tm.add_threat()
tm.threat.name("Unauthorized Data Access or Theft")
tm.threat.description("Threat of unauthorized access or theft of sensitive data by attackers")

# Define attack paths
tm.attack_path(attacker, dataflow, "Unauthorized Data Access or Theft Attack")

# Generate the threat model diagram
tm.generate_diagram("unauthorized_data_access_theft_threat_model.png")
```




### Unauthorized physical access

This code creates a threat model using PyTM and represents the "Unauthorized Physical Access" threat scenario. It includes actors such as "Attacker," "Physical Attacker," and "User" and defines a dataflow between the user and a sensitive equipment datastore.

The threat model defines the "Unauthorized Physical Access" threat and describes the threat of unauthorized physical access to sensitive equipment by attackers.

The code generates a threat model diagram in PNG format, named "unauthorized_physical_access_threat_model.png."


```
from pytm import TM, Actor, Datastore, Boundary, Dataflow

# Create a new threat model
tm = TM("Unauthorized Physical Access Threat Model")

# Create actors
attacker = Actor("Attacker")
physical_attacker = Actor("Physical Attacker")
user = Actor("User")

# Create a boundary
boundary = Boundary("Physical Location")

# Create a datastore
datastore = Datastore("Sensitive Equipment")

# Define dataflows
dataflow = Dataflow(user, datastore, "Data Access")

# Define Unauthorized Physical Access threat
tm.add_threat()
tm.threat.name("Unauthorized Physical Access")
tm.threat.description("Threat of unauthorized physical access to sensitive equipment by attackers")

# Define attack paths
tm.attack_path(physical_attacker, dataflow, "Unauthorized Physical Access Attack")

# Generate the threat model diagram
tm.generate_diagram("unauthorized_physical_access_threat_model.png")
```




### Theft or destruction of hardware

This code creates a threat model using PyTM and represents the "Theft or Destruction of Hardware" threat scenario. It includes actors such as "Attacker," "Physical Attacker," and "User" and defines a dataflow between the user and a hardware datastore.

The threat model defines the "Theft or Destruction of Hardware" threat and describes the threat of theft or destruction of hardware by attackers.

The code generates a threat model diagram in PNG format, named "theft_destruction_hardware_threat_model.png."


```
from pytm import TM, Actor, Datastore, Boundary, Dataflow

# Create a new threat model
tm = TM("Theft or Destruction of Hardware Threat Model")

# Create actors
attacker = Actor("Attacker")
physical_attacker = Actor("Physical Attacker")
user = Actor("User")

# Create a boundary
boundary = Boundary("Physical Location")

# Create a datastore
datastore = Datastore("Hardware")

# Define dataflows
dataflow = Dataflow(user, datastore, "Data Access")

# Define Theft or Destruction of Hardware threat
tm.add_threat()
tm.threat.name("Theft or Destruction of Hardware")
tm.threat.description("Threat of theft or destruction of hardware by attackers")

# Define attack paths
tm.attack_path(physical_attacker, dataflow, "Theft or Destruction of Hardware Attack")

# Generate the threat model diagram
tm.generate_diagram("theft_destruction_hardware_threat_model.png")
```


### Vulnerabilities in third-party components

This code creates a threat model using PyTM and represents the "Vulnerabilities in Third-Party Components" threat scenario. It includes actors such as "Attacker" and "User" and defines a dataflow between the user and a sensitive data datastore.

The threat model defines the "Vulnerabilities in Third-Party Components" threat and describes the threat of vulnerabilities in third-party components used in the system.

The code generates a threat model diagram in PNG format, named "third_party_component_vulnerabilities_threat_model.png."

```
from pytm import TM, Actor, Datastore, Dataflow, Boundary

# Create a new threat model
tm = TM("Vulnerabilities in Third-Party Components Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")

# Create a boundary
boundary = Boundary("System Boundary")

# Create a datastore
datastore = Datastore("Sensitive Data")

# Define dataflows
dataflow = Dataflow(user, datastore, "Data Access")

# Define Vulnerabilities in Third-Party Components threat
tm.add_threat()
tm.threat.name("Vulnerabilities in Third-Party Components")
tm.threat.description("Threat of vulnerabilities in third-party components used in the system")

# Define attack paths
tm.attack_path(attacker, dataflow, "Exploitation of Third-Party Component Vulnerabilities")

# Generate the threat model diagram
tm.generate_diagram("third_party_component_vulnerabilities_threat_model.png")
```




### Lack of oversight on third-party activities

This code creates a threat model using PyTM and represents the "Lack of Oversight on Third-Party Activities" threat scenario. It includes actors such as "Attacker," "User," and "Third-Party" and defines dataflows between the user, third-party process, and a sensitive data datastore.

The threat model defines the "Lack of Oversight on Third-Party Activities" threat and describes the threat of insufficient oversight on third-party activities in the system.

The code generates a threat model diagram in PNG format, named "lack_of_oversight_third_party_activities_threat_model.png."



```
from pytm import TM, Actor, Process, Datastore, Dataflow, Boundary

# Create a new threat model
tm = TM("Lack of Oversight on Third-Party Activities Threat Model")

# Create actors
attacker = Actor("Attacker")
user = Actor("User")
third_party = Actor("Third-Party")

# Create a boundary
boundary = Boundary("System Boundary")

# Create a process
process = Process("Third-Party Process")

# Create a datastore
datastore = Datastore("Sensitive Data")

# Define dataflows
dataflow1 = Dataflow(user, process, "Data Sharing")
dataflow2 = Dataflow(process, datastore, "Data Storage")

# Define Lack of Oversight on Third-Party Activities threat
tm.add_threat()
tm.threat.name("Lack of Oversight on Third-Party Activities")
tm.threat.description("Threat of lack of oversight on third-party activities in the system")

# Define attack paths
tm.attack_path(attacker, dataflow1, "Unauthorized Data Sharing")
tm.attack_path(attacker, dataflow2, "Unauthorized Data Storage")

# Generate the threat model diagram
tm.generate_diagram("lack_of_oversight_third_party_activities_threat_model.png")
```




## Threat detection 


![stride](../../../assets/images/threats.png)


| Abnormal network traffic    | Potential threats    | 
|:---------------|:---------------------|
| `Port/host scan` | The port or host scan behaviors mean one of the hosts may have been infected by a malware program, and the malware program is looking for vulnerabilities, other services, or hosts on the network.	 | 
| `A high number of outbound DNS requests from the same host` | This is a symptom of Command and Control (C&C) malware, establishing communication between the infected host and the C&C server using the DNS protocol. 	 | 
| `A high number of outbound HTTP requests from the same host` | This is a symptom of C&C, establishing communication between the infected host and the C&C server using the HTTP protocol.	 | 
| `Periodical outbound traffic with samesized requests or during the same period of time every day ` | This is a symptom of C&C malware, establishing communication between the infected host and the C&C server.	 | 
| `Outbound traffic to an external web or DNS listed as a known threat by threat intelligence feeds` | The user may be tricked through social engineering to connect to an external known threat web or the C&C connection is successfully established. 	 | 

To visualize the network threat status, there are two recommended open source tools: Malcom and Maltrail (Malicious Traffic detection system). Malcom can present a host communication relationship diagram. It helps us to understand whether there are any internal hosts connected to an external suspicious C&C server or known bad sites
https://github.com/tomchop/malcom#what-is-malcom





## Indicators of compromises 

An analysis of hosts for suspicious behaviors also poses a significant challenge due to the availability of logs. For example, dynamic runtime information may not be logged in files and the original process used to drop a suspicious file may not be recorded. Therefore, it is always recommended to install a host IDS/IPS such as OSSEC (Open Source HIDS SEcurity) or host antivirus software as the first line of defense against malware. Once the host IDS/IPS or antivirus software is in place, threat intelligence and big data analysis are supplementary, helping us to understand the overall host's security posture and any known Indicators of Compromises (IoCs) in existing host environments.

Based on the level of severity, the following are key behaviors that may indicate a compromised host:


 
### External source client IP
The source of IP address analysis can help to identify the following: 
A known bad IP or TOR exit node 
Abnormal geolocation changes 
Concurrent connections from different geolocations 
The MaxMind GeoIP2 database can be used to translate the IP address to a geolocation: 
https://dev.maxmind.com/geoip/geoip2/geolite2/#Downloads

### Client fingerprint (OS, browser, user agent, devices, and so on)
The client fingerprint can be used to identify whether there are any unusual client or non-browser connections. The open source ClientJS is a pure JavaScript that can be used to collect client fingerprint information. The JA3 provided by Salesforce uses SSL/TLS connection profiling to identify malicious clients.
ClientJS: https://clientjs.org/
JA3: https://github.com/salesforce/ja3

### Web site reputation
When there is an outbound connection to an external website, we may check the threat reputation of that target website. This can be done by means of the web application firewall, or web gateway security solutions
https://www.virustotal.com/

### Random Domain Name by Domain Generation Algorithms (DGAs)
The domain name of the C&C server can be generated by DGAs. The key characteristics of the DGA domain are high entropy, high consonant count, and long length of a domain name. Based on these indicators, we may analyze whether the domain name is generated by DGAs and could be a potential C&C server. 
DGA Detector: https://github.com/exp0se/dga_detector/
In addition, in order to reduce false positives, we may also use Alexa's top one million sites as a website whitelist. Refer to https://s3.amazonaws.com/alexa-static/top-1m.csv.zip. 

### Suspicious file downloads
Cuckoo sandbox suspicious file analysis: 
https://cuckoosandbox.org/

### DNS query 
In the case of DNS query analysis, the following are the key indicators of compromises:
DNS query to unauthorized DNS servers. 
Unmatched DNS replies can be an indicator of DNS spoofing.
Clients connect to multiple DNS servers. 
A long DNS query, such as one in excess of 150 characters, which is an indicator of DNS tunneling. 
A domain name with high entropy. This is an indicator of DNS tunneling or a C&C server.




