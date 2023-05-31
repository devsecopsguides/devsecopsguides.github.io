---
layout: default
title: Threat Intelligence
parent: Production
---

# Threat Intelligence
{: .no_toc }

Threat intelligence is the process of gathering and analyzing information about potential and existing cybersecurity threats, such as malware, phishing attacks, and data breaches. The goal of threat intelligence is to provide organizations with actionable insights that can help them identify and mitigate potential security risks before they can cause harm.

In the context of DevSecOps, threat intelligence is an important component of a comprehensive security strategy. By gathering and analyzing information about potential security threats, organizations can better understand the security risks that they face and take steps to mitigate them. This can include implementing security controls and countermeasures, such as firewalls, intrusion detection systems, and security information and event management (SIEM) systems, to protect against known threats.

Threat intelligence can also be used to enhance other DevSecOps practices, such as vulnerability management and incident response. By identifying potential vulnerabilities and threats in real-time, security teams can take swift action to remediate issues and prevent security incidents from occurring.

Some of the key benefits of threat intelligence in DevSecOps include:

1. Improved threat detection: Threat intelligence provides organizations with the information they need to detect potential security threats before they can cause harm.

2. Better decision-making: By providing actionable insights, threat intelligence helps organizations make informed decisions about their security posture and response to potential threats.

3. Proactive threat mitigation: Threat intelligence enables organizations to take a proactive approach to threat mitigation, allowing them to stay ahead of emerging threats and reduce their risk of being compromised.

4. Enhanced incident response: Threat intelligence can be used to enhance incident response, allowing organizations to quickly and effectively respond to security incidents and minimize their impact.



## DevOps threat matrix

![Microsoft DevOps Threat](./assets/images/microsoft-devops-threat.png)

A DevOps Threat Matrix is a comprehensive framework or resource that identifies and categorizes potential security threats and risks associated with implementing DevOps practices. It aims to provide organizations with insights into the security challenges they may encounter while adopting a DevOps approach and offers guidance on mitigating these risks.

The Microsoft Security Blog, which you mentioned, likely provides detailed information on their DevOps Threat Matrix. It may cover different threat categories such as:

* Insider Threats: This includes potential risks arising from employees or individuals with authorized access to systems, data, or infrastructure.

* External Attacks: These are threats posed by external entities, such as hackers, who attempt to exploit vulnerabilities in the DevOps environment.

* Data Loss and Leakage: This category encompasses risks related to the unauthorized disclosure or loss of sensitive information during the DevOps pipeline.

* Supply Chain Attacks: These threats involve compromising the software supply chain, targeting third-party libraries, dependencies, or build processes.

* Infrastructure Vulnerabilities: This focuses on weaknesses within the infrastructure components of the DevOps environment, such as misconfigurations or insecure cloud services.

* Compliance and Regulatory Risks: DevOps practices need to align with industry standards and regulatory requirements. Failure to comply may lead to legal and financial consequences.

The DevOps Threat Matrix is likely to provide organizations with actionable recommendations, best practices, and security controls that can be implemented at various stages of the DevOps lifecycle. This could include secure coding practices, continuous monitoring, vulnerability scanning, access controls, and incident response procedures.


### Initial access

In the context of the DevOps Threat Matrix, "Initial Access" refers to a category of threats that focus on unauthorized entry points or mechanisms through which an attacker gains initial access to a system or network. It involves the exploitation of vulnerabilities or weaknesses in the DevOps infrastructure, applications, or processes to establish a foothold for further malicious activities.


#### SCM authentication

SCM authentication refers to the process of authenticating and accessing an organization's source code management (SCM) system. It typically involves using authentication methods such as personal access tokens (PATs), SSH keys, or other allowed credentials. However, attackers may attempt to exploit this authentication process, gaining unauthorized access to the SCM by employing techniques like phishing attacks. This can pose a significant threat to the organization's source code and sensitive information. To mitigate this risk, it's crucial to be aware of potential attacks and implement robust security measures.




#### CI/CD service authentication

CI/CD service authentication refers to the process of authenticating and accessing the Continuous Integration/Continuous Deployment (CI/CD) service used by an organization for automating software delivery pipelines. Attackers may attempt to exploit vulnerabilities in the authentication process to gain unauthorized access to the CI/CD service, which can lead to potential compromises in the organization's DevOps environment. To mitigate this risk, it is important to employ strong authentication methods and implement security measures to protect the CI/CD service from unauthorized access.





#### Organization’s public repositories


Access to an organization's public repositories with CI/CD capabilities can pose a security risk if not properly secured. Attackers may attempt to gain unauthorized access to these repositories and exploit their CI/CD capabilities to execute malicious code or disrupt the organization's pipelines. To mitigate this risk, organizations should implement strong access controls, monitor repository activity, and ensure secure CI/CD configurations.




#### Endpoint compromise


Endpoint compromise refers to a scenario where an attacker gains access to an organization's resources by compromising a developer's workstation or endpoint device. Once an endpoint is compromised, the attacker can leverage the compromised workstation to gain unauthorized access to the organization's source code management (SCM), registry, or other critical resources. To mitigate this risk, organizations should implement strong endpoint security measures and follow best practices for securing developer workstations.





#### Configured webhooks

Configured webhooks can become a potential security risk if not properly secured. Attackers can exploit these webhooks to gain initial access to an organization's network. By triggering requests through the source code management (SCM) system, attackers can potentially gain unauthorized access to services that should not be publicly exposed or might be running outdated and vulnerable software versions within the organization's private network. To mitigate this risk, organizations should implement secure webhook configurations, monitor webhook activity, and apply necessary access controls.






### Execution

The execution tactic in the DevOps Threat Matrix refers to the methods used by attackers to gain execution access on pipeline resources, including the pipeline itself or the deployment resources. Attackers may exploit vulnerabilities or employ various techniques to gain unauthorized control over these resources. Understanding these techniques and implementing appropriate security measures is crucial for mitigating the risk of unauthorized execution and maintaining the integrity of the DevOps pipeline.



#### Poisoned pipeline execution (PPE)

Poisoned pipeline execution (PPE) is a technique employed by attackers to inject malicious code into an organization's repository, allowing them to execute unauthorized actions within the repository's CI/CD system. This technique poses a significant threat as it can lead to the execution of malicious code during the CI/CD process, compromising the integrity of the pipeline and potentially allowing further unauthorized access. Understanding and mitigating the risks associated with poisoned pipeline execution is crucial to maintain the security of the CI/CD system.





##### Direct PPE (d-PPE)


Direct Poisoned Pipeline Execution (d-PPE) is a technique used by attackers to directly modify the configuration file inside a repository. By injecting malicious commands into the configuration file, the attacker can execute those commands during the pipeline run, potentially compromising the integrity of the pipeline and the associated resources. Mitigating the risk of d-PPE requires implementing secure practices, ensuring strict access controls, and performing thorough validation of configuration files.






##### Indirect PPE (i-PPE)


Indirect Poisoned Pipeline Execution (i-PPE) is a technique employed by attackers when they cannot directly modify configuration files or when these changes are not considered during pipeline execution. In such cases, attackers target scripts used by the pipeline, such as make-files, test scripts, build scripts, or other similar files, to inject malicious code. By infecting these scripts, the attacker can execute unauthorized code during the pipeline run, potentially compromising the pipeline and associated resources. To mitigate the risk of i-PPE, it is important to implement secure practices, conduct thorough code reviews, and ensure the integrity of pipeline scripts.




##### Public PPE


Public Poisoned Pipeline Execution (Public PPE) refers to scenarios where the pipeline is triggered by an open-source project. In such cases, attackers can exploit the pipeline by employing techniques like Direct Poisoned Pipeline Execution (d-PPE) or Indirect Poisoned Pipeline Execution (i-PPE) on the public repository. By infecting the pipeline in the open-source project, the attacker can execute unauthorized code during the pipeline run, potentially compromising the integrity of the pipeline and the resources it interacts with. To mitigate the risk of Public PPE, it is essential to implement secure practices, conduct thorough code reviews, and monitor the pipeline execution.





#### Dependency tampering


Dependency tampering is a technique used by attackers to execute malicious code in the DevOps or production environment by injecting harmful code into a repository's dependencies. When these dependencies are downloaded and integrated into the system, the malicious code gets executed, potentially leading to unauthorized access or compromising the integrity of the environment. Preventing and mitigating the risk of dependency tampering requires implementing secure practices, regularly auditing dependencies, and ensuring their integrity.






##### Public dependency confusion

Public dependency confusion is a technique employed by attackers where they publish malicious packages with the same name as private packages in public registries. When package-control mechanisms search for packages, they often prioritize public registries, making it possible for the malicious package to be downloaded instead of the intended private package. This technique can lead to the execution of malicious code in the DevOps environment or production environment. Preventing and mitigating the risk of public dependency confusion requires implementing secure practices, verifying package sources, and prioritizing trusted registries.




##### Public package hijack (“repo-jacking”)

Public package hijacking, also known as "repo-jacking," involves attackers gaining control of a public package by compromising the maintainer account. This technique can occur when attackers exploit vulnerabilities or weaknesses in the package maintainers' accounts, such as through the exploitation of GitHub's user rename feature. Once in control, attackers can modify the package's code, inject malicious code, or redirect users to malicious resources. Mitigating the risk of public package hijacking requires implementing security measures, regularly monitoring package repositories, and ensuring the integrity of maintainers' accounts.




##### Typosquatting

Typosquatting is a technique employed by attackers where they publish malicious packages with names similar to well-known public packages. By creating these deceptive package names, attackers aim to confuse users into inadvertently downloading the malicious packages instead of the intended ones. This technique can lead to the execution of unauthorized or malicious code in the DevOps environment or production environment. Preventing and mitigating the risk of typosquatting requires implementing secure practices, verifying package sources, and educating users about potential risks.





#### DevOps resources compromise


DevOps resources compromise refers to scenarios where attackers target the compute resources used for executing CI/CD agents and other software within the pipeline. By exploiting vulnerabilities in the operating system, agent code, or other software installed on the virtual machines (VMs) or network devices, attackers can gain unauthorized access to the pipeline. This compromise can lead to the execution of unauthorized code, data theft, or disruption of the CI/CD process. To mitigate the risk of DevOps resources compromise, it is crucial to implement security measures, regularly update and patch software, and monitor the infrastructure for suspicious activities.





#### Control of common registry


Control of a common registry refers to a situation where an attacker gains control over a registry used by the organization, allowing them to introduce and execute malicious images or packages within the CI/CD pipeline or production environment. This compromise can lead to the execution of unauthorized or malicious code, data breaches, or disruption of the CI/CD process. Protecting against the control of a common registry requires implementing robust security measures, controlling access to the registry, and monitoring for any suspicious or unauthorized activities.







### Persistence

The persistency tactic in the context of DevOps threat matrix refers to techniques employed by attackers to maintain access to a victim's environment even after initial compromise. These techniques allow attackers to persistently control and access the compromised systems, potentially leading to further unauthorized activities, data breaches, or system disruptions. Mitigating the risk of persistency requires implementing strong security practices, conducting regular system audits, and promptly addressing any identified vulnerabilities or unauthorized access.




#### Changes in repository

Changes in repository refer to techniques where adversaries exploit the automatic tokens within the CI/CD pipeline to access and push code changes to the repository. By leveraging these tokens, which often have sufficient permissions, attackers can achieve persistency within the environment. This persistence can enable unauthorized code modifications, data exfiltration, or further exploitation of the organization's systems. Preventing and mitigating the risk of changes in the repository requires implementing secure practices, controlling access to tokens, and monitoring repository activities for any suspicious or unauthorized changes.

* Change/add scripts in code – we can change some of the initialization scripts/add new scripts, so they download a backdoor/starter for the attacker, so each time the pipeline is executing these scripts, the attacker’s code will be executed too.

* Change the pipeline configuration – we can add new steps in the pipeline to download an attacker-controlled script to the pipeline before continuing with the build process.

* Change the configuration for dependencies locations – to use attacker-controlled packages.


##### Inject in Artifacts

Injecting code into artifacts involves exploiting the functionality of Continuous Integration (CI) environments that allow the creation and sharing of artifacts between pipeline executions. Attackers can manipulate these artifacts to inject malicious code or files, which can lead to unauthorized code execution or compromise of the CI/CD pipeline. Preventing and mitigating the risk of artifact injection requires implementing security measures, validating artifacts, and monitoring for any suspicious or unauthorized changes.






##### Modify images in registry


Modifying images in the registry refers to a technique where an attacker gains access to the image registry used by CI/CD pipelines and manipulates the images stored in the registry. By modifying or planting malicious images, the attacker can ensure that these images are executed by the user's containers, leading to the execution of unauthorized or malicious code within the production environment. Preventing and mitigating the risk of image modification in the registry requires implementing strong security measures, controlling access to the registry, and monitoring for any unauthorized changes.





##### Create service credentials

Creating service credentials in the context of DevOps refers to the process of generating and managing authentication credentials for services or applications used within the CI/CD pipeline or infrastructure. Service credentials provide secure access to various resources, such as cloud platforms, databases, or external APIs, and help establish trust and authorization between different components of the DevOps environment. Properly managing service credentials is crucial for maintaining the security and integrity of the DevOps pipeline and ensuring authorized access to sensitive resources.






### Privilege escalation

Privilege escalation techniques in the context of DevOps refer to the methods used by an attacker to elevate their privileges within a victim's environment. By gaining higher privileges, the attacker can access more sensitive resources, manipulate configurations, and potentially compromise the entire DevOps infrastructure. Understanding and mitigating privilege escalation risks is crucial to maintaining the security and integrity of the DevOps environment.




#### Secrets in private repositories

The presence of secrets in private repositories poses a significant security risk within the DevOps environment. Attackers who have gained initial access can leverage this access to scan private repositories in search of hidden secrets. Private repositories are typically considered more secure as they are inaccessible from outside the organization. However, if sensitive information such as API keys, passwords, or cryptographic keys are mistakenly committed or stored within these repositories, they can be exposed to unauthorized individuals. Detecting and mitigating the presence of secrets in private repositories is essential to maintain the confidentiality and integrity of the organization's assets.





##### Commit/push to protected branches


Committing or pushing code to protected branches in a repository can pose a significant security risk in the DevOps environment. If the pipeline has access to the repository and the repository's access controls are permissive, it may allow an attacker to bypass normal code review and approval processes and inject malicious code directly into important branches without the intervention of the development team. This can lead to unauthorized code execution, compromising the integrity and security of the application or system. Implementing proper access controls and review processes is crucial to mitigate the risk of unauthorized code changes in protected branches.






##### Certificates and identities from metadata services



In cloud-hosted pipelines, attackers may exploit the access they already have to the environment to gain unauthorized access to certificates and identities stored in metadata services. These services, often provided by cloud platforms, store sensitive information such as certificates, authentication tokens, and identity-related data. Extracting such information allows the attacker to assume the privileges associated with those certificates or identities, potentially compromising the security and confidentiality of the DevOps environment. Protecting and securing certificates and identities from metadata services is crucial to prevent unauthorized access and maintain the integrity of the system.






### Credential access

Credential access techniques refer to the methods used by attackers to steal credentials within the DevOps environment. By obtaining valid credentials, attackers can gain unauthorized access to critical systems, services, or resources. It is crucial to protect credentials and implement measures to prevent their unauthorized access or theft. Understanding and mitigating credential access risks is essential to maintain the security and integrity of the DevOps environment.




#### User credentials


User credentials are often required in CI pipelines to access external services such as databases, APIs, or other resources. However, if not properly secured, these credentials can become a target for attackers. They may try to gain access to the pipeline and extract the credentials to gain unauthorized access to external services. Protecting user credentials is crucial to prevent unauthorized access and maintain the security of the DevOps environment.





##### Service credentials

Service credentials, such as service principal names (SPN) and shared access signature (SAS) tokens, are commonly used in DevOps environments to authenticate and authorize access to various services and resources. However, if these credentials are compromised, an attacker can gain unauthorized access to other services directly from the pipeline. Protecting service credentials is essential to prevent unauthorized access and maintain the security of the DevOps environment.








### Lateral movement


The lateral movement tactic in CI/CD environments refers to the techniques used by attackers to move through different resources within the DevOps pipeline. Attackers aim to gain access to deployment resources, build artifacts, registries, or other targets to expand their reach and carry out malicious activities. Detecting and preventing lateral movement is crucial to maintain the security and integrity of the CI/CD environment.




#### Compromise build artifacts

Compromising build artifacts is a supply chain attack where an attacker gains control over the CI pipelines and manipulates the build artifacts. By injecting malicious code into the building materials before the build process is completed, the attacker can introduce malicious functionality into the final build artifacts. Protecting build artifacts is essential to prevent the deployment of compromised or malicious software.





##### Registry injection


Registry injection is a technique where an attacker infects the registry used for storing build artifacts in a CI/CD pipeline. By injecting malicious images into the registry, the attacker aims to have these images downloaded and executed by containers that rely on the infected registry. Preventing registry injection is crucial to ensure the integrity and security of the build artifacts used in the CI/CD process.






##### Spread to deployment resources


Spreading to deployment resources refers to the scenario where an attacker gains access to the deployment resources within a CI/CD pipeline. By leveraging the access granted to the pipeline, the attacker can propagate their presence to the deployment environment, leading to potential code execution, data exfiltration, and other malicious activities. Preventing the spread to deployment resources is crucial to maintain the security and integrity of the deployment environment.






### Defense evasion

Defense evasion techniques are employed by attackers to bypass or evade the security measures and defenses implemented in a DevOps environment. By evading detection and mitigation mechanisms, attackers can continue their attacks undetected and maintain persistence within the environment. Understanding and mitigating these evasion techniques is crucial to ensure the security and resilience of a DevOps environment.




#### Service logs manipulation

Service logs manipulation is a technique where an attacker, who has gained access to the environment, modifies the logs generated by various services. By tampering with the logs, the attacker aims to hide their activities and prevent defenders from detecting their presence or identifying the attacks they have executed. Detecting and preventing service logs manipulation is crucial for maintaining the integrity and reliability of log data for security analysis.





##### Compilation manipulation

Compilation manipulation is a technique used by attackers to inject malicious code into the compilation process, which can result in the inclusion of backdoors or vulnerabilities in the final software build. By tampering with the compilation process, the attacker aims to evade detection and introduce malicious functionality into the software without leaving obvious traces in the source code or version control system.







##### Reconfigure branch protections


Reconfiguring branch protections is a technique where an attacker with administrative permissions modifies the configuration settings of branch protection tools. By altering these settings, the attacker can bypass the controls and introduce code into a branch without the need for any user intervention or approval. This can enable the attacker to inject malicious code into the codebase and potentially compromise the integrity of the repository.






### Impact

The impact tactic refers to techniques used by attackers to exploit access to CI/CD resources for malicious purposes. Unlike other tactics, these techniques are not intended to be stealthy or covert, but rather to cause immediate and noticeable damage or disruption to the organization's CI/CD pipelines and resources. These techniques can have a significant impact on the availability, integrity, and confidentiality of the software development and deployment processes.




#### DDoS

DDoS (Distributed Denial of Service) is a type of attack where an adversary overwhelms a target system or network with a flood of traffic from multiple sources, causing service disruptions or outages. In a CI/CD environment, an attacker with access to compute resources can misuse them to launch DDoS attacks against external targets.




##### Cryptocurrency mining

Cryptocurrency mining is the process of using computational resources to solve complex mathematical problems and earn cryptocurrency rewards. In a compromised CI/CD environment, an attacker may utilize the compute resources for unauthorized cryptocurrency mining, consuming system resources and potentially causing performance degradation.


##### Local DoS

Local Denial of Service (DoS) attacks are performed by an attacker who has gained access to the CI pipelines. The attacker uses the pipelines to launch DoS attacks against the organization's own infrastructure or services, causing disruptions or overloading the virtual machines (VMs) used in the CI/CD environment.




##### Resource deletion

Resource deletion is a technique used by attackers who have gained access to CI/CD resources to cause denial of service by permanently deleting critical resources, such as cloud resources or repositories. By deleting these resources, the attacker disrupts the organization's operations and prevents normal functioning of the CI/CD environment.










### Exfiltration

The exfiltration tactic involves various techniques used by attackers to extract sensitive data from a victim's environment in a CI/CD context. These techniques aim to bypass security controls and transfer data outside the organization's network or infrastructure.




#### Clone private repositories

In this scenario, the attacker leverages their access to the CI pipelines to clone private repositories, giving them access to sensitive code and potentially valuable intellectual property. They exploit the permissions and tokens available within the CI environment, such as GITHUB_TOKEN in GitHub, to clone private repositories.




##### Pipeline logs


In this scenario, the attacker exploits their access to the CI/CD pipelines to access and view the pipeline execution logs. These logs often contain valuable information about the build process, deployment details, and potentially sensitive data such as credentials to services and user accounts.




##### Exfiltrate data from production resources


In this scenario, the attacker exploits their access to the CI/CD pipelines, which also have access to production resources. This allows the attacker to exfiltrate sensitive data from the production environment using the pipeline as a means of transportation.





## Threat Hunting


## Shodan

A search engine for internet-connected devices that allows you to identify potential attack surfaces and vulnerabilities in your network.	


```
shodan scan submit --filename scan.json "port:22"
```

## VirusTotal

A threat intelligence platform that allows you to analyze files and URLs for potential threats and malware.	

```
curl --request POST --url 'https://www.virustotal.com/api/v3/urls' --header 'x-apikey: YOUR_API_KEY' --header 'content-type: application/json' --data '{"url": "https://example.com"}'
```

## ThreatConnect

A threat intelligence platform that allows you to collect, analyze, and share threat intelligence with your team and community.	

```
curl -H "Content-Type: application/json" -X POST -d '{"name": "Example Threat Intel", "description": "This is an example threat intelligence report."}' https://api.threatconnect.com/api/v2/intelligence
```

## MISP

An open-source threat intelligence platform that allows you to collect, store, and share threat intelligence with your team and community.	

```
curl -X POST 'http://misp.local/events/restSearch' -H 'Authorization: YOUR_API_KEY' -H 'Content-Type: application/json' -d '{ "returnFormat": "json", "eventid": [1,2,3], "enforceWarninglist":0 }'
```