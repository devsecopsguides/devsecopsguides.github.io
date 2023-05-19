---
layout: default
title: Jenkins
parent: Checklists
---

# Jenkins Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Jenkins for DevSecOps


### Enable security


Go to "Manage Jenkins" -> "Configure Global Security" and select "Enable security"



### Use secure connection	


Go to "Manage Jenkins" -> "Configure Global Security" and select "Require secure connections"



### Restrict project access	

Go to the project configuration -> "Configure" -> "Enable project-based security"



### Use plugins with caution


Install only necessary plugins from trusted sources and regularly update them


### Limit user permissions

Assign minimal necessary permissions to each user or group



### Use credentials securely

Store credentials in Jenkins credentials store and use them only where necessary





### Regularly update Jenkins	

Keep Jenkins updated with the latest security patches and updates



### Enable audit logging		


Enable audit logging to track and investigate security incidents



### Secure access to Jenkins server	


Limit access to Jenkins server by configuring firewall rules and setting up VPN access



### Use Jenkins agent securely	


Use secure connections between Jenkins master and agents and limit access to agents



### Use build tools securely	


Use secure and updated build tools and avoid using system tools or commands directly in build scripts



### Follow secure coding practices	


Follow secure coding practices to avoid introducing vulnerabilities in build scripts or plugins
