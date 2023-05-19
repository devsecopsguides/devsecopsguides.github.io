---
layout: default
title: Cloud Scanning
parent: Production
---

# Cloud Scanning
{: .no_toc }

Cloud scanning in production DevSecOps refers to the process of continuously scanning the production environment of an application deployed on cloud infrastructure for potential security vulnerabilities and threats. This is done to ensure that the application remains secure and compliant with security policies and standards even after it has been deployed to the cloud.

Cloud scanning tools can perform a variety of security scans on the production environment, including vulnerability scanning, penetration testing, and compliance auditing. These tools can help to identify security issues in real-time and provide alerts and notifications to the security team.

Some of the benefits of cloud scanning in production DevSecOps include:

1. Real-time security monitoring: Cloud scanning enables security teams to monitor the production environment in real-time, providing early detection and response to potential security threats.

2. Automated security checks: Cloud scanning tools can be integrated into the DevOps pipeline to perform automated security checks on the production environment, enabling teams to catch security issues early in the development cycle.

3. Improved compliance: Cloud scanning tools can help to ensure that the application remains compliant with industry standards and regulations by continuously monitoring the production environment for compliance violations.

4. Reduced risk: Cloud scanning can help to reduce the risk of security breaches and other security incidents by detecting and addressing potential vulnerabilities in the production environment.


## AWS Inspector	

A tool that analyzes the behavior and configuration of AWS resources for potential security issues.	

```
aws inspector start-assessment-run --assessment-template-arn arn:aws:inspector:us-west-2:123456789012:target/0-nvgHXqLm/template/0-iMhM7g4p
```


## Azure Security Center	

A tool that provides threat protection across all of your services and deploys quickly with no infrastructure to manage.	

```
az security assessment create --location westus --name "Example Assessment" --resource-group "MyResourceGroup" --scope /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM
```

## Google Cloud Security Scanner	


A tool that scans your App Engine app for common web vulnerabilities.	

```
gcloud beta app deploy --no-promote --version staging<br>gcloud beta app gen-config --custom<br>gcloud beta app deploy --config=cloudbuild.yaml --version=v1
```


## CloudPassage Halo	


A tool that provides visibility, security, and compliance across your entire cloud infrastructure.	


```
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST https://api.cloudpassage.com/v1/scans -d '{ "name": "Example Scan", "ip_address": "10.0.0.1", "port": 22, "option_profile": "pci"}'
```