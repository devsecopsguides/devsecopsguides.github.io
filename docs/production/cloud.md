---
layout: default
title: Cloud
parent: Production
---

## Cloud Scanning
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


Cloud scanning in production DevSecOps refers to the process of continuously scanning the production environment of an application deployed on cloud infrastructure for potential security vulnerabilities and threats. This is done to ensure that the application remains secure and compliant with security policies and standards even after it has been deployed to the cloud.

Cloud scanning tools can perform a variety of security scans on the production environment, including vulnerability scanning, penetration testing, and compliance auditing. These tools can help to identify security issues in real-time and provide alerts and notifications to the security team.

Some of the benefits of cloud scanning in production DevSecOps include:

1. Real-time security monitoring: Cloud scanning enables security teams to monitor the production environment in real-time, providing early detection and response to potential security threats.

2. Automated security checks: Cloud scanning tools can be integrated into the DevOps pipeline to perform automated security checks on the production environment, enabling teams to catch security issues early in the development cycle.

3. Improved compliance: Cloud scanning tools can help to ensure that the application remains compliant with industry standards and regulations by continuously monitoring the production environment for compliance violations.

4. Reduced risk: Cloud scanning can help to reduce the risk of security breaches and other security incidents by detecting and addressing potential vulnerabilities in the production environment.




### CloudPassage Halo	


A tool that provides visibility, security, and compliance across your entire cloud infrastructure.	


```
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST https://api.cloudpassage.com/v1/scans -d '{ "name": "Example Scan", "ip_address": "10.0.0.1", "port": 22, "option_profile": "pci"}'
```



## Cloud Application

### AWS


- [ ] **Create an IAM User**	

```
aws iam create-user --user-name <username>
```

- [ ] Attach an IAM Policy to a User	

```
aws iam attach-user-policy --user-name <username> --policy-arn <policy-arn>
```

- [ ] Create an IAM Group	

```
aws iam create-group --group-name <group-name>
```

- [ ] Add a User to an IAM Group	

```
aws iam add-user-to-group --user-name <username> --group-name <group-name>
```

- [ ] Create an IAM Role	

```
aws iam create-role --role-name <role-name> --assume-role-policy-document <trust-policy>
```

- [ ] Attach an IAM Policy to a Role	

```
aws iam attach-role-policy --role-name <role-name> --policy-arn <policy-arn>
```

- [ ] Enable MFA for an IAM User	

```
aws iam enable-mfa-device --user-name <username> --serial-number <mfa-serial-number> --authentication-code-one <code1> --authentication-code-two <code2>
```

- [ ] Create a Security Group	

```
aws ec2 create-security-group --group-name <group-name> --description <description> --vpc-id <vpc-id>
```

- [ ] Authorize Ingress Traffic for a Security Group	

```
aws ec2 authorize-security-group-ingress --group-id <group-id> --protocol <protocol> --port <port> --source <source>
```

- [ ] Create a Network Access Control List (NACL)	

```
aws ec2 create-network-acl --vpc-id <vpc-id>
```

- [ ] Add an Inbound Rule to a NACL	

```
aws ec2 create-network-acl-entry --network-acl-id <nacl-id> --rule-number <rule-number> --protocol <protocol> --rule-action <action> --cidr-block <cidr-block> --port-range From=<from-port>,To=<to-port>
```

- [ ] Create an AWS WAF WebACL	

```
aws wafv2 create-web-acl --name <acl-name> --scope <scope> --default-action <default-action>
```

- [ ] Associate a WebACL with a Resource	

```
aws wafv2 associate-web-acl --web-acl-arn <acl-arn> --resource-arn <resource-arn>
```

- [ ] Enable AWS CloudTrail	

```
aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <bucket-name>
```

- [ ] Create an AWS Config Rule	

```
aws configservice put-config-rule --config-rule <rule-definition>
```

- [ ] Enable AWS GuardDuty	

```
aws guardduty create-detector --enable
```

- [ ] Enable AWS Macie	

```
aws macie2 enable-macie
```

- [ ] Enable AWS SecurityHub	

```
aws securityhub enable-security-hub
```


#### AWS Inspector	

A tool that analyzes the behavior and configuration of AWS resources for potential security issues.	

```
aws inspector start-assessment-run --assessment-template-arn arn:aws:inspector:us-west-2:123456789012:target/0-nvgHXqLm/template/0-iMhM7g4p
```





### GCloud

- [ ] Create a Service Account	

```
gcloud iam service-accounts create <service-account-name> --display-name <display-name>
```

- [ ] Grant IAM Role to a Service Account	

```
gcloud projects add-iam-policy-binding <project-id> --member serviceAccount:<service-account-email> --role <role>
```

- [ ] Create a Firewall Rule	

```
gcloud compute firewall-rules create <rule-name> --network <network-name> --allow <protocol>:<port-range> --source-ranges <source-range>
```

- [ ] Enable VPC Flow Logs	

```
gcloud compute networks subnets update <subnet-name> --region <region> --enable-flow-logs --filter <filter-expression>
```

- [ ] Create a Cloud Security Command Center (Cloud SCC) Notification Config	

```
gcloud scc notifications create <notification-config-id> --pubsub-topic <topic-name> --organization <organization-id> --filter <filter-expression>
```

- [ ] Enable Data Loss Prevention (DLP) API	

```
gcloud services enable dlp.googleapis.com
```

- [ ] Create a Cloud Security Scanner Scan	

```
gcloud beta web-security-scanner scans create <scan-id> --target <target-url>
```

- [ ] Enable Cloud Security Command Center (Cloud SCC)	

```
gcloud services enable securitycenter.googleapis.com
```

- [ ] Create a Security Key	

```
gcloud alpha cloud-shell ssh-key create
```

- [ ] Enable Cloud Armor	

```
gcloud compute security-policies create <policy-name> --description <description>
```

- [ ] Enable Cloud Identity-Aware Proxy (IAP)	

```
gcloud compute backend-services update <backend-service-name> --iap=enabled
```

- [ ] Create a Security Health Analytics Policy	

```
gcloud alpha security health-policies create <policy-name> --resource-type <resource-type> --filter <filter-expression>
```

- [ ] Enable Binary Authorization	

```
gcloud services enable binaryauthorization.googleapis.com
```

- [ ] Enable Cloud Security Scanner	

```
gcloud services enable securityscanner.googleapis.com
```


- [ ] Create a Cloud Key Management Service (KMS) Keyring	

```
gcloud kms keyrings create <keyring-name> --location <location>
```

- [ ] Create a Cloud Security Scanner Crawl Schedule	

```
gcloud beta web-security-scanner scan-configs create <config-id> --schedule <schedule-expression> --target <target-url>
```

- [ ] Enable Cloud Data Loss Prevention (DLP)	

```
gcloud services enable dlp.googleapis.com
```

- [ ] Create a Cloud Security Command Center (Cloud SCC) Source	

```
gcloud scc sources create <source-id> --source <source-type> --resource <resource-name> --service-account <service-account-email>
```



#### Google Cloud Security Scanner	


A tool that scans your App Engine app for common web vulnerabilities.	

```
gcloud beta app deploy --no-promote --version staging<br>gcloud beta app gen-config --custom<br>gcloud beta app deploy --config=cloudbuild.yaml --version=v1
```


### Azure

- [ ] Create a Resource Group	

```
az group create --name <resource-group-name> --location <location>
```

- [ ] Create a Virtual Network	

```
az network vnet create --name <vnet-name> --resource-group <resource-group-name> --subnet-name <subnet-name>
```

- [ ] Create a Network Security Group	

```
az network nsg create --name <nsg-name> --resource-group <resource-group-name>
```

- [ ] Create a Network Security Group Rule	

```
az network nsg rule create --name <rule-name> --nsg-name <nsg-name> --resource-group <resource-group-name> --priority <priority> --protocol <protocol> --source-address-prefix <source-address> --destination-address-prefix <destination-address> --access <access> --direction <direction>
```

- [ ] Create a Key Vault	

```
az keyvault create --name <vault-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Create a Key Vault Secret	

```
az keyvault secret set --name <secret-name> --vault-name <vault-name> --value <secret-value>
```

- [ ] Enable Azure Security Center	

```
az security center pricing create --tier <pricing-tier> --resource-group <resource-group-name> --subscription <subscription-id>
```

- [ ] Enable Just-In-Time (JIT) VM Access	

```
az security jit-policy create --name <policy-name> --resource-group <resource-group-name> --vm-name <vm-name>
```

- [ ] Enable Azure Firewall	

```
az network firewall create --name <firewall-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Create a Security Center Adaptive Application Control Policy	

```
az security applocker-policy create --name <policy-name> --resource-group <resource-group-name> --location <location>
```


- [ ] Enable Azure Active Directory (AAD) Identity Protection	

```
az ad identity-protection enable --tenant-id <tenant-id>
```

- [ ] Enable Azure Sentinel	

```
az security workspace create --name <workspace-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Create a Security Center Regulatory Compliance Assessment	

```
az security regulatory-compliance-assessments create --name <assessment-name> --resource-group <resource-group-name> --standard-name <standard-name>
```

- [ ] Enable Azure Advanced Threat Protection (ATP)	

```
az security atp storage enable --resource-group <resource-group-name> --storage-account <storage-account-name>
```

- [ ] Enable Azure DDoS Protection	

```
az network ddos-protection create --name <protection-plan-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Create a Security Center Security Contact	

```
az security contact create --name <contact-name> --resource-group <resource-group-name> --email <email-address>
```

- [ ] Enable Azure Information Protection	

```
az ad rms registration create --resource-group <resource-group-name> --tenant-id <tenant-id>
```

- [ ] Enable Azure Disk Encryption	

```
az vm encryption enable --name <vm-name> --resource-group <resource-group-name> --disk-encryption-keyvault <keyvault-name>
```

#### Azure Security Center	

A tool that provides threat protection across all of your services and deploys quickly with no infrastructure to manage.	

```
az security assessment create --location westus --name "Example Assessment" --resource-group "MyResourceGroup" --scope /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM
```
