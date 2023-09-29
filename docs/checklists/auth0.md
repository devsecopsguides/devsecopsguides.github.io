---
layout: default
title: auth0
parent: Checklists
---

# auth0 Security Checklist for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to auth0 for DevSecOps




### Enable Multi-Factor Authentication (MFA) 

```
auth0 rules create --name enable-mfa
```


### Set Strong Password Policies    

```
auth0 connections update
```

### Limit Number of Devices                

```
Use Auth0 Dashboard to set device limits
```


### Enable Anomaly Detection

```
auth0 anomaly enable
```

### Regularly Rotate Client Secrets 

```
auth0 clients rotate-secret
```

### Restrict Allowed Callback URLs

```
auth0 clients update --callbacks
```

### Enable Automated Log Monitoring and Alerts  

```
Use Auth0 Dashboard to configure alerts
```


### Use Role-Based Access Control (RBAC)  

```
auth0 roles create
```

