---
layout: default
title: AWS
parent: Checklists
---

# AWS Security Checklist for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to AWS for DevSecOps




### Enable multi-factor authentication (MFA)

```
aws cognito-idp set-user-mfa-preference
```


### Set a strong password policy

```
aws cognito-idp update-user-pool
```

### Enable advanced security features      

```
aws cognito-idp set-user-pool-policy
```


### Limit the number of devices a user can remember 

```
aws cognito-idp set-device-configuration
```

### Set a session timeout for your user pool    

```
aws cognito-idp update-user-pool-client
```

### Enable account recovery method 

```
aws cognito-idp set-account-recovery
```

### Monitor and log all sign-in and sign-out events 

```
aws cognito-idp create-user-pool-domain
```

### Restrict access to your user pool only from certain IP ranges

```
aws cognito-idp update-resource-server
```
