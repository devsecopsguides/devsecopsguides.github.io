---
layout: default
title: ArgoCD
parent: Checklists
---

# ArgoCD Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden ArgoCD for DevSecOps


### Disable anonymous access to the ArgoCD API server


```
argocd-server --disable-auth
```


### Enable HTTPS for ArgoCD server communication



```
argocd-server --tls-cert-file /path/to/tls.crt --tls-private-key-file /path/to/tls.key
```


### Use a strong password for ArgoCD administrative users


```
argocd-server --admin-password <password>
```


### Restrict access to ArgoCD API server by IP address	


Modify `argocd-server` configuration file to specify `--client-ca-file` and `--auth-mode cert` options and create a certificate authority file and client certificate signed by the CA for each client host.



### Enable RBAC for fine-grained access control to ArgoCD resources	

```
argocd-server --rbac-policy-file /path/to/rbac.yaml
```



### Set secure cookie options for ArgoCD web UI


```
argocd-server --secure-cookie
```




### Use least privilege principle for ArgoCD API access

Create a dedicated ArgoCD service account with minimal necessary permissions.



### Regularly update ArgoCD to latest stable version		


`argocd version --client` to check client version and `argocd version --server` to check server version. Use package manager or manual upgrade as needed.



### Regularly audit ArgoCD logs and access control		


`argocd-server --loglevel debug` to enable debug level logging. Use a log analyzer or SIEM tool to monitor logs for anomalies.



### Implement backup and recovery plan for ArgoCD data		


`argocd-util export /path/to/export` to export ArgoCD data and configuration. Store backups securely and test restoration procedure periodically.

