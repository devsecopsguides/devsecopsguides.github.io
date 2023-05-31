---
layout: default
title: etcd
parent: Checklists
---

# etcd Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden etcd for DevSecOps


### Enable authentication for etcd	 

```
etcd --auth-enable=true
```

### Configure TLS encryption for etcd communication	

```
etcd --cert-file=/path/to/cert.pem --key-file=/path/to/key.pem --client-cert-auth=true --trusted-ca-file=/path/to/ca.pem
``` 

### Enable etcd access control lists (ACLs)	


```
Enable etcd access control lists (ACLs)
```

### Limit network access to etcd ports	

```
iptables -A INPUT -p tcp --dport 2379 -j DROP
```
