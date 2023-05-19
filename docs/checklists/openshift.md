---
layout: default
title: OpenShift
parent: Checklists
---

# OpenShift Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden OpenShift for DevSecOps


### Disable insecure protocols and ciphers	

```
oc adm policy reconcile-cluster-role-binding
```

Enable authentication and RBAC

```
oc adm policy add-cluster-role-to-user
```

Limit privileged access to the cluster	

```
oc adm policy add-scc-to-user
```

Enable audit logging	

```
oc adm audit
```

Enforce resource limits and quotas	


```
oc adm pod-network
```

Enable network policies for isolation	

```
oc create networkpolicy
```

Configure container runtime security	

```
oc adm policy add-scc-to-group
```

Secure etcd and master nodes	

```
oc adm manage-node
```

Regularly update and patch OpenShift components	

```
oc adm upgrade
```

Enable image signing and verification	

```
oc image sign
```

Use secure registry for image pull	

```
oc create secret
```

Enable encryption for data in transit	

```
oc adm router
```

Harden worker node security	

```
oc adm manage-node
```

Implement multi-factor authentication	

```
oc adm policy
```

Enable centralized logging and monitoring	

```
oc adm logs
```