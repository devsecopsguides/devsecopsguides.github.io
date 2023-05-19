---
layout: default
title: Kuberneties
parent: Checklists
---

# Kuberneties Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Kuberneties for DevSecOps


### Restrict Kubernetes API access to specific IP ranges



`kubectl edit svc/kubernetes` <br> Update `spec.loadBalancerSourceRanges`



### Use Role-Based Access Control (RBAC)


```
kubectl create serviceaccount <name> <br> kubectl create clusterrolebinding <name> --clusterrole=<role> --serviceaccount=<namespace>:<name>
```


### Enable PodSecurityPolicy (PSP)	

```
kubectl create serviceaccount psp-sa <br> kubectl create clusterrolebinding psp-binding --clusterrole=psp:vmxnet3 --serviceaccount=default:psp-sa
```


### Use Network Policies


```
kubectl apply -f networkpolicy.yml
```

### Enable Audit Logging

```
kubectl apply -f audit-policy.yaml <br> kubectl edit cm/kube-apiserver -n kube-system <br> Update --audit-log-path and --audit-policy-file
```

### Use Secure Service Endpoints	


```
kubectl patch svc <svc-name> -p '{"spec": {"publishNotReadyAddresses": true, "sessionAffinity": "ClientIP"}}'
```


### Use Pod Security Context



`kubectl create sa pod-sa` <br> `kubectl create rolebinding pod-sa --role=psp:vmxnet3 --serviceaccount=default:pod-sa`



### Use Kubernetes Secrets	

```
kubectl create secret generic <name> --from-file=<path-to-file>
```



### Enable Container Runtime Protection	

```
kubectl apply -f falco.yaml
```



### Enable Admission Controllers	


`kubectl edit cm/kube-apiserver -n kube-system` <br> Update `--enable-admission-plugins`



