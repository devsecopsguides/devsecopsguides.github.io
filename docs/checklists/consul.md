---
layout: default
title: Consul
parent: Checklists
---

# Consul Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Consul for DevSecOps


### Enable TLS encryption for Consul communication	


```
consul agent -config-dir=/etc/consul.d -encrypt=<encryption-key> -ca-file=/path/to/ca.crt -cert-file=/path/to/consul.crt -key-file=/path/to/consul.key
```


### Restrict access to Consul API



```
consul acl bootstrap; consul acl policy create -name "secure-policy" -rules @secure-policy.hcl; consul acl token create -description "secure-token" -policy-name "secure-policy" -secret <secure-token>
```


### Limit the resources allocated to Consul service	


`systemctl edit consul.service` and add `CPUQuota=50%` and `MemoryLimit=512M`


### Disable unnecessary HTTP APIs


```
consul agent -disable-http-apis=stats
```


### Enable and configure audit logging

```
consul agent -config-dir=/etc/consul.d -audit-log-path=/var/log/consul_audit.log
```



### Enable and configure health checks


```
consul agent -config-dir=/etc/consul.d -enable-script-checks=true -script-check-interval=10s -script-check-timeout=5s -script-check-id=<check-id> -script-check=<check-command>
```




### Enable rate limiting to prevent DDoS attacks	

```
consul rate-limiting enable; consul rate-limiting config set -max-burst 1000 -rate 100
```




### Set up backup and recovery procedures for Consul data		


```
consul snapshot save /path/to/snapshot; consul snapshot restore /path/to/snapshot
```



