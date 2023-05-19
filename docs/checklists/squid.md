---
layout: default
title: Squid
parent: Checklists
---

# Squid Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Squid for DevSecOps


### Disable HTTP TRACE method	


```
acl HTTP-methods method TRACE<br>http_access deny HTTP-methods
```


### Limit maximum object size


```
maximum_object_size 1 MB
```


### Enable access logging


```
access_log /var/log/squid/access.log
```


### Limit client connections


`acl clients src 192.168.1.0/24`<br>`http_access allow clients`<br>`http_max_clients 50`



### Restrict allowed ports	


`acl Safe_ports port 80 443 8080`<br>`http_access deny !Safe_ports`
