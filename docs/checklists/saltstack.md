---
layout: default
title: SaltStack
parent: Checklists
---

# SaltStack Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden SaltStack for DevSecOps


### Generate SSL certificates for SaltStack communication

```
salt-call --local tls.create_self_signed_cert
```

### Enable SSL encryption for SaltStack communication by updating the Salt master configuration file

```
# /etc/salt/master
ssl_cert: /etc/pki/tls/certs/salt.crt
ssl_key: /etc/pki/tls/private/salt.key
``` 

### Disable unnecessary services and open ports	

Disable unused services and close unnecessary ports on Salt Master and Salt Minions


### Restrict network access	

Configure firewalls or network ACLs to allow access only from trusted sources


### Manage Salt Minion keys securely

Properly distribute, manage, and secure Salt Minion keys



### Implement strong authentication	

Utilize strong passwords or key-based authentication for Salt Master and Minion access


### Secure Salt Minions


- [x] Securely distribute and manage Salt Minion keys.
- [x] Disable unnecessary services and open ports on Salt Minions.
- [x] Restrict network access to Salt Minions using firewalls or network ACLs.
- [x] Enable authentication mechanisms, such as TLS/SSL, for secure communication.
- [x] Implement strong passwords or key-based authentication for Salt Minion access.
- [x] Regularly update Salt Minions to the latest stable version.
- [x] Enable logging on Salt Minions and monitor logs for security events.






