---
layout: default
title: Redis
parent: Checklists
---

# Redis Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Redis for DevSecOps


### Disable the CONFIG command


```
redis-cli config set config-command " "
```


### Disable the FLUSHDB and FLUSHALL commands


```
redis-cli config set stop-writes-on-bgsave-error yes
```


### Enable authentication


Set a password in the Redis configuration file (`redis.conf`) using the `requirepass` directive. Restart Redis service to apply changes.



### Bind Redis to a specific IP address	


Edit the `bind` directive in the Redis configuration file to specify a specific IP address.



### Enable SSL/TLS encryption	


Edit the `redis.conf` file to specify SSL/TLS options and certificate files. Restart Redis service to apply changes.


### Disable unused Redis modules	


Edit the `redis.conf` file to disable modules that are not needed. Use the `module-load` and `module-unload` directives to control modules.


### Set limits for memory and connections	

Edit the `maxmemory` and `maxclients` directives in the `redis.conf` file to set limits for Redis memory and connections.


### Monitor Redis logs

Regularly check Redis logs for suspicious activities and errors. Use a log analyzer tool to help detect anomalies.


### Regularly update Redis

Keep Redis up-to-date with the latest security patches and updates. Monitor vendor security advisories for any vulnerabilities that may affect Redis.
