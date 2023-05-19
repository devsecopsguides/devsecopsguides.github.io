---
layout: default
title: Memcached
parent: Checklists
---

# Memcached Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Memcached for DevSecOps


### Disable UDP listener	


```
sed -i 's/^-U 0/#-U 0/g' /etc/sysconfig/memcached
```


### Enable SASL authentication



`sed -i 's/^#-S/-S/g' /etc/sysconfig/memcached`<br>`yum install cyrus-sasl-plain`<br>`htpasswd -c /etc/sasl2/memcached-sasldb username`<br>`chmod 600 /etc/sasl2/memcached-sasldb`



### Limit incoming traffic to known IP addresses


```
iptables -A INPUT -p tcp --dport 11211 -s 192.168.1.100 -j ACCEPT
```


### Limit maximum memory usage


```
echo 'CACHESIZE="128"' > /etc/sysconfig/memcached
```


### Run as non-root user	

```
sed -i 's/^-u root/-u memcached/g' /etc/sysconfig/memcached
```



### Enable logging	

`sed -i 's/^logfile/#logfile/g' /etc/sysconfig/memcached`<br>`mkdir /var/log/memcached`<br>`touch /var/log/memcached/memcached.log`<br>`chown memcached:memcached /var/log/memcached/memcached.log`<br>`sed -i 's/^#logfile/LOGFILE="\/var\/log\/memcached\/memcached.log"/g' /etc/sysconfig/memcached`





### Upgrade to the latest version	

```
yum update memcached
```




### Disable unused flags		


`sed -i 's/^-I 1m/#-I 1m/g' /etc/sysconfig/memcached`<br>`sed -i 's/^-a 0765/#-a 0765/g' /etc/sysconfig/memcached`




