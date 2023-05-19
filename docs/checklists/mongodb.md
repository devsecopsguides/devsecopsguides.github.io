---
layout: default
title: MongoDB
parent: Checklists
---

# MongoDB Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden MongoDB for DevSecOps


### Disable HTTP interface


```
sed -i '/httpEnabled/ s/true/false/g' /etc/mongod.conf
```


### Enable authentication	


```
sed -i '/security:/a \ \ \ \ authorization: enabled' /etc/mongod.conf
```


### Set strong password for admin user	


```
mongo admin --eval "db.createUser({user: 'admin', pwd: 'new_password_here', roles: ['root']})"
```


### Disable unused network interfaces	


```
sed -i '/net:/a \ \ \ \ bindIp: 127.0.0.1' /etc/mongod.conf
```


### Enable access control		


```
sed -i '/security:/a \ \ \ \ authorization: enabled' /etc/mongod.conf
```

### Enable SSL/TLS encryption	

```
mongod --sslMode requireSSL --sslPEMKeyFile /path/to/ssl/key.pem --sslCAFile /path/to/ca/ca.pem --sslAllowInvalidHostnames
```

### Enable audit logging	

```
sed -i '/systemLog:/a \ \ \ \ destination: file\n\ \ \ \ path: /var/log/mongodb/audit.log\n\ \ \ \ logAppend: true\n\ \ \ \ auditLog:\n\ \ \ \ \ \ \ \ destination: file\n\ \ \ \ \ \ \ \ format: JSON' /etc/mongod.conf
```

### Set appropriate file permissions	

```
chown -R mongodb:mongodb /var/log/mongodb<br>chmod -R go-rwx /var/log/mongodb
```

### Disable unused MongoDB features	

```
sed -i '/operationProfiling:/a \ \ \ \ mode: off' /etc/mongod.conf<br>sed -i '/setParameter:/a \ \ \ \ quiet: true' /etc/mongod.conf
```


### Enable firewalls and limit access to MongoDB ports	

```
ufw allow from 192.168.1.0/24 to any port 27017 proto tcp<br>ufw enable
```