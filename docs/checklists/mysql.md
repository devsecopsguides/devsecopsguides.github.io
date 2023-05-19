---
layout: default
title: MySQL
parent: Checklists
---

# MySQL Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden MySQL for DevSecOps


### Remove test database and anonymous user	


```
mysql -u root -p -e "DROP DATABASE IF EXISTS test; DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); FLUSH PRIVILEGES;"
```


### Limit access to the root user	


```
mysql -u root -p -e "CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON *.* TO 'newuser'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"
```


### Enable the query cache	


```
mysql -u root -p -e "SET GLOBAL query_cache_size = 67108864; SET GLOBAL query_cache_type = ON;"
```


### Disable remote root login	


Edit `/etc/mysql/mysql.conf.d/mysqld.cnf` and set `bind-address` to the IP address of the MySQL server, then restart MySQL: `systemctl restart mysql`


### Enable SSL for secure connections		

Edit `/etc/mysql/mysql.conf.d/mysqld.cnf` and add the following lines: `ssl-ca=/etc/mysql/certs/ca-cert.pem` `ssl-cert=/etc/mysql/certs/server-cert.pem ssl-key=/etc/mysql/certs/server-key.pem` Then restart MySQL: `systemctl restart mysql`

