---
layout: default
title: CouchDB
parent: Checklists
---

# CouchDB Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden CouchDB for DevSecOps


### Disable admin party	 


Edit the CouchDB configuration file `local.ini` located at `/opt/couchdb/etc/couchdb/`. Change the line `; [admins] to [admins]`, and add your admin username and password. Save and exit the file. Restart CouchDB. Example command: `sudo nano /opt/couchdb/etc/couchdb/local.ini`


### Restrict access to configuration files	

Change the owner and group of the CouchDB configuration directory `/opt/couchdb/etc/couchdb/` to the CouchDB user and group. Example command: `sudo chown -R couchdb:couchdb /opt/couchdb/etc/couchdb/`


### Use SSL/TLS encryption	

Create SSL/TLS certificates and configure CouchDB to use HTTPS. Example command for creating self-signed certificates: `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/couchdb.key -out /etc/ssl/certs/couchdb.crt`


### Limit access to ports	

Use a firewall to limit access to only the necessary ports. Example command using `ufw`: `sudo ufw allow from 192.168.1.0/24 to any port 5984`


### Update CouchDB regularly	

Install updates and security patches regularly to keep the system secure. Example command for updating packages: `sudo apt-get update && sudo apt-get upgrade`
