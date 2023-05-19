---
layout: default
title: Elasticsearch
parent: Checklists
---

# Elasticsearch Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Elasticsearch for DevSecOps


### Disable dynamic scripting and disable inline scripts	 


sudo nano /etc/elasticsearch/elasticsearch.yml<br> Set the following configurations:<br>script.inline: false<br>script.stored: false<br>script.engine: "groovy"



### Disable unused HTTP methods


`sudo nano /etc/elasticsearch/elasticsearch.yml` Add the following configuration:<br>`http.enabled: true`<br>`http.cors.allow-origin: "/.*/"``http.cors.enabled: true`<br>`http.cors.allow-methods: HEAD,GET,POST,PUT,DELETE,OPTIONS`<br>`http.cors.allow-headers: "X-Requested-With,Content-Type,Content-Length"`<br>`http.max_content_length: 100mb`



### Restrict access to Elasticsearch ports		

`sudo nano /etc/sysconfig/iptables`<br> Add the following rules to only allow incoming connections from trusted IP addresses:<br>`-A INPUT -p tcp -m tcp --dport 9200 -s 10.0.0.0/8 -j ACCEPT`<br>`-A INPUT -p tcp -m tcp --dport 9200 -s 192.168.0.0/16 -j ACCEPT`<br>`-A INPUT -p tcp -m tcp --dport 9200 -j DROP`<br>Restart the iptables service to apply changes.<br>`sudo service iptables restart`



### Use a reverse proxy to secure Elasticsearch	

Set up a reverse proxy (e.g. Nginx, Apache) in front of Elasticsearch and configure SSL/TLS encryption and authentication.

