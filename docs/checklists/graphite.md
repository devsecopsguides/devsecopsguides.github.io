---
layout: default
title: Graphite
parent: Checklists
---

# Graphite Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Graphite for DevSecOps


### Disable debug mode	 


```
sed -i 's/DEBUG = True/DEBUG = False/g' /opt/graphite/webapp/graphite/local_settings.py
```


### Set a strong secret key for Django	


```
sed -i "s/SECRET_KEY = 'UNSAFE_DEFAULT'/SECRET_KEY = 'your-strong-secret-key-here'/g" /opt/graphite/webapp/graphite/local_settings.py
```


### Enable HTTPS


```
Install a SSL certificate and configure NGINX to serve Graphite over HTTPS
```


### Restrict access to Graphite web interface


```
Configure NGINX to require authentication or restrict access to specific IP addresses
```

### Restrict access to Graphite API	

Configure NGINX to require authentication or restrict access to specific IP addresses


### Disable unused Graphite components		

Remove unused Carbon cache backends or Django apps to reduce attack surface


### Enable authentication for Graphite data ingestion	

Configure Carbon to require authentication for incoming data


### Enable Graphite logging	

Configure Graphite to log access and error messages for easier troubleshooting



### Monitor Graphite metrics

Use a monitoring tool like Prometheus or Nagios to monitor Graphite metrics and detect any anomalies





### Keep Graphite up-to-date

Regularly update Graphite and its dependencies to address any known security vulnerabilities






