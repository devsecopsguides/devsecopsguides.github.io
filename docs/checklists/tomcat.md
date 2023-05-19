---
layout: default
title: Tomcat
parent: Checklists
---

# Tomcat Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Tomcat for DevSecOps


### Disable unused connectors

 Modify `server.xml` to remove the connectors not in use, e.g.:

 ```
 <Connector port="8080" protocol="HTTP/1.1"
           connectionTimeout="20000"
           redirectPort="8443" />
 ```


### Use secure HTTPS configuration

Modify `server.xml` to enable HTTPS and configure SSL/TLS, e.g.:

```
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
           maxThreads="150" scheme="https" secure="true"
           clientAuth="false" sslProtocol="TLS" 
           keystoreFile="/path/to/keystore"
           keystorePass="password" />
```


### Disable version information in error pages

Modify `server.xml` to add the following attribute to the `<Host>` element:

```
errorReportValveClass="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"
```


### Use secure settings for Manager and Host Manager

Modify `tomcat-users.xml` to add roles and users with the appropriate permissions, e.g.:


```
<role rolename="manager-gui"/>
<user username="tomcat" password="password" roles="manager-gui"/>
```


### Use secure settings for access to directories

Modify `context.xml` to add the following element to the `<Context>` element:


```
<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1|192\.168\.0\.\d+"/>
```


