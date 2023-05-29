---
layout: default
title: Weblogic
parent: Checklists
---

# Weblogic Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Weblogic for DevSecOps


### Disable default accounts and passwords	  

```
wlst.sh $WL_HOME/common/tools/configureSecurity.py -removeDefaultConfig
``` 

### Use secure administration port 

```
wlst.sh $WL_HOME/common/tools/configureSecurity.py -securityModel=OPSS -defaultRealm -realmName=myrealm -adminPortEnabled=true -adminPort=9002 -sslEnabled=true -sslListenPort=9003
```

### Enable secure communications between servers 

```
wlst.sh $WL_HOME/common/tools/configureSSL.py -action=create -identity keystore.jks -identity_pwd keystorepassword -trust keystore.jks -trust_pwd keystorepassword -hostName myhost.example.com -sslEnabledProtocols TLSv1.2 -enabledProtocols TLSv1.2 -keystoreType JKS -server SSL
``` 

### Enable secure connections for JDBC data sources 

```
wlst.sh $WL_HOME/common/tools/config/jdbc/SecureJDBCDataSource.py -url jdbc:oracle:thin:@//mydb.example.com:1521/HR -name myDataSource -user myuser -password mypassword -target myServer -trustStore myTrustStore.jks -trustStorePassword myTrustStorePassword -identityStore myIdentityStore.jks -identityStorePassword myIdentityStorePassword
```

### Restrict access to WebLogic console 

Add `<security-constraint>` and `<login-config>` elements in `$DOMAIN_HOME/config/fmwconfig/system-jazn-data.xml` file 

### Enable Secure Sockets Layer (SSL) for Node Manager	 

```
wlst.sh $WL_HOME/common/tools/configureNodeManager.py -Dweblogic.management.server=http://myserver.example.com:7001 -Dweblogic.management.username=myusername -Dweblogic.management.password=mypassword -Dweblogic.NodeManager.sslEnabled=true -Dweblogic.NodeManager.sslHostnameVerificationIgnored=true -Dweblogic.NodeManager.KeyStores=CustomIdentityAndJavaTrust
```