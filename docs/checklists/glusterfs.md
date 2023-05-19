---
layout: default
title: GlusterFS
parent: Checklists
---

# GlusterFS Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden GlusterFS for DevSecOps


### Disable insecure management protocols		 


```
gluster volume set <volname> network.remote-dio.disable on
```


### Enable SSL encryption for management


```
gluster volume set <volname> network.remote.ssl-enabled on
```


### Limit access to trusted clients		


```
gluster volume set <volname> auth.allow <comma-separated list of trusted IPs>
```


### Enable client-side SSL encryption


```
gluster volume set <volname> client.ssl on
```

### Enable authentication for client connections	

```
gluster volume set <volname> client.auth on
```

### Set proper permissions for GlusterFS files and directories	

```
chown -R root:glusterfs /etc/glusterfs /var/lib/glusterd /var/log/glusterfs
```

### Disable root access to GlusterFS volumes	

```
gluster volume set <volname> auth.reject-unauthorized on
```

### Enable TLS encryption for GlusterFS traffic	

```
gluster volume set <volname> transport-type 
```


### Monitor GlusterFS logs for security events	

```
tail -f /var/log/glusterfs/glusterd.log
```