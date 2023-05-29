---
layout: default
title: Apache
parent: Checklists
---

# Apache Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Apache for DevSecOps


### Disable directory listing	 

```
Options -Indexes
```

### Enable server signature 

```
ServerSignature On
``` 

### Disable server signature 

```
ServerSignature Off
```

### Change server header 

```
ServerTokens Prod
```

### Disable server header 

`ServerTokens Prod` and `ServerSignature Off` 

### Enable HTTPS 

Install SSL certificate and configure Apache to use it 

### Disable HTTP TRACE method 

```
TraceEnable off
```

### Set secure HTTP response headers 

```
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options SAMEORIGIN
Header always set Content-Security-Policy "default-src 'self'"
```