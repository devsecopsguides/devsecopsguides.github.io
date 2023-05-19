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


| ID    | Description   | Commands   | 
|:---------------|:---------------------|:---------------------|
| `1` | Disable directory listing	 | `Options -Indexes` |
| `2` | Enable server signature | `ServerSignature On` |
| `3` | Disable server signature | `ServerSignature Off` |
| `4` | Change server header | `ServerTokens Prod` |
| `5` | Disable server header | `ServerTokens Prod` and `ServerSignature Off` |
| `6` | Enable HTTPS | Install SSL certificate and configure Apache to use it |
| `7` | Disable HTTP TRACE method | `TraceEnable off` |
| `8` | Set secure HTTP response headers | `Header always set X-XSS-Protection "1; mode=block"<br>Header always set X-Content-Type-Options nosniff<br>Header always set X-Frame-Options SAMEORIGIN<br>Header always set Content-Security-Policy "default-src 'self'"` |