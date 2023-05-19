---
layout: default
title: Nginx
parent: Checklists
---

# Nginx Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Nginx for DevSecOps


| ID    | Description   | Commands   | 
|:---------------|:---------------------|:---------------------|
| `1` | Disable server tokens	 | `server_tokens off;` |
| `2` | Set appropriate file permissions | `chmod 640 /etc/nginx/nginx.conf` or `chmod 440 /etc/nginx/nginx.conf` depending on your setup |
| `3` | Implement SSL/TLS with appropriate ciphers and protocols | `ssl_protocols TLSv1.2 TLSv1.3;` <br> `ssl_ciphers HIGH:!aNULL:!MD5;` |
| `4` | Enable HSTS | `add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";` |
| `5` | Set up HTTP/2 | `listen 443 ssl http2;` |
| `6` | Restrict access to certain directories | `location /private/ { deny all; }` |
| `7` | Disable unnecessary modules | Comment out or remove unused modules from `nginx.conf` file. |
| `8` | Implement rate limiting | `limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;	` |
| `9` | Implement buffer overflow protection | `proxy_buffer_size 128k;` <br> `proxy_buffers 4 256k;` <br> `proxy_busy_buffers_size 256k;` |
| `10` | Implement XSS protection | `add_header X-XSS-Protection "1; mode=block";` |
