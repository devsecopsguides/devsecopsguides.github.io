---
layout: default
title: Ceph
parent: Checklists
---

# Ceph Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Ceph for DevSecOps


| ID    | Description   | Commands   | 
|:---------------|:---------------------|:---------------------|
| `1` | Update Ceph to the latest version	 | `sudo apt-get update && sudo apt-get upgrade ceph -y` |
| `2` | Enable SSL/TLS encryption for Ceph traffic | `ceph config set global network.ssl true` |
| `3` | Set secure file permissions for Ceph configuration files | `sudo chmod 600 /etc/ceph/*` |
| `4` | Limit access to the Ceph dashboard | `sudo ufw allow 8443/tcp && sudo ufw allow 8003/tcp && sudo ufw allow 8080/tcp` |
| `5` | Configure Ceph to use firewall rules | `sudo ceph config set global security firewall iptables` |
| `6` | Implement network segmentation for Ceph nodes | `sudo iptables -A INPUT -s <trusted network> -j ACCEPT` |
| `7` | Configure Ceph to use encrypted OSDs | `sudo ceph-osd --mkfs --osd-uuid <osd-uuid> --cluster ceph --osd-data <path to data directory> --osd-journal <path to journal directory> --osd-encrypted` |
| `8` | Use SELinux or AppArmor to restrict Ceph processes | `sudo setenforce 1` (for SELinux) or `sudo aa-enforce /etc/apparmor.d/usr.bin.ceph-osd` (for AppArmor) |