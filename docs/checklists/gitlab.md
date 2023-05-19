---
layout: default
title: Gitlab
parent: Checklists
---

# Gitlab Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Gitlab for DevSecOps


### Update GitLab to the latest version	


```
sudo apt-get update && sudo apt-get upgrade gitlab-ee
```


### Enable SSL/TLS for GitLab	


Edit /etc/gitlab/gitlab.rb and add the following lines: <br>external_url 'https://gitlab.example.com'<br>nginx['redirect_http_to_https'] = true<br>nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"<br>nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"<br>gitlab_rails['gitlab_https'] = true<br>gitlab_rails['trusted_proxies'] = ['192.168.1.1'] (replace 192.168.1.1 with the IP address of your proxy) <br> Then run sudo gitlab-ctl reconfigure



### Disable GitLab sign up	

Edit /etc/gitlab/gitlab.rb and add the following line:<br>gitlab_rails['gitlab_signup_enabled'] = false <br> Then run sudo gitlab-ctl reconfigure



### Set a strong password policy


Edit /etc/gitlab/gitlab.rb and add the following lines: <br>gitlab_rails['password_minimum_length'] = 12<br>gitlab_rails['password_complexity'] = 2<br> Then run sudo gitlab-ctl reconfigure


### Limit the maximum file size

Edit /etc/gitlab/gitlab.rb and add the following line:<br>gitlab_rails['max_attachment_size'] = 10.megabytes <br> Then run sudo gitlab-ctl reconfigure


### Enable two-factor authentication (2FA)

Go to GitLab's web interface, click on your profile picture in the top-right corner, and select "Settings". Then select "Account" from the left-hand menu and follow the prompts to set up 2FA.



### Enable audit logging	

Edit /etc/gitlab/gitlab.rb and add the following line:<br>gitlab_rails['audit_events_enabled'] = true<br> Then run sudo gitlab-ctl reconfigure



### Configure GitLab backups		


Edit /etc/gitlab/gitlab.rb and add the following lines:<br>gitlab_rails['backup_keep_time'] = 604800<br>gitlab_rails['backup_archive_permissions'] = 0644<br>gitlab_rails['backup_pg_schema'] = 'public'<br>gitlab_rails['backup_path'] = "/var/opt/gitlab/backups"<br> Then run sudo gitlab-ctl reconfigure



### Restrict SSH access


Edit /etc/gitlab/gitlab.rb and add the following line:<br>gitlab_rails['gitlab_shell_ssh_port'] = 22<br> Then run sudo gitlab-ctl reconfigure


### Enable firewall rules


Configure your firewall to only allow incoming traffic on ports that are necessary for GitLab to function, such as 80, 443, and 22. Consult your firewall documentation for instructions on how to configure the firewall rules.

