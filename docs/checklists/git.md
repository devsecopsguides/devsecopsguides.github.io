---
layout: default
title: Git
parent: Checklists
---

# Git Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Git for DevSecOps


### Enable GPG signature verification		

```
git config --global commit.gpgsign true
```


### Set a strong passphrase for GPG key	


gpg --edit-key <KEY_ID> and then use the passwd command to set a strong passphrase


### Use HTTPS instead of SSH for remote repositories


```
git config --global url."https://".insteadOf git://
```


### Enable two-factor authentication	

Enable it through the Git service provider's website


### Set Git to ignore file mode changes


```
git config --global core.fileMode false
```

### Configure Git to use a credential helper

`git config --global credential.helper <helper>` where `<helper>` is the name of the credential helper (e.g., `manager`, `store`)


### Use signed commits

```
git commit -S
```
 or 

```
 git config --global commit.gpgsign true
```



### Set Git to automatically prune stale remote-tracking branches

```
git config --global fetch.prune true
```


### Set Git to always rebase instead of merge when pulling


```
git config --global pull.rebase true
```


### Use Git's `ignore` feature to exclude sensitive files	



Add files or file patterns to the `.gitignore` file







