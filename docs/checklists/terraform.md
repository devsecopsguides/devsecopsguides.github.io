---
layout: default
title: Terraform
parent: Checklists
---

# Terraform Security Checklist for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to Terraform for DevSecOps




### Enable detailed audit logging

```
terraform apply -var 'logging=true'
```


### Encrypt state files   

```
terraform apply -var 'encrypt=true'
```

### Use a strong backend access policy      

```
terraform apply -backend-config="..."
```


### Limit the permissions of automation accounts 

```
terraform apply -var 'permissions=limited'
```

### Rotate secrets and access keys regularly    

```
terraform apply -var 'rotate_secrets=true'
```

### Use version constraints in configuration files 

```
terraform apply -var 'version=..."
```

### Validate configuration files before applying 

```
terraform validate
```

### Regularly update Terraform and providers

```
terraform init -upgrade
```
