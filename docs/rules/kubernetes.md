---
layout: default
title: Kubernetes
parent: Rules
---

# Kubernetes
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Hardcoded Credential

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          value: "mysql://root:password@localhost:3306/my_database"
```

In this noncompliant code, the Kubernetes Deployment configuration file contains a hardcoded database connection string in the env section. The database URL, including the username (root), password (password), and other sensitive details, is directly embedded in the configuration file. This approach introduces security risks, as sensitive information is exposed and can be easily compromised if the configuration file is accessed by unauthorized users.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: my-app-secrets
              key: database-url
```


In the compliant code, the hardcoded database connection string is replaced with a reference to a Kubernetes Secret. The Secret, named my-app-secrets, contains the sensitive information such as the database URL, username, and password. The valueFrom field in the env section instructs Kubernetes to retrieve the value of the database-url key from the specified Secret.

By leveraging Secrets, you can centralize and securely manage sensitive information in Kubernetes, preventing hardcoded vulnerabilities. Secrets can be encrypted, access-controlled, and rotated more easily compared to hardcoded values.

Ensure that you follow secure practices for managing Secrets, such as granting appropriate permissions, encrypting Secrets at rest and in transit, regularly rotating Secrets, and utilizing Kubernetes RBAC (Role-Based Access Control) to control access to Secrets.

By using Secrets to store and retrieve sensitive information, you enhance the security, maintainability, and portability of your Kubernetes deployments.

