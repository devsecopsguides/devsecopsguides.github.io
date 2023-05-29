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








## Container Escape Attack

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: privileged-container
    image: my-image
    securityContext:
      privileged: true
```

The noncompliant code sets the privileged flag to true, which allows the container to run with extended privileges, making it easier for an attacker to escape the container and gain access to the host.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  containers:
  - name: restricted-container
    image: my-image
    securityContext:
      privileged: false
```

The compliant code sets the privileged flag to false, which restricts the container from running with extended privileges, reducing the risk of container escape attacks.




## Kubernetes API Server Attack

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
apiVersion: v1
kind: ServiceAccount
metadata:
  name: privileged-service-account
  namespace: default
```

The noncompliant code creates a privileged service account without specifying any RBAC (Role-Based Access Control) restrictions, allowing the account to have wide-ranging access to the Kubernetes API server.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
apiVersion: v1
kind: ServiceAccount
metadata:
  name: restricted-service-account
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restricted-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: restricted-role-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: restricted-role
subjects:
- kind: ServiceAccount
  name: restricted-service-account
  namespace: default
```

The compliant code creates a restricted service account and applies RBAC rules to limit its access. In this example, the service account is only granted permissions to get, list, and watch pods, providing a more secure configuration.



## Pod-to-Pod Network Attack

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: unsecured-pod
spec:
  containers:
  - name: container-a
    image: image-a
  - name: container-b
    image: image-b
```

The noncompliant code deploys two containers within the same pod without any network policies or restrictions, allowing unrestricted communication between the containers.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
spec:
  containers:
  - name: container-a
    image: image-a
  - name: container-b
    image: image-b
  networkPolicy:
    podSelector:
      matchLabels:
        app: secured-pod
    ingress:
    - from:
        podSelector:
          matchLabels:
            app: secured-pod
```

The compliant code introduces network policies to restrict communication between the containers within the pod. In this example, both container-a and container-b are part of the secured-pod, and the network policy ensures that only pods labeled as secured-pod can initiate ingress traffic to this pod. This setup limits the attack surface and prevents unauthorized access or interception of network traffic from other pods.



## Privilege Escalation Attack

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: privileged-container
    image: my-image
    securityContext:
      runAsUser: 0
```

The noncompliant code sets the runAsUser field to 0, which runs the container as the root user, providing extensive privileges and increasing the risk of privilege escalation attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  containers:
  - name: restricted-container
    image: my-image
    securityContext:
      runAsUser: 1000
```

The compliant code sets the runAsUser field to a non-root user (e.g., UID 1000), reducing the container's privileges and mitigating the risk of privilege escalation attacks.


## Denial-of-Service (DoS) Attack

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
apiVersion: v1
kind: Deployment
metadata:
  name: resource-hungry-app
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: resource-hungry-container
        image: my-image
        resources:
          requests:
            cpu: "1000m"
            memory: "2Gi"
```

The noncompliant code specifies resource requests that are significantly higher than necessary, which can lead to resource exhaustion and potential DoS attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
apiVersion: v1
kind: Deployment
metadata:
  name: optimized-app
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: optimized-container
        image: my-image
        resources:
          requests:
            cpu: "100m"
            memory: "256Mi"
```

The compliant code sets resource requests to more appropriate values, ensuring that each container consumes only the necessary amount of CPU and memory resources, mitigating the risk of DoS attacks.
