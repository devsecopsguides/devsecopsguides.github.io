---
layout: default
title: Docker
parent: Rules
---

# Docker
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### Container runs as the root user

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
# Noncompliant code
FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    software-properties-common \
    python3 \
    python3-pip

COPY . /app
WORKDIR /app

RUN pip3 install -r requirements.txt

CMD ["python3", "app.py"]
```

In this noncompliant code, a Dockerfile is used to build a container image for a Python application. However, the image is based on the ubuntu:latest image, which includes unnecessary packages and potentially exposes security risks. Additionally, the container runs as the root user, which is considered a security concern.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
# Compliant code
FROM python:3.9-slim

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

CMD ["python", "app.py"]

```


In the compliant code, the Dockerfile is updated to use the python:3.9-slim base image, which is a lightweight and more secure image specifically designed for Python applications. This eliminates unnecessary packages and reduces the attack surface of the container.

Furthermore, the container runs with a non-root user by default, providing an added layer of security. The COPY, WORKDIR, and RUN instructions are updated accordingly to work within the new image.

By using a more secure base image and running the container with a non-root user, the compliant code reduces the risk of vulnerabilities and enhances the overall security of the Docker container.

It's important to regularly update the base image and dependencies in your Dockerfile to leverage the latest security patches. Additionally, consider implementing other best practices such as:

* Using multi-stage builds to minimize the size of the final image and exclude unnecessary build-time dependencies.
* Implementing container security scanning tools to identify and address vulnerabilities in the image.
* Restricting container privileges and capabilities to limit potential exploits.
* Employing secrets management techniques to securely handle sensitive data within the container.

By following secure coding practices and taking proactive measures to reduce the attack surface and address vulnerabilities, you can enhance the security and resilience of your Docker containers.
To address this issue, here's an example of compliant code:



