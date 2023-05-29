---
layout: default
title: Container Attacks
parent: Attacks
---

# Container Attacks
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


## Insecure Container Images: 

Using container images that contain vulnerable or outdated software components, which can be exploited by attackers. Example: A container image that includes a vulnerable version of a web server software.

### Malicious Images via Aqua

* docker-network-bridge-
* ipv6:0.0.2
* docker-network-bridge-
* ipv6:0.0.1
* docker-network-ipv6:0.0.12
* ubuntu:latest
* ubuntu:latest
* ubuntu:18.04
* busybox:latest
* alpine: latest
* alpine-curl
* xmrig:latest
* alpine: 3.13
* dockgeddon: latest
* tornadorangepwn:latest
* jaganod: latest
* redis: latest
* gin: latest (built on host)
* dockgeddon:latest
* fcminer: latest
* debian:latest
* borg:latest
* docked:latestk8s.gcr.io/pause:0.8
* dockgeddon:latest
* stage2: latest
* dockerlan:latest
* wayren:latest
* basicxmr:latest
* simpledockerxmr:latest
* wscopescan:latest
* small: latest
* app:latest
* Monero-miner: latest
* utnubu:latest
* vbuntu:latest
* swarm-agents:latest
* scope: 1.13.2
* apache:latest
* kimura: 1.0
* xmrig: latest
* sandeep078: latest
* tntbbo:latest
* kuben2


### Other Images

* OfficialImagee
* Ubuntuu
* Cent0S
* Alp1ne
* Pythoon




## Privileged Container

Running containers with elevated privileges, allowing potential attackers to gain control over the underlying host system. Example: Running a container with root-level access and unrestricted capabilities.

In the noncompliant code, the container is launched with the --privileged flag, enabling privileged mode. This grants the container unrestricted access to the host system, potentially compromising its security boundaries.



```
# Noncompliant: Privileged container

FROM ubuntu
...
# Running container in privileged mode
RUN docker run -it --privileged ubuntu /bin/bash
```

The compliant code addresses the vulnerability by running the container without privileged mode. This restricts the container's access to system resources and reduces the risk of privilege escalation and unauthorized access to the host.




```
# Compliant: Non-privileged container

FROM ubuntu
...
# Running container without privileged mode
RUN docker run -it ubuntu /bin/bash
```

## Exposed Container APIs 

Insecurely exposing container APIs without proper authentication or access controls, allowing attackers to manipulate or extract sensitive information from containers. Example: Exposing Docker API without any authentication or encryption.

In the noncompliant code, the container's API is exposed on port 8080 without any authentication or authorization mechanisms in place. This allows unrestricted access to the container API, making it susceptible to unauthorized access and potential attacks.



```
# Noncompliant: Exposed container API without authentication/authorization

FROM nginx
...
# Expose container API on port 8080
EXPOSE 8080
```

The compliant code addresses the vulnerability by exposing the container's API internally on port 8080 and leveraging a reverse proxy or API gateway for authentication and authorization. The reverse proxy or API gateway acts as a security layer, handling authentication/authorization requests before forwarding them to the container API.

To further enhance the security of exposed container APIs, consider the following best practices:

1. Implement strong authentication and authorization mechanisms: Use industry-standard authentication protocols (e.g., OAuth, JWT) and enforce access controls based on user roles and permissions.
1. Employ Transport Layer Security (TLS) encryption: Secure the communication between clients and the container API using TLS certificates to protect against eavesdropping and tampering.
1. Regularly monitor and log API activity: Implement logging and monitoring mechanisms to detect and respond to suspicious or malicious activity.
1. Apply rate limiting and throttling: Protect the API from abuse and denial-of-service attacks by enforcing rate limits and throttling requests.


```
# Compliant: Secured container API with authentication/authorization

FROM nginx
...
# Expose container API on port 8080 (internal)
EXPOSE 8080

# Use a reverse proxy or API gateway for authentication/authorization
```


## Container Escape

Exploiting vulnerabilities in the container runtime or misconfigurations to break out of the container's isolation and gain unauthorized access to the host operating system. Example: Exploiting a vulnerability in the container runtime to access the host system and other containers.


The below code creates and starts a container without any security isolation measures. This leaves the container susceptible to container escape attacks, where an attacker can exploit vulnerabilities in the container runtime or misconfigured security settings to gain unauthorized access to the host system.

```
# Noncompliant: Running a container without proper security isolation

require 'docker'

# Create a container with default settings
container = Docker::Container.create('Image' => 'nginx')
container.start
```

we introduce security enhancements to mitigate the risk of container escape. The HostConfig parameter is used to configure the container's security settings. Here, we:

Set 'Privileged' => false to disable privileged mode, which restricts access to host devices and capabilities.
Use 'CapDrop' => ['ALL'] to drop all capabilities from the container, minimizing the potential attack surface.
Add 'SecurityOpt' => ['no-new-privileges'] to prevent privilege escalation within the container.


```
# Compliant: Running a container with enhanced security isolation

require 'docker'

# Create a container with enhanced security settings
container = Docker::Container.create(
  'Image' => 'nginx',
  'HostConfig' => {
    'Privileged' => false,           # Disable privileged mode
    'CapDrop' => ['ALL'],            # Drop all capabilities
    'SecurityOpt' => ['no-new-privileges']  # Prevent privilege escalation
  }
)
container.start
```


## Container Image Tampering

Modifying or replacing container images with malicious versions that may contain malware, backdoors, or vulnerable components. Example: Tampering with a container image to inject malicious code that steals sensitive information.


The below code directly pulls and runs a container image without verifying its integrity. This leaves the application vulnerable to container image tampering, where an attacker can modify the container image to include malicious code or compromise the application's security.

```
#Pulling and running a container image without verifying integrity

require 'docker'

# Pull the container image
image = Docker::Image.create('fromImage' => 'nginx')

# Run the container image
container = Docker::Container.create('Image' => image.id)
container.start
```

we address this issue by introducing integrity verification. The code calculates the expected digest of the pulled image using the SHA256 hash algorithm. It then compares this expected digest with the actual digest of the image obtained from the Docker API. If the digests do not match, an integrity verification failure is raised, indicating that the image may have been tampered with.

```
# Compliant: Pulling and running a container image with integrity verification

require 'docker'
require 'digest'

# Image name and tag
image_name = 'nginx'
image_tag = 'latest'

# Pull the container image
image = Docker::Image.create('fromImage' => "#{image_name}:#{image_tag}")

# Verify the integrity of the pulled image
expected_digest = Digest::SHA256.hexdigest(image.connection.get("/images/#{image.id}/json").body)
actual_digest = image.info['RepoDigests'].first.split('@').last
if expected_digest != actual_digest
  raise "Integrity verification failed for image: #{image_name}:#{image_tag}"
end

# Run the container image
container = Docker::Container.create('Image' => image.id)
container.start
```

## Insecure Container Configuration

Misconfigurations in container settings, such as weak access controls or excessive permissions, allowing attackers to compromise the container or its environment. Example: Running a container with unnecessary capabilities or insecure mount points.

The noncompliant code creates and starts a container with default settings, which may have insecure configurations. These misconfigurations can lead to vulnerabilities, such as privilege escalation, excessive container privileges, or exposure of sensitive resources.


```
# Noncompliant: Running a container with insecure configuration

require 'docker'

# Create a container with default settings
container = Docker::Container.create('Image' => 'nginx')
container.start
```

In the compliant code, we address these security concerns by applying secure container configurations. The HostConfig parameter is used to specify the container's configuration. Here, we:

Set 'ReadOnly' => true to make the container's filesystem read-only, preventing potential tampering and unauthorized modifications.
Use 'CapDrop' => ['ALL'] to drop all capabilities from the container, minimizing the attack surface and reducing the potential impact of privilege escalation.
Add 'SecurityOpt' => ['no-new-privileges'] to prevent the container from gaining additional privileges.
Specify 'NetworkMode' => 'bridge' to isolate the container in a bridge network, ensuring separation from the host and other containers.
Use 'PortBindings' to bind the container's port to a specific host port ('80/tcp' => [{ 'HostPort' => '8080' }]). This restricts network access to the container and avoids exposing unnecessary ports.

```
# Compliant: Running a container with secure configuration

require 'docker'

# Create a container with secure settings
container = Docker::Container.create(
  'Image' => 'nginx',
  'HostConfig' => {
    'ReadOnly' => true,               # Set container as read-only
    'CapDrop' => ['ALL'],             # Drop all capabilities
    'SecurityOpt' => ['no-new-privileges'],  # Prevent privilege escalation
    'NetworkMode' => 'bridge',        # Use a bridge network for isolation
    'PortBindings' => { '80/tcp' => [{ 'HostPort' => '8080' }] }  # Bind container port to a specific host port
  }
)
container.start
```



## Denial-of-Service (DoS)

Overloading container resources or exploiting vulnerabilities in the container runtime to disrupt the availability of containerized applications. Example: Launching a DoS attack against a container by overwhelming it with excessive requests.


The noncompliant code snippet shows a Dockerfile that is vulnerable to resource overloading and DoS attacks. It does not implement any resource limitations or restrictions, allowing the container to consume unlimited resources. This can lead to a DoS situation if an attacker overwhelms the container with excessive requests or exploits vulnerabilities in the container runtime.




```
# Noncompliant: Vulnerable Dockerfile with unlimited resource allocation

FROM nginx:latest

COPY app /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

The compliant code snippet addresses this vulnerability by not explicitly setting any resource limitations. However, it is essential to implement resource management and limit container resources based on your application's requirements and the resources available in your environment. This can be achieved by configuring resource limits such as CPU, memory, and network bandwidth using container orchestration platforms or Docker-compose files.



```
version: '3'
services:
  nginx:
    image: nginx:latest
    ports:
      - 80:80
    volumes:
      - ./app:/usr/share/nginx/html
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: '256M'
```


## Kernel Vulnerabilities

Exploiting vulnerabilities in the kernel or host operating system to gain unauthorized access or control over containers. Example: Exploiting a kernel vulnerability to escalate privileges and compromise containers.


```
# Noncompliant: Ignoring kernel vulnerabilities

docker run -d ubuntu:latest /bin/bash
```

To mitigate kernel vulnerabilities, it is important to regularly check for updates and apply security patches to the host system. Additionally, you can use tools to scan and assess the vulnerability status of the kernel before creating a Docker container.

Here's an example of compliant code that incorporates checking for kernel vulnerabilities using the kubehunter tool before creating the container:

```
# Compliant: Checking kernel vulnerabilities

# Perform vulnerability assessment using kubehunter
kubehunter scan

# Check the output for kernel vulnerabilities

# If vulnerabilities are found, take necessary steps to address them

# Create the Docker container
docker run -d ubuntu:latest /bin/bash
```

In the compliant code snippet, the kubehunter tool is used to perform a vulnerability assessment, including checking for kernel vulnerabilities. The output of the tool is examined, and if any vulnerabilities are found, appropriate steps are taken to address them before creating the Docker container.



## Shared Kernel Exploitation

Containers sharing the same kernel can be vulnerable to attacks that exploit kernel vulnerabilities, allowing attackers to affect multiple containers. Example: Exploiting a kernel vulnerability to gain unauthorized access to multiple containers on the same host.


In the noncompliant code, the Docker image installs a vulnerable package and runs a vulnerable application. If an attacker manages to exploit a kernel vulnerability within the container, they could potentially escape the container and compromise the host or other containers.



```
# Noncompliant: Vulnerable to container breakout

FROM ubuntu:latest

# Install vulnerable package
RUN apt-get update && apt-get install -y vulnerable-package

# Run vulnerable application
CMD ["vulnerable-app"]
```


The compliant code addresses the vulnerability by ensuring that the container image only includes necessary and secure packages. It performs regular updates and includes security patches to mitigate known vulnerabilities. By running a secure application within the container, the risk of a container breakout is reduced.

To further enhance security, additional measures can be taken such as utilizing container isolation techniques like running containers with restricted privileges, leveraging security-enhanced kernels (such as those provided by certain container platforms), and monitoring and logging container activity to detect potential exploitation attempts.

```
# Compliant: Mitigated container breakout vulnerability

FROM ubuntu:latest

# Install security updates and necessary packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y secure-package

# Run secure application
CMD ["secure-app"]
```


## Insecure Container Orchestration

Misconfigurations or vulnerabilities in container orchestration platforms, such as Kubernetes, can lead to unauthorized access, privilege escalation, or exposure of sensitive information. Example: Exploiting a misconfigured Kubernetes cluster to gain unauthorized access to sensitive resources.


In the noncompliant code, the Pod definition enables privileged mode for the container, granting it elevated privileges within the container orchestration environment. If an attacker gains access to this container, they could exploit the elevated privileges to perform malicious actions on the host or compromise other containers.


```
# Noncompliant: Vulnerable to privilege escalation

apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
    - name: vulnerable-container
      image: vulnerable-image
      securityContext:
        privileged: true  # Privileged mode enabled
```

The compliant code addresses the vulnerability by explicitly disabling privileged mode for the container. By running containers with reduced privileges, the impact of a potential compromise is limited, and the attack surface is minimized.

In addition to disabling privileged mode, other security measures should be implemented to enhance the security of container orchestration. This includes configuring appropriate RBAC (Role-Based Access Control) policies, enabling network segmentation and isolation, regularly applying security patches to the orchestration system, and monitoring the environment for suspicious activities.

```
# Compliant: Mitigated privilege escalation

apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: secure-container
      image: secure-image
      securityContext:
        privileged: false  # Privileged mode disabled
```