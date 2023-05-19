---
layout: default
title: Docker
parent: Checklists
---

# Docker Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Docker for DevSecOps


### Enable Docker Content Trust


```
export DOCKER_CONTENT_TRUST=1
```


### Restrict communication with Docker daemon to local socket


sudo chmod 660 /var/run/docker.sock<br>sudo chgrp docker /var/run/docker.sock



### Enable Docker Swarm Mode	

docker swarm init


### Set up network security for Docker Swarm


docker network create --driver overlay my-network

### Implement resource constraints on Docker containers

```
docker run --cpu-quota=50000 --memory=512m my-image
```

### Use Docker Secrets to protect sensitive data


```
docker secret create my-secret my-secret-data.txt
```


### Limit access to Docker APIs



Use a reverse proxy like NGINX or Apache to limit access to the Docker API endpoint



### Rotate Docker TLS certificates regularly	


```
dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
```
