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



### Use non-root user	


```
user: <non-root-user>
```


### Limit container capabilities	


```
cap_drop: [CAP_SYS_ADMIN]
```


### Restrict container resources	


```
resources:
	 limits:
	 	 cpus: 0.5
	 	 memory: 512M
```


### Enable read-only file system	


```
read_only: true
```


### Set container restart policy	


```
restart: unless-stopped
```


### Use TLS/SSL for secure communication	


```
docker run -d -p 443:443 --name registry -v /path/to/certs:/certs -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key registry:latest
```



### Enable authentication	


```
docker run -d -p 443:443 --name registry -v /path/to/auth:/auth -e REGISTRY_AUTH=htpasswd -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd registry:latest
```


### Limit access to trusted clients	


```
docker run -d -p 443:443 --name registry -e REGISTRY_HTTP_SECRET=mysecret registry:latest
```


### Implement access control policies	


```
docker run -d -p 443:443 --name registry -v /path/to/config.yml:/etc/docker/registry/config.yml registry:latest
```


### Enable content trust (image signing)		


```
export DOCKER_CONTENT_TRUST=1
```




















