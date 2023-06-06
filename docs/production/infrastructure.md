---
layout: default
title: Infrastructure
parent: Production
---

# Infrastructure
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


## Service Mesh


### linkerd + istioctl

Linkerd Security Cheatsheet:



- [ ] Inject Linkerd's sidecar proxy into deployment YAML files for automatic mTLS.

```
linkerd --context <context> inject --manual <input.yaml> | kubectl apply -f -
```

- [ ] Enable mTLS for a specific deployment.

```
linkerd --context <context> -n <namespace> -o yaml tls web deployment/<deployment> | kubectl apply -f -
```
 

- [ ] Tap into the traffic of a specific deployment, monitoring for unauthorized access attempts

```
linkerd --context <context> -n <namespace> tap deploy/<deployment> --namespace=<target-namespace> --to <target-deployment> --method=<http-method>
```


- [ ] Observe traffic and analyze potential security-related issues using Linkerd's tap command.

```
linkerd --context <context> -n <namespace> -o json tap deploy/<deployment> | jq . | less
```


- [ ] Install Istio with automatic mTLS enabled.

```
istioctl --context <context> install --set profile=demo --set values.global.mtls.auto=true: 
```

- [ ] Generate Istio manifest files for the current configuration.

```
istioctl --context <context> manifest generate | kubectl apply -f -: 
```

- [ ] Perform a TLS handshake check for a specific host and namespace.

```
istioctl --context <context> authn tls-check <host> -n <namespace>: 
```


- [ ] Check Istio authorization policies for specific traffic flows.

```
istioctl --context <context> -n <namespace> authz check deploy/<deployment> --from <source-deployment> --to <target-deployment> --namespace=<target-namespace> --method=<http-method>
```


- [ ] Generate a packet capture (PCAP) file for a specific pod for in-depth analysis.

```
istioctl --context <context> -n <namespace> pcaps <pod-name> -o <output-file.pcap>
```

- [ ] Open Jaeger, the distributed tracing system, to visualize and analyze Istio-traced requests.

```
istioctl --context <context> -n <namespace> dashboard jaeger
```

### Chaos


- [ ] Configure Chaos Monkey

Edit the `chaos.properties` file to specify the target service, frequency of chaos events, and other settings.

- [ ] Start Chaos Monkey	

```
./gradlew bootRun
```

- [ ] Verify Chaos Monkey is running	

Access the Chaos Monkey dashboard at `http://localhost:8080/chaosmonkey`

- [ ] Enable Chaos Monkey for a specific service	

Set the `chaos.monkey.enabled` property to `true` for the desired service in the configuration file.

- [ ] Disable Chaos Monkey for a specific service	

Set the `chaos.monkey.enabled` property to `false` for the desired service in the configuration file.

- [ ] Customize Chaos Monkey behavior	

Modify the `chaos.monkey...` properties in the configuration file to define the chaos events, such as `chaos.monkey.watcher.probablility` for adjusting the likelihood of an event occurring.


## Container


- [ ] Run a specific benchmark

```
kube-bench --benchmark <benchmark-name>
```

- [ ] Generate a JSON report for a specific benchmark

```
kube-bench --benchmark <benchmark-name> --json
```


- [ ] Run benchmarks as a non-root user

```
kube-bench --benchmark <benchmark-name> --run-as non-root
```

- [ ] Export the benchmark results to a log file.


```
kube-bench --benchmark <benchmark-name> --log <log-file>
```




### KubeLinter

Scan Kubernetes YAML Files:

```
kube-linter lint <path/to/kubernetes/yaml/files>
```


### Helm


- [ ] Validate Chart Signatures

Helm supports chart signing using cryptographic signatures. It is recommended to validate the signatures of the charts you download before deploying them to ensure they haven't been tampered with. You can use the helm verify command to verify the chart signature.

```
helm verify <chart-name>
```

- [ ] Limit Chart Sources

To minimize the risk of downloading malicious or insecure charts, it's best to limit the sources from which you fetch charts. You can configure your Helm repositories to only allow trusted sources by modifying the repositories.yaml file.


```
helm repo list
helm repo remove <repository-name>
```

- [ ] Scan Charts for Vulnerabilities

Before deploying a chart, it's crucial to scan it for known vulnerabilities. Tools like Trivy or Anchore Engine can help you perform vulnerability scanning on Helm charts.

```
trivy <chart-path>
```

- [ ] Enable RBAC


Helm allows you to enable Role-Based Access Control (RBAC) to control access to the cluster and restrict who can perform Helm operations. Configure RBAC rules to limit the permissions of Helm users and ensure only authorized users can install or upgrade charts.

```
kubectl create role <role-name> --verb=<allowed-verbs> --resource=<allowed-resources>
kubectl create rolebinding <role-binding-name> --role=<role-name> --user=<user> --namespace=<namespace>
```


- [ ] Monitor Helm Releases

Regularly monitor the status and changes of your Helm releases. Tools like Helm Operator or Prometheus can help you monitor the health and performance of your Helm deployments.

```
helm ls
```



- [ ] Scanning Helm Charts with Trivy

Trivy can also scan Helm charts for vulnerabilities before deploying them. Here's an example of using Trivy to scan a Helm chart:

```
trivy chart <chart-path>
```



### Checkov


- [ ] Scan Terraform Files

```
checkov -d <path/to/terraform/files>: 
```

- [ ] Output Scan Results in JSON Format

```
checkov -o json: Generate scan results in JSON format.
```

- [ ] Ignore Specific Check IDs or File Paths

```
checkov --skip-check <check1,check2>: 
```



### Twistlock


- [ ] Pull Twistlock Scanner Image:

```
docker pull twistlock/scanner:latest: Pull the latest Twistlock Scanner image from Docker Hub.
```

- [ ] Scan a Docker Image:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest <image-name>:<tag>: Perform a security scan on the specified Docker image.
```

- [ ] Authenticate Twistlock Console:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --auth <console-url> --user <username> --password <password>: Authenticate the Twistlock Scanner with the Twistlock Console.
```

- [ ] Generate HTML Report:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --output-file <report-file.html> <image-name>:<tag>: Generate an HTML report for the scan results.
```

- [ ] Specify Scan Policies:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --policy-file <policy-file.yaml> <image-name>:<tag>: Use a custom policy file for the scan.
```




### Terrascan


- [ ] Scan Terraform Files:

```
terrascan scan -i <path/to/terraform/files>
```


- [ ] Specify Policy Path

```
terrascan scan -p <path/to/policy>
```


- [ ] Output Scan Results in JSON Format:

```
terrascan scan -f json
```

- [ ] Ignore Specific Rules or Resources:

```
terrascan scan --skip-rules <rule1,rule2>
```


### Tfsec


- [ ] Scan Terraform Files

```
tfsec <path/to/terraform/files>
```


- [ ] Output Scan Results in JSON Format

```
tfsec --format=json: Generate scan results in JSON format.
```


- [ ] Ignore Specific Rules or Warnings

```
tfsec --ignore <rule1,rule2>
```




## Security Scanning

Infrastructure scanning in production DevSecOps refers to the process of continuously scanning the underlying infrastructure of an application deployed on cloud infrastructure for potential security vulnerabilities and threats. This is done to ensure that the infrastructure remains secure and compliant with security policies and standards even after it has been deployed to the cloud.


### Nessus

A tool that scans your network for vulnerabilities and provides detailed reports.	


```
nessuscli scan new --policy "Basic Network Scan" --target "192.168.1.1"
```


### OpenVAS

An open-source vulnerability scanner that provides detailed reports and supports a wide range of platforms.	

```
omp -u admin -w password -G "Full and fast" -T 192.168.1.1
```

### Qualys

A cloud-based security and compliance tool that provides continuous monitoring and detailed reporting.	

```
curl -H "X-Requested-With: Curl" -u "username:password" "https://qualysapi.qualys.com/api/2.0/fo/scan/?action=launch&scan_title=Example Scan&target=192.168.1.1"
```

### Security Onion	

A Linux distro for intrusion detection, network security monitoring, and log management.	

```
sudo so-import-pcap -r 2022-01-01 -c example.pcap
```

### Lynis

A tool for auditing security on Unix-based systems that performs a system scan and provides detailed reports.	

```
sudo lynis audit system
```

### Nuclei

A fast and customizable vulnerability scanner that supports a wide range of platforms and technologies.	

```
nuclei -u http://example.com -t cves/CVE-2021-1234.yaml
```


### Nuclei Templates	

A collection of templates for Nuclei that cover a wide range of vulnerabilities and misconfigurations.	

```
nuclei -u http://example.com -t cves/ -max-time 5m
```

### Nuclei with Burp Suite	

A combination of Nuclei and Burp Suite that allows you to quickly scan and identify vulnerabilities in web applications.	

```
nuclei -t web-vulns -target http://example.com -proxy http://localhost:8080
```

### Nuclei with Masscan	

A combination of Nuclei and Masscan that allows you to quickly scan large IP ranges and identify vulnerabilities.	

```
masscan -p1-65535 192.168.1.1-254 -oL ips.txt && cat ips.txt
```


### Define Guardrails via HashiCorp

Applies HashiCorp Sentinel policies to enforce guardrails defined in the policy file.

```
sentinel apply -policy=<policy_file>
```

### Vulnerability Scanning via nessuscli

Initiates a vulnerability scan on the target system using Nessus.

```
nessuscli scan -t <target>
```

### Patch Vulnerabilities via Ansible playbook

Executes an Ansible playbook to patch vulnerabilities specified in the playbook.

```
ansible-playbook -i inventory.ini patch_vulnerabilities.yml
```

### Compliance Checks via aws-nuke

Deletes AWS resources non-compliant with the defined configuration in the AWS Nuke configuration file.

```
aws-nuke --config=config.yml
```

### Continuous Compliance Monitoring via opa

Evaluates Open Policy Agent (OPA) policies against input data to enforce compliance.

```
opa eval -i <input_data> -d <policy_file>
```


## Tunnel & Proxy


### Nebula

Generates a certificate authority (CA) for Nebula using the specified name and outputs the CA certificate and key files.

```
nebula-cert ca -name "<ca_name>" -out <ca_cert_file> -key <ca_key_file>
```

Signs a node certificate with the specified CA certificate and key files, node name, IP address, and outputs the node certificate file.

```
nebula-cert sign -ca-crt <ca_cert_file> -ca-key <ca_key_file> -name "<node_name>" -out <node_cert_file> -ip <node_ip>
```

Starts a Nebula node using the specified configuration file

```
nebula -config <config_file>
```

Adds a static route to the Nebula node for the specified destination subnet via the specified node

```
nebula route add -dst-subnet <destination_subnet> -via <via_node>
```

Starts a Nebula proxy using the specified configuration file.

```
nebula-proxy -config <config_file>
```

Initiates a connection to a remote host using the Nebula overlay network.

```
nebula connect <host_ip>
```

Checks the status and connectivity of the Nebula node.

```
nebula status
```

Displays statistics and metrics about the Nebula node.

```
nebula stats
```


### Chisel


Starts the Chisel server on the specified port, enabling reverse tunneling.

```
chisel server -p <listen_port> --reverse
```

Starts the Chisel client and establishes a reverse tunnel to the Chisel server. It forwards traffic from the local port to the remote host and port.

```
chisel client <server_host>:<server_port> R:<remote_host>:<remote_port>:<local_port>
```


Creates a tunnel from the local port to the remote host and port via the Chisel server. The -f flag keeps the connection alive.

```
chisel client <server_host>:<server_port> -f -L <local_port>:<remote_host>:<remote_port>
```

Sets up a local HTTP proxy that forwards traffic to the Chisel server and then to the internet.

```
chisel client <server_host>:<server_port> -f -P <local_port>
```

Configures a local SOCKS proxy that routes traffic through the Chisel server.


```
chisel client <server_host>:<server_port> -f -S <local_port>
```

Description: 

Sets up a reverse tunnel and exposes a local web service through the Chisel server using the HTTP proxy protocol.

```
chisel client <server_host>:<server_port> --reverse --proxy-protocol http
```


Creates multiple tunnels from different local ports to different remote hosts and ports via the Chisel server.

```
chisel client <server_host>:<server_port> -f -L <local_port1>:<remote_host1>:<remote_port1> -L <local_port2>:<remote_host2>:<remote_port2>
```


Tests the connectivity to the Chisel server and displays the round-trip time (RTT).

```
chisel client <server_host>:<server_port> --ping
```


## Incident Management




### PagerDuty



```
import requests

def trigger_pagerduty_incident(service_key, description, details):
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": service_key,
        "event_action": "trigger",
        "payload": {
            "summary": description,
            "severity": "error",
            "source": "vulnerability-scanner",
            "custom_details": details
        }
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 202:
        print("PagerDuty incident triggered successfully")
    else:
        print("Failed to trigger PagerDuty incident")

# Usage example:
service_key = "YOUR_PAGERDUTY_SERVICE_KEY"
description = "Critical vulnerability detected"
details = {
    "scan_target": "example.com",
    "vulnerability_description": "CVE-2023-1234",
    "remediation_steps": "Update library version to 2.0.1"
}

trigger_pagerduty_incident(service_key, description, details)
```



In this example, the trigger_pagerduty_incident function sends a PagerDuty event to trigger an incident. It includes a summary, severity, source, and custom details such as the scan target, vulnerability description, and suggested remediation steps.


Then we have defined three incident rules based on different vulnerability priorities: Critical, Medium, and Low. Each rule specifies a condition based on the priority field, and if the condition is met, corresponding actions are triggered.


```
incident_rules:
  - name: Critical Vulnerability
    description: Notify the Security Team for critical vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P1
    actions:
      - type: notify-team
        team: Security Team
        message: "Critical vulnerability detected. Please investigate and take immediate action."
      - type: add-note
        content: "Critical vulnerability detected. Incident created for further investigation."
  - name: Medium Vulnerability
    description: Notify the Development Team for medium vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P2
    actions:
      - type: notify-team
        team: Development Team
        message: "Medium vulnerability detected. Please review and prioritize for remediation."
      - type: add-note
        content: "Medium vulnerability detected. Incident created for further review."
  - name: Low Vulnerability
    description: Notify the Operations Team for low vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P3
    actions:
      - type: notify-team
        team: Operations Team
        message: "Low vulnerability detected. Please assess and plan for future updates."
      - type: add-note
        content: "Low vulnerability detected. Incident created for tracking and monitoring."
```



### Opsgenie


```
import requests

def create_opsgenie_alert(api_key, message, priority, details):
    url = "https://api.opsgenie.com/v2/alerts"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"GenieKey {api_key}"
    }
    payload = {
        "message": message,
        "priority": priority,
        "details": details
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 202:
        print("Opsgenie alert created successfully")
    else:
        print("Failed to create Opsgenie alert")

# Usage example:
api_key = "YOUR_OPSGENIE_API_KEY"
message = "Critical vulnerability detected"
priority = "P1"
details = {
    "scan_target": "example.com",
    "vulnerability_description": "CVE-2023-1234",
    "remediation_steps": "Update library version to 2.0.1"
}

create_opsgenie_alert(api_key, message, priority, details)
```


In this example, the create_opsgenie_alert function sends an alert to Opsgenie, specifying the message, priority, and additional details such as the scan target, vulnerability description, and suggested remediation steps.



Then we have defined three incident rules based on different vulnerability priorities: Critical, Medium, and Low. Each rule specifies a condition based on the priority field, and if the condition is met, corresponding actions are triggered.


```
rules:
  - name: Critical Vulnerability
    description: Notify the Security Team for critical vulnerabilities
    condition: priority == "P1"
    actions:
      - notify-team:
          name: Security Team
          message: "Critical vulnerability detected. Please investigate and take immediate action."
      - add-note:
          content: "Critical vulnerability detected. Incident created for further investigation."
  - name: Medium Vulnerability
    description: Notify the Development Team for medium vulnerabilities
    condition: priority == "P2"
    actions:
      - notify-team:
          name: Development Team
          message: "Medium vulnerability detected. Please review and prioritize for remediation."
      - add-note:
          content: "Medium vulnerability detected. Incident created for further review."
  - name: Low Vulnerability
    description: Notify the Operations Team for low vulnerabilities
    condition: priority == "P3"
    actions:
      - notify-team:
          name: Operations Team
          message: "Low vulnerability detected. Please assess and plan for future updates."
      - add-note:
          content: "Low vulnerability detected. Incident created for tracking and monitoring."
```




## Harbor

### Create a new project in Harbor

```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"project_name": "myproject"}' https://<HARBOR_HOST>/api/v2.0/projects
```



### Add a new user to Harbor


```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"username": "newuser", "password": "password123"}' https://<HARBOR_HOST>/api/v2.0/users
```


### Scan an image for vulnerabilities in Harbor


```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"registry": "https://<REGISTRY_HOST>", "repository": "myimage", "tag": "latest"}' https://<HARBOR_HOST>/api/v2.0/scan
```


### Delete a project in Harbor

```
curl -X DELETE -H 'Authorization: Bearer <TOKEN>' https://<HARBOR_HOST>/api/v2.0/projects/myproject
```


### Retrieve the list of repositories in Harbor

```
curl -H 'Authorization: Bearer <TOKEN>' https://<HARBOR_HOST>/api/v2.0/repositories
```



## Clair


### Scan a Docker image with Clair

```
clairctl analyze -l <image_name>
```



### Retrieve vulnerability report for a Docker image from Clair


```
clairctl report -l <image_name>
```




### Update vulnerability database in Clair


```
clairctl update
```



### Delete a Docker image from Clair's database


```
clairctl delete -l <image_name>
```



### Get vulnerability details for a specific CVE in Clair


```
clairctl vulnerability <CVE_ID>
```


## Podman

### Run a container in a rootless mode

```
podman run --rm -it --userns=keep-always <image_name>
```


### Enable seccomp profile for a container


```
podman run --rm -it --security-opt seccomp=/path/to/seccomp.json <image_name>
```


### Apply SELinux context to a container


```
podman run --rm -it --security-opt label=type:container_runtime_t <image_name>
```


### Configure AppArmor profile for a container


```
podman run --rm -it --security-opt apparmor=docker-default <image_name>
```


### Enable read-only root filesystem for a container


```
podman run --rm -it --read-only <image_name>
```


## skopeo


### Copy an image from one container registry to another, verifying its authenticity:

```
skopeo copy --src-creds=<source_credentials> --dest-creds=<destination_credentials> --src-tls-verify=true --dest-tls-verify=true docker://<source_registry>/<source_image>:<tag> docker://<destination_registry>/<destination_image>:<tag>
```




### Inspect an image manifest to view its details and verify its integrity:


```
skopeo inspect --tls-verify=true docker://<registry>/<image>:<tag>
```




### Copy an image from a container registry to the local filesystem, validating its signature:


```
skopeo copy --src-creds=<source_credentials> --dest-tls-verify=true docker://<registry>/<image>:<tag> oci:<destination_directory>
```




### List the tags available for a specific image in a container registry:


```
skopeo list-tags --tls-verify=true docker://<registry>/<image>
```





### Delete an image from a container registry:



```
skopeo delete --creds=<registry_credentials> --tls-verify=true docker://<registry>/<image>:<tag>
```




## Open Containers Initiative (OCI)


### Verify Image Integrity



```
import (
    "fmt"
    "github.com/opencontainers/go-digest"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func verifyImageIntegrity(manifest v1.Manifest) error {
    for _, layer := range manifest.Layers {
        if layer.MediaType == "application/vnd.oci.image.layer.v1.tar" {
            digest := layer.Digest
            // Verify the integrity of the layer using the digest
            isValid, err := verifyLayerDigest(digest)
            if err != nil {
                return err
            }
            if !isValid {
                return fmt.Errorf("Layer integrity check failed")
            }
        }
    }
    return nil
}

func verifyLayerDigest(digest digest.Digest) (bool, error) {
    // Implement logic to verify the digest against the stored layer
    // Return true if the digest is valid, false otherwise
}
```


### Enforce Image Vulnerability Scanning:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func enforceVulnerabilityScanning(manifest v1.Manifest) error {
    for _, annotation := range manifest.Annotations {
        if annotation.Name == "com.example.vulnerability-scanning" && annotation.Value != "enabled" {
            return fmt.Errorf("Vulnerability scanning is not enabled for the image")
        }
    }
    return nil
}
```


### Implement Image Signing:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func signImage(manifest v1.Manifest, privateKey string) error {
    // Use the private key to sign the image manifest
    // Return an error if signing fails
}
```


### Enforce Image Content Trust:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func enforceContentTrust(manifest v1.Manifest) error {
    for _, annotation := range manifest.Annotations {
        if annotation.Name == "com.example.content-trust" && annotation.Value != "true" {
            return fmt.Errorf("Content trust is not enabled for the image")
        }
    }
    return nil
}
```


### Secure Image Transmission:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func secureImageTransmission(manifest v1.Manifest) error {
    for _, layer := range manifest.Layers {
        if layer.MediaType == "application/vnd.oci.image.layer.v1.tar" {
            // Implement logic to enforce secure transmission of the layer
            // Return an error if the transmission is not secure
        }
    }
    return nil
}
```




## API Umbrella and Kong


### Rate Limiting


```
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "settings": {
      "rate_limit_mode": "custom",
      "rate_limits": [
        {
          "duration": 1,
          "limit_by": "ip",
          "limit": 100
        }
      ]
    }
  }' \
  https://your-api-umbrella-host/admin/api/settings
```





### Authentication and Authorization


```
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name": "jwt-auth",
    "config": {
      "uri_param_names": ["token"],
      "secret_is_base64": false
    },
    "plugin": "jwt"
  }' \
  http://localhost:8001/services/{service_id}/plugins
```





### SSL/TLS Termination


```
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "frontend_host": "your-api.example.com",
    "backend_protocol": "https",
    "backend_ssl_cert": "YOUR_SSL_CERT",
    "backend_ssl_key": "YOUR_SSL_KEY"
  }' \
  https://your-api-umbrella-host/admin/api/services/{service_id}
```





### Logging and Monitoring


```
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name": "file-log",
    "config": {
      "path": "/var/log/kong/access.log"
    },
    "plugin": "file-log"
  }' \
  http://localhost:8001/services/{service_id}/plugins
```





### API Key Management


```
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "api_key": {
      "user_id": "your-user-id",
      "key": "your-api-key",
      "created_at": "2022-01-01T00:00:00Z"
    }
  }' \
  https://your-api-umbrella-host/admin/api/api_keys
```





## Argo CD


### Enable authentication for Argo CD using OIDC (OpenID Connect)

```
# rbac-config.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: argocd-admin
  namespace: argocd
subjects:
- kind: User
  name: <username>
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
```



### Enable SSL/TLS encryption for Argo CD

```
# values.yaml
server:
  config:
    tls.enabled: true
    tls.insecure: false
    tls.crt: |
      -----BEGIN CERTIFICATE-----
      <your_certificate_here>
      -----END CERTIFICATE-----
    tls.key: |
      -----BEGIN PRIVATE KEY-----
      <your_private_key_here>
      -----END PRIVATE KEY-----
```



### Restrict access to Argo CD's API server using network policies

```
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: argocd-network-policy
  namespace: argocd
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: <allowed_namespace>
```


### Enable Webhook authentication for Argo CD

```
# values.yaml
server:
  config:
    repository.credentials:
    - name: <repo_name>
      type: helm
      helm:
        url: <helm_repo_url>
        auth:
          webhook:
            url: <webhook_url>
            secret: <webhook_secret>
```








## flux2


### Enable RBAC (Role-Based Access Control) for Flux

```
# flux-system-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flux-system-rbac
subjects:
- kind: ServiceAccount
  name: flux-system
  namespace: flux-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```




### Enable image scanning with Trivy for Flux workloads

```
# flux-system-policies.yaml
apiVersion: image.toolkit.fluxcd.io/v1alpha2
kind: Policy
metadata:
  name: flux-system-policies
  namespace: flux-system
spec:
  policyType: tag
  repositories:
  - name: <repository_name>
    imagePolicy:
      name: trivy
      enabled: true
      args:
        - "--severity"
        - "HIGH,CRITICAL"
```





### Use GitOps for managing Kubernetes secrets with Flux

```
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: <secret_name>
  namespace: <namespace>
stringData:
  <key>: <value>
```





### Configure multi-tenancy with Flux using Git branches

```
# flux-system-repo.yaml
apiVersion: source.toolkit.fluxcd.io/v1alpha2
kind: GitRepository
metadata:
  name: flux-system-repo
  namespace: flux-system
spec:
  url: <repository_url>
  ref:
    branch: <branch_name>
  interval: 1m
```





### Enable cluster auto-scaling using Flux and Kubernetes Horizontal Pod Autoscaler (HPA)

```
# flux-system-autoscaler.yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: <hpa_name>
  namespace: <namespace>
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: <deployment_name>
  minReplicas: <min_replicas>
  maxReplicas: <max_replicas>
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: <cpu_utilization>
```








## GoCD


### Enable SSL/TLS for GoCD Server

```
<server>
  <!-- Other server configuration settings -->

  <ssl>
    <keystore>/path/to/keystore.jks</keystore>
    <keystore-password>keystore_password</keystore-password>
    <key-password>key_password</key-password>
  </ssl>
</server>
```



### Implement Role-Based Access Control (RBAC)

```
curl -u <admin_username>:<admin_password> -H 'Content-Type: application/json' -X POST \
  -d '{
    "name": "Developers",
    "users": ["user1", "user2"],
    "pipelines": {
      "read": ["pipeline1", "pipeline2"]
    }
  }' \
  http://localhost:8153/go/api/admin/security/roles
```

### Configure LDAP or Active Directory Integration

```
<security>
  <!-- Other security settings -->

  <ldap uri="ldap://ldap.example.com:389" managerDn="cn=admin,dc=example,dc=com" managerPassword="password">
    <loginFilter>(uid={0})</loginFilter>
    <searchBases>ou=users,dc=example,dc=com</searchBases>
    <loginAttribute>uid</loginAttribute>
    <searchUsername>uid=admin,ou=users,dc=example,dc=com</searchUsername>
    <searchPassword>password</searchPassword>
  </ldap>
</security>
```

### Implement Two-Factor Authentication (2FA)

```
<security>
  <!-- Other security settings -->

  <authConfigs>
    <authConfig id="google_auth" pluginId="cd.go.authentication.plugin.google.oauth">
      <property>
        <key>ClientId</key>
        <value>your_client_id</value>
      </property>
      <property>
        <key>ClientSecret</key>
        <value>your_client_secret</value>
      </property>
    </authConfig>
  </authConfigs>
</security>
```

### Enable Security Scanning of GoCD Agents

```
pipeline:
  stages:
    - name: Build
      # Build stage configuration

    - name: SonarQube
      jobs:
        - name: RunSonarQube
          tasks:
            - exec: sonar-scanner
```




## Calico

### Enable Calico network policies  

```
kubectl apply -f calico-policy.yaml
```


### Check Calico network policies    

```
kubectl get networkpolicies
```


### View Calico logs    

```
kubectl logs -n kube-system <calico-pod-name>
```


### Network Policy for Denying All Ingress Traffic:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```


### Network Policy for Allowing Ingress Traffic from a Specific Namespace:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-namespace
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: allowed-namespace
```

### Network Policy for Allowing Egress Traffic to a Specific IP or IP Range:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-ip-range
spec:
  podSelector: {}
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
```

### Network Policy for Enforcing Pod Labels:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: enforce-pod-labels
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
```

### Network Policy for Enforcing eBPF-based Network Security:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: enforce-ebpf-security
spec:
  podSelector: {}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          calico/knsname: kube-system
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          calico/knsname: kube-system
```




## AWS CloudFormation Guard

### Create a Guard rule file    

```
cfn-guard init <rule-file-name>.ruleset
```


### Evaluate a CloudFormation template against Guard rules  

```
cfn-guard validate -t <template-file> -r <rule-file>
```

### Generate a template with Guard conditions   


```
cfn-guard generate -t <template-file> -r <rule-file> -o <output-file>
```

### Enable verbose output for evaluation results    

```
cfn-guard validate -t <template-file> -r <rule-file> --verbose
```


### Run Guard with custom configuration 


```
cfn-guard validate -t <template-file> -r <rule-file> --config <config-file>
```


### Check if an EC2 instance type is allowed:



```
rules:
  - id: ec2InstanceTypeRule
    description: Check allowed EC2 instance types
    matches:
      - resources:
          - MyEC2Instance
        properties:
          instanceType:
            notEquals: t2.micro
```




### Enforce tagging for an S3 bucket:



```
rules:
  - id: s3BucketTaggingRule
    description: Enforce tagging for S3 buckets
    matches:
      - resources:
          - MyS3Bucket
        properties:
          tags:
            notPresent: "my-tag"
```



### Ensure a specific VPC CIDR range is used:



```
cfn-guard validate -t <template-file> -r <rule-file> --config <config-file>
```




### Ensure a specific VPC CIDR range is used:
 


```
rules:
  - id: vpcCIDRRule
    description: Ensure a specific VPC CIDR range is used
    matches:
      - resources:
          - MyVPC
        properties:
          cidrBlock:
            equals: 10.0.0.0/16
```




### Restrict the use of insecure security groups:



```
rules:
  - id: securityGroupRule
    description: Restrict the use of insecure security groups
    matches:
      - resources:
          - MySecurityGroup
        properties:
          securityGroupIngress:
            notMatches:
              - cidrIp: 0.0.0.0/0
                ipProtocol: -1
```




### Ensure encryption is enabled for an RDS instance:



```
rules:
  - id: rdsEncryptionRule
    description: Ensure encryption is enabled for RDS instances
    matches:
      - resources:
          - MyRDSInstance
        properties:
          storageEncrypted:
            equals: true
```




## Regula


### Scan a directory for compliance violations    

```
regula scan -d <directory-path>
```

### Scan a specific file for compliance violations      

```
regula scan -f <file-path>
```

### Scan a remote repository for compliance violations     

```
regula scan -r <repository-url>
```

### Scan a Terraform plan file for compliance violations        

```
regula scan -p <plan-file>
```

### Scan a directory and output results in JSON format      

```
regula scan -d <directory-path> --output json
```

### Check for unrestricted S3 bucket policies:
   

```
name: S3 bucket policy should not be unrestricted
resource_type: aws_s3_bucket_policy
violating_actions:
  - "*"
```

### Ensure that security groups do not allow unrestricted ingress traffic:


```
name: Security groups should not allow unrestricted ingress traffic
resource_type: aws_security_group_rule
violating_actions:
  - ingress
violating_fields:
  - source_security_group_id: "sg-00000000"
  - cidr_blocks:
      - "0.0.0.0/0"
```

### Enforce encryption for EBS volumes:
  

```
name: EBS volumes should be encrypted
resource_type: aws_ebs_volume
violating_actions:
  - create
  - modify
violating_fields:
  - encrypted: false
```

### Check for publicly accessible EC2 instances:
   

```
name: EC2 instances should not be publicly accessible
resource_type: aws_instance
violating_fields:
  - public_ip_address: "*"
```

### Ensure IAM policies do not have wildcard resource permissions:
    

```
name: IAM policies should not have wildcard resource permissions
resource_type: aws_iam_policy
violating_fields:
  - resources:
      - "*"
```























