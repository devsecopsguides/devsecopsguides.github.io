---
layout: default
title: Infrastructure
parent: Production
---

# Infrastructure
{: .no_toc }


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




