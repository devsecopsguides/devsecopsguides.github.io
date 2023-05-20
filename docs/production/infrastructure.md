---
layout: default
title: Infrastructure
parent: Production
---

# Infrastructure
{: .no_toc }


## Service Mesh


Linkerd Security Cheatsheet:



1- Inject Linkerd's sidecar proxy into deployment YAML files for automatic mTLS.

```
linkerd --context <context> inject --manual <input.yaml> | kubectl apply -f -
```

2- Enable mTLS for a specific deployment.
```
linkerd --context <context> -n <namespace> -o yaml tls web deployment/<deployment> | kubectl apply -f -
```
 

3- Tap into the traffic of a specific deployment, monitoring for unauthorized access attempts

```
linkerd --context <context> -n <namespace> tap deploy/<deployment> --namespace=<target-namespace> --to <target-deployment> --method=<http-method>
```


4- Observe traffic and analyze potential security-related issues using Linkerd's tap command.

```
linkerd --context <context> -n <namespace> -o json tap deploy/<deployment> | jq . | less
```


5- Install Istio with automatic mTLS enabled.

```
istioctl --context <context> install --set profile=demo --set values.global.mtls.auto=true: 
```

6- Generate Istio manifest files for the current configuration.

```
istioctl --context <context> manifest generate | kubectl apply -f -: 
```

7- Perform a TLS handshake check for a specific host and namespace.

```
istioctl --context <context> authn tls-check <host> -n <namespace>: 
```


8- Check Istio authorization policies for specific traffic flows.

```
istioctl --context <context> -n <namespace> authz check deploy/<deployment> --from <source-deployment> --to <target-deployment> --namespace=<target-namespace> --method=<http-method>
```


9- Generate a packet capture (PCAP) file for a specific pod for in-depth analysis.

```
istioctl --context <context> -n <namespace> pcaps <pod-name> -o <output-file.pcap>
```

10- Open Jaeger, the distributed tracing system, to visualize and analyze Istio-traced requests.

```
istioctl --context <context> -n <namespace> dashboard jaeger
```



## Container


1- Run a specific benchmark

```
kube-bench --benchmark <benchmark-name>
```

2- Generate a JSON report for a specific benchmark

```
kube-bench --benchmark <benchmark-name> --json
```


3- Run benchmarks as a non-root user

```
kube-bench --benchmark <benchmark-name> --run-as non-root
```

4- Export the benchmark results to a log file.


```
kube-bench --benchmark <benchmark-name> --log <log-file>
```




### KubeLinter

Scan Kubernetes YAML Files:

```
kube-linter lint <path/to/kubernetes/yaml/files>
```



### Checkov


1- Scan Terraform Files

```
checkov -d <path/to/terraform/files>: 
```

2- Output Scan Results in JSON Format

```
checkov -o json: Generate scan results in JSON format.
```

3- Ignore Specific Check IDs or File Paths

```
checkov --skip-check <check1,check2>: 
```



### Twistlock


1- Pull Twistlock Scanner Image:

```
docker pull twistlock/scanner:latest: Pull the latest Twistlock Scanner image from Docker Hub.
```

2- Scan a Docker Image:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest <image-name>:<tag>: Perform a security scan on the specified Docker image.
```

3- Authenticate Twistlock Console:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --auth <console-url> --user <username> --password <password>: Authenticate the Twistlock Scanner with the Twistlock Console.
```

4- Generate HTML Report:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --output-file <report-file.html> <image-name>:<tag>: Generate an HTML report for the scan results.
```

5- Specify Scan Policies:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --policy-file <policy-file.yaml> <image-name>:<tag>: Use a custom policy file for the scan.
```




### Terrascan


1- Scan Terraform Files:

```
terrascan scan -i <path/to/terraform/files>
```


2- Specify Policy Path

```
terrascan scan -p <path/to/policy>
```


3- Output Scan Results in JSON Format:

```
terrascan scan -f json
```

4- Ignore Specific Rules or Resources:

```
terrascan scan --skip-rules <rule1,rule2>
```


### Tfsec


1- Scan Terraform Files

```
tfsec <path/to/terraform/files>
```


2- Output Scan Results in JSON Format

```
tfsec --format=json: Generate scan results in JSON format.
```


3- Ignore Specific Rules or Warnings

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




