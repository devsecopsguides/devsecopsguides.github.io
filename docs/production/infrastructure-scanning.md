---
layout: default
title: Infrastructure Scanning
parent: Production
---

# Infrastructure Scanning
{: .no_toc }

Infrastructure scanning in production DevSecOps refers to the process of continuously scanning the underlying infrastructure of an application deployed on cloud infrastructure for potential security vulnerabilities and threats. This is done to ensure that the infrastructure remains secure and compliant with security policies and standards even after it has been deployed to the cloud.


## Nessus

A tool that scans your network for vulnerabilities and provides detailed reports.	


```
nessuscli scan new --policy "Basic Network Scan" --target "192.168.1.1"
```


## OpenVAS

An open-source vulnerability scanner that provides detailed reports and supports a wide range of platforms.	

```
omp -u admin -w password -G "Full and fast" -T 192.168.1.1
```

## Qualys

A cloud-based security and compliance tool that provides continuous monitoring and detailed reporting.	

```
curl -H "X-Requested-With: Curl" -u "username:password" "https://qualysapi.qualys.com/api/2.0/fo/scan/?action=launch&scan_title=Example Scan&target=192.168.1.1"
```

## Security Onion	

A Linux distro for intrusion detection, network security monitoring, and log management.	

```
sudo so-import-pcap -r 2022-01-01 -c example.pcap
```

## Lynis

A tool for auditing security on Unix-based systems that performs a system scan and provides detailed reports.	

```
sudo lynis audit system
```

## Nuclei

A fast and customizable vulnerability scanner that supports a wide range of platforms and technologies.	

```
nuclei -u http://example.com -t cves/CVE-2021-1234.yaml
```


## Nuclei Templates	

A collection of templates for Nuclei that cover a wide range of vulnerabilities and misconfigurations.	

```
nuclei -u http://example.com -t cves/ -max-time 5m
```

## Nuclei with Burp Suite	

A combination of Nuclei and Burp Suite that allows you to quickly scan and identify vulnerabilities in web applications.	

```
nuclei -t web-vulns -target http://example.com -proxy http://localhost:8080
```

## Nuclei with Masscan	

A combination of Nuclei and Masscan that allows you to quickly scan large IP ranges and identify vulnerabilities.	

```
masscan -p1-65535 192.168.1.1-254 -oL ips.txt && cat ips.txt
```