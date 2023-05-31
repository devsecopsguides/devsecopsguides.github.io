---
layout: default
title: DAST
parent: Build & Test
---

# DAST
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


DAST stands for Dynamic Application Security Testing. It is a type of application security testing that involves testing an application in a running state to identify security vulnerabilities that may be present.

DAST tools work by interacting with an application in much the same way as a user would, by sending HTTP requests to the application and analyzing the responses that are received. This allows DAST tools to identify vulnerabilities that may be present in the application's logic, configuration, or architecture.

Here are some key features of DAST:

* Realistic testing: DAST provides a more realistic testing environment than SAST because it tests the application in a running state, simulating how an attacker would interact with it.

* Automation: DAST tools can be automated to provide continuous testing, allowing for faster feedback on vulnerabilities.

* Scalability: DAST tools can be scaled to test large and complex applications, making them suitable for enterprise-level testing.

* Coverage: DAST tools can provide coverage for a wide range of security vulnerabilities, including those that may be difficult to detect through other forms of testing.

* Ease of use: DAST tools are typically easy to use and require minimal setup, making them accessible to developers and security teams.



| DAST Tool    | Description   | 
|:---------------|:---------------------|
| `OWASP ZAP` | an open-source web application security scanner	 | 
| `Burp Suite` | a web application security testing toolkit	 | 






Assuming we have a web application that we want to test for security vulnerabilities using DAST, we can use OWASP ZAP, an open-source web application security scanner, in our pipeline.


1- **First, we need to install OWASP ZAP and configure it with our web application. This can be done by running the following commands in the pipeline:**

```
- name: Install OWASP ZAP
  run: |
    wget https://github.com/zaproxy/zaproxy/releases/download/v2.10.0/ZAP_2.10.0_Core.zip
    unzip ZAP_2.10.0_Core.zip -d zap
- name: Start OWASP ZAP
  run: |
    zap/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true
- name: Configure OWASP ZAP
  run: |
    zap/zap-cli.py -p 8080 open-url https://example.com

```

2- **Next, we need to run the security scan using OWASP ZAP. This can be done by running the following command in the pipeline:**

```
- name: Run OWASP ZAP scan
  run: |
    zap/zap-cli.py -p 8080 spider https://example.com
    zap/zap-cli.py -p 8080 active-scan https://example.com

```

This will start the OWASP ZAP spider to crawl the web application and then run an active scan to identify security vulnerabilities.

3- **Finally, we need to generate a report of the security scan results. This can be done by running the following command in the pipeline:**

```
- name: Generate OWASP ZAP report
  run: |
    zap/zap-cli.py -p 8080 report -o zap-report.html -f html

```

This will generate an HTML report of the security scan results that can be reviewed and acted upon.

