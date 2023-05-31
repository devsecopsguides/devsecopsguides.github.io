---
layout: default
title: IAST
parent: Build & Test
---

# IAST
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


IAST stands for Interactive Application Security Testing. It is a type of application security testing that combines the benefits of SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) tools.

IAST tools are designed to be integrated into the application being tested, and work by instrumenting the application's code to provide real-time feedback on any security vulnerabilities that are identified during runtime. This allows IAST tools to detect vulnerabilities that may not be visible through other forms of testing, such as those that are introduced by the application's configuration or environment.

Here are some key features of IAST:

1. Real-time feedback: IAST tools provide real-time feedback on security vulnerabilities as they are identified during runtime, allowing developers to fix them as they are found.

2. Accuracy: IAST tools have a high degree of accuracy because they are able to detect vulnerabilities in the context of the application's runtime environment.

3. Low false positive rate: IAST tools have a low false positive rate because they are able to distinguish between actual vulnerabilities and benign code.

4. Integration: IAST tools can be integrated into the development process, allowing developers to incorporate security testing into their workflows.

5. Automation: IAST tools can be automated, allowing for continuous testing and faster feedback on vulnerabilities.

6. Coverage: IAST tools can provide coverage for a wide range of security vulnerabilities, including those that may be difficult to detect through other forms of testing.


| IAST Tool    | Description   | 
|:---------------|:---------------------|
| `Contrast Security` | an IAST tool that automatically identifies and tracks vulnerabilities in real-time during the software development process. It can be integrated into a CI/CD pipeline to provide continuous monitoring and protection.	 | 
| `Hdiv Security` | an IAST solution that detects and prevents attacks by monitoring the runtime behavior of applications. It provides detailed insights into vulnerabilities and generates reports for developers and security teams.	 | 
| `RIPS Technologies` | a security testing tool that combines IAST with SAST (Static Application Security Testing) to provide comprehensive security analysis of web applications. It supports multiple programming languages and frameworks.	 | 
| `Acunetix` | a web application security tool that offers IAST capabilities for detecting vulnerabilities in real-time. It provides detailed reports and integrates with CI/CD pipelines to automate the security testing process.	 | 
| `AppSecEngineer` | an open-source IAST tool for detecting and preventing security vulnerabilities in web applications. It integrates with popular web frameworks such as Spring, Django, and Ruby on Rails, and provides detailed reports of vulnerabilities and attack attempts.	 | 



an example of a CI/CD pipeline with IAST using Contrast Security:

```
stages:
  - build
  - test
  - iast
  - deploy

build:
  stage: build
  script:
    - mvn clean package

test:
  stage: test
  script:
    - mvn test

iast:
  stage: iast
  image: contrastsecurity/contrast-agent
  script:
    - java -javaagent:/opt/contrast/contrast.jar -jar target/myapp.jar
  allow_failure: true

deploy:
  stage: deploy
  script:
    - mvn deploy
  only:
    - master
```

In this pipeline, the IAST stage is added after the test stage. The script in the IAST stage starts the Contrast Security agent using the Java command with the `-javaagent` option, and then starts the application using the `jar` command. The agent will monitor the application for security vulnerabilities and provide real-time feedback.

Note that this is just an example pipeline and it can be customized according to your needs. Also, make sure to configure the IAST tool properly and follow best practices for secure development and deployment.