---
layout: default
title: Artifacts
parent: Build & Test
---

# Artifacts
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

Artifacts are typically created during the build and deployment process, and are stored in a repository or other storage location so that they can be easily retrieved and deployed as needed. There are a number of methods that can be used to save artifacts in a DevSecOps environment, including:

1. Build Artifacts: Build artifacts are created during the build process and include compiled code, libraries, and other files that are needed to deploy and run the application. These artifacts can be saved in a repository or other storage location for later use.

2. Container Images: Container images are a type of artifact that contain everything needed to run the application, including the code, runtime, and dependencies. These images can be saved in a container registry or other storage location and can be easily deployed to any environment that supports containers.

3. Infrastructure as Code (IaC) Artifacts: IaC artifacts are created as part of the configuration management process and include scripts, templates, and other files that are used to define and manage the infrastructure of the application. These artifacts can be stored in a repository or other storage location and can be used to deploy the infrastructure to any environment.

4. Test Artifacts: Test artifacts include test scripts, test results, and other files that are created as part of the testing process. These artifacts can be stored in a repository or other storage location for later reference and analysis.




## Checklist for developing an artifact in DevSecOps



1- Create a secure development environment:

* Set up a development environment that is separate from production.
* Use version control to track changes to the source code.
* Use secrets management tools to store sensitive information like API keys and passwords.

2- Implement security testing into the development process:

* Use static analysis security testing (SAST) tools to analyze the source code for vulnerabilities.
* Use dynamic application security testing (DAST) tools to test the application in a real-world environment.
* Use interactive application security testing (IAST) tools to detect vulnerabilities in real-time during testing.

3- Automate the build process:

Use build automation tools like Maven or Gradle to compile the source code and build the artifact.
Include security testing tools in the build process.

4- Automate deployment:

* Use configuration management tools like Ansible or Chef to automate deployment of the artifact.
* Use infrastructure-as-code tools like Terraform or CloudFormation to automate the creation and management of infrastructure.

5- Implement continuous integration/continuous delivery (CI/CD) practices:

* Use a CI/CD pipeline to automate the entire development process.
* Use tools like Jenkins or CircleCI to manage the pipeline and run tests automatically.




## Nexsus

### Define an Artifact

```
artifact:
  name: MyVulnerabilityScan
  type: vulnerability_scan
  target: target_host
```

### Schedule Artifact Execution

```
artifact_schedule:
  name: DailyVulnerabilityScan
  artifact: MyVulnerabilityScan
  schedule: cron(0 0 * * *)
```


### Run Artifact

```
artifact_run:
  name: VulnerabilityScan
  artifact: MyVulnerabilityScan
```

### Retrieve Artifact Results

```
artifact_results:
  name: VulnerabilityScanResults
  artifact: MyVulnerabilityScan
```


### Remediate Vulnerabilities

```
artifact_remediation:
  name: VulnerabilityRemediation
  artifact: MyVulnerabilityScan
  remediation_script: remediation_script.sh
```






