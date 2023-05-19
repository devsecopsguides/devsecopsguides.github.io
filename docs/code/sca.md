---
layout: default
title:  SCA
parent: Code
---

# SCA
{: .no_toc }




SCA stands for Software Composition Analysis. It is a type of application security testing that focuses on identifying and managing third-party components and dependencies used within an application. SCA tools scan an application's codebase and build artifacts to identify any third-party libraries or components, and then assess those components for known security vulnerabilities or other issues.


the SCA process typically involves the following steps:

1. **Discovery**: The SCA tool scans the application's codebase and build artifacts to identify any third-party libraries or components used within the application.

2. **Inventory**: The SCA tool creates an inventory of all the third-party components and libraries used within the application, including their versions, license types, and any known security vulnerabilities or issues.

3. **Assessment**: The SCA tool assesses each component in the inventory for known security vulnerabilities or other issues, using sources such as the National Vulnerability Database (NVD) and Common Vulnerabilities and Exposures (CVE) databases.

4. **Remediation**: Based on the results of the assessment, the SCA tool may provide recommendations for remediation, such as upgrading to a newer version of a component, or switching to an alternative component that is more secure.

By performing SCA, organizations can gain visibility into the third-party components and libraries used within their applications, and can proactively manage any security vulnerabilities or issues associated with those components. This can help to improve the overall security and resilience of the application.

SCA tools work by scanning your codebase and identifying the open source components that are used in your application. They then compare this list against known vulnerabilities in their database and alert you if any vulnerabilities are found. This helps you to manage your open source components and ensure that you are not using any vulnerable components in your application.






| SCA Tool    | Description   | Languages Supported |
|:---------------|:---------------------|:---------------------|
| `Sonatype Nexus Lifecycle	` | A software supply chain automation and management tool	 | Java, .NET, Ruby, JavaScript, Python, Go, PHP, Swift |
| `Black Duck` | An open source security and license compliance management tool	 | Over 20 languages including Java, .NET, Python, Ruby, JavaScript, PHP |
| `WhiteSource` | A cloud-based open source security and license compliance management tool	 | Over 30 languages including Java, .NET, Python, Ruby, JavaScript, PHP |
| `Snyk` | A developer-first security and dependency management tool	 | Over 40 languages including Java, .NET, Python, Ruby, JavaScript, PHP, Go |
| `FOSSA` | A software development tool that automates open source license compliance and vulnerability management	 | Over 30 languages including Java, .NET, Python, Ruby, JavaScript, PHP |





Here is an example of how to use SCA in a CI/CD pipeline:

1. Choose an SCA tool: There are several SCA tools available in the market, such as Snyk, Black Duck, and WhiteSource. You need to choose an SCA tool that is compatible with your application stack and provides the features that you need.

2. Integrate the tool into your CI/CD pipeline: Once you have chosen an SCA tool, you need to integrate it into your CI/CD pipeline. This can be done by adding a step in your pipeline that runs the SCA tool and reports the results.

3. Configure the tool: You need to configure the SCA tool to scan your application code and identify the open source components that are used in your application. This can be done by providing the tool with access to your source code repository and specifying the dependencies of your application.

4. Analyze the results: Once the SCA tool has finished scanning your codebase, it will generate a report of the open source components that are used in your application and any vulnerabilities that are associated with those components. You need to analyze the report and take action on any vulnerabilities that are identified.

5. Remediate the vulnerabilities: If any vulnerabilities are identified, you need to remediate them by either upgrading the vulnerable components or removing them from your application.


Here is an example of a CI/CD pipeline that includes an SCA step:


```
name: MyApp CI/CD Pipeline

on:
  push:
    branches: [ master ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Build and test
      run: |
        npm install
        npm test

    - name: Run SCA
      uses: snyk/actions@v1
      with:
        file: package.json
        args: --severity-threshold=high

    - name: Deploy to production
      if: github.ref == 'refs/heads/master'
      run: deploy.sh

```


In this example, the SCA tool is integrated into the pipeline using the Snyk GitHub Action. The tool is configured to scan the package.json file and report any vulnerabilities with a severity threshold of "high". If any vulnerabilities are identified, the pipeline will fail and the developer will be notified to take action.







