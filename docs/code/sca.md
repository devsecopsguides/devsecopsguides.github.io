---
layout: default
title:  SCA
parent: Code
---

# SCA
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




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




## OWASP Dependency-Check


1- Perform a scan on a local project

```
dependency-check.sh --scan <path/to/project>
```


2- Scan a Maven Project

```
dependency-check.sh --scan <path/to/pom.xml>
```


3- Scan a Gradle Project

```
dependency-check.sh --scan <path/to/build.gradle>
```


4- Perform a scan on a local project

```
dependency-check.sh --updateonly
```


5- Specify Database Connection String

```
dependency-check.sh --scan <path/to/project> --connectionString <db-connection-string>
```

6- Specify CVSS Severity Threshold

```
dependency-check.sh --scan <path/to/project> --suppression <suppression-file>
```

7- Specify Output Format

```
dependency-check.sh --scan <path/to/project> --format <output-format>
```



## scancode-toolkit


1. Install scancode-toolkit:

```
pip install scancode-toolkit
```


2. Perform a scan on a specific project or directory

```
scancode <path-to-project>
```

3. Generate a scan report in JSON format

```
scancode --json-pp <path-to-project> > report.json
```

4. Exclude specific licenses from the scan

```
scancode --license-exclude <license-name> <path-to-project>
```



## Nexus Dependency Management

1. Install Nexus Repository Manager 

```
wget <nexus_download_url> -O nexus.zip
unzip nexus.zip  
cd nexus-x.x.x ./bin/nexus start
```

2. Configure Nexus Repository Manager 

Open web browser and access `http://localhost:8081`



{: .note }
Integrate vulnerability scanning tools like OWASP Dependency Check or Sonatype Nexus IQ with Nexus Repository Manager. These tools can analyze your dependencies for known security vulnerabilities and provide actionable insights to mitigate risks. Regularly scan your repositories for vulnerabilities and apply patches or upgrade dependencies as necessary.


{: .note }
Continuous Integration and Deployment (CI/CD) Integration: Integrate Nexus Repository Manager with your CI/CD pipelines to automate dependency management. Use build tool plugins or APIs provided by Nexus Repository Manager to fetch dependencies and publish artifacts seamlessly within your build and deployment processes.


### Dependency Vulnerability Management

Integrate Nexus Lifecycle or Nexus IQ into your CI/CD pipeline to scan and analyze dependencies for vulnerabilities.

```
# .gitlab-ci.yml
stages:
  - build
  - test

scan_dependencies:
  stage: build
  image: maven:3.8.4
  script:
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list -B
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-open -B
    - mvn clean package
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close -B
  only:
    - master
```

### License Compliance

Code: Integrate Nexus Lifecycle or Nexus IQ to scan and enforce license compliance.

```
# Jenkinsfile
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'mvn clean install'
      }
    }
    stage('Scan Licenses') {
      steps {
        sh 'mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list'
        // Perform license compliance checks
        sh 'mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close'
      }
    }
  }
}
```

Configuration: Configure Nexus Repository Manager to enforce license policies and restrictions.

```
<!-- pom.xml -->
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.sonatype.plugins</groupId>
        <artifactId>nexus-staging-maven-plugin</artifactId>
        <version>1.6.8</version>
      </plugin>
    </plugins>
  </build>
</project>
```

### Continuous Monitoring

Code: Implement continuous monitoring and scanning of your CI/CD pipeline for security vulnerabilities and compliance issues.

```
# .travis.yml
language: java
script:
  - mvn clean install
  - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list
  # Run additional security scans and tests
  - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close
```

Configuration: Set up automated alerts and notifications for any security or compliance issues detected during the CI/CD process.

```
<!-- pom.xml -->
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.sonatype.plugins</groupId>
        <artifactId>nexus-staging-maven-plugin</artifactId>
        <version>1.6.8</version>
        <configuration>
          <!-- Nexus Repository URL -->
          <serverId>nexus-server</serverId>
          <nexusUrl>https://nexus.example.com</nexusUrl>
          <autoReleaseAfterClose>true</autoReleaseAfterClose>
        </configuration>
        <executions>
          <execution>
            <id>default-deploy</id>
            <phase>deploy</phase>
            <goals>
              <goal>deploy</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
  <!-- Other project configurations -->
</project>
```









