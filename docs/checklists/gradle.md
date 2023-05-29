---
layout: default
title: Gradle
parent: Checklists
---

# Gradle Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Gradle for DevSecOps


### Use the latest stable version of Gradle	



Check the latest version on the official website: https://gradle.org/releases/, and then install it. For example: wget https://services.gradle.org/distributions/gradle-7.0.2-bin.zip, unzip gradle-7.0.2-bin.zip, and set the PATH environment variable to the Gradle bin directory.



### Disable or restrict Gradle daemon	


You can disable the daemon by adding the following line to the gradle.properties file: org.gradle.daemon=false. Alternatively, you can restrict the maximum amount of memory that can be used by the daemon by setting the org.gradle.jvmargs property.


### Configure Gradle to use HTTPS for all repositories	

Add the following code to the build.gradle file to enforce using HTTPS for all repositories:

```
allprojects {
    repositories {
        mavenCentral {
            url "https://repo1.maven.org/maven2/"
        }
        maven {
            url "https://plugins.gradle.org/m2/"
        }
    }
}

```


### Use secure credentials for accessing repositories

Use encrypted credentials in the `build.gradle` file or environment variables for accessing repositories.


### Use plugins and dependencies from trusted sources only

Use plugins and dependencies from official sources, and avoid using those from unknown or untrusted sources. 


### Implement access controls for Gradle builds

Implement access controls to ensure that only authorized users can execute or modify Gradle builds.



### Regularly update Gradle and plugins

Regularly update Gradle and its plugins to ensure that security vulnerabilities are fixed and new features are added. Use the `gradle wrapper` command to ensure that all team members use the same version of Gradle.


