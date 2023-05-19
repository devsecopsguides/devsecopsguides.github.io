n---
layout: default
title: Maven
parent: Checklists
---

# Maven Hardening for DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>List of some best practices to harden Maven for DevSecOps


### Use Maven Central with HTTPS	

Set Maven to use HTTPS when communicating with the Maven Central repository by adding the following to your `settings.xml` file:<br><br>`<mirrors><mirror><id>central</id><url>https://repo.maven.apache.org/maven2</url><mirrorOf>central</mirrorOf></mirror></mirrors>`



### Verify PGP signatures	


Download the .asc file for each dependency and plugin from Maven Central and verify its PGP signature using the gpg --verify command.


### Limit repository access	

Only grant repository access to trusted users and machines. Limit access to write operations where possible.



### Use a private repository

Set up a private Maven repository to store artifacts and dependencies that are not publicly available. This limits the risk of downloading compromised or malicious artifacts.


### Use Maven wrapper

Use the `mvnw` script or `mvnw.cmd` script on Windows instead of relying on a system-wide installation of Maven. This ensures that the same version of Maven is used across all environments and reduces the risk of dependency conflicts.


### Scan for vulnerabilities

Use a dependency scanner such as OWASP Dependency-Check or Snyk to scan for known vulnerabilities in your dependencies.


### Use least privilege

Use the principle of least privilege to limit the permissions of your Maven build process.



### Enable verbose logging

Enable verbose logging in Maven to capture more information about the build process. This can help diagnose issues and detect any suspicious behavior.



### Keep Maven up-to-date

Keep Maven and its plugins up-to-date to ensure that security vulnerabilities are addressed in a timely manner.
