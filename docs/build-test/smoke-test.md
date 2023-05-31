---
layout: default
title: Smoke Test
parent: Build & Test
---

# Smoke Test
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


Smoke tests are typically conducted on a small subset of the application's functionality, and are designed to be quick and easy to execute. They may include basic checks such as verifying that the application can be launched, that key features are functional, and that data is being processed correctly. If the smoke test passes, the application can be considered ready for further testing.


Example commands for performing smoke tests in DevSecOps:

## HTTP requests:

* Use tools like cURL or HTTPie to make HTTP requests to the application's endpoints and verify that they return the expected responses.
* For example, you might run a command like `curl http://localhost:8080/api/health` to check the health of the application.


## Database queries:

* Use SQL queries to verify that the application is correctly reading from and writing to the database.
* For example, you might run a command like `mysql -u user -p password -e "SELECT * FROM users WHERE id=1"` to verify that a user with ID 1 exists in the database.


## Scripted tests:

* Use testing frameworks like Selenium or Puppeteer to automate browser-based tests and verify that the application's UI is working correctly.
* For example, you might create a script using Puppeteer that logs in to the application and verifies that the user profile page is displayed correctly.


## Unit tests:

* Use unit testing frameworks like JUnit or NUnit to test individual functions and methods in the application.
* For example, you might run a command like `mvn test` to run all of the unit tests in a Java application.
