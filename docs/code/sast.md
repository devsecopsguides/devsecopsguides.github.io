---
layout: default
title:  SAST
parent: Code
---

# SAST
{: .no_toc }





SAST, or Static Application Security Testing, is a technique used in application security to analyze the source code of an application for security vulnerabilities. SAST tools work by scanning the source code of an application without actually executing the code, searching for common coding errors, security flaws, and potential vulnerabilities.

SAST is a type of white-box testing, meaning that it relies on the tester having access to the source code of the application being tested. This allows SAST tools to perform a thorough analysis of the codebase, identifying potential vulnerabilities that may not be apparent through other testing techniques.




| SAST Tool    | Description   | Languages Supported |
|:---------------|:---------------------|:---------------------|
| `Checkmarx` | A SAST tool that analyzes source code for security vulnerabilities, providing real-time feedback to developers on potential issues.	 | Java, .NET, PHP, Python, Ruby, Swift, C/C++, Objective-C, Scala, Kotlin, JavaScript |
| `SonarQube` | A tool that provides continuous code inspection, identifying and reporting potential security vulnerabilities, as well as code quality issues.	 | Over 25 programming languages, including Java, C/C++, Python, JavaScript, PHP, Ruby |
| `Fortify Static Code Analyzer` | A SAST tool that analyzes source code for security vulnerabilities, providing detailed reports and recommendations for improving security.	 | Java, .NET, C/C++, Python, JavaScript |
| `Veracode Static Analysis` | A SAST tool that analyzes code for security vulnerabilities and compliance with industry standards, providing detailed reports and actionable recommendations.	 | Over 25 programming languages, including Java, .NET, Python, Ruby, PHP, JavaScript, C/C++ |
| `Semgrep` | Semgrep is designed to be fast and easy to use, and it supports multiple programming languages, including Python, Java, JavaScript, Go, and more. It uses a simple pattern matching language to identify patterns of code that are known to be vulnerable, and it can be configured to scan specific parts of a codebase, such as a single file or a directory.	 | Over 25 programming languages, including Java, .NET, Python, Ruby, PHP, JavaScript, C/C++ |
| `CodeQL` | CodeQL is based on a database of semantic code representations that allows it to perform complex analysis on code that other static analysis tools may miss. It supports a wide range of programming languages, including C, C++, C#, Java, JavaScript, Python, and more. CodeQL can be used to analyze both open source and proprietary code, and it can be used by both developers and security researchers.	 | Over 25 programming languages, including Java, .NET, Python, Ruby, PHP, JavaScript, C/C++ |





## Semgrep

Semgrep is designed to be fast and easy to use, and it supports multiple programming languages, including Python, Java, JavaScript, Go, and more. It uses a simple pattern matching language to identify patterns of code that are known to be vulnerable, and it can be configured to scan specific parts of a codebase, such as a single file or a directory.

Semgrep can be used as part of the software development process to identify vulnerabilities early on, before they can be exploited by attackers. It can be integrated into a CI/CD pipeline to automatically scan code changes as they are made, and it can be used to enforce security policies and coding standards across an organization.

create a sample rule. Here are the steps:

1. Install and set up Semgrep: To use Semgrep, you need to install it on your system. You can download Semgrep from the official website, or install it using a package manager like pip. Once installed, you need to set up a project and configure the scan settings.

2. Create a new Semgrep rule: To create a new Semgrep rule, you need to write a YAML file that defines the rule. The YAML file should contain the following information:

* The rule ID: This is a unique identifier for the rule.
* The rule name: This is a descriptive name for the rule.
* The rule description: This describes what the rule does and why it is important.
* The rule pattern: This is the pattern that Semgrep will use to search for the vulnerability.
* The rule severity: This is the severity level of the vulnerability (e.g. high, medium, low).
* The rule language: This is the programming language that the rule applies to (e.g. Python, Java, JavaScript).
* The rule tags: These are optional tags that can be used to categorize the rule.


Here is an example rule that checks for SQL injection vulnerabilities in Python code:

```
id: sql-injection-py
name: SQL Injection in Python Code
description: Checks for SQL injection vulnerabilities in Python code.
severity: high
language: python
tags:
  - security
  - sql-injection
patterns:
  - pattern: |
      db.execute("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'")
    message: |
      SQL injection vulnerability found in line {line}: {code}
```

3. Run Semgrep with the new rule: Once you have created the new rule, you can run Semgrep to scan your code. To run Semgrep, you need to specify the path to the code you want to scan and the path to the YAML file that contains the rule. Here is an example command:

```
semgrep --config path/to/rule.yaml path/to/code/
```

4. Review the scan results: After the scan is complete, Semgrep will display the results in the terminal. The results will include information about the vulnerabilities that were found, including the severity level, the location in the code where the vulnerability was found, and the code that triggered the rule.


how to use Semgrep in a CI/CD pipeline on GitHub:

1. Set up Semgrep in your project: To use Semgrep in your CI/CD pipeline, you need to install it and set it up in your project. You can do this by adding a semgrep.yml file to your project's root directory. The semgrep.yml file should contain the rules that you want to apply to your codebase.

Here is an example semgrep.yml file that checks for SQL injection vulnerabilities in Python code:

```
rules:
  - id: sql-injection-py
    pattern: db.execute("SELECT * FROM users WHERE username = $username AND password = $password")
```

2. Create a GitHub workflow: Once you have set up Semgrep in your project, you need to create a GitHub workflow that runs Semgrep as part of your CI/CD pipeline. To create a workflow, you need to create a .github/workflows directory in your project and add a YAML file that defines the workflow.


Here is an example semgrep.yml workflow that runs Semgrep on every push to the master branch:

```
name: Semgrep
on:
  push:
    branches:
      - master
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v2
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        args: -c semgrep.yml

```


3. Push changes to GitHub: Once you have created the workflow, you need to push the changes to your GitHub repository. This will trigger the workflow to run Semgrep on your codebase.

4. Review the results: After the workflow has completed, you can review the results in the GitHub Actions tab. The results will include information about the vulnerabilities that were found, including the severity level, the location in the code where the vulnerability was found, and the code that triggered the rule.



## CodeQL

CodeQL is based on a database of semantic code representations that allows it to perform complex analysis on code that other static analysis tools may miss. It supports a wide range of programming languages, including C, C++, C#, Java, JavaScript, Python, and more. CodeQL can be used to analyze both open source and proprietary code, and it can be used by both developers and security researchers.

To use CodeQL, developers write queries in a dedicated query language called QL. QL is a declarative language that allows developers to express complex analyses in a concise and understandable way. Queries can be written to check for a wide range of issues, such as buffer overflows, SQL injection vulnerabilities, race conditions, and more.

CodeQL can be integrated into a variety of development tools, such as IDEs, code review tools, and CI/CD pipelines. This allows developers to run CodeQL automatically as part of their development process and catch issues early in the development cycle.

Here is an example of how to create a CodeQL rule and run it:

1. Identify the issue: Let's say we want to create a CodeQL rule to detect SQL injection vulnerabilities in a Java web application.

2. Write the query: To write the query, we can use the CodeQL libraries for Java and the CodeQL built-in functions for detecting SQL injection vulnerabilities. Here is an example query:


```
import java

class SqlInjection extends JavaScript {
  SqlInjection() {
    this = "sql injection"
  }

  from MethodCall call, DataFlow::PathNode arg, SQL::StringExpression sqlExpr
  where call.getMethod().getName() = "executeQuery" and
        arg = call.getArgument(1) and
        arg = sqlExpr.getAnOperand() and
        exists (SQL::TaintedFlow tainted |
          tainted = dataFlow::taintThrough(arg, tainted) and
          tainted.(SQL::Source) and
          tainted.(SQL::Sink)
        )
  select call, "Potential SQL injection vulnerability"
}

```

This query looks for calls to the executeQuery method with a string argument that can be tainted with user input, and then checks if the argument is used in a way that could lead to a SQL injection vulnerability. If a vulnerability is detected, the query returns the call and a message indicating the potential vulnerability.

3. Test the query: To test the query, we can run it against a small sample of our codebase using the CodeQL CLI tool. Here is an example command:

```
$ codeql query run --database=MyAppDB --format=csv --output=results.csv path/to/query.ql
```

This command runs the query against a CodeQL database named MyAppDB and outputs the results to a CSV file named results.csv.

4. Integrate the query: To integrate the query into our development process, we can add it to our CodeQL database and run it automatically as part of our CI/CD pipeline. This can be done using the CodeQL CLI tool and the CodeQL GitHub Action.

Here is an example command to add the query to our CodeQL database:

```
$ codeql database analyze MyAppDB --queries=path/to/query.ql
```

And here is an example GitHub Action workflow to run the query automatically on every push to the master branch:

```
name: CodeQL

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/
```