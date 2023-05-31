---
layout: default
title: Virtual Patching
parent: Operate
---

# Virtual Patching
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---


Virtual patching is a security technique used in DevSecOps to provide temporary protection against known vulnerabilities in software applications or systems. Virtual patching involves the use of security policies, rules, or filters that are applied to network traffic, system logs, or application code to prevent known vulnerabilities from being exploited.

Virtual patching can be used when a vendor-provided patch is not available or when patching is not feasible due to operational constraints or business needs. It allows organizations to quickly and easily protect their systems against known vulnerabilities without having to take the application or system offline or make changes to the underlying code.

Some of the key benefits of virtual patching in DevSecOps include:

1. Reduced risk of exploitation: By applying virtual patches to known vulnerabilities, organizations can reduce the risk of these vulnerabilities being exploited by attackers.

2. Improved security posture: Virtual patching allows organizations to quickly and easily protect their systems against known vulnerabilities, improving their overall security posture.

3. Reduced downtime: Virtual patching can be implemented quickly and easily, without requiring system downtime or disrupting business operations.

4. Improved compliance: Virtual patching can help organizations meet regulatory requirements for timely patching of known vulnerabilities.

Virtual patching can be implemented using a variety of techniques, including intrusion prevention systems (IPS), web application firewalls (WAF), and network-based security devices. It can also be implemented through the use of automated security policies or scripts that are applied to systems and applications.






## Log Collection



### Splunk

1- Configure Data Inputs: Configure data inputs to receive data from various sources, such as network devices, servers, and applications. Configure data inputs for the following:

* Syslog
* Windows Event Logs
* Network Traffic (using the Splunk Stream add-on)
* Cloud Platform Logs (e.g., AWS CloudTrail, Azure Audit Logs)

2- Create Indexes: Create indexes to store the data from the configured data inputs. Indexes can be created based on data types, such as security events, network traffic, or application logs.

3- Create a Dashboard: Create a dashboard to visualize the data collected from the data inputs. A dashboard can display the following:

* Real-time events and alerts
* Trending graphs and charts
* Security reports and metrics
 
4- Create a Sample Rule for Detection: Create a sample rule to detect an attack or security incident. For example, create a rule to detect failed login attempts to a web application. The following steps show how to create the rule in Splunk:

* Create a search query: Create a search query to identify failed login attempts in the web application logs. For example:


```
sourcetype=apache_access combined=*login* status=401 | stats count by clientip
```



## Virtual Patching

Virtual patching is a security mechanism that helps protect applications and systems from known vulnerabilities while developers work on creating and testing a patch to fix the vulnerability. It involves implementing a temporary, software-based solution that can block or mitigate the attack vectors that could be used to exploit the vulnerability. This is done by creating rules or policies within security software, such as web application firewalls or intrusion detection/prevention systems, that block or alert on malicious traffic attempting to exploit the vulnerability.

Virtual patching can be an effective way to quickly and temporarily secure systems against known vulnerabilities, particularly those that may be actively targeted by attackers. It can also provide time for organizations to test and implement permanent patches without leaving their systems exposed to attacks.





| Name    | Language   | 
|:---------------|:---------------------|
| `Java` | Contrast Security, Sqreen, AppSealing, JShielder |
| `.NET	` | Contrast Security, Sqreen, Nettitude, Antimalware-Research |
| `Node.js	` | Sqreen, RASP.js, Jscrambler, nexploit |
| `Python` | RASP-Protect, PyArmor, Striker, nexploit |
| `PHP` | Sqreen, RIPS Technologies, RSAS, nexploit |
| `Ruby` | Sqreen, RASP-Ruby, nexploit |




example RASP rule to mitigate SQL Injection vulnerability:

```
import javax.servlet.http.HttpServletRequest;
import com.rasp.scanner.RASP;
import com.rasp.scanner.ELExpression;

public class SQLInjectionRule {

  public static void checkSQLInjection(HttpServletRequest request) {

    // Get the input parameters from the request
    String username = request.getParameter("username");
    String password = request.getParameter("password");

    // Check for SQL injection in the username parameter
    if (RASP.isSQLInjection(username)) {
      // Log the attack attempt
      RASP.log("SQL injection detected in username parameter");
      // Block the request
      RASP.blockRequest("SQL injection detected");
    }

    // Check for SQL injection in the password parameter
    if (RASP.isSQLInjection(password)) {
      // Log the attack attempt
      RASP.log("SQL injection detected in password parameter");
      // Block the request
      RASP.blockRequest("SQL injection detected");
    }
  }
}
```

This rule checks for SQL injection attacks in the "username" and "password" parameters of a HTTP request. If an attack is detected, the rule logs the attempt and blocks the request.



Cheatsheet for prevention rules for the OWASP Top 10 vulnerabilities

```

OWASP Type      Vulnerability                    Rule/Policy

Injection       SQL Injection                    /^[^']*$/i
                Command Injection                /^[^']*$/i
                LDAP Injection                   /^[^']*$/i
                XPath Injection                  /^[^']*$/i
                OS Command Injection             /^[^']*$/i
                Expression Language Injection    /^[^']*$/i

Broken          Broken Authentication            2FA or MFA implementation
Authentication  Password Management              Password complexity and expiry policy
                Brute Force Prevention           Account lockout policy

Sensitive Data  Sensitive Data Exposure           Encryption in transit and at rest
Exposure        Cross-Site Request Forgery (CSRF)CSRF tokens for all forms
                Broken Access Control            Role-based access control

Security        Security Misconfiguration        Regular security assessments and compliance checks
Misconfiguration
                Insecure Cryptographic Storage   Strong cryptographic algorithms and key management
                Insufficient Logging & Monitoring Log all security-relevant events
                Insufficient Attack Protection   Application firewall (WAF) to prevent OWASP Top 10 attacks

Cross-Site      Cross-Site Scripting (XSS)        Encoding user input
Scripting
                Insecure Direct Object References Access control checks and input validation

Insecure        Using Components with            Regular patching and updates
Components      Known Vulnerabilities

```


### SQL Injection

#### RASP

```
when {
    event.type == "http" &&
    event.action == "param_value" &&
    http.param.name.matches("(?i).*((select|union|insert|update|delete|from|where|order by|group by|having|or|and).*)")
} then {
    block();
    raise "SQL Injection detected in param: " + http.param.name;
}
```

#### WAF

```
SecRule ARGS "@rx ^[a-zA-Z0-9\s]+$" \
    "id:1,\
    phase:2,\
    t:none,\
    deny,\
    msg:'Possible SQL Injection Attack'"
```

### Command Injection

```
when {
    event.type == "http" &&
    event.action == "param_value" &&
    http.param.name.matches("(?i).*((;|&|`|\\|\\||\\||&&).*)")
} then {
    block();
    raise "Command Injection detected in param: " + http.param.name;
}
```

#### RASP

```
SecRule ARGS "@rx ^[a-zA-Z0-9\s]+$" \
    "id:2,\
    phase:2,\
    t:none,\
    deny,\
    msg:'Possible Command Injection Attack'"
```

#### WAF

```
SecRule ARGS "@rx ^[a-zA-Z0-9\s]+$" \
    "id:2,\
    phase:2,\
    t:none,\
    deny,\
    msg:'Possible Command Injection Attack'"
```


### XSS

#### RASP

```
when {
    event.type == "http" &&
    event.action == "param_value" &&
    http.param.value.matches("(?i).*((<script|<img|alert|prompt|document.cookie|window.location|onerror|onload).*)")
} then {
    block();
    raise "XSS detected in param: " + http.param.name;
}
```

#### WAF

##### Script Tag Prevention Rule


```
SecRule ARGS|XML:/* "@rx <script.*?>" \
    "id:3,\
    phase:2,\
    t:none,\
    deny,\
    msg:'Possible XSS Attack via Script Tag'"
```

##### Attribute Injection Prevention Rule


```
SecRule ARGS|XML:/* "(<|&lt;)script[\s\S]+?=" \
    "id:4,\
    phase:2,\
    t:none,\
    deny,\
    msg:'Possible XSS Attack via Attribute Injection'"

```