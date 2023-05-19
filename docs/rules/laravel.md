---
layout: default
title: Laravel
parent: Rules
---

# Laravel
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public function store(Request $request)
{
    $name = $request->input('name');
    $message = $request->input('message');
    
    DB::table('comments')->insert([
        'name' => $name,
        'message' => $message,
    ]);
    
    return redirect()->back();
}
```

In this noncompliant code, the store method receives user input through the $request object and directly inserts it into the database without any validation or sanitization. This makes the application vulnerable to Cross-Site Scripting (XSS) attacks, as an attacker can submit malicious JavaScript code as the message input, which will be rendered as-is when displayed back to users.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
// Compliant code
public function store(Request $request)
{
    $name = $request->input('name');
    $message = $request->input('message');
    
    $sanitizedMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    
    DB::table('comments')->insert([
        'name' => $name,
        'message' => $sanitizedMessage,
    ]);
    
    return redirect()->back();
}
```


In the compliant code, the htmlspecialchars function is used to sanitize the user input before inserting it into the database. This function escapes special characters that have special meaning in HTML, preventing them from being interpreted as HTML tags or entities when displayed in the browser. This sanitization process helps mitigate XSS vulnerabilities by ensuring that user-supplied input is treated as plain text rather than executable code.

It's important to note that while the htmlspecialchars function provides basic protection against XSS attacks, it is context-specific. Depending on the specific output context (e.g., HTML attributes, JavaScript, CSS), additional sanitization or encoding may be required. Consider using specialized libraries or functions that are tailored to the specific output context to provide more comprehensive protection against XSS vulnerabilities.

In addition to input sanitization, other security measures you can implement in Laravel to mitigate XSS vulnerabilities include:

* Utilizing Laravel's built-in CSRF protection to prevent cross-site request forgery attacks.
* Applying output encoding using Laravel's Blade templating engine or helper functions like {{ }} to automatically escape variables.
* Implementing content security policies (CSP) to control the types of content allowed to be loaded and executed on your web pages.

By properly sanitizing user input and implementing security measures throughout your Laravel application, you can effectively mitigate XSS vulnerabilities and enhance the overall security of your web application.