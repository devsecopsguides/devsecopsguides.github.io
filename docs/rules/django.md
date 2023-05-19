---
layout: default
title: Django
parent: Rules
---

# Django
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
# Noncompliant code
from django.shortcuts import render

def post_comment(request):
    name = request.POST.get('name')
    message = request.POST.get('message')

    return render(request, 'comment.html', {'name': name, 'message': message})
```

In this noncompliant code, the post_comment view function retrieves user input from the request and directly passes it to the template without any form of sanitization or validation. This leaves the application vulnerable to Cross-Site Scripting (XSS) attacks, as an attacker can submit malicious script tags or code that will be rendered as-is when the template is rendered.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
# Compliant code
from django.shortcuts import render
from django.utils.html import escape

def post_comment(request):
    name = request.POST.get('name')
    message = request.POST.get('message')
    
    sanitized_message = escape(message)

    return render(request, 'comment.html', {'name': name, 'message': sanitized_message})
```


In the compliant code, the escape function from django.utils.html is used to sanitize the user input by escaping special characters that have special meaning in HTML. This ensures that user-supplied input is treated as plain text when rendered in the template, preventing it from being executed as code.

It's important to note that while the escape function provides basic protection against XSS attacks, it is context-specific. Depending on the specific output context (e.g., HTML attributes, JavaScript, CSS), additional sanitization or encoding may be required. Django provides other utilities like mark_safe and template filters (safe, escapejs, etc.) that can be used to handle different output contexts.

In addition to input sanitization, other security measures you can implement in Django to mitigate XSS vulnerabilities include:

* Using Django's built-in template engine and its automatic HTML escaping features to ensure that user-generated content is properly escaped.
* Applying proper output encoding when rendering dynamic data within HTML attributes or other contexts that require different escaping rules.
* Implementing Content Security Policies (CSP) to control the types of content allowed to be loaded and executed on your web pages.

By properly sanitizing user input and implementing security measures throughout your Django application, you can effectively mitigate XSS vulnerabilities and enhance the overall security of your web application.

