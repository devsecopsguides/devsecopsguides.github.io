---
layout: default
title: Ruby on Rails
parent: Rules
---

# Ruby on Rails
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
def create
  @comment = Comment.new(comment_params)
  
  if @comment.save
    redirect_to @comment
  else
    render 'new'
  end
end
```

In this noncompliant code, the create action is handling the creation of a comment in Ruby on Rails. However, it does not include any sanitization or validation of the user input. Consequently, if an attacker submits a comment with malicious HTML or JavaScript code, it will be rendered as-is when the comment is displayed, leading to a Cross-Site Scripting (XSS) vulnerability.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
# Compliant code
def create
  @comment = Comment.new(comment_params)
  
  if @comment.save
    redirect_to @comment
  else
    flash.now[:error] = "Comment creation failed."
    render 'new'
  end
end
```


In the compliant code, a new comment is created as before, but instead of rendering the 'new' template when there is an error, a flash message is set to notify the user about the failure. By using the flash.now mechanism, the message is displayed within the same request-response cycle, ensuring that the user input is not directly rendered back to the browser and reducing the risk of XSS attacks.

To further enhance the protection against XSS vulnerabilities in Ruby on Rails, you can utilize the built-in HTML escaping mechanisms provided by the framework. For example, when rendering user-generated content in a view template, you can use the h or html_escape method to escape any HTML entities:

```
<%= h @comment.body %>
```


This ensures that the content is displayed as plain text and any HTML tags or special characters are properly escaped, preventing them from being executed as code.

In addition to input sanitization and HTML escaping, other security measures you can implement in Ruby on Rails to mitigate XSS vulnerabilities include:

* Using the Rails form helpers, such as form_for or form_tag, which automatically apply the necessary escaping and protection against CSRF attacks.
* Implementing Content Security Policies (CSP) to control the types of content allowed to be loaded and executed on your web pages.
* Applying proper output encoding or using specific rendering mechanisms, such as raw or html_safe, when rendering content that should be treated as trusted HTML.

By properly sanitizing user input, applying HTML escaping, and implementing security measures throughout your Rails application, you can effectively mitigate XSS vulnerabilities and enhance the overall security of your web application.




