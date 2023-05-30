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


```php
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


```php
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









### SQL injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$userInput = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '".$userInput."'";
$results = DB::select($query);
```

In this noncompliant code, the user input is directly concatenated into the SQL query string, creating a vulnerability known as SQL injection. An attacker can manipulate the input to inject malicious SQL statements, potentially gaining unauthorized access to the database or manipulating its contents.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$userInput = $_GET['username'];
$results = DB::select("SELECT * FROM users WHERE username = ?", [$userInput]);
```


In the compliant code, Laravel's query builder is used with prepared statements to mitigate SQL injection. The user input is bound to a placeholder (?) in the query, and Laravel handles the proper escaping and sanitization of the input.

By using prepared statements, the compliant code ensures that user input is treated as data rather than executable SQL code, thereby preventing SQL injection attacks.








### Broken Access Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function deletePost(Request $request, $postId)
{
    $post = Post::find($postId);
    
    // Check if the currently authenticated user is the owner of the post
    if ($post->user_id == Auth::user()->id) {
        $post->delete();
        return redirect('/dashboard')->with('success', 'Post deleted successfully.');
    } else {
        return redirect('/dashboard')->with('error', 'You do not have permission to delete this post.');
    }
}
```

In this noncompliant code, the deletePost method assumes that the currently authenticated user is authorized to delete any post based solely on their user ID. However, it fails to perform proper access control checks to ensure that the user is the actual owner of the post. This can lead to broken access control, allowing unauthorized users to delete posts.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function deletePost(Request $request, $postId)
{
    $post = Post::find($postId);
    
    // Check if the currently authenticated user is the owner of the post
    if ($post->user_id == Auth::user()->id) {
        $post->delete();
        return redirect('/dashboard')->with('success', 'Post deleted successfully.');
    } else {
        abort(403, 'Unauthorized');
    }
}
```

In the compliant code, the deletePost method performs the same check to verify if the authenticated user is the owner of the post. However, instead of redirecting with an error message, it throws a 403 Forbidden exception using the abort function if the user is not authorized. This ensures that unauthorized users cannot determine the existence of a post they don't have access to.








### Cryptographic Failures

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function encryptData($data, $key)
{
    return encrypt($data, $key);
}

public function decryptData($encryptedData, $key)
{
    return decrypt($encryptedData, $key);
}
```

In this noncompliant code, the encryptData and decryptData functions use the default Laravel encryption functions encrypt and decrypt to perform cryptographic operations. However, this code does not consider important aspects of cryptographic security, such as key management, algorithm selection, and secure handling of sensitive data. This can lead to cryptographic failures and vulnerabilities in the application.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
use Illuminate\Support\Facades\Crypt;

public function encryptData($data, $key)
{
    return Crypt::encryptString($data);
}

public function decryptData($encryptedData, $key)
{
    try {
        return Crypt::decryptString($encryptedData);
    } catch (DecryptException $e) {
        // Handle decryption error
    }
}
```


In the compliant code, we use Laravel's Crypt facade to perform the encryption and decryption operations. The encryptString and decryptString methods provided by the Crypt facade offer a more secure approach for cryptographic operations. Additionally, error handling is implemented using a try-catch block to properly handle decryption errors, such as when an incorrect key is provided.






### Insecure Design

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function getUserProfile($userId)
{
    $user = User::find($userId);

    if ($user) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role,
        ];
    }

    return null;
}
```

In this noncompliant code, the getUserProfile function retrieves a user's profile information based on the provided $userId. However, it lacks proper access control and authorization checks. Any user can potentially access the profile information of any other user, bypassing the necessary security measures.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function getUserProfile($userId, $requestingUserId)
{
    $requestingUser = User::find($requestingUserId);

    if ($requestingUser && $requestingUser->isAdmin()) {
        $user = User::find($userId);

        if ($user) {
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
            ];
        }
    }

    return null;
}
```

In the compliant code, we have introduced an additional parameter $requestingUserId to identify the user making the request. We first check if the requesting user exists and if they have the necessary privileges, such as being an administrator, to access the profile information. Only if these conditions are met, the profile information is returned. Otherwise, null is returned, indicating the lack of authorization.







### Security Misconfiguration

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// config/database.php

return [
    'default' => 'mysql',
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => '127.0.0.1',
            'port' => '3306',
            'database' => 'mydatabase',
            'username' => 'root',
            'password' => '',
            'unix_socket' => '',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => false,
            'engine' => null,
        ],
    ],
];
```

In this noncompliant code, the database configuration file config/database.php contains sensitive information, such as the database credentials. The password field is empty, which means the application is using a default or weak password, making it vulnerable to unauthorized access. Additionally, the strict mode is disabled, which can lead to insecure SQL queries.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// config/database.php

return [
    'default' => env('DB_CONNECTION', 'mysql'),
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'mydatabase'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ],
    ],
];
```


In the compliant code, sensitive information such as the database credentials are not hard-coded directly in the configuration file. Instead, environment variables are used to retrieve the values. This allows for better security by keeping the sensitive information separate from the codebase and configurable based on the deployment environment.



By using environment variables, you can easily manage different configurations for development, testing, and production environments without exposing sensitive information in the codebase or version control system.






### Vulnerable and Outdated Components

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
composer require laravel/framework:5.7.0
```

In this noncompliant code, the Laravel framework version 5.7.0 is explicitly specified. This can lead to using a vulnerable and outdated version of the framework, as newer versions may contain security patches and bug fixes.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
composer require laravel/framework:^8.0
```


In the compliant code, the Laravel framework version is specified using a version constraint ^8.0. This allows Composer, the PHP dependency manager, to install the latest compatible version of the Laravel framework within the major version 8.x. This ensures that you receive the latest security updates and improvements.






### Identification and Authentication Failures

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    if (Auth::attempt($credentials)) {
        // User authenticated successfully
        return redirect()->intended('/dashboard');
    } else {
        // Authentication failed
        return redirect()->back()->withErrors(['Invalid credentials']);
    }
}
```

In this noncompliant code, the authentication process solely relies on the Auth::attempt() method, which attempts to authenticate the user based on the provided email and password. However, this code does not handle certain authentication failures appropriately, such as account lockouts or brute-force protection.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    if (Auth::attempt($credentials)) {
        // User authenticated successfully
        return redirect()->intended('/dashboard');
    } else {
        // Authentication failed
        if (Auth::exists(['email' => $request->input('email')])) {
            // Invalid password provided
            return redirect()->back()->withErrors(['Invalid password']);
        } else {
            // Invalid email provided
            return redirect()->back()->withErrors(['Invalid email']);
        }
    }
}
```


In the compliant code, we have enhanced the authentication process by considering different types of authentication failures. If the provided email exists in the system database but the password is incorrect, we show an appropriate error message indicating an invalid password. If the provided email does not exist, we show an error message indicating an invalid email.






### Software and Data Integrity Failures

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function updateProfile(Request $request)
{
    $user = Auth::user();

    $user->name = $request->input('name');
    $user->email = $request->input('email');
    $user->save();

    return redirect('/profile');
}
```

In this noncompliant code, the user's profile information is updated directly based on the user input received from the request. While this code successfully updates the user's name and email, it lacks proper validation and sanitization of the input, which can lead to software and data integrity failures.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function updateProfile(Request $request)
{
    $user = Auth::user();

    $validatedData = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|email|unique:users,email,' . $user->id,
    ]);

    $user->name = $validatedData['name'];
    $user->email = $validatedData['email'];
    $user->save();

    return redirect('/profile');
}
```


In the compliant code, we have added validation rules to ensure the integrity of the software and data. The validate() method is used to validate the input fields against specific rules. In this example, the name field is required and should be a string with a maximum length of 255 characters. The email field is also required and must be a valid email format. Additionally, the email field is validated for uniqueness, ensuring that no other user in the database has the same email.





### Security Logging and Monitoring Failures

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function deleteUser(Request $request)
{
    $userId = $request->input('user_id');

    $user = User::find($userId);

    if ($user) {
        $user->delete();
    }

    return redirect('/users');
}
```

In this noncompliant code, when a user is deleted, there is no logging or monitoring mechanism in place to track this activity. The code simply deletes the user if found and redirects back to the list of users. Without proper logging and monitoring, it becomes challenging to identify and investigate any unauthorized or suspicious user deletions.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function deleteUser(Request $request)
{
    $userId = $request->input('user_id');

    $user = User::find($userId);

    if ($user) {
        $user->delete();

        // Log the user deletion activity
        Log::info('User deleted', ['user_id' => $userId]);
    }

    return redirect('/users');
}
```


In the compliant code, we have added a logging mechanism to track the user deletion activity. After successfully deleting the user, we use Laravel's Log facade to record an information-level log entry. The log message includes relevant details such as the user ID that was deleted. By incorporating logging into the code, we can keep a record of important security-related events and establish an audit trail for future analysis and monitoring.





### Server-Side Request Forgery

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
public function fetchExternalData(Request $request)
{
    $url = $request->input('url');

    $data = file_get_contents($url);

    return response()->json(['data' => $data]);
}
```

In this noncompliant code, the fetchExternalData method takes a URL input from the user and directly uses the file_get_contents function to fetch data from that URL. This can lead to a Server-Side Request Forgery vulnerability, where an attacker can provide a malicious URL that causes the application to perform unintended actions or access internal resources.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
public function fetchExternalData(Request $request)
{
    $url = $request->input('url');

    // Validate and sanitize the URL to prevent SSRF
    $validatedUrl = filter_var($url, FILTER_VALIDATE_URL);
    
    if (!$validatedUrl) {
        return response()->json(['error' => 'Invalid URL'], 400);
    }

    // Restrict allowed domains if necessary
    $allowedDomains = ['example.com', 'trusteddomain.com'];
    $parsedUrl = parse_url($validatedUrl);
    
    if (!in_array($parsedUrl['host'], $allowedDomains)) {
        return response()->json(['error' => 'Access to the specified domain is not allowed'], 403);
    }

    // Fetch the data
    $data = file_get_contents($validatedUrl);

    return response()->json(['data' => $data]);
}
```


In the compliant code, several measures are taken to mitigate the Server-Side Request Forgery vulnerability:

1. URL Validation and Sanitization: The URL input is validated and sanitized using the filter_var function with the FILTER_VALIDATE_URL filter. This ensures that the URL provided by the user is a valid URL.

1. Restrict Allowed Domains: If necessary, a whitelist of trusted domains can be maintained. The parsed URL's host is checked against this list to ensure that only trusted domains are accessed. This helps prevent access to potentially malicious or internal resources.

1. Proper Error Handling: In case of an invalid URL or unauthorized domain, appropriate error responses are returned. This ensures that potential SSRF attempts are properly handled and communicated to the user or client.
















