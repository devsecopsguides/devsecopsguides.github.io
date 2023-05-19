---
layout: default
title: PHP
parent: Rules
---

# PHP
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// Noncompliant code - exposing sensitive information in error log
function processUserInput($input) {
  // Process user input
  // ...
  
  // Log error with sensitive information
  error_log("Error processing user input: $input");
}
```

In this noncompliant code example, the function processUserInput() logs an error message that includes the user input directly into the error log. This can potentially expose sensitive information to anyone who has access to the error log file, including unauthorized users.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// Compliant code - avoiding exposure of sensitive information in error log
function processUserInput($input) {
  // Process user input
  // ...
  
  // Log error without sensitive information
  error_log("Error processing user input"); // Log generic error message
}
```


In the compliant code example, the function processUserInput() logs a generic error message without including the user input. By avoiding the inclusion of sensitive information in the error log, the code mitigates the risk of exposing sensitive data to unauthorized individuals.

It's important to note that error logs should only contain information necessary for debugging and should not include any sensitive data. Additionally, it's recommended to configure error log settings appropriately and restrict access to the error log files to authorized personnel only.



## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
// This code sends a user's password to a remote API as part of a JSON payload
$payload = json_encode(array('username' => 'alice', 'password' => 's3cret'));
$response = file_get_contents('https://example.com/api', null, stream_context_create(array(
    'http' => array(
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\n",
        'content' => $payload,
    ),
)));
?>
```

In the noncompliant code above, a user's password is included in a JSON payload that is sent to a remote API over HTTPS. However, since HTTPS only encrypts the payload in transit and not at rest, the password may be vulnerable to exposure if the remote API is compromised.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
// This code sends a user's password to a remote API as a URL parameter using HTTPS
$username = 'alice';
$password = 's3cret';
$api_url = 'https://example.com/api?username=' . urlencode($username) . '&password=' . urlencode($password);
$response = file_get_contents($api_url, null, stream_context_create(array(
    'http' => array(
        'method' => 'GET',
    ),
)));
?>
```


In the compliant code above, the user's password is not included in the payload but is instead sent as a URL parameter using HTTPS. This ensures that the password is encrypted in transit and not vulnerable to exposure if the remote API is compromised. Note that using GET requests to send sensitive information is not recommended, but this example is just for illustration purposes. A POST request would be more appropriate in most cases.




## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Transfer Funds">
</form>
```

In this noncompliant example, a form is submitted to a PHP script called "transfer.php" that transfers funds. The amount to be transferred is sent as a hidden form field called "amount". However, this code does not include any CSRF protection, meaning that an attacker could create a form on a different website that submits the same data to "transfer.php", tricking the user into transferring funds without their knowledge.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
session_start();
$_SESSION['token'] = bin2hex(random_bytes(32));
?>

<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
    <input type="submit" value="Transfer Funds">
</form>
```


In this compliant example, a unique token is generated and stored in a session variable before the form is displayed. The token is then included as a hidden field in the form. When the form is submitted, the token is checked in the PHP script to ensure that the request came from a legitimate source. If the token is missing or invalid, the transfer is not allowed.

This provides a basic protection against CSRF attacks, as the attacker would not be able to generate a valid token without having access to the user's session data.



## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// This code includes a hard-coded password directly in the script
$password = "MyHardCodedPassword123";
$connection = mysqli_connect("localhost", "myuser", $password, "mydatabase");
```




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// This code stores the password in a separate configuration file with restricted access
$config = parse_ini_file("/etc/myapp/config.ini");
$connection = mysqli_connect("localhost", "myuser", $config['db_password'], "mydatabase");
```

Hard-coded passwords in code are a security risk as they can be easily discovered by attackers and used to gain unauthorized access. In the noncompliant code example, the password is directly included in the script, making it vulnerable to exposure.

The compliant code example addresses this issue by storing the password in a separate configuration file with restricted access. This helps to protect the password from being easily discovered by attackers and limits its exposure to authorized personnel who have access to the configuration file.




## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
function encryptData($data, $key) {
    $iv = mcrypt_create_iv(16, MCRYPT_DEV_RANDOM);
    $encryptedData = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
    return $encryptedData;
}
```


In this example, the function encryptData() uses the mcrypt_encrypt() function with the MCRYPT_RIJNDAEL_128 algorithm for encryption. This algorithm is considered insecure and vulnerable to attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
function encryptData($data, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encryptedData);
}

```
In this example, the encryptData() function uses the openssl_encrypt() function with the aes-256-cbc algorithm for encryption, which is currently considered secure. Additionally, it uses openssl_random_pseudo_bytes() to generate a random initialization vector (IV) for each encryption, which improves the security of the encryption.

Broken or risky cryptographic algorithms are often used in applications and systems to protect sensitive data. However, the use of such algorithms can lead to vulnerabilities that can be exploited by attackers. In the noncompliant code example, the mcrypt_encrypt() function with the MCRYPT_RIJNDAEL_128 algorithm is used for encryption, which is considered insecure and vulnerable to attacks. In the compliant code example, the openssl_encrypt() function with the aes-256-cbc algorithm is used instead, which is currently considered secure. Additionally, the openssl_random_pseudo_bytes() function is used to generate a random initialization vector for each encryption, which further enhances the security of the encryption.





## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$token = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 8);
```


Insufficient entropy can lead to weak or easily guessable keys, tokens, or passwords, making them susceptible to brute-force attacks.

The above code generates a random token of 8 characters by shuffling a fixed set of characters. However, the set of characters is too small, and the token is easily guessable and susceptible to brute-force attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$token = bin2hex(random_bytes(16));
```

The above code generates a random token of 16 bytes using the random_bytes() function, which generates cryptographically secure pseudo-random bytes. The bin2hex() function converts the binary data into a hexadecimal string. The resulting token is much stronger and less susceptible to brute-force attacks.

In general, to avoid insufficient entropy vulnerability, it is recommended to use a cryptographically secure random number generator, such as random_bytes() or openssl_random_pseudo_bytes(), and ensure that the output has sufficient entropy, such as by using a sufficiently large key size or password length.




## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
$username = $_GET['username'];
echo "Welcome " . $username . "!";
?>
```

This code is noncompliant because it takes input directly from the user through the URL parameter "username" and displays it on the page without any validation or sanitization. An attacker could exploit this by injecting malicious JavaScript code into the "username" parameter, which would then execute in the user's browser, allowing the attacker to perform actions on the user's behalf or steal sensitive information.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
$username = htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');
echo "Welcome " . $username . "!";
?>
```


This code is compliant because it uses the PHP `htmlspecialchars` function to sanitize the user input in the "username" parameter. This function converts special characters such as `<`, `>`, and `&` to their HTML entity equivalents, preventing them from being interpreted as code by the browser. The `ENT_QUOTES` flag ensures that both single and double quotes are converted to their corresponding entities, and the `'UTF-8'` parameter specifies the character encoding used. By using this function, the code effectively mitigates the risk of XSS attacks.






## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
```

This code is vulnerable to SQL injection attacks because it uses user input directly in the SQL query without any validation or sanitization. An attacker can easily manipulate the input and inject malicious SQL code.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
```

This code uses mysqli_real_escape_string function to escape special characters in the user input, making it safe to use in the SQL query. However, it's worth noting that parameterized queries or prepared statements are generally a better approach for preventing SQL injection in PHP. Here's an example of how to use parameterized queries:

Compliant code with parameterized query:


```
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
```

This code uses a parameterized query with placeholders (?) for the user input and binds the values using bind_param function, which is a safer way to prevent SQL injection attacks.




## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$filename = $_GET['filename'];
$file = '/path/to/directory/' . $filename;
if (file_exists($file)) {
  // do something with the file
} else {
  // handle error
}
```


In the example above, the `$filename` variable is taken directly from user input via the `$_GET` superglobal. This means an attacker can manipulate the value of `$filename` to try to access files outside of the intended directory.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$filename = basename($_GET['filename']);
$file = '/path/to/directory/' . $filename;
if (file_exists($file) && is_file($file)) {
  // do something with the file
} else {
  // handle error
}
```

In the compliant code, the `basename()` function is used to extract only the file name portion of the user input. This helps to prevent directory traversal attacks. Additionally, the `is_file()` function is used to ensure that the path corresponds to an actual file rather than a directory or symlink.





## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
}
?>
```


In this noncompliant code, the application displays an error message that reveals the fact that the username or password entered was incorrect, which could help an attacker in a brute-force attack.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
} else {
  // Valid login
}
?>
```

In the compliant code, the application returns the same error message for an incorrect username or password, making it more difficult for an attacker to determine which field was incorrect.

Additionally, the application could be configured to log error messages that contain sensitive information, while providing a more generic error message to the user. This would allow the system administrator to identify and fix any errors while keeping sensitive information from being exposed to potential attackers.



## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];
$file = fopen('credentials.txt', 'w');
fwrite($file, "Username: $username, Password: $password");
fclose($file);
```



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$dbConnection = mysqli_connect('localhost', 'user', 'password', 'mydatabase');
$query = "INSERT INTO users (username, password) VALUES ('$username', '$hashedPassword')";
mysqli_query($dbConnection, $query);
```

The noncompliant code above writes the entered username and password to a text file without any encryption or protection. This could lead to a potential data breach if the text file falls into the wrong hands.

In the compliant code, the password is first hashed using the PHP password_hash() function, which uses a strong one-way hashing algorithm to securely store the password. The hashed password is then stored in a database using a prepared statement to prevent SQL injection attacks.




## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = ".$user_id;
$results = mysqli_query($conn, $query);
```

In the noncompliant code, the value of `$user_id` is taken directly from `$_GET`, which is an untrusted source, and then used in a SQL query without any validation or sanitization. This can allow an attacker to modify the SQL query and potentially extract or modify sensitive data from the database.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($user_id === false) {
    // handle invalid input
} else {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $results = $stmt->get_result();
}
```


In the compliant code, the value of `$user_id` is filtered using `filter_input()` with the `FILTER_VALIDATE_INT` filter, which ensures that the value is an integer. Then, a prepared statement is used to safely pass the value to the SQL query. This prevents SQL injection attacks by properly separating the query logic from the data values.





## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$password = $_POST['password'];
$hashed_password = sha1($password);
$query = "INSERT INTO users (username, password) VALUES ('{$_POST['username']}', '{$hashed_password}')";
mysqli_query($conn, $query);
```

In this code, the user's password is retrieved from the `$_POST` request without any validation or sanitation, and then hashed using the SHA-1 algorithm, which is no longer considered secure for password storage. Additionally, the hashed password is then inserted directly into a SQL query, which could be vulnerable to SQL injection attacks.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$password = $_POST['password'];
if (strlen($password) < 8) {
    // Handle error: password must be at least 8 characters long
}
$salt = bin2hex(random_bytes(16));
$hashed_password = password_hash($password . $salt, PASSWORD_ARGON2ID);
$stmt = $conn->prepare("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $_POST['username'], $hashed_password, $salt);
$stmt->execute();
```


In this code, the user's password is first validated to ensure it is at least 8 characters long. Then, a random 16-byte salt is generated using a cryptographically secure random number generator. The password and salt are then hashed using the Argon2id algorithm, which is currently considered one of the most secure password hashing algorithms. Finally, the prepared statement is used to insert the username, hashed password, and salt into the database, protecting against SQL injection attacks.





## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);

// use $xml here
```

In the noncompliant code, LIBXML_NOENT is used as an option to the simplexml_load_string function. This allows the XML parser to process entity references, which can be used by an attacker to inject malicious code and execute it on the server.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$disableEntities = libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);
libxml_disable_entity_loader($disableEntities);

// use $xml here
```


In the compliant code, libxml_disable_entity_loader is used to disable the loading of external entities in the XML parser. This prevents the parser from resolving external entity references, effectively mitigating the XXE vulnerability.





## display_errors 1

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// Example of security misconfiguration
ini_set('display_errors', 1);
```

In the noncompliant code example, the ini_set() function is used to enable the display of errors to the user. This can potentially expose sensitive information and error messages to attackers.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// Example of secure configuration
// Disable the display of errors to the user
ini_set('display_errors', 0);
// Log errors to a secure log file instead
ini_set('error_log', '/var/log/php_errors.log');
```


In the compliant code example, the ini_set() function is used to disable the display of errors to the user, and instead log them to a secure log file. This helps to ensure that sensitive information is not exposed to attackers and that any errors are properly logged for debugging purposes.


## Vulnerable and Outdated Components

### PHPMailer library

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
// Example of vulnerable and outdated components
// using an old version of PHPMailer library

require_once 'PHPMailer/class.phpmailer.php';

$mail = new PHPMailer();

$mail->IsSMTP();
$mail->SMTPDebug = 1;
$mail->SMTPAuth = true;
$mail->SMTPSecure = 'ssl';

$mail->Host = 'smtp.gmail.com';
$mail->Port = 465;

$mail->Username = 'example@gmail.com';
$mail->Password = 'password';

$mail->SetFrom('from@example.com', 'From Name');
$mail->AddReplyTo('reply@example.com', 'Reply-to Name');

$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

$mail->AddAddress('recipient@example.com', 'Recipient Name');

if (!$mail->Send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
} else {
    echo 'Message has been sent.';
}
?>
```

The noncompliant code example shows the use of an outdated version of the PHPMailer library, which is vulnerable to security exploits. Specifically, it uses a vulnerable authentication method that can be exploited to gain unauthorized access to the email account, and it sends emails over an insecure connection.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
// Example of secure and up-to-date code
// using the latest version of PHPMailer library

require_once 'PHPMailer/src/PHPMailer.php';
require_once 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer\PHPMailer\PHPMailer(true);

$mail->SMTPDebug = SMTP::DEBUG_SERVER;
$mail->isSMTP();
$mail->Host = 'smtp.gmail.com';
$mail->SMTPAuth = true;
$mail->Username = 'example@gmail.com';
$mail->Password = 'password';
$mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;

$mail->setFrom('from@example.com', 'From Name');
$mail->addAddress('recipient@example.com', 'Recipient Name');

$mail->isHTML(true);
$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

if (!$mail->send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
```


The compliant code example uses the latest version of the PHPMailer library, which has improved security and is up-to-date with the latest security best practices. Specifically, it uses a secure authentication method, sends emails over an encrypted connection, and is set up to display server-side debug information in case of errors.





## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$host = $_SERVER['HTTP_HOST'];
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://example.com', false, $context);
```

In the noncompliant code above, the `$host` variable is set to the HTTP host provided by the client. This means that an attacker can easily manipulate the HTTP host header and bypass certificate validation by setting a different host. This can lead to man-in-the-middle attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$host = 'example.com';
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://'.$host, false, $context);
```


In the compliant code above, the `$host` variable is set to a trusted value, `example.com`. This ensures that the certificate is validated against the correct host and reduces the risk of man-in-the-middle attacks.





## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// Example 1: Weak Password
$password = $_POST['password'];
if ($password === 'password123') {
    // Allow access
} else {
    // Deny access
}

// Example 2: Hardcoded Credentials
$username = 'admin';
$password = 'password';
if ($_POST['username'] === $username && $_POST['password'] === $password) {
    // Allow access
} else {
    // Deny access
}
```

The noncompliant code examples illustrate two common improper authentication issues. The first example shows the use of a weak password that can easily be guessed by attackers. The second example shows the use of hardcoded credentials that can be easily discovered by attackers.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// Example 1: Strong Password
$password = $_POST['password'];
if (password_verify($password, $hashedPassword)) {
    // Allow access
} else {
    // Deny access
}

// Example 2: Stored Credentials
$username = $_POST['username'];
$password = $_POST['password'];

// Validate the user's credentials against a secure database
if (validateCredentials($username, $password)) {
    // Allow access
} else {
    // Deny access
}
```


The compliant code examples address these issues by using strong password hashing algorithms and storing user credentials securely in a database. The first example uses the `password_verify` function to compare the user's input password with a hashed password stored in the database. The second example validates the user's credentials against a secure database, rather than using hardcoded credentials in the application code.





## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
```

In the noncompliant code above, the session ID is generated when `session_start()` is called. However, the authenticated session is not regenerated after a successful login. This leaves the user's session vulnerable to session fixation attacks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    // Regenerate session ID after successful login
    session_regenerate_id();
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
```


In the compliant code above, the `session_regenerate_id()` function is called after a successful login to regenerate the session ID. This ensures that the user's session is protected against session fixation attacks.





## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
<?php
$remoteUrl = $_GET['url'];
include($remoteUrl);
?>
```

In this code, an attacker can control the `url` parameter and specify a malicious URL that contains code to be executed within the application's context. This can lead to arbitrary code execution, information disclosure, and other security issues.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
<?php
$remoteUrl = $_GET['url'];
if (filter_var($remoteUrl, FILTER_VALIDATE_URL)) {
  include($remoteUrl);
} else {
  // handle error
}
?>
```


In the compliant code, input validation is added to ensure that the `url` parameter is a valid URL before including the remote file. This reduces the risk of including a malicious file and protects against potential code execution and other security issues.



## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$url = 'https://example.com/package.tar.gz';
$pkg = file_get_contents($url);
file_put_contents('/tmp/package.tar.gz', $pkg);
system('tar -xvf /tmp/package.tar.gz');
```

In this example, the code downloads a tarball package from a remote location and extracts its contents. However, the code does not verify the integrity of the downloaded package before use, making it susceptible to tampering by attackers.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$url = 'https://example.com/package.tar.gz';
$hash = file_get_contents($url . '.sha256');
$pkg = file_get_contents($url);

if (hash('sha256', $pkg) === trim($hash)) {
    file_put_contents('/tmp/package.tar.gz', $pkg);
    system('tar -xvf /tmp/package.tar.gz');
} else {
    throw new Exception('Package hash does not match expected value');
}
```


In the compliant code, the integrity of the downloaded package is verified using a SHA-256 hash. The hash is downloaded from a trusted source (e.g., the package repository), and the downloaded package is compared with the expected hash. If the hashes match, the package is stored and extracted; otherwise, an exception is raised.




## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// Noncompliant code for Deserialization of Untrusted Data

// unserialize() function is used to deserialize the input data from a string
$userData = unserialize($_COOKIE['user']);

// Use the data from $userData
$name = $userData['name'];
$id = $userData['id'];
```

In this noncompliant code, the `unserialize()` function is used to deserialize the user input data from the `$_COOKIE` array directly, without any validation or sanitization. This can be dangerous because an attacker can manipulate the input data to execute malicious code during the deserialization process.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// Compliant code for Deserialization of Untrusted Data

// Deserialize the input data after validating and sanitizing it
$userData = json_decode(filter_input(INPUT_COOKIE, 'user', FILTER_SANITIZE_STRING));

// Use the data from $userData
if (isset($userData->name)) {
    $name = $userData->name;
}
if (isset($userData->id)) {
    $id = $userData->id;
}
```


In this compliant code, the input data from the `$_COOKIE` array is first validated and sanitized using the `filter_input()` function with the `FILTER_SANITIZE_STRING` filter. Then, the input data is deserialized using the `json_decode()` function, which is safer than `unserialize()` because it only deserializes JSON-formatted data.

Finally, the data from `$userData` is used only after checking that the expected properties exist using `isset()`, which reduces the risk of accessing unexpected properties or executing malicious code.




## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
function transferMoney($amount, $recipient) {
  // some code to transfer money
  // ...
  
  // log the transaction
  file_put_contents('transaction.log', "Transfered $amount to $recipient", FILE_APPEND);
}
```

In the above code, the transferMoney function logs transaction information to a file, but the logging is insufficient. There are no timestamps, severity levels, or any other useful information that could help detect or investigate security incidents.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
function transferMoney($amount, $recipient) {
  // some code to transfer money
  // ...
  
  // log the transaction with useful information
  $log = fopen('transaction.log', 'a');
  if ($log) {
    $datetime = date('Y-m-d H:i:s');
    $severity = 'INFO';
    $message = "Transfered $amount to $recipient";
    $entry = "$datetime [$severity]: $message\n";
    fwrite($log, $entry);
    fclose($log);
  } else {
    error_log('Unable to open transaction log file');
  }
}
```


In the compliant code, the `transferMoney` function logs transaction information to a file with useful information, such as a timestamp, severity level, and a formatted message. Additionally, the function handles errors that might occur while logging, such as the inability to open the log file, by logging an error message to the system log. This helps ensure that security incidents can be detected and investigated quickly and effectively.



## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];

// log the username and password to a file
file_put_contents('logs.txt', 'Username: '.$username.' Password: '.$password);
```

In the noncompliant code example, the `$_POST` variables are not sanitized before being logged to the file. This could allow an attacker to inject malicious input and log it to the file, potentially compromising the system.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];

// sanitize the input using filter_var
$sanitized_username = filter_var($username, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
$sanitized_password = filter_var($password, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);

// log the sanitized username and password to a file
file_put_contents('logs.txt', 'Username: '.$sanitized_username.' Password: '.$sanitized_password);
```


In the compliant code example, the `filter_var` function is used to sanitize the input before being logged to the file. The `FILTER_SANITIZE_STRING` flag removes any character that is not a letter, digit, or whitespace. The `FILTER_FLAG_STRIP_LOW` and `FILTER_FLAG_STRIP_HIGH` flags remove any character with an ASCII value below 32 or above 126, respectively. This ensures that only safe and valid characters are logged to the file.





## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    // user is authenticated
    // do some sensitive operation
} else {
    // user is not authenticated
    echo "Invalid credentials";
}
```




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "ss", $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) > 0) {
    // user is authenticated
    // do some sensitive operation
} else {
    // user is not authenticated
    echo "Invalid credentials";
}
```


Omission of security-relevant information is a vulnerability that occurs when important security-related information, such as error messages, is not provided to the user or logged for later analysis. In the noncompliant code example, an attacker can use the error message "Invalid credentials" to determine if a given username exists in the system. This information can be used in further attacks to try and guess the correct password. The compliant code example uses prepared statements to prevent SQL injection, and does not provide any information in the error message that could be used by an attacker to determine if a username exists in the system or not.






## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
// sensitive data is logged without proper redaction
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".$username." and password: ".$password);
```

The noncompliant code shows an example where sensitive data (i.e. username and password) is directly logged to an error log file. This can be dangerous as it may expose this sensitive information to unauthorized parties who have access to the log file.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
// sensitive data is redacted before being logged
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".redact($username)." and password: ".redact($password));

function redact($string) {
  // replace sensitive data with asterisks
  return preg_replace('/./', '*', $string);
}
```


The compliant code shows an example of how to properly redact the sensitive data before logging it. In this example, the redact function replaces every character in the sensitive string with an asterisk, effectively hiding the sensitive data. The redacted strings are then used in the error log message, which will not reveal the sensitive data.




## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
$url = $_GET['url'];
$file = file_get_contents($url);
echo $file;
```

In this noncompliant code, an attacker can pass a malicious URL through the "url" parameter in the GET request and the server will make a request to that URL using the file_get_contents() function. This allows the attacker to perform unauthorized actions on behalf of the server.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) {
    echo "Invalid URL";
} else {
    $file = file_get_contents($url);
    echo $file;
}
```


In this compliant code, the input from the "url" parameter is validated using the FILTER_VALIDATE_URL filter, which checks if the URL is valid. If the URL is invalid, the script will return an error message. If the URL is valid, the server will retrieve the contents of the URL using the file_get_contents() function. This prevents the server from making requests to malicious URLs.


It is important to note that in addition to input validation, other measures such as using a whitelist of allowed URLs and limiting network access can also help prevent SSRF attacks.

