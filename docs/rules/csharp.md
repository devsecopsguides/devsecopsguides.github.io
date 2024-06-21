---
layout: default
title: Csharp
parent: Rules
---

# Csharp
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---







## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

class Program
{
    static void Main()
    {
        try
        {
            // Simulating an error
            throw new Exception("An error occurred: Sensitive information");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
```

In this noncompliant code, the throw statement intentionally generates an exception with an error message that includes sensitive information, such as a database connection string, a password, or any other confidential data. The error message is then printed to the console, potentially exposing sensitive information to unauthorized users or attackers.


To address this issue and prevent the exposure of sensitive information via error messages, here's an example of compliant code:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;

class Program
{
    static void Main()
    {
        try
        {
            // Simulating an error
            throw new Exception("An error occurred");
        }
        catch (Exception ex)
        {
            Console.WriteLine("An unexpected error occurred");
            // Log the exception for debugging or monitoring purposes
            LogException(ex);
        }
    }

    static void LogException(Exception ex)
    {
        // Log the exception to a secure log file or logging service
        // Include necessary information for debugging, but avoid sensitive data
        Console.WriteLine("Error occurred: " + ex.ToString());
    }
}
```


In the compliant code, the error message intentionally omits any sensitive information and provides a generic error message instead. The sensitive information is logged on the server side for debugging or monitoring purposes, but it is not exposed to the user or client.


By ensuring that error messages do not contain sensitive information, the compliant code reduces the risk of exposing confidential data to potential attackers or unauthorized users.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'catch \(Exception ex\)\n\s+Console\.WriteLine\(ex\.Message\);'
    message: "Sensitive information exposure in exception handling"
```

CodeQL:



```
import csharp

from TryCatchStatement tryCatch
where exists(CatchClause catchClause |
  catchClause.getParameter().getType().toString() = "System.Exception" and
  exists(MethodInvocation println |
    println.getTarget().toString() = "System.Console.WriteLine" and
    println.getArgument(0).toString().indexOf("ex.Message") >= 0
  )
)
select tryCatch
```



## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body: " + sensitiveData);

            client.Send(message);
        }
    }
}
```

In this noncompliant code, the sensitive information (stored in the sensitiveData variable) is concatenated with the email body without any encryption or obfuscation. This means that the sensitive data is directly included in the sent data without any protection, which can lead to potential exposure or unauthorized access to the information.


To address this issue and ensure the protection of sensitive information in sent data, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body");

            // Attach the sensitive data as a secure attachment
            var attachment = new Attachment(sensitiveData);
            message.Attachments.Add(attachment);

            client.Send(message);
        }
    }
}
```


In the compliant code, instead of directly inserting the sensitive information into the email body, it is attached as a secure attachment. This helps to protect the sensitive data during transmission, ensuring that it is not exposed in the sent data.

By properly handling sensitive information and avoiding direct insertion into sent data, the compliant code enhances the security and privacy of the sensitive data, reducing the risk of unauthorized access or exposure.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'new MailMessage\(.+\, ".+"\, ".+"\, "Body: .+"\)'
    message: "Sensitive information exposure in email communication"
```

CodeQL:



```
import csharp

from ObjectCreation messageCreation
where messageCreation.getType().toString() = "System.Net.Mail.MailMessage" and
  messageCreation.getArgument(3).toString().indexOf("Body:") >= 0
select messageCreation
```




## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // Noncompliant code: No CSRF protection implemented
        if (Request.QueryString["action"] == "delete")
        {
            string id = Request.QueryString["id"];
            // Delete the record with the given ID
            // ...
        }
    }
}
```

In this noncompliant code, the page performs a delete action based on a query parameter action and an ID specified in the query parameter id. However, there is no CSRF protection implemented, which means that an attacker can craft a malicious link or form on a different website that performs a delete action on behalf of the user without their consent.


To address this issue and implement CSRF protection, here's an example of compliant code:



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (IsPostBack)
        {
            // Verify CSRF token
            if (ValidateCsrfToken())
            {
                // Process the request
                if (Request.QueryString["action"] == "delete")
                {
                    string id = Request.QueryString["id"];
                    // Delete the record with the given ID
                    // ...
                }
            }
            else
            {
                // CSRF token validation failed, handle the error
                // ...
            }
        }
        else
        {
            // Generate and store CSRF token in session or view state
            GenerateCsrfToken();
        }
    }

    private bool ValidateCsrfToken()
    {
        // Retrieve CSRF token from session or view state
        string csrfToken = Session["CsrfToken"] as string;

        // Compare the CSRF token from the request with the stored token
        string requestToken = Request.Form["__RequestVerificationToken"];
        return csrfToken == requestToken;
    }

    private void GenerateCsrfToken()
    {
        // Generate a unique CSRF token
        string csrfToken = Guid.NewGuid().ToString();

        // Store the CSRF token in session or view state
        Session["CsrfToken"] = csrfToken;

        // Include the CSRF token in the rendered HTML
        Page.ClientScript.RegisterHiddenField("__RequestVerificationToken", csrfToken);
    }
}
```


In the compliant code, CSRF protection is implemented using a unique CSRF token. The token is generated and stored in the session or view state when the page is loaded. On subsequent requests, the token is validated to ensure that the request originated from the same site and not from an attacker's site.

By implementing CSRF protection, the compliant code prevents unauthorized actions by verifying the integrity of the requests and ensuring that they are originated from the legitimate user. This helps to protect against CSRF attacks and improves the security of the application.



Semgrep:


```
rules:
  - id: csrf-vulnerability
    patterns:
      - pattern: 'if \(Request\.QueryString\["action"\] == "delete"\)'
    message: "Potential CSRF vulnerability"
```

CodeQL:



```
import csharp

from MethodDeclaration method
where method.getName() = "Page_Load" and
  exists(BinaryExpression binaryExpr |
    binaryExpr.getOperator().toString() = "==" and
    binaryExpr.getLeftOperand().toString() = "Request.QueryString[\"action\"]" and
    binaryExpr.getRightOperand().toString() = "\"delete\""
  )
select method
```




## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = "Server=myServerAddress;Database=myDatabase;User Id=myUsername;Password=myPassword;";

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Connect to the database
            connection.Open();
            // Perform database operations
            // ...
        }
    }
}
```

In this noncompliant code, the database connection string contains a hard-coded password. Storing sensitive information like passwords directly in the source code poses a security risk, as the password can be easily discovered if the code is accessed or leaked.


To address this issue and implement a more secure approach, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Configuration;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = ConfigurationManager.ConnectionStrings["MyConnectionString"].ConnectionString;

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Connect to the database
            connection.Open();
            // Perform database operations
            // ...
        }
    }
}
```

In the compliant code, the password is not hard-coded in the source code. Instead, it is stored in a secure configuration file (e.g., web.config or app.config) and accessed using the ConfigurationManager class. The configuration file should be properly protected and access should be restricted to authorized personnel.

By removing the hard-coded password and storing it in a secure configuration file, the compliant code improves the security of the application by preventing unauthorized access to sensitive information.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'private string connectionString = "Server=.+;Database=.+;User Id=.+;Password=.+;"'
    message: "Sensitive information exposure in database connection string"
```

CodeQL:



```
import csharp

from FieldDeclaration field
where field.getType().toString() = "System.String" and
  field.getInitializer().toString().indexOf("Server=") >= 0 and
  field.getInitializer().toString().indexOf("Database=") >= 0 and
  field.getInitializer().toString().indexOf("User Id=") >= 0 and
  field.getInitializer().toString().indexOf("Password=") >= 0
select field
```




## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

        TripleDESCryptoServiceProvider desCryptoProvider = new TripleDESCryptoServiceProvider();
        desCryptoProvider.Key = keyBytes;
        desCryptoProvider.Mode = CipherMode.ECB; // Using ECB mode, which is insecure
        desCryptoProvider.Padding = PaddingMode.PKCS7;

        ICryptoTransform encryptor = desCryptoProvider.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
        encryptor.Dispose();
        desCryptoProvider.Clear();

        return Convert.ToBase64String(encryptedData);
    }
}
```


In this noncompliant code, the TripleDESCryptoServiceProvider class is used with the ECB (Electronic Codebook) mode, which is known to be insecure. ECB mode does not provide proper encryption, as it encrypts each block of data independently, leading to potential vulnerabilities.


To address this issue and use a more secure cryptographic algorithm, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        string Result = "";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
    
        using (var aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.Mode = CipherMode.CBC; //Better security
            aes.Padding = PaddingMode.PKCS7;
    
            aes.GenerateIV(); //Generate a random IV (Init Vector) for each encryption
    
            using var encryptor = aes.CreateEncryptor();
            Result = Convert.ToBase64String(aes.IV.Concat(encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length)).ToArray());
        }
    
        return Result;
    }

    public string Decrypt(string encryptedData, string key)
    {
        string Result = "";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytesWithIV = Convert.FromBase64String(encryptedData);
    
        using (var aes = Aes.Create()) 
        {
            aes.Key = keyBytes;
            aes.Mode = CipherMode.CBC; //Better security
            aes.Padding = PaddingMode.PKCS7;
    
            //Extract IV from the encrypted data
            aes.IV = encryptedBytesWithIV.Take(aes.BlockSize / 8).ToArray(); //Set IV for decryption
            byte[] encryptedBytes = encryptedBytesWithIV.Skip(aes.BlockSize / 8).ToArray();
    
            using var decryptor = aes.CreateDecryptor();
            Result = Encoding.UTF8.GetString(decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length));
        }
        return Result;
    }
}
```

In the compliant code, the AesCryptoServiceProvider class is used with the CBC (Cipher Block Chaining) mode, which is more secure than ECB mode. Additionally, proper disposal of cryptographic objects is implemented using the using statement to ensure proper resource management.

By using a secure cryptographic algorithm like AES with CBC mode, the compliant code improves the security of the encryption process, making it resistant to known cryptographic vulnerabilities.





Semgrep:


```
rules:
  - id: insecure-encryption-mode
    patterns:
      - pattern: 'desCryptoProvider.Mode = CipherMode\.ECB'
    message: "Insecure encryption mode (ECB) detected"
```

CodeQL:



```
import csharp

from Assignment assignment
where assignment.getRightOperand().toString() = "CipherMode.ECB"
select assignment
```



## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        Random random = new Random();
        return random.Next(minValue, maxValue);
    }
}
```


In this noncompliant code, the Random class from the System namespace is used to generate random numbers. However, the Random class uses a time-based seed by default, which can result in predictable and easily guessable random numbers. This is because the seed value is based on the current system time, which can be easily determined or even repeated if the code is executed within a short time span.



To address this issue and improve the entropy of the random number generation, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Security.Cryptography;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        using (RNGCryptoServiceProvider rngCryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] randomBytes = new byte[4];
            rngCryptoProvider.GetBytes(randomBytes);
            int randomNumber = BitConverter.ToInt32(randomBytes, 0);

            return Math.Abs(randomNumber % (maxValue - minValue + 1)) + minValue;
        }
    }
}
```

In the compliant code, the RNGCryptoServiceProvider class from the System.Security.Cryptography namespace is used to generate random bytes with sufficient entropy. These random bytes are then converted into an integer using BitConverter.ToInt32 method. By utilizing a cryptographic random number generator, we ensure a higher degree of entropy and reduce the predictability of the generated numbers.

The compliant code provides a more secure and random number generation mechanism, making it suitable for applications that require unpredictable and non-reproducible random values.





Semgrep:


```
rules:
  - id: random-without-seed
    patterns:
      - pattern: 'new Random\(\)'
    message: "Random number generator initialized without a specified seed"
```

CodeQL:



```
import csharp

from ObjectCreation randomCreation, MethodAccess randomNextAccess
where randomCreation.getType().toString() = "System.Random" and
  randomNextAccess.getTarget().toString() = randomCreation.toString() and
  not exists(Expression seedArg |
    randomCreation.getArguments() = seedArg and
    seedArg.toString().startsWith("new Random(")
  )
select randomCreation
```



## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = userInput.Replace("<", "&lt;").Replace(">", "&gt;");
        return sanitizedInput;
    }
}
```

In this noncompliant code, the ProcessUserInput method attempts to sanitize user input by replacing the < and > characters with their corresponding HTML entities (&lt; and &gt;). However, this approach is insufficient to prevent XSS attacks because it only focuses on these specific characters and fails to handle other potentially malicious input.


To address this issue and properly protect against XSS attacks, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Web;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = HttpUtility.HtmlEncode(userInput);
        return sanitizedInput;
    }
}
```


In the compliant code, the HtmlEncode method from the System.Web namespace is used to properly encode the user input. This method replaces special characters with their corresponding HTML entities, ensuring that the input is rendered as plain text rather than interpreted as HTML or JavaScript code.

By using HtmlEncode, the compliant code mitigates the risk of XSS attacks by encoding all potentially dangerous characters in the user input, making it safe to display the input on web pages without the risk of executing unintended scripts.

It's important to note that the best approach to prevent XSS attacks is to use contextual output encoding at the point of rendering, rather than relying solely on input sanitization. This ensures that the output is properly encoded based on the context in which it is being used, such as HTML attributes, JavaScript, or CSS, providing robust protection against XSS vulnerabilities.





Semgrep:


```
rules:
  - id: xss-sanitization
    patterns:
      - pattern: 'Replace\(\"<\"'
    message: "Potential XSS vulnerability: User input not properly sanitized"
```

CodeQL:



```
import csharp

from MethodInvocation replaceMethod
where replaceMethod.getTarget().toString() = "userInput.Replace"
select replaceMethod
```




## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username='" + username + "' AND Password='" + password + "'";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
```

In this noncompliant code, the AuthenticateUser method constructs a SQL query by directly concatenating the username and password values into the query string. This approach is highly vulnerable to SQL injection attacks, as an attacker can manipulate the input to execute arbitrary SQL commands.


To prevent SQL injection attacks and ensure secure database interactions, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username=@Username AND Password=@Password";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@Password", password);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
```

In the compliant code, parameterized queries are used to handle user input securely. The query string includes placeholders (@Username and @Password) for the input values. The actual values are then provided using the AddWithValue method on the SqlCommand object, which adds the values as parameters rather than concatenating them directly into the query.

By using parameterized queries, the compliant code ensures that the user input is treated as data rather than executable code, effectively preventing SQL injection attacks. The database engine handles the proper escaping and sanitization of the input values, keeping the application secure.




Semgrep:


```
rules:
  - id: sql-injection
    patterns:
      - pattern: 'SELECT .* FROM .* WHERE .*'
    message: "Potential SQL injection vulnerability: User input not properly parameterized"
```

CodeQL:



```
import csharp

from BinaryExpression binaryExpr
where binaryExpr.getLeftOperand().toString().startsWith("\"SELECT ") and
  binaryExpr.getOperator().toString() = "+" and
  binaryExpr.getRightOperand().toString().contains("\"")
select binaryExpr
```



## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.IO;

public class FileProcessor
{
    public void ProcessFile(string fileName)
    {
        string filePath = "C:\\Temp\\" + fileName;
        if (File.Exists(filePath))
        {
            // Process the file
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
```


In this noncompliant code, the ProcessFile method constructs the file path by directly concatenating the fileName parameter with a fixed base directory (C:\Temp\). This approach is vulnerable to external control of the file name, as an attacker can manipulate the fileName input to access files outside the intended directory.


To prevent external control of file name or path attacks and ensure secure file operations, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.IO;

public class FileProcessor
{
    private readonly string baseDirectory = "C:\\Temp\\";

    public void ProcessFile(string fileName)
    {
        string sanitizedFileName = Path.GetFileName(fileName);
        string filePath = Path.Combine(baseDirectory, sanitizedFileName);
        if (File.Exists(filePath))
        {
            // Process the file
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
```

In the compliant code, the Path.GetFileName method is used to extract the file name from the fileName parameter, discarding any directory information. The Path.Combine method is then used to construct the full file path by combining the base directory (C:\Temp\) with the sanitized file name.

By using these secure file path handling techniques, the compliant code ensures that the file name or path provided by the user is properly validated and prevents unauthorized access to files outside the intended directory.






Semgrep:


```
rules:
  - id: path-traversal
    patterns:
      - pattern: 'C:\\Temp\\\\'
    message: "Potential path traversal vulnerability: Unsanitized file path concatenation"
```

CodeQL:



```
import csharp

from Addition addExpr
where addExpr.getLeftOperand().toString() = "\"C:\\Temp\\" and
  addExpr.getOperator().toString() = "+" and
  addExpr.getRightOperand().toString().contains("\"")
select addExpr
```



## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid username or password.");
        }

        // Authenticate the user
    }
}
```


In this noncompliant code, when the AuthenticateUser method receives an empty or null username or password, it throws an ArgumentException with an error message that discloses sensitive information ("Invalid username or password"). Revealing such details in error messages can assist attackers in identifying valid usernames and potentially launch further attacks.


To address this issue and prevent exposure of sensitive information, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid credentials.");
        }

        // Authenticate the user
    }
}
```

In the compliant code, the error message has been generalized to "Invalid credentials" instead of explicitly mentioning the username or password. This approach avoids revealing sensitive information in error messages, making it harder for attackers to gather useful details.

By following this approach, the compliant code ensures that error messages do not disclose sensitive information, thus reducing the risk of potential attacks targeting user credentials.





Semgrep:


```
rules:
  - id: empty-username-password
    patterns:
      - pattern: 'string.IsNullOrEmpty\({{ _ }}\)'
    message: "Potential issue: Empty or null username or password"
```

CodeQL:



```
import csharp

from Invocation invocation
where invocation.getTarget().toString() = "string.IsNullOrEmpty" and
  invocation.getArgument(0).toString() = "{{ _ }}"
select invocation
```


## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class UserController
{
    private string _username;
    private string _password;

    public void SetCredentials(string username, string password)
    {
        _username = username;
        _password = password;
    }

    public void AuthenticateUser()
    {
        // Authenticate the user using the stored credentials
    }
}
```

In this noncompliant code, the SetCredentials method stores the username and password provided by the user in class-level variables `_username` and `_password`, respectively. However, these credentials are stored in plain text without any additional protection, such as encryption or secure storage mechanisms. This leaves the sensitive information vulnerable to unauthorized access if an attacker gains access to the application or the system.


To address this security issue and ensure the protected storage of credentials, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Security.Cryptography;

public class UserController
{
    private byte[] _encryptedCredentials;

    public void SetCredentials(string username, string password)
    {
        byte[] encryptedUsername = EncryptData(username);
        byte[] encryptedPassword = EncryptData(password);

        _encryptedCredentials = CombineArrays(encryptedUsername, encryptedPassword);
    }

    public void AuthenticateUser()
    {
        // Decrypt and use the stored credentials for user authentication
        string decryptedUsername = DecryptData(GetUsernameFromEncryptedCredentials());
        string decryptedPassword = DecryptData(GetPasswordFromEncryptedCredentials());

        // Authenticate the user using the decrypted credentials
    }

    private byte[] EncryptData(string data)
    {
        // Use a secure encryption algorithm (e.g., AES) to encrypt the data
        // and return the encrypted byte array
        // ...
    }

    private string DecryptData(byte[] encryptedData)
    {
        // Use the same encryption algorithm and decryption process
        // to decrypt the data and return the plaintext
        // ...
    }

    private byte[] CombineArrays(byte[] array1, byte[] array2)
    {
        // Combine two byte arrays into one
        // ...
    }

    private byte[] GetUsernameFromEncryptedCredentials()
    {
        // Extract and return the encrypted username from the stored credentials
        // ...
    }

    private byte[] GetPasswordFromEncryptedCredentials()
    {
        // Extract and return the encrypted password from the stored credentials
        // ...
    }
}
```

In the compliant code, the sensitive information (username and password) is no longer stored directly as plain text. Instead, the SetCredentials method encrypts the username and password using a secure encryption algorithm (such as AES) before storing them in the _encryptedCredentials variable. The AuthenticateUser method then retrieves and decrypts the credentials for authentication purposes.


By encrypting the credentials, the compliant code ensures that even if an attacker gains unauthorized access to the stored credentials, they would be in an encrypted form, significantly reducing the risk of exposing sensitive information.




Semgrep:


```
rules:
  - id: insecure-credentials-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Credentials stored in memory"
```

CodeQL:



```
import csharp

class StoredCredentials extends FieldAccess {
  StoredCredentials() {
    this.getTarget().toString().matches("_username") or
    this.getTarget().toString().matches("_password")
  }
}

from StoredCredentials access
select access
```


## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class PaymentController
{
    private string _creditCardNumber;

    public void ProcessPayment(string creditCardNumber)
    {
        _creditCardNumber = creditCardNumber;
        // Process the payment using the credit card number
    }
}
```

In this noncompliant code, the ProcessPayment method accepts a credit card number as a parameter and directly stores it in the _creditCardNumber variable within the PaymentController class. The credit card number is treated as trusted data within the class, even though it comes from an external source. This violates the trust boundary by assuming the data is safe and trustworthy, which can lead to potential security vulnerabilities.


To address this security issue and enforce a proper trust boundary, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;

public class PaymentController
{
    public void ProcessPayment(string creditCardNumber)
    {
        // Perform input validation and sanitization of the credit card number
        if (IsValidCreditCardNumber(creditCardNumber))
        {
            // Process the payment using the credit card number
        }
        else
        {
            // Handle the case when an invalid credit card number is provided
        }
    }

    private bool IsValidCreditCardNumber(string creditCardNumber)
    {
        // Implement proper credit card number validation logic
        // to ensure the input meets the required format and integrity
        // ...
    }
}
```


In the compliant code, the ProcessPayment method performs input validation and sanitization of the credit card number before processing the payment. The method checks if the credit card number is valid by calling the IsValidCreditCardNumber function, which implements the necessary validation logic to ensure the input meets the required format and integrity.

By implementing proper input validation and sanitization, the compliant code establishes a trust boundary and ensures that only valid and trusted data is processed, reducing the risk of security vulnerabilities arising from untrusted or malicious input.





Semgrep:


```
rules:
  - id: insecure-credit-card-storage
    patterns:
      - pattern: '_creditCardNumber = {{ _ }}'
    message: "Potential security issue: Credit card number stored in memory"
```

CodeQL:



```
import csharp

class StoredCreditCardNumber extends FieldAccess {
  StoredCreditCardNumber() {
    this.getTarget().toString().matches("_creditCardNumber")
  }
}

from StoredCreditCardNumber access
select access
```



## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class LoginController
{
    private string _username;
    private string _password;

    public bool Authenticate(string username, string password)
    {
        _username = username;
        _password = password;
        
        // Perform authentication logic
        // ...
        
        return true;
    }
}
```

In this noncompliant code, the Authenticate method accepts a username and password as parameters and directly stores them in the _username and _password variables within the LoginController class. The credentials are stored in plain text without any additional protection mechanisms such as encryption or hashing. Storing credentials in plain text increases the risk of unauthorized access and potential data breaches if the credentials are compromised.

To address this security issue and ensure the proper protection of credentials, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Security.Cryptography;

public class LoginController
{
    public bool Authenticate(string username, string password)
    {
        string hashedPassword = HashPassword(password);
        
        // Perform authentication logic using the hashed password
        // ...
        
        return true;
    }

    private string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
```


In the compliant code, the Authenticate method still accepts a username and password as parameters, but instead of storing them directly, the password is hashed using a secure cryptographic hash function (in this case, SHA-256). The HashPassword function takes the password as input, generates a hash value, and returns the hashed password as a string.


By hashing the password, the compliant code ensures that the credentials are not stored in plain text and adds an additional layer of protection. When performing authentication, the stored hashed password is compared with the hashed version of the user's input, rather than comparing the plain-text passwords directly.

Using proper password hashing techniques helps mitigate the impact of data breaches and unauthorized access, as even if the stored hashes are obtained, they are computationally difficult to reverse back to the original password.






Semgrep:


```
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
```

CodeQL:



```
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
```




## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlContent);
        
        // Process the XML document
        // ...
    }
}
```

In this noncompliant code, the ParseXml method takes an XML content as a string and loads it into an XmlDocument object using the LoadXml method. However, this code does not enforce any restriction on external entity references, making it vulnerable to XXE attacks.


To address this security issue and restrict XML external entity references, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;

        using (XmlReader reader = XmlReader.Create(new System.IO.StringReader(xmlContent), settings))
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(reader);

            // Process the XML document
            // ...
        }
    }
}
```


In the compliant code, the ParseXml method sets up an instance of XmlReaderSettings and explicitly sets the DtdProcessing property to DtdProcessing.Prohibit. This setting prevents the parsing of any external entities defined in the XML content, effectively mitigating XXE attacks.


By enforcing this restriction, the compliant code ensures that XML parsing is performed without evaluating external entity references, thus protecting against potential attacks that leverage XXE vulnerabilities.






Semgrep:


```
rules:
  - id: xml-parsing-insecure
    pattern: |
      XmlDocument xmlDoc = new XmlDocument();
      xmlDoc.LoadXml({{ _ }});
    message: "Potential security issue: Insecure XML parsing"
```

CodeQL:



```
import csharp

class InsecureXmlParsing extends MethodCall {
  InsecureXmlParsing() {
    this.getTarget().toString().matches("XmlDocument.LoadXml")
  }
}

from InsecureXmlParsing call
select call
```



## Vulnerable and Outdated Components


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using Newtonsoft.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Fetch user data from the database
        UserData user = Database.GetUserDetails();

        // Convert user data to JSON
        string json = JsonConvert.SerializeObject(user);

        // Send the JSON response to the client
        HttpResponse.Write(json);
    }
}
```

In this noncompliant code, the UserController fetches user data from the database and converts it to JSON using the JsonConvert.SerializeObject method from the Newtonsoft.Json library. However, the code uses an outdated version of the library, which may contain known vulnerabilities.


To address this security issue and ensure the usage of secure and up-to-date components, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Text.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Fetch user data from the database
        UserData user = Database.GetUserDetails();

        // Convert user data to JSON
        string json = JsonSerializer.Serialize(user);

        // Send the JSON response to the client
        HttpResponse.Write(json);
    }
}
```


In the compliant code, the UserController uses the built-in System.Text.Json namespace instead of the Newtonsoft.Json library. By leveraging the latest version of the built-in JSON serializer, the code ensures the usage of secure and up-to-date components.


It is crucial to regularly update and replace vulnerable or outdated components with their latest versions or more secure alternatives to mitigate potential security risks.





Semgrep:


```
rules:
  - id: json-serialization-insecure
    pattern: |
      JsonConvert.SerializeObject({{ _ }});
    message: "Potential security issue: Insecure JSON serialization"
```

CodeQL:



```
import csharp

class InsecureJsonSerialization extends MethodCall {
  InsecureJsonSerialization() {
    this.getTarget().toString().matches("JsonConvert.SerializeObject")
  }
}

from InsecureJsonSerialization call
select call
```



## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Create HttpClient instance
        HttpClient client = new HttpClient();

        // Disable SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) => true;

        // Send a request to a remote server
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Process the response
        if (response.IsSuccessStatusCode)
        {
            // Do something with the successful response
            Console.WriteLine("Request succeeded!");
        }
        else
        {
            // Handle the error response
            Console.WriteLine("Request failed!");
        }
    }
}
```

In this noncompliant code, the HttpClientExample class sends a request to a remote server using the HttpClient class. However, the code disables SSL certificate validation by modifying the ServicePointManager.ServerCertificateValidationCallback event to always return true. This means that the code will accept any certificate, even if it has a host mismatch, expired, or has other security issues.


To address this security issue and ensure proper validation of certificates with host matches, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Create HttpClient instance
        HttpClient client = new HttpClient();

        // Enable SSL certificate validation
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return true;
                
                // Check if the certificate matches the host
                string requestedHost = new Uri("https://example.com").Host;
                return certificate.Subject.Equals($"CN={requestedHost}", StringComparison.OrdinalIgnoreCase);
            };

        // Send a request to a remote server
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Process the response
        if (response.IsSuccessStatusCode)
        {
            // Do something with the successful response
            Console.WriteLine("Request succeeded!");
        }
        else
        {
            // Handle the error response
            Console.WriteLine("Request failed!");
        }
    }
}
```


In the compliant code, the ServicePointManager.ServerCertificateValidationCallback event is modified to perform proper certificate validation. It checks if the certificate subject matches the requested host, ensuring that the certificate is valid and not subject to host mismatch vulnerabilities.

By properly validating certificates with host matches, the compliant code reduces the risk of man-in-the-middle attacks and other security vulnerabilities associated with improper certificate validation.




Semgrep:


```
rules:
  - id: disable-ssl-certificate-validation
    pattern: |
      ServicePointManager.ServerCertificateValidationCallback += {{ _ }};
    message: "Potential security issue: Disabling SSL certificate validation"
```

CodeQL:



```
import csharp

class DisableSSLCertificateValidation extends MethodCall {
  DisableSSLCertificateValidation() {
    this.getTarget().toString().matches("ServicePointManager.ServerCertificateValidationCallback +=")
  }
}

from DisableSSLCertificateValidation call
select call
```





## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Construct the SQL query with user-provided input
        string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Open the connection
            connection.Open();

            // Execute the query
            SqlDataReader reader = command.ExecuteReader();

            // Check if the user exists
            bool userExists = reader.HasRows;

            // Close the connection
            connection.Close();

            return userExists;
        }
    }
}
```

In this noncompliant code, the AuthenticateUser method performs authentication by constructing a SQL query with user-provided input for the username and password. This code is susceptible to SQL injection attacks, as the user input is directly concatenated into the query string without proper sanitization or parameterization.


To address this security issue and ensure proper authentication, here's an example of compliant code that uses parameterized queries:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Construct the parameterized SQL query
        string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Add parameters to the command
            command.Parameters.AddWithValue("@username", username);
            command.Parameters.AddWithValue("@password", password);

            // Open the connection
            connection.Open();

            // Execute the query
            SqlDataReader reader = command.ExecuteReader();

            // Check if the user exists
            bool userExists = reader.HasRows;

            // Close the connection
            connection.Close();

            return userExists;
        }
    }
}
```


In the compliant code, the SQL query is parameterized, and the user-provided input is passed as parameters to the SqlCommand object. This ensures that the input is properly handled and prevents SQL injection attacks by treating the input as data rather than executable code.

By using parameterized queries, the compliant code mitigates the risk of SQL injection and ensures proper authentication of users.





Semgrep:


```
rules:
  - id: sql-injection
    pattern: |
      SqlCommand command = new SqlCommand({{ query }}, {{ connection }});
    message: "Potential SQL injection vulnerability"
```

CodeQL:



```
import csharp

class SQLInjection extends MethodCall {
  SQLInjection() {
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String)")
    or
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String, SqlConnection)")
  }
}

from SQLInjection call, DataFlow::PathNode query
where query.asExpr().getValue().toString().matches(".*[\"'].*")
select query, call
```




## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Create a new session
        HttpSessionState session = HttpContext.Current.Session;

        // Set the username in the session
        session["username"] = username;
    }

    public bool IsUserAuthenticated()
    {
        // Retrieve the session
        HttpSessionState session = HttpContext.Current.Session;

        // Check if the username exists in the session
        return session["username"] != null;
    }
}
```

In this noncompliant code, the Login method creates a new session and sets the username provided by the user. However, the session ID remains the same throughout the user's session, making it vulnerable to session fixation attacks. An attacker can force a user to use a specific session ID, potentially compromising the user's session.


To address this security issue and prevent session fixation attacks, here's an example of compliant code that regenerates the session ID after successful authentication:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Create a new session
        HttpSessionState session = HttpContext.Current.Session;

        // Set the username in the session
        session["username"] = username;

        // Regenerate the session ID
        session.RegenerateID();
    }

    public bool IsUserAuthenticated()
    {
        // Retrieve the session
        HttpSessionState session = HttpContext.Current.Session;

        // Check if the username exists in the session
        return session["username"] != null;
    }
}
```


In the compliant code, after setting the username in the session, the session ID is regenerated using the RegenerateID method. This ensures that a new session ID is generated after successful authentication, effectively preventing session fixation attacks.

By regenerating the session ID, the compliant code mitigates the risk of session fixation and ensures that each user is assigned a unique session ID upon authentication.





Semgrep:


```
rules:
  - id: session-fixation
    pattern: |
      HttpSessionState session = HttpContext.Current.Session;
    message: "Potential session fixation vulnerability"
```

CodeQL:



```
import csharp

class SessionFixation extends MethodAccess {
  SessionFixation() {
    this.getTarget().toString().matches("HttpSessionState HttpSessionState(HttpContext)")
  }
}

from SessionFixation call, DataFlow::PathNode session
select session, call
```


## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Save the uploaded file to a specified directory
        string savePath = "C:\\Uploads\\" + filename;
        File.WriteAllBytes(savePath, fileData);
        
        // Execute a command on the uploaded file
        string command = "C:\\Windows\\System32\\cmd.exe /C echo File uploaded successfully!";
        Process.Start(command, savePath);
    }
}
```

In this noncompliant code, the UploadFile method accepts a file name and its corresponding data as input. The file is saved to a specified directory without proper validation or sanitization. After saving the file, a command is executed on the uploaded file using Process.Start. This code is vulnerable to arbitrary code execution, as an attacker can upload a malicious file and execute arbitrary commands on the server.


To address this security issue and prevent the inclusion of functionality from untrusted control, here's an example of compliant code that restricts the uploaded file's execution:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Validate and sanitize the filename
        string sanitizedFilename = SanitizeFilename(filename);
        if (sanitizedFilename == null)
        {
            // Invalid filename, abort the upload
            return;
        }

        // Save the uploaded file to a specified directory
        string savePath = "C:\\Uploads\\" + sanitizedFilename;
        File.WriteAllBytes(savePath, fileData);
        
        // Perform other operations on the uploaded file (e.g., logging, virus scanning)

        // Notify the user about the successful upload
        Console.WriteLine("File uploaded successfully!");
    }

    private string SanitizeFilename(string filename)
    {
        // Implement proper filename validation and sanitization logic
        // Ensure that the filename conforms to your desired format and does not contain any malicious characters or path traversal sequences
        
        // Example implementation: removing any path information and disallowing specific characters
        string sanitizedFilename = Path.GetFileName(filename);
        if (sanitizedFilename.IndexOfAny(Path.GetInvalidFileNameChars()) != -1)
        {
            // Invalid filename, return null
            return null;
        }

        return sanitizedFilename;
    }
}
```


In the compliant code, several improvements have been made to ensure the security of the file upload functionality. The filename is validated and sanitized using the SanitizeFilename method, which removes any path information and disallows specific characters. If the filename is deemed invalid or contains malicious content, the upload is aborted.

Furthermore, the code no longer executes arbitrary commands on the uploaded file. Instead, it performs other necessary operations such as logging or virus scanning. Finally, the user is notified about the successful upload without exposing the server to potential security risks.




Semgrep:


```
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
```

CodeQL:



```
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
```



## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Net;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            string code = client.DownloadString(url);
            
            // Execute the downloaded code
            ExecuteCode(code);
        }
    }

    private void ExecuteCode(string code)
    {
        // Execute the downloaded code without performing an integrity check
        Console.WriteLine("Executing downloaded code: " + code);
        // ...
    }
}
```

In this noncompliant code, the DownloadCode method downloads code from a specified URL using the WebClient class. Once the code is downloaded, it is immediately executed without performing any integrity check or validation. This approach introduces the risk of executing malicious or untrusted code, which can lead to security vulnerabilities and compromise the system.


To address this security issue and ensure the integrity of the downloaded code, here's an example of compliant code that includes an integrity check:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            byte[] downloadedData = client.DownloadData(url);
            
            // Verify the integrity of the downloaded code
            if (IsCodeIntegrityValid(downloadedData))
            {
                string code = Encoding.UTF8.GetString(downloadedData);
                
                // Execute the downloaded code
                ExecuteCode(code);
            }
            else
            {
                Console.WriteLine("Code integrity check failed. Aborting execution.");
            }
        }
    }

    private bool IsCodeIntegrityValid(byte[] downloadedData)
    {
        // Implement integrity check logic here
        // For example, calculate the hash of the downloaded code and compare it with a trusted hash value
        
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(downloadedData);

            // Compare the calculated hash with the trusted hash value
            byte[] trustedHash = GetTrustedHash(); // Retrieve the trusted hash value from a secure source

            return ByteArrayEquals(hash, trustedHash);
        }
    }

    private bool ByteArrayEquals(byte[] array1, byte[] array2)
    {
        // Compare two byte arrays for equality
        if (array1.Length != array2.Length)
            return false;

        for (int i = 0; i < array1.Length; i++)
        {
            if (array1[i] != array2[i])
                return false;
        }

        return true;
    }

    private void ExecuteCode(string code)
    {
        // Execute the downloaded code
        Console.WriteLine("Executing downloaded code: " + code);
        // ...
    }
}
```


In the compliant code, additional measures have been implemented to ensure the integrity of the downloaded code. The DownloadData method is used instead of DownloadString to retrieve the code as a byte array. The IsCodeIntegrityValid method calculates the hash of the downloaded code using a secure hashing algorithm (SHA-256 in this example) and compares it with a trusted hash value obtained from a secure source.

If the integrity check passes, the code is converted to a string and then executed. Otherwise, if the integrity check fails, the code execution is aborted. This approach ensures that only code with a valid integrity can be executed, mitigating the risk of downloading and executing malicious or tampered code.





Semgrep:


```
rules:
  - id: insecure-code-download
    pattern: WebClient().DownloadString($url)
    message: "Potential security risk: Insecure code download"
```

CodeQL:



```
import csharp

class CodeDownload extends MethodCall {
  CodeDownload() {
    this.getTarget().toString().matches("WebClient().DownloadString($url)")
  }
}

from CodeDownload
select CodeDownload
```


## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        MemoryStream memoryStream = new MemoryStream(data);
        
        // Deserialize the untrusted data
        object deserializedData = formatter.Deserialize(memoryStream);
        
        return deserializedData;
    }
}
```

In this noncompliant code, the DeserializeData method deserializes the provided byte[] data using the BinaryFormatter class without performing any validation or security checks. Deserializing untrusted data without proper validation can lead to serious security vulnerabilities, including remote code execution and object injection attacks.


To address this security issue and ensure the safe deserialization of data, here's an example of compliant code:





Semgrep:


```
rules:
  - id: insecure-data-deserialization
    pattern: BinaryFormatter().Deserialize($stream)
    message: "Potential security risk: Insecure data deserialization"
```

CodeQL:



```
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().Deserialize($stream)")
  }
}

from DataDeserialization
select DataDeserialization
```



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        
        // Set up a custom SerializationBinder to restrict deserialization to trusted types
        formatter.Binder = new TrustedSerializationBinder();
        
        using (MemoryStream memoryStream = new MemoryStream(data))
        {
            try
            {
                // Deserialize the data with proper validation
                object deserializedData = formatter.Deserialize(memoryStream);
                
                // Perform additional validation on the deserialized object, if required
                
                return deserializedData;
            }
            catch (SerializationException ex)
            {
                Console.WriteLine("Error occurred during deserialization: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error occurred: " + ex.Message);
            }
        }
        
        return null;
    }
}

// Custom SerializationBinder to restrict deserialization to trusted types
public class TrustedSerializationBinder : SerializationBinder
{
    public override Type BindToType(string assemblyName, string typeName)
    {
        // Check if the requested type is trusted
        if (IsTypeTrusted(typeName))
        {
            // Return the trusted type for deserialization
            Type trustedType = GetTypeFromTrustedAssembly(typeName);
            return trustedType;
        }
        
        // For untrusted types, throw an exception or return null to prevent deserialization
        throw new SerializationException("Attempted deserialization of untrusted type: " + typeName);
    }
    
    private bool IsTypeTrusted(string typeName)
    {
        // Implement your logic to determine if the type is trusted
        // For example, maintain a whitelist of trusted types
        
        // Return true if the type is trusted, false otherwise
        // ...
    }
    
    private Type GetTypeFromTrustedAssembly(string typeName)
    {
        // Retrieve the trusted type from a known and trusted assembly
        // For example, look up the type in a predefined assembly
        
        // Return the Type object for the trusted type
        // ...
    }
}
```


In the compliant code, several measures have been taken to ensure the safe deserialization of data. First, a custom SerializationBinder is implemented to restrict deserialization to trusted types. The BindToType method in the TrustedSerializationBinder class is called during deserialization and checks if the requested type is trusted. If the type is trusted, it returns the corresponding Type object for deserialization. Otherwise, it throws a SerializationException to prevent the deserialization of untrusted types.



Additionally, exception handling is implemented to catch any potential errors during deserialization and provide appropriate error messages.




Semgrep:


```
rules:
  - id: secure-data-deserialization
    pattern: BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }
    message: "Ensure secure data deserialization"
```

CodeQL:



```
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }")
  }
}

class DeserializationExceptionHandling extends TryStatement {
  DeserializationExceptionHandling() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ThrowStatement and
    getBody().getChildren().get(1) instanceof CatchClause
  }
}

from DataDeserialization d, DeserializationExceptionHandling e
where d.getAncestor(Statement+) = e.getAncestor(Statement+)
select d, e
```





## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class PaymentProcessor
{
    public void ProcessPayment(double amount, string creditCardNumber)
    {
        // Process the payment logic
        
        try
        {
            // Perform payment processing
            
            // Log a success message
            Console.WriteLine("Payment processed successfully.");
        }
        catch (Exception ex)
        {
            // Log the exception message only
            Console.WriteLine("Payment processing failed. Exception: " + ex.Message);
        }
    }
}
```

In this noncompliant code, the ProcessPayment method performs payment processing but lacks sufficient logging. The code only logs the exception message when an error occurs during payment processing, providing limited information for troubleshooting and investigation.


To address this issue and improve logging, here's an example of compliant code:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.IO;

public class PaymentProcessor
{
    private readonly ILogger logger;

    public PaymentProcessor(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(double amount, string creditCardNumber)
    {
        try
        {
            // Perform payment processing

            // Log a success message with detailed information
            string logMessage = $"Payment processed successfully. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}";
            logger.LogInfo(logMessage);
        }
        catch (Exception ex)
        {
            // Log the exception with detailed information
            string errorMessage = $"Payment processing failed. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}, Exception: {ex}";
            logger.LogError(errorMessage);
        }
    }

    private string MaskCreditCardNumber(string creditCardNumber)
    {
        // Implement logic to mask sensitive information
        // For example, replace all but the last four digits with asterisks
        int maskLength = creditCardNumber.Length - 4;
        string maskedNumber = new string('*', maskLength) + creditCardNumber.Substring(maskLength);
        return maskedNumber;
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


In the compliant code, a separate ILogger interface is introduced to handle logging functionality. The PaymentProcessor class now receives an instance of ILogger via dependency injection. The ProcessPayment method logs a success message with detailed information when the payment processing is successful. It includes the payment amount and a masked credit card number to avoid logging sensitive information.


When an exception occurs during payment processing, the code logs an error message that includes the payment amount, masked credit card number, and the exception details. This provides more comprehensive logging for troubleshooting and investigation purposes.


Note: The implementation of the ILogger interface is not provided in the code snippet as it can vary based on the logging framework or storage mechanism used in your application.




Semgrep:


```
rules:
  - id: secure-payment-processing
    pattern: |
      try {
        $processPaymentExpr
      } catch (Exception $ex) {
        Console.WriteLine("Payment processing failed. Exception: " + $ex.Message);
      }
    message: "Ensure secure payment processing"
```

CodeQL:



```
import csharp

class PaymentProcessing extends TryStatement {
  PaymentProcessing() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ExpressionStatement and
    getBody().getChildren().get(0).getChildren().get(0).toString().matches("$processPaymentExpr")
  }
}

from PaymentProcessing p
select p
```




## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Log the user login
        logger.LogInfo("User login: " + username);
    }
}
```

In this noncompliant code, the LogUserLogin method logs the user login by concatenating the username directly into the log message. This can lead to log injection vulnerabilities if the username contains special characters that can alter the log format or content.


To address this issue and ensure proper output neutralization, here's an example of compliant code:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Log the user login with neutralized output
        string logMessage = $"User login: {NeutralizeLogOutput(username)}";
        logger.LogInfo(logMessage);
    }

    private string NeutralizeLogOutput(string input)
    {
        // Implement logic to neutralize special characters or control characters in the log output
        // For example, replace newlines, carriage returns, or other potentially dangerous characters
        string neutralizedOutput = input.Replace("\r", "").Replace("\n", "");
        return neutralizedOutput;
    }
}

public interface ILogger
{
    void LogInfo(string message);
}
```


In the compliant code, the LogUserLogin method uses string interpolation to construct the log message, ensuring proper output neutralization. The NeutralizeLogOutput method is introduced to neutralize any special characters or control characters that could pose a security risk when included in the log output. In this example, newlines and carriage returns are removed from the username before logging.

By neutralizing the log output, the compliant code mitigates the risk of log injection vulnerabilities and ensures that the log messages accurately represent the intended content without any unintended effects on the log system.





Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class LoginController
      {
          private readonly ILogger logger;
      
          public LoginController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void LogUserLogin(string username)
          {
              // Log the user login
              logger.LogInfo("User login: " + $username);
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "LoginController" and
  ma2.getTarget().getName() = "LogUserLogin" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```




## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Process payment logic
        try
        {
            // Payment processing code here...

            logger.LogInfo("Payment processed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError("Payment processing failed");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


In this noncompliant code, the logger interface (ILogger) is used to log both informational and error messages during the payment processing. However, the code does not include any security-relevant information in the log messages. It only provides generic messages without any specific details that could help identify or diagnose potential security issues.


To address this issue, here's an example of compliant code that includes security-relevant information in the log messages:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Process payment logic
        try
        {
            // Payment processing code here...

            logger.LogInfo($"Payment processed successfully. Amount: {amount}");
        }
        catch (Exception ex)
        {
            logger.LogError($"Payment processing failed. Amount: {amount}. Error: {ex.Message}");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


In the compliant code, the log messages include the sensitive information, such as the payment amount, in addition to the generic message. This provides more context and helps in auditing, troubleshooting, and detecting any potential security incidents.






Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class PaymentController
      {
          private readonly ILogger logger;
      
          public PaymentController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void ProcessPayment(decimal amount)
          {
              // Process payment logic
              try
              {
                  // Payment processing code here...
      
                  logger.LogInfo($"Payment processed successfully: {amount}");
              }
              catch (Exception ex)
              {
                  logger.LogError("Payment processing failed");
              }
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "PaymentController" and
  ma2.getTarget().getName() = "ProcessPayment" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```






## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username, string password)
    {
        try
        {
            // User creation logic here...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```

In this noncompliant code, the UserController class includes a method CreateUser that logs sensitive information, namely the username and password, into the log file. Storing such sensitive information in plain text in the log file is a security vulnerability as it could lead to unauthorized access if the log files are compromised.


To address this issue, here's an example of compliant code that avoids logging sensitive information into the log file:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username)
    {
        try
        {
            // User creation logic here...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


In the compliant code, the CreateUser method no longer accepts the password as a parameter, and therefore it is not logged into the log file. Only the username, which is considered non-sensitive information, is logged for auditing and troubleshooting purposes. It's crucial to avoid logging sensitive information to minimize the risk of data breaches and unauthorized access.




Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      using System.IO;

      public class UserController
      {
          private readonly ILogger logger;

          public UserController(ILogger logger)
          {
              this.logger = logger;
          }

          public void CreateUser(string username, string password)
          {
              try
              {
                  // User creation logic here...

                  logger.LogInfo($"User '{username}' created successfully");
              }
              catch (Exception ex)
              {
                  logger.LogError($"Failed to create user '{username}'");
              }
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "UserController" and
  ma2.getTarget().getName() = "CreateUser" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```






## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Display the image on the website
        // ...
    }
}
```

In this noncompliant code, the DisplayImage method takes a URL as input and directly makes a request to that URL using the WebClient class. This code is susceptible to SSRF attacks because it allows an attacker to specify arbitrary URLs, including internal or restricted network resources. An attacker could abuse this functionality to make requests to sensitive internal systems, retrieve confidential information, or perform actions on behalf of the server.


To mitigate this vulnerability, here's an example of compliant code that includes input validation and implements a whitelist-based approach to restrict the URLs that can be accessed:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        if (!IsAllowedURL(url))
        {
            throw new ArgumentException("Invalid image URL");
        }

        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Display the image on the website
        // ...
    }

    private bool IsAllowedURL(string url)
    {
        // Implement logic to check if the URL is allowed
        // Example: Validate against a whitelist of trusted domains or patterns
        // ...
    }
}
```

In the compliant code, the DisplayImage method now includes input validation to ensure that only allowed URLs can be accessed. The IsAllowedURL method performs the necessary validation checks, such as comparing the URL against a whitelist of trusted domains or patterns. If the URL is not allowed, an exception is thrown, preventing the SSRF vulnerability.

By implementing proper input validation and restricting access to only trusted URLs, the compliant code mitigates the risk of SSRF attacks and helps ensure that requests are made to legitimate and authorized resources.




Semgrep:


```
metadata:
  difficulty: Easy

rules:
  - id: display-image-insecure
    message: "Insecure image display: Potential security vulnerability when displaying images from external sources."
    severity: warning
    languages:
      - csharp
    patterns:
      - pattern: "WebClient client = new WebClient();\nbyte\\[\\] imageData = client.DownloadData($url$);"
        capture:
          - variable: url
```

CodeQL:



```
import csharp

from MethodAccess ma
where ma.getMethod().getName() = "DownloadData" and ma.getQualifier().getType().getName() = "WebClient"
select ma
```
