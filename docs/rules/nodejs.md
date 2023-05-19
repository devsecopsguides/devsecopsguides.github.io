---
layout: default
title: NodeJS
parent: Rules
---

# NodeJS
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const fs = require('fs');

function login(username, password) {
  // Validate the username and password
  if (username === 'admin' && password === 'password123') {
    // Log the successful login
    fs.appendFileSync('logs.txt', `Successful login: ${username}`);
    return true;
  } else {
    // Log the failed login
    fs.appendFileSync('logs.txt', `Failed login: ${username}`);
    return false;
  }
}
```

In this noncompliant code, the login function logs sensitive information, such as the username, directly into a log file (logs.txt). This is a security risk as the log file may be accessible to unauthorized users, potentially exposing sensitive information like usernames or passwords.


To address this issue, here's a compliant code example that avoids exposing sensitive information in the log file:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const fs = require('fs');

function login(username, password) {
  // Validate the username and password
  if (username === 'admin' && password === 'password123') {
    // Log the successful login without sensitive information
    fs.appendFileSync('logs.txt', 'Successful login');
    return true;
  } else {
    // Log the failed login without sensitive information
    fs.appendFileSync('logs.txt', 'Failed login');
    return false;
  }
}
```


In this compliant code, the sensitive information (username) is not logged directly. Instead, only a generic log message indicating a successful or failed login is recorded in the log file. By avoiding the direct exposure of sensitive information in the log file, you can protect user credentials and prevent potential misuse or unauthorized access.

Additionally, it's important to ensure that the log files themselves are properly secured and access is restricted to authorized personnel only. This can include setting appropriate file permissions, encrypting the log files, or utilizing a centralized logging solution that offers robust access controls and security features.





## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Include sensitive information in the response
  res.json({
    id: userId,
    username: userData.username,
    email: userData.email,
    password: userData.password
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

In this noncompliant code, when the /user endpoint is called with a query parameter id, it retrieves user data for the specified ID and includes sensitive information such as the password in the response JSON. This can pose a security risk as the sensitive information may be intercepted or accessed by unauthorized parties.


To address this issue, here's a compliant code example that avoids inserting sensitive information into sent data:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Exclude sensitive information from the response
  const { id, username, email } = userData;
  res.json({ id, username, email });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```


In this compliant code, only the necessary non-sensitive information (such as user ID, username, and email) is included in the response JSON. The sensitive information, such as the password, is excluded from the response, reducing the risk of exposing sensitive data to unauthorized users.

It's important to ensure that sensitive information is handled securely and only shared with authorized users or in appropriate contexts. By following the principle of least privilege and excluding sensitive data from sent data, you can mitigate the risk of unauthorized access or exposure of sensitive information.






## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/transfer-money', (req, res) => {
  const amount = req.query.amount;
  const toAccount = req.query.to;

  // Transfer money to the specified account
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

In this noncompliant code, the /transfer-money endpoint allows the transfer of money by making a GET request with query parameters for the amount and the recipient account. This design is vulnerable to CSRF attacks because an attacker can create a malicious website that automatically triggers this request on behalf of a victim who visits the website. As a result, the victim's money can be transferred without their consent or knowledge.



To address this issue, here's a compliant code example that implements CSRF protection using tokens:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const csrf = require('csurf');
const app = express();

// Enable CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

// Generate and send CSRF token to the client
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Transfer money only for valid CSRF-protected requests
app.post('/transfer-money', csrfProtection, (req, res) => {
  const amount = req.body.amount;
  const toAccount = req.body.to;

  // Transfer money to the specified account
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```


In this compliant code, the CSRF protection middleware (csurf) is used to generate and validate CSRF tokens. First, a separate route (/csrf-token) is added to generate and send the CSRF token to the client. Then, the /transfer-money endpoint is modified to accept only POST requests and include the CSRF protection middleware. This ensures that the transfer of money can only be performed if a valid CSRF token is provided with the request.


By implementing CSRF protection, the compliant code prevents unauthorized parties from performing malicious actions, such as transferring money, through forged requests. The use of CSRF tokens helps verify the authenticity of requests and protects against CSRF attacks.







## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;
const password = 'myHardcodedPassword';

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error hashing password:', err);
    return;
  }

  // Store the hashed password in the database
  storePasswordInDatabase(hash);
});
```

In this noncompliant code, the variable password contains a hard-coded password value. Storing passwords directly in code poses a significant security risk because if an attacker gains access to the codebase, they will have immediate knowledge of the password, potentially compromising user accounts or system security.


To address this issue, here's a compliant code example that avoids the use of hard-coded passwords:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }

    // Store the hashed password in the database
    storePasswordInDatabase(hash, callback);
  });
}

// Usage
const password = 'myPassword';
hashPassword(password, (err) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Password hashed and stored successfully');
});
```

In this compliant code, the hashPassword function takes the password as a parameter and generates a secure hash using the bcrypt library. The hashed password is then stored in the database. By separating the password from the code and passing it as a parameter, the hard-coded password is no longer present in the codebase. Instead, the password is supplied at runtime, reducing the risk of unauthorized access to sensitive information.

By avoiding the use of hard-coded passwords, the compliant code enhances the security of the application and reduces the risk of unauthorized access to user accounts or system resources.







## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const crypto = require('crypto');

function hashPassword(password) {
  const hash = crypto.createHash('md5').update(password).digest('hex');
  return hash;
}

// Usage
const password = 'myPassword';
const hashedPassword = hashPassword(password);
console.log('Hashed password:', hashedPassword);
```


In this noncompliant code, the crypto.createHash function is used with the MD5 algorithm to hash the password. However, MD5 is considered to be insecure for password hashing due to its vulnerability to collision attacks and the availability of faster computing resources. It's important to use stronger and more secure algorithms, such as bcrypt or Argon2, for password hashing to protect user credentials.


To address this issue, here's a compliant code example that uses the bcrypt library for secure password hashing:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }
    return callback(null, hash);
  });
}

// Usage
const password = 'myPassword';
hashPassword(password, (err, hashedPassword) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Hashed password:', hashedPassword);
});
```

In this compliant code, the bcrypt library is used to securely hash the password. The bcrypt.hash function generates a salted hash with the specified number of rounds, providing a high level of security against brute-force and dictionary attacks.

By using bcrypt instead of the insecure MD5 algorithm, the compliant code significantly improves the security of password hashing in the application. This helps protect user credentials and prevents attackers from easily obtaining the original passwords through brute-force or rainbow table attacks.







## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
function generateApiKey() {
  const length = 32;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let apiKey = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    apiKey += chars.charAt(randomIndex);
  }

  return apiKey;
}

// Usage
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
```


In this noncompliant code, the generateApiKey function attempts to generate a random API key by selecting random characters from a predetermined set of characters. However, the random values are generated using the Math.random() function, which may not provide sufficient entropy for secure random number generation. The Math.random() function relies on the underlying random number generator of the JavaScript runtime, which may not be suitable for cryptographic purposes.

To address this issue, here's a compliant code example that uses the crypto module in Node.js to generate a secure random API key:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const crypto = require('crypto');

function generateApiKey() {
  const length = 32;
  const buffer = crypto.randomBytes(length);
  const apiKey = buffer.toString('hex');
  return apiKey;
}

// Usage
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
```

In this compliant code, the crypto.randomBytes function from the crypto module is used to generate a buffer of cryptographically secure random bytes. The buffer is then converted to a hexadecimal string representation using the toString method. This approach ensures the generation of random values with sufficient entropy for secure purposes.

By using the crypto.randomBytes function instead of Math.random(), the compliant code improves the entropy of the generated API key, making it more secure and resistant to prediction or guessing attacks.







## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  const response = `Search results for: ${query}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the /search endpoint retrieves the search query from the request's query parameters (req.query.q) and includes it directly in the response without any sanitization or validation. This can lead to an XSS vulnerability because an attacker can craft a malicious query that includes JavaScript code, which will be executed when the response is rendered in a user's browser.


To address this issue, here's a compliant code example that properly sanitizes user input to prevent XSS attacks:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const xss = require('xss');

app.get('/search', (req, res) => {
  const query = req.query.q;
  const sanitizedQuery = xss(query);
  const response = `Search results for: ${sanitizedQuery}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In this compliant code, the xss library is used to sanitize the user input (query) before including it in the response. The xss function escapes any HTML tags and special characters in the query, preventing them from being interpreted as code when rendered in the browser. This ensures that the response is safe from XSS attacks by effectively neutralizing any potentially malicious input.

By incorporating proper input sanitization using a library like xss, the compliant code mitigates the risk of XSS vulnerabilities and ensures that user input is properly handled and rendered safely in the browser.








## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Execute the SQL query and return the results
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the /users endpoint retrieves the user ID from the request's query parameters (req.query.id) and directly interpolates it into the SQL query (SELECT * FROM users WHERE id = ${userId}). This makes the code vulnerable to SQL injection attacks. An attacker can manipulate the userId parameter and inject malicious SQL code, potentially gaining unauthorized access to the database or performing other harmful actions.


To address this issue, here's a compliant code example that uses prepared statements to mitigate the SQL injection vulnerability:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });

  connection.query(query, [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this compliant code, a prepared statement is used by replacing the user input with a placeholder (?) in the SQL query (SELECT * FROM users WHERE id = ?). The actual user input (userId) is passed as a parameter to the connection.query method, ensuring that it is properly escaped and treated as a value, rather than being executed as part of the SQL query itself. This effectively prevents SQL injection attacks by separating the SQL code from the user input.

By using prepared statements or parameterized queries, the compliant code ensures that user input is handled safely and prevents malicious SQL injection attacks by treating user input as data rather than executable code.





## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const filePath = `/path/to/files/${fileName}`;

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In this noncompliant code, the /download endpoint allows users to specify the file name in the query parameter (req.query.file). The code directly uses the user-supplied file name to construct the file path (/path/to/files/${fileName}) and attempts to read and send the file's content. This approach introduces a security vulnerability known as external control of file name or path, where an attacker can manipulate the file parameter to access arbitrary files on the server's file system.


To address this issue, here's a compliant code example that validates and sanitizes the file name to prevent external control of file name or path attacks:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const sanitizedFileName = path.basename(fileName); // Sanitize the file name
  const filePath = path.join('/path/to/files', sanitizedFileName);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${sanitizedFileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this compliant code, the file name obtained from the user input (req.query.file) is sanitized using path.basename to extract the file name and discard any directory information or path traversal attempts. The sanitized file name is then securely joined with the base directory path using path.join to ensure a valid and safe file path is constructed. By validating and sanitizing the file name, the compliant code prevents external control of file name or path attacks and restricts the file access to the intended directory.

It's important to note that the code examples provided assume a simplified scenario for demonstration purposes. In practice, it is recommended to implement additional security measures such as access controls, file type validation, and proper error handling to enhance the security of file downloads.






## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    throw new Error(`User ${userId} not found`); // Noncompliant: Error message contains sensitive information
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In this noncompliant code, when a user is not found in the database, an error is thrown with an error message that includes the user ID (User ${userId} not found). This approach poses a security risk as it exposes sensitive information (the user ID) to potential attackers. Error messages containing sensitive information can be exploited by malicious actors to gather intelligence about the system and potentially mount further attacks.


To address this issue, here's a compliant code example that avoids including sensitive information in error messages:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    res.status(404).send('User not found'); // Compliant: Generic error message without sensitive information
    return;
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this compliant code, when a user is not found, a generic error message is sent without including any sensitive information. By providing a generic error message, the code avoids leaking potentially sensitive data and provides limited information to potential attackers.

It's crucial to handle errors carefully and avoid exposing sensitive information through error messages. Additionally, it's recommended to log errors on the server side for debugging and monitoring purposes, while ensuring that the logs do not contain sensitive information.






## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

let databaseCredentials = {
  username: 'admin',
  password: 'secretpassword'
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the database credentials (username and password) are stored directly in a variable (databaseCredentials) without any protection. Storing credentials in plain text in the source code or configuration files is highly insecure and exposes them to potential unauthorized access. Any person with access to the codebase can easily retrieve the credentials, posing a significant security risk.


To address this issue, here's a compliant code example that demonstrates a better approach for handling credentials:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

// These credentials should be stored securely, such as environment variables or a separate configuration file.
const databaseCredentials = {
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In the compliant code, the credentials are loaded from environment variables (process.env) instead of being hardcoded directly in the code. Storing sensitive information, such as database credentials, in environment variables provides an additional layer of security. By utilizing environment variables, the credentials are kept separate from the codebase and can be easily managed and protected in a secure manner.


Remember to configure the environment variables securely on the server hosting the application to ensure the credentials are properly protected.




## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = req.body.isAdmin;

  if (isAdmin) {
    // Perform privileged operation
    grantAdminAccess();
  } else {
    // Process user request
    processUserRequest();
  }

  res.send('Form submitted successfully');
});

function grantAdminAccess() {
  // Code to grant admin access
  // ...
}

function processUserRequest() {
  // Code to process user request
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, there is no proper validation or enforcement of the trust boundary between user input and privileged operations. The code blindly trusts the value of req.body.isAdmin to determine whether the user should be granted admin access or not. This trust boundary violation allows an attacker to manipulate the value of isAdmin and gain unauthorized admin privileges.


To address this issue, here's a compliant code example that demonstrates proper trust boundary enforcement:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = Boolean(req.body.isAdmin);

  if (isAdmin) {
    // Verify user authentication and authorization before granting admin access
    authenticateAndAuthorizeUser(req)
      .then(() => {
        grantAdminAccess();
        res.send('Admin access granted');
      })
      .catch(() => {
        res.status(403).send('Access denied');
      });
  } else {
    // Process user request
    processUserRequest();
    res.send('Form submitted successfully');
  }
});

function grantAdminAccess() {
  // Code to grant admin access
  // ...
}

function processUserRequest() {
  // Code to process user request
  // ...
}

function authenticateAndAuthorizeUser(req) {
  // Perform user authentication and authorization
  // ...
  // Return a promise that resolves if the user is authenticated and authorized, or rejects otherwise
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

```

In the compliant code, the value of req.body.isAdmin is properly validated and converted to a boolean using Boolean(req.body.isAdmin). Additionally, the code enforces a trust boundary by explicitly checking the user's authentication and authorization before granting admin access. The authenticateAndAuthorizeUser function is responsible for performing the necessary authentication and authorization checks and returns a promise that resolves if the user is authenticated and authorized or rejects otherwise.


By enforcing the trust boundary and properly validating user input, the code mitigates the risk of unauthorized access and ensures that privileged operations are only performed when appropriate authentication and authorization are established.




## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Store the credentials in plain text
  storeCredentials(username, password);

  // Perform authentication
  const isAuthenticated = authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

function storeCredentials(username, password) {
  // Code to store credentials (noncompliant)
  // ...
}

function authenticate(username, password) {
  // Code to authenticate user
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the user's credentials are stored in plain text by calling the storeCredentials function. Storing sensitive information, such as passwords, in plain text leaves them vulnerable to unauthorized access if the system is compromised.


To address this issue, here's a compliant code example that demonstrates the proper protection of credentials using a secure hashing algorithm:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

const saltRounds = 10;

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Hash the password
  const hashedPassword = await hashPassword(password);

  // Store the hashed password
  storeCredentials(username, hashedPassword);

  // Perform authentication
  const isAuthenticated = await authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

async function hashPassword(password) {
  // Hash the password using bcrypt
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

function storeCredentials(username, hashedPassword) {
  // Code to store hashed credentials
  // ...
}

async function authenticate(username, password) {
  // Retrieve hashed password from storage
  const storedHashedPassword = await getHashedPassword(username);

  // Compare the provided password with the stored hashed password
  const isAuthenticated = await bcrypt.compare(password, storedHashedPassword);
  return isAuthenticated;
}

async function getHashedPassword(username) {
  // Code to retrieve hashed password from storage
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the user's password is protected by using the bcrypt library to securely hash the password before storing it. The hashPassword function generates a salt and hashes the password using bcrypt. The resulting hashed password is then stored using the storeCredentials function.

During authentication, the stored hashed password is retrieved using the getHashedPassword function. The provided password is compared with the stored hashed password using the bcrypt.compare function, which performs a secure comparison without revealing the original password.

By properly protecting credentials with a strong hashing algorithm like bcrypt, the code ensures that even if the stored passwords are compromised, they are not easily readable or usable by an attacker.




## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Parse the XML data
  xml2js.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Process the XML data
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the XML data received from the client is parsed using the xml2js library without proper restriction of XML external entity references. This can lead to XXE attacks where an attacker can include external entities and read arbitrary files from the server or perform other malicious actions.


To address this issue, here's a compliant code example that demonstrates the restriction of XML external entity references:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Configure the XML parser to disable external entity references
  const parser = new xml2js.Parser({
    explicitCharkey: true,
    explicitRoot: false,
    explicitArray: false,
    ignoreAttrs: true,
    mergeAttrs: false,
    xmlns: false,
    allowDtd: false,
    allowXmlExternalEntities: false, // Disable external entity references
  });

  // Parse the XML data
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Process the XML data
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the XML parser from the xml2js library is configured with the allowXmlExternalEntities option set to false, which disables external entity references. This prevents potential XXE attacks by disallowing the parsing of external entities and ensures that only safe XML data is processed.

By restricting XML external entity references, the code mitigates the risk of XXE attacks and helps maintain the integrity and security of the application.




## Vulnerable and Outdated Components


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongo = require('mongo');

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  mongo.connect('mongodb://localhost:27017', (err, client) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          res.status(500).send('Internal Server Error');
        } else {
          res.status(200).send('User created successfully');
        }
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, there are two issues related to vulnerable and outdated components:

1. The mongo package is used to connect to a MongoDB database. However, the version of the package being used may have known vulnerabilities or be outdated. This can expose the application to potential security risks.

2. The code does not handle error scenarios properly. In case of an error during the database connection or user insertion, the application simply responds with an "Internal Server Error" message. This lack of detailed error handling can make it difficult to identify and resolve security issues or potential vulnerabilities.



To address these issues, here's a compliant code example that demonstrates the use of secure and up-to-date components as well as improved error handling:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  MongoClient.connect('mongodb://localhost:27017', { useUnifiedTopology: true }, (err, client) => {
    if (err) {
      console.error(err);
      res.status(500).send('Database connection error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send('User creation error');
        } else {
          res.status(200).send('User created successfully');
        }
        client.close(); // Close the database connection
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the following improvements have been made:

1. The mongo package has been replaced with mongodb package, which is actively maintained and up-to-date.

2. The useUnifiedTopology option is added to the MongoClient connection to ensure a secure and recommended connection topology.

3. Detailed error handling is implemented by logging the error messages to the console. This provides better visibility into potential issues and aids in troubleshooting.

4. The client.close() method is called to close the database connection after the operation is completed. This helps prevent resource leaks and ensures proper management of the database connection.

By using secure and up-to-date components, as well as implementing improved error handling practices, the compliant code reduces the risk of vulnerabilities and ensures a more robust and secure application.





## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const https = require('https');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  rejectUnauthorized: false, // Disabling certificate validation
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
```

In this noncompliant code, the rejectUnauthorized option is set to false, effectively disabling certificate validation. This means that the Node.js application will accept any certificate, even if it doesn't match the expected hostname (example.com in this case). This can lead to security vulnerabilities, such as man-in-the-middle attacks or spoofing.


To address this issue, here's a compliant code example that demonstrates proper validation of the certificate with the expected hostname:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const https = require('https');
const tls = require('tls');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  checkServerIdentity: (host, cert) => {
    const err = tls.checkServerIdentity(host, cert);
    if (err) {
      throw err; // Terminate the connection on certificate mismatch
    }
  },
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
```


In the compliant code, the checkServerIdentity option is used to provide a custom callback function that performs proper certificate validation. The tls.checkServerIdentity function is used to compare the expected hostname (example.com) with the certificate's Common Name (CN) or Subject Alternative Names (SANs). If there is a mismatch, an error is thrown, terminating the connection.

By implementing proper certificate validation, the compliant code ensures that the certificate presented by the server matches the expected hostname, reducing the risk of man-in-the-middle attacks and providing a more secure communication channel.







## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === 'admin' && password === 'admin123') {
    // Successful authentication
    res.send('Login successful!');
  } else {
    // Failed authentication
    res.send('Invalid username or password!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the authentication mechanism relies on a simple username and password check. The username and password are received from the request body, and a hardcoded comparison is performed to determine whether the authentication is successful. This approach is insecure because it lacks proper security measures, such as hashing and salting passwords, implementing strong authentication protocols, and protecting against brute-force attacks.


To address this issue, here's a compliant code example that demonstrates improved authentication practices:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');

// Mock user data
const users = [
  {
    username: 'admin',
    password: '$2b$10$rZrVJnI1.Y9OyK6ZrLqmguXHBXYTNcIQ00CJQc8XU1gYRGmdxcqzK', // Hashed password: "admin123"
  },
];

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = users.find((user) => user.username === username);
  if (!user) {
    // User not found
    return res.status(401).send('Invalid username or password!');
  }

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) {
      // Error during password comparison
      return res.status(500).send('Internal Server Error');
    }

    if (result) {
      // Successful authentication
      res.send('Login successful!');
    } else {
      // Failed authentication
      res.status(401).send('Invalid username or password!');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, several improvements are made to the authentication process. Instead of a simple comparison, the code uses the bcrypt library to hash and compare passwords securely. The user's password is stored as a hashed value in the user data. When a login request is received, the code retrieves the user from the user data based on the provided username. Then, bcrypt.compare is used to compare the provided password with the stored hashed password.

By implementing proper password hashing and secure comparison, the compliant code enhances the security of the authentication process, making it more resistant to password cracking attempts and improving overall application security.







## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const session = require('express-session');
const app = express();

app.use(
  session({
    secret: 'insecuresecret',
    resave: false,
    saveUninitialized: true,
  })
);

app.get('/login', (req, res) => {
  // Generate a new session ID and store it in the session cookie
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Accessing the profile without authentication
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application uses the express-session middleware to manage sessions. However, it is vulnerable to session fixation attacks. The code generates a new session ID upon visiting the /login route but does not invalidate the existing session ID. This allows an attacker to fixate a session ID by initiating a session and then tricking the victim into using the same session ID.


To address this issue, here's a compliant code example that demonstrates session fixation prevention:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

app.use(
  session({
    secret: 'securesecret',
    resave: false,
    saveUninitialized: true,
    genid: () => {
      // Generate a unique session ID
      return crypto.randomBytes(16).toString('hex');
    },
  })
);

app.get('/login', (req, res) => {
  // Regenerate session ID to prevent session fixation
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Accessing the profile without authentication
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the session ID is regenerated upon successful login by using the regenerate method provided by the express-session middleware. This invalidates the previous session ID and generates a new, unique one. By doing so, the code prevents session fixation attacks because the attacker's fixed session ID becomes invalid.

By implementing session ID regeneration and ensuring that a new session ID is issued upon login, the compliant code mitigates the session fixation vulnerability and enhances the overall security of the application.





## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Execute the specified function from untrusted user input
  eval(functionName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application exposes an endpoint /dynamic that takes a function query parameter. The code uses the eval() function to directly execute the specified function from the untrusted user input. This approach is highly dangerous as it allows arbitrary code execution, enabling attackers to execute malicious code on the server.


To address this issue, here's a compliant code example that avoids the inclusion of functionality from untrusted control:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Validate the function name against a whitelist
  if (isFunctionAllowed(functionName)) {
    // Call the allowed function from a predefined set
    const result = callAllowedFunction(functionName);
    res.send(result);
  } else {
    res.status(400).send('Invalid function');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFunctionAllowed(functionName) {
  // Check if the function name is in the allowed set
  const allowedFunctions = ['function1', 'function2', 'function3'];
  return allowedFunctions.includes(functionName);
}

function callAllowedFunction(functionName) {
  // Implement the logic for each allowed function
  if (functionName === 'function1') {
    return 'Function 1 called';
  } else if (functionName === 'function2') {
    return 'Function 2 called';
  } else if (functionName === 'function3') {
    return 'Function 3 called';
  }
}
```


In the compliant code, the application validates the function query parameter against a whitelist of allowed functions using the isFunctionAllowed() function. If the specified function is allowed, the code calls the corresponding function from a predefined set using the callAllowedFunction() function. This approach ensures that only safe and intended functionality is executed based on the whitelist, mitigating the risk of executing arbitrary or malicious code.

By implementing this approach, the compliant code prevents the inclusion of functionality from untrusted control and helps protect the application from potential security vulnerabilities and attacks.





## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Download the file without integrity check
  res.download(fileName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application exposes an endpoint /download that takes a filename query parameter. The code uses the res.download() function to download the file specified by the user without performing any integrity check. This approach is insecure because it allows users to download potentially malicious or tampered files, which can lead to security vulnerabilities in the application or compromise the user's system.


To address this issue, here's a compliant code example that incorporates an integrity check before downloading the file:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const crypto = require('crypto');

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Read the file contents
  fs.readFile(fileName, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
      return;
    }

    // Calculate the file's hash
    const fileHash = crypto.createHash('sha256').update(data).digest('hex');

    // Perform integrity check
    if (isFileIntegrityValid(fileHash)) {
      // Download the file
      res.download(fileName);
    } else {
      res.status(403).send('Integrity check failed');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFileIntegrityValid(fileHash) {
  // Compare the calculated hash with a trusted hash
  const trustedHash = '...'; // Replace with the trusted hash
  return fileHash === trustedHash;
}
```


In the compliant code, the application reads the file specified by the user using the fs.readFile() function and calculates its hash using a secure cryptographic hash function (sha256 in this example). The code then compares the calculated hash with a trusted hash to perform an integrity check using the isFileIntegrityValid() function. If the file's integrity is valid, the code allows the file to be downloaded using the res.download() function. Otherwise, an appropriate error response is sent.

By implementing this approach, the compliant code ensures that files are downloaded only after passing an integrity check. This helps protect the application and its users from downloading potentially malicious or tampered files, reducing the risk of security vulnerabilities and compromising the system's integrity.






## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const deserialize = require('deserialize');

// Middleware to parse JSON data
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Deserialize user data without validation
  const user = deserialize(userData);

  // Process user data
  // ...

  res.status(200).send('User data processed successfully');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application exposes a POST endpoint /user that expects JSON data containing user information. The code uses the deserialize library to deserialize the JSON data into a user object without performing any validation or sanitization. This approach is insecure because it allows the deserialization of untrusted data, which can lead to remote code execution, object injection, or other security vulnerabilities.


To address this issue, here's a compliant code example that incorporates proper validation and sanitization before deserializing the data:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const validateUser = require('./validateUser');

// Middleware to parse JSON data
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Validate user data
  const validationResult = validateUser(userData);

  if (validationResult.isValid) {
    // Sanitize user data
    const sanitizedData = sanitizeUserData(validationResult.data);

    // Deserialize user data
    const user = deserialize(sanitizedData);

    // Process user data
    // ...

    res.status(200).send('User data processed successfully');
  } else {
    res.status(400).send('Invalid user data');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the application includes a validation step using the validateUser() function before deserializing the data. The validateUser() function performs necessary checks and returns a validation result object indicating whether the data is valid or not. If the data is valid, the code proceeds to sanitize the user data using the sanitizeUserData() function, which ensures that any potentially dangerous content is removed or properly handled. Finally, the sanitized data is deserialized using the deserialize() function, and the application can safely process the user data.



By implementing this approach, the compliant code ensures that untrusted data is properly validated, sanitized, and deserialized, reducing the risk of deserialization vulnerabilities and protecting the application from potential security exploits.






## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application has an endpoint /user/:id that retrieves user details based on the provided id. However, the code lacks sufficient logging, making it challenging to track and investigate potential issues or security events. Without proper logging, it becomes difficult to identify unauthorized access attempts, suspicious activities, or errors that occur during user retrieval.


To address this issue, here's a compliant code example that incorporates sufficient logging practices:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const logger = require('winston');

// Configure logger
logger.configure({
  transports: [
    new logger.transports.Console(),
    new logger.transports.File({ filename: 'app.log' })
  ]
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  logger.info(`User retrieval requested for id: ${userId}`);

  // Fetch user from the database
  const user = db.getUser(userId);

  if (user) {
    // Log successful user retrieval
    logger.info(`User retrieved successfully: ${user.name}`);

    // Return user details
    res.status(200).json(user);
  } else {
    // Log unsuccessful user retrieval
    logger.warn(`User not found for id: ${userId}`);

    // Return appropriate error response
    res.status(404).json({ error: 'User not found' });
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the application incorporates the Winston logging library to log relevant events. The logger is configured with two transports: the console for immediate visibility during development and a file transport for persistent logging.

The code adds logging statements to record important events such as user retrieval requests, successful user retrievals, and unsuccessful attempts. This information helps in tracking user interactions and identifying potential security issues or application errors.

By implementing this approach, the compliant code ensures that sufficient logging is in place, providing valuable insights into the application's behavior, security-related events, and potential areas of concern.



## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  const logMessage = `User retrieval requested for id: ${userId}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application logs the user retrieval event by directly appending the log message to a log file using fs.appendFile(). However, the log message is not properly neutralized, which can lead to log injection vulnerabilities. An attacker could potentially inject malicious content into the log message, leading to log forging or other security risks.


To address this issue, here's a compliant code example that incorporates proper output neutralization for logs:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const { sanitizeLogMessage } = require('./utils');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Log the user retrieval event
  const logMessage = `User retrieval requested for id: ${sanitizeLogMessage(userId)}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Fetch user from the database
  const user = db.getUser(userId);

  // Return user details
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, a separate sanitizeLogMessage function is introduced to properly neutralize the log message. This function can apply necessary escaping or filtering techniques to prevent log injection attacks. The sanitizeLogMessage function should be implemented with appropriate techniques based on the log storage format and requirements.

By using proper output neutralization, the compliant code ensures that any user-controlled input included in log messages is properly sanitized or encoded, preventing log injection vulnerabilities and maintaining the integrity and security of the log records.





## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Perform login logic

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In this noncompliant code, the application handles user login functionality but fails to provide detailed error messages or log security-relevant information. When the login fails, it simply responds with a generic "Invalid credentials" message, which does not provide enough information to the user or the application administrators to understand the reason for the login failure. This lack of specific error information can make it difficult to troubleshoot and address security issues effectively.


To address this issue, here's a compliant code example that includes security-relevant information in error messages and logs:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Perform login logic

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    console.error(`Login failed for username: ${username}`);
    res.status(401).send('Invalid username or password');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, when the login fails, the application logs an error message that includes the username that failed to log in. Additionally, the response message is updated to provide a more informative error message, indicating that either the username or password is invalid. This improvement helps in identifying and troubleshooting login failures, as well as providing more meaningful feedback to the user.


By including security-relevant information in error messages and logs, the compliant code enhances the application's security posture by improving visibility and enabling better incident response and debugging capabilities.








## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user information from the database
  const user = User.findById(userId);

  // Log user information
  console.log(`User information: ${user}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application logs sensitive user information using the console.log function. The user object, which contains potentially confidential data, is directly passed to the log statement. This practice can expose sensitive information to the log files, making them accessible to unauthorized users or increasing the risk of data leakage.


To address this issue, here's a compliant code example that avoids logging sensitive information:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Fetch user information from the database
  const user = User.findById(userId);

  // Log a generic message instead of sensitive information
  console.log(`User requested: ${userId}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


In the compliant code, the application logs a generic message indicating that a user was requested, without directly exposing any sensitive information. By avoiding the logging of sensitive data, the compliant code helps protect user privacy and reduces the risk of data leakage through log files.


It's important to remember that sensitive information should not be logged in clear text or in a format that can easily be traced back to specific individuals or data records. Proper log management practices should be followed, such as using log levels, sanitizing logs, and implementing access controls to restrict log file access to authorized personnel.






## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
const express = require('express');
const axios = require('axios');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Make a request to the provided URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this noncompliant code, the application accepts a url query parameter from the user and directly makes a request to that URL using the axios library. This approach poses a significant security risk as an attacker can supply a malicious URL that targets internal network resources or exposes sensitive information.


To mitigate the SSRF vulnerability, here's a compliant code example:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Validate the URL to ensure it is not an internal resource
  const parsedUrl = new URL(url);
  if (parsedUrl.hostname !== 'example.com') {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Make a request to the provided URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In the compliant code, the URL parameter is validated to ensure that it points to an allowed domain (example.com in this case) before making the request. By enforcing this validation, the code prevents SSRF attacks by only allowing requests to trusted external resources.

It's important to note that the specific validation logic may vary depending on the application's requirements and security policies. The example above demonstrates a basic approach, but additional security measures such as IP whitelisting, input sanitization, and request timeout should be considered to further enhance SSRF protection.