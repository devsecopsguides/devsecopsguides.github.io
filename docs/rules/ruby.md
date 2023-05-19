---
layout: default
title: Ruby
parent: Rules
---

# Ruby
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def process_payment(user, amount)
  # Log the payment details including sensitive information
  puts "Payment processed for user #{user.name} with amount #{amount}"
  # Process the payment
  # ...
end
```

The noncompliant code directly logs sensitive information, such as the user's name and payment amount, using the puts method. This practice poses a security risk because log files are often accessible to multiple users, increasing the potential for unauthorized access to sensitive information. Attackers can exploit this vulnerability to gather user details or financial information.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
require 'logger'

def process_payment(user, amount)
  # Initialize a logger with appropriate settings
  logger = Logger.new('payment.log')
  
  # Log a message without sensitive information
  logger.info("Payment processed for user with ID #{user.id}")
  
  # Process the payment
  # ...
end
```


The compliant code uses the Logger class from Ruby's standard library to log messages with appropriate settings. The sensitive information, such as the user's name and payment amount, is not directly included in the log message. Instead, a message containing non-sensitive information, such as the user's ID, is logged.

By using the Logger class, you can control the log file's location, format, and access permissions. You can also configure log rotation and encryption if necessary. It's important to ensure that the log files are stored in a secure location with restricted access, limiting the exposure of sensitive information.

Remember to customize the logger settings according to your specific requirements, such as defining the log level, formatting options, and log file rotation strategies.

The compliant code helps mitigate the risk of exposing sensitive information via logs by avoiding direct inclusion of sensitive data in log messages and using a dedicated logging framework that provides better control over log file storage and access.




## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def send_data(user, data)
  # Include sensitive information in the sent data
  request_body = { user: user, data: data }
  HTTP.post('https://api.example.com/data', body: request_body.to_json)
end
```

The noncompliant code includes sensitive information, such as the user object, directly in the data payload that is sent to an external API. This practice can expose sensitive details to potential attackers if they intercept or gain unauthorized access to the transmitted data.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
def send_data(user, data)
  # Exclude sensitive information from the sent data
  request_body = { data: data }
  HTTP.post('https://api.example.com/data', body: request_body.to_json)
end
```


The compliant code removes the sensitive information, such as the user object, from the data payload before sending it to the external API. By excluding sensitive information from the sent data, you reduce the risk of exposing sensitive details to unintended recipients.

It's important to ensure that sensitive information is handled securely and is only shared with trusted and authorized entities. If necessary, consider encrypting the sensitive data before transmission to add an additional layer of protection.

By following the compliant code approach, you separate sensitive information from the data sent to external services, reducing the chances of accidental exposure and mitigating potential security risks.







## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
get '/transfer_funds' do
  amount = params[:amount]
  recipient = params[:recipient]

  # Transfer funds logic here
  # ...
end
```

In this noncompliant code, there is no CSRF protection implemented. An attacker could craft a malicious HTML page that includes a form to transfer funds, and if the user is authenticated and visits this page while also being logged into a vulnerable website, the funds transfer could be triggered without the user's explicit consent.



To address this vulnerability, you need to implement CSRF protection. Here's an example of compliant code that includes CSRF protection:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
enable :sessions

before do
  csrf_token = session[:csrf_token]
  unless params[:csrf_token] == csrf_token
    halt 403, 'CSRF token verification failed!'
  end
end

get '/transfer_funds' do
  amount = params[:amount]
  recipient = params[:recipient]

  # Transfer funds logic here
  # ...
end
```


In the compliant code, the enable :sessions line enables session handling in Sinatra, which will store a unique session ID in the user's browser cookie. This session ID will be associated with the user's session data on the server.

The before block is executed before each request, and it checks if the CSRF token sent in the request matches the one stored in the session. If the tokens don't match, a 403 Forbidden response is returned, indicating that the CSRF token verification failed.

To use this CSRF protection, you need to generate and include a CSRF token in your HTML forms. For example:







## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def login(username, password)
  if username == 'admin' && password == 'password123'
    puts 'Login successful'
  else
    puts 'Invalid credentials'
  end
end
```

In this noncompliant code, the username and password are hardcoded directly into the code. This is a security risk because anyone with access to the code can easily see and potentially abuse the hardcoded credentials. If the code is shared or stored in a version control system, the sensitive password becomes even more exposed.



To address this security concern, it's important to avoid hardcoding passwords in your code. Here's an example of compliant code that avoids using hard-coded passwords:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
def login(username, password)
  stored_password = retrieve_password_from_database(username)

  if stored_password && stored_password == password
    puts 'Login successful'
  else
    puts 'Invalid credentials'
  end
end
```

In the compliant code, the hard-coded password is replaced with a function call retrieve_password_from_database(username). This function fetches the password associated with the given username from a secure data source, such as a database.


By storing passwords securely and retrieving them dynamically when needed, you can prevent the risks associated with hardcoding passwords in your code. It's important to ensure that the password storage mechanism, such as a database, follows industry best practices for security, such as properly hashing and salting the passwords.

Additionally, it's worth noting that in a real-world scenario, you would typically not have a puts statement for indicating a successful login. Instead, you would typically redirect the user to an authenticated session or perform further actions based on the login result. The example provided focuses solely on the password handling aspect.








## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'openssl'

def encrypt_data(data, key)
  cipher = OpenSSL::Cipher.new('DES')
  cipher.encrypt
  cipher.key = key
  encrypted_data = cipher.update(data) + cipher.final
  encrypted_data
end
```


In this noncompliant code, the Data Encryption Standard (DES) algorithm is used for encrypting data. DES is considered insecure and outdated, as it has known vulnerabilities and is susceptible to brute-force attacks. Using DES for encryption can compromise the confidentiality and security of the data.

To address this security concern, it's important to use modern and secure cryptographic algorithms. Here's an example of compliant code that uses a secure algorithm:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'openssl'

def encrypt_data(data, key)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  encrypted_data = cipher.update(data) + cipher.final
  encrypted_data
end
```

In the compliant code, the Advanced Encryption Standard (AES) algorithm with a 256-bit key size and Cipher Block Chaining (CBC) mode is used. AES is widely regarded as secure and is widely used in various applications and industries.

The code generates a random initialization vector (IV) using cipher.random_iv and uses it in combination with the key to encrypt the data. Including a random IV for each encryption operation adds an additional layer of security to the encryption process.

It's important to stay updated with current cryptographic best practices and choose algorithms that are considered secure by industry standards. Additionally, ensure that you handle cryptographic keys securely and follow recommended practices for key management, such as properly storing and protecting keys from unauthorized access.









## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def generate_password(length)
  charset = Array('A'..'Z') + Array('a'..'z') + Array('0'..'9')
  password = Array.new(length) { charset.sample }.join
  password
end
```


In this noncompliant code, a password is generated using a limited character set consisting only of uppercase letters, lowercase letters, and digits. While this approach may seem reasonable at first glance, it lacks sufficient entropy, making the generated passwords relatively weak.

To address this security concern, it's important to improve the entropy of the generated passwords. Here's an example of compliant code that uses a more robust approach:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'securerandom'

def generate_password(length)
  charset = Array('A'..'Z') + Array('a'..'z') + Array('0'..'9') + ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
  password = Array.new(length) { charset.sample }.join
  password
end

def generate_secure_password(length)
  password = SecureRandom.urlsafe_base64(length)
  password
end
```

In the compliant code, two functions are provided for generating passwords. The first function, generate_password, improves the entropy by expanding the character set to include additional special characters. This increases the number of possible combinations and makes the generated passwords stronger.

The second function, generate_secure_password, leverages Ruby's SecureRandom module to generate a secure random password using a cryptographically strong random number generator. The urlsafe_base64 method ensures that the generated password is URL-safe by using a character set specifically designed for such purposes.

It's important to note that the choice of password length and character set should be carefully considered based on the specific requirements and security policies of your application. Additionally, encouraging users to choose longer, unique, and complex passwords is essential for maintaining strong security practices.







## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
get '/search' do
  query = params[:query]
  "<h1>Search Results for #{query}</h1>"
end
```

In this noncompliant code, the user-supplied query parameter is directly embedded into an HTML response without any sanitization or validation. This makes the application vulnerable to XSS attacks. An attacker can exploit this vulnerability by injecting malicious code into the query parameter, which will be executed when other users view the search results page.

To address this security concern, it's important to properly sanitize user input to prevent XSS attacks. Here's an example of compliant code that mitigates the XSS vulnerability:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'rack/utils'

get '/search' do
  query = params[:query]
  sanitized_query = Rack::Utils.escape_html(query)
  "<h1>Search Results for #{sanitized_query}</h1>"
end
```


In the compliant code, the Rack::Utils.escape_html method is used to escape any HTML characters in the query parameter. This ensures that the user input is treated as plain text and prevents any HTML or JavaScript code from being executed in the browser.

By properly sanitizing user input and escaping special characters, you can prevent XSS attacks and protect your application and users from potential security risks. It's important to sanitize user input whenever it is being rendered in HTML or other contexts that can interpret it as executable code.






## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
get '/search' do
  query = params[:query]
  result = DB.execute("SELECT * FROM products WHERE name = '#{query}'")
  # Process and return search results
end
```

In this noncompliant code, the user-supplied query parameter is directly interpolated into the SQL query string. This can lead to SQL Injection vulnerabilities if an attacker manipulates the query parameter to execute malicious SQL statements. For example, an attacker could input ' OR '1'='1' -- as the query value, causing the query to become SELECT * FROM products WHERE name = '' OR '1'='1' --', bypassing any intended query logic and potentially exposing sensitive data.

To mitigate SQL Injection vulnerabilities, it's important to use parameterized queries or prepared statements. Here's an example of compliant code that protects against SQL Injection:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
get '/search' do
  query = params[:query]
  result = DB.execute("SELECT * FROM products WHERE name = ?", query)
  # Process and return search results
end
```

In the compliant code, a parameterized query is used instead of directly interpolating the user input into the SQL query string. The ? placeholder is used to represent the query parameter. The actual value of query is passed separately to the database query function, ensuring that it is treated as a parameter and not as executable SQL code.

By using parameterized queries or prepared statements, you separate the SQL logic from the user-supplied input, effectively preventing SQL Injection attacks. The database engine handles the proper escaping and quoting of the parameter values, eliminating the risk of SQL Injection vulnerabilities.

It's crucial to adopt this approach whenever user input is incorporated into SQL queries to ensure the security and integrity of your application's database interactions.






## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
get '/download' do
  filename = params[:filename]
  file_path = "/path/to/files/#{filename}"
  send_file(file_path, disposition: 'attachment')
end
```


In this noncompliant code, the filename parameter is directly used to construct the file path without any validation or sanitization. This can lead to security vulnerabilities, such as directory traversal attacks, where an attacker can manipulate the filename parameter to access files outside the intended directory.


To address this security concern, it's important to validate and sanitize the file name or path before using it. Here's an example of compliant code that mitigates the External Control of File Name or Path vulnerability:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
get '/download' do
  filename = params[:filename]
  sanitized_filename = File.basename(filename)
  file_path = File.join("/path/to/files/", sanitized_filename)

  if File.exist?(file_path) && File.file?(file_path)
    send_file(file_path, disposition: 'attachment')
  else
    halt 404, 'File not found'
  end
end
```

In the compliant code, the File.basename method is used to extract the base file name from the user-supplied filename parameter. This removes any directory traversal components and prevents unauthorized file access. The File.join method is then used to construct the full file path by combining the sanitized file name with the base file path.

Before sending the file, the code checks if the file exists and is a regular file using File.exist? and File.file?. If the file is not found or is not a valid file, a 404 response is returned, preventing unauthorized file downloads.

By validating and sanitizing the file name or path before using it, you can mitigate the risk of external control over file names or paths and prevent unauthorized access to sensitive files on the server.







## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
get '/user/:id' do
  user_id = params[:id]
  user = User.find(user_id)

  if user.nil?
    error_message = "User with ID #{user_id} not found"
    raise StandardError, error_message
  end

  # Process and return user data
end
```


In this noncompliant code, when the requested user ID is not found, an error message containing the sensitive information (the user ID) is generated and raised as an exception. This can potentially expose sensitive information to attackers or unintended users, allowing them to gather information about the system or specific users.

To address this security concern, it's important to avoid exposing sensitive information in error messages. Here's an example of compliant code that avoids disclosing sensitive information:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
get '/user/:id' do
  user_id = params[:id]
  user = User.find(user_id)

  if user.nil?
    error_message = "User not found"
    raise StandardError, error_message
  end

  # Process and return user data
end
```

In the compliant code, the error message is generalized to provide minimal information, avoiding any specific details that could expose sensitive information. Instead of including the user ID in the error message, a more generic message is used to indicate that the user was not found.

By avoiding the inclusion of sensitive information in error messages, you reduce the risk of inadvertent exposure of sensitive data to potential attackers or unintended users. It's important to carefully consider the information shared in error messages and ensure they do not reveal any confidential or personally identifiable information.







## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
API_KEY = 'my_api_key'
DB_PASSWORD = 'my_db_password'
```

In this noncompliant code, the credentials (API key and database password) are directly hardcoded into the source code. Storing credentials in this manner poses a significant security risk because anyone with access to the source code can easily view and misuse these sensitive credentials. If the code is shared or stored in a version control system, the credentials become even more exposed.

To address this security concern, it's crucial to avoid storing credentials in unprotected and easily accessible locations. Here's an example of compliant code that improves the storage of credentials:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'dotenv'

Dotenv.load('.env')

API_KEY = ENV['API_KEY']
DB_PASSWORD = ENV['DB_PASSWORD']
```

In the compliant code, we use the dotenv gem to load environment variables from a .env file. The .env file is not version controlled and is typically kept separate from the source code repository. The credentials are stored as environment variables within the .env file.

By loading credentials from environment variables, you can keep sensitive information separate from the source code and provide an extra layer of protection. Environment variables can be set on the deployment environment or loaded from a secure configuration file specific to the deployment environment, such as a server's environment variables or a cloud provider's secrets management service.

Ensure that you follow secure practices for managing environment variables, such as restricting access to the .env file and ensuring that sensitive credentials are kept confidential and encrypted. Additionally, regularly review and rotate credentials to maintain security.




## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def process_user_input(user_input)
  if user_input.admin?
    grant_admin_privileges()
  end

  # Process user input
end
```

In this noncompliant code, the process_user_input function takes user_input as a parameter and checks if the user is an admin using the admin? method. If the user is determined to be an admin, the function grants them admin privileges without any further validation or authorization checks. This violates the trust boundary by assuming that the admin? method is a secure and reliable way to determine the user's privileges.

To address this security concern, it's important to ensure proper validation and authorization of user privileges. Here's an example of compliant code that avoids trust boundary violations:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
def process_user_input(user_input, user_role)
  if user_role == 'admin'
    grant_admin_privileges()
  end

  # Process user input
end
```


In the compliant code, the process_user_input function now takes an additional parameter, user_role, which explicitly indicates the user's role or privilege level. Instead of relying solely on a method or property of the user_input object, the function now relies on the user_role parameter to determine whether the user should be granted admin privileges.

By passing the user's role or privilege level as a separate parameter, you establish a clear trust boundary and avoid making assumptions about the security or reliability of specific properties or methods. This allows for more controlled and explicit authorization checks based on trusted information.

Remember to always validate and authorize user privileges on the server-side, even if similar checks are performed on the client-side. Client-side checks can be bypassed or manipulated, making server-side validation critical for maintaining secure trust boundaries and protecting sensitive functionality or data.







## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
API_KEY = 'my_api_key'
DB_PASSWORD = 'my_db_password'

# Code that uses the API key and database password
```

In this noncompliant code, the credentials (API key and database password) are directly hardcoded into the source code as plaintext. Storing credentials in this manner poses a significant security risk because anyone with access to the source code can easily view and misuse these sensitive credentials.

To address this security concern, it's crucial to protect credentials using appropriate encryption or secure storage mechanisms. Here's an example of compliant code that improves the protection of credentials:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'openssl'
require 'base64'

def encrypt_credentials(plaintext)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = ENV['ENCRYPTION_KEY']
  encrypted = cipher.update(plaintext) + cipher.final
  Base64.encode64(encrypted)
end

API_KEY = encrypt_credentials('my_api_key')
DB_PASSWORD = encrypt_credentials('my_db_password')

# Code that uses the encrypted credentials
```


In the compliant code, we use the OpenSSL library to encrypt the credentials using the AES-256-CBC encryption algorithm. The encryption key is loaded from an environment variable (ENV['ENCRYPTION_KEY']), which should be stored securely and not directly in the source code.

By encrypting the credentials, we add an additional layer of protection. Even if an attacker gains access to the source code, they will only see the encrypted versions of the credentials, making it much more difficult for them to misuse the sensitive information.

It's important to note that the compliant code only provides an example of how to encrypt credentials. The actual implementation may vary depending on the specific requirements and security practices of your application. Additionally, ensure that you follow secure practices for managing encryption keys, such as storing them securely and rotating them periodically.

Remember to protect sensitive credentials at rest and in transit to ensure the security and integrity of your application's data and systems.








## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'nokogiri'

xml_data = "<user><name>John Doe</name><credit_card>&xxe;</credit_card></user>"
doc = Nokogiri::XML(xml_data)

# Process XML document
```

In this noncompliant code, an XML document containing a user's name and a credit card element (<credit_card>) is parsed using the Nokogiri library. The value of the <credit_card> element is defined as &xxe;, which is an entity reference that could potentially trigger an XXE attack if the XML parser is not properly configured.

To address this security concern, it's important to properly restrict XML external entity references. Here's an example of compliant code that mitigates the risk of XXE attacks:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'nokogiri'

xml_data = "<user><name>John Doe</name><credit_card>&amp;xxe;</credit_card></user>"
doc = Nokogiri::XML(xml_data) do |config|
  config.nonet # Disable network access
  config.noblanks # Ignore whitespace nodes
  config.noent # Disable entity expansion
end

# Process XML document
```


In the compliant code, the XML data is modified to properly escape the & character in the entity reference as &amp;. Additionally, when parsing the XML document using Nokogiri, a block is provided to configure the parser options. The following options are set:

* config.nonet disables network access, preventing the XML parser from making external network requests.
* config.noblanks ignores whitespace nodes, reducing the risk of XXE attacks through whitespace-based exploitation techniques.
* config.noent disables entity expansion, preventing the XML parser from resolving and expanding external entities.


By properly configuring the XML parser and escaping entity references, you can effectively restrict XML external entity references and mitigate the risk of XXE attacks. It's important to review and configure the parser options based on your specific requirements and to stay updated with the latest best practices for XML processing and security.




## Vulnerable and Outdated Components


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'sinatra'

get '/hello' do
  "Hello, World!"
end
```

In this noncompliant code, the application uses the Sinatra framework without considering the version or potential vulnerabilities of the framework itself. This code does not account for the fact that older versions of Sinatra may contain security vulnerabilities or outdated dependencies, which can expose the application to potential attacks.

To address this security concern, it's important to regularly update and use secure components in your application. Here's an example of compliant code that addresses the use of vulnerable and outdated components:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'sinatra'

get '/hello' do
  "Hello, World!"
end
```

In the compliant code, the same Sinatra framework is used, but the focus is on ensuring that the framework and its dependencies are kept up to date. This involves regularly monitoring for security updates and applying them as soon as they become available. It's also crucial to stay informed about any vulnerabilities or security advisories related to the framework or its dependencies.

By proactively updating and managing your application's components, you reduce the risk of using outdated and vulnerable software. This helps to protect your application from known security vulnerabilities and ensures that you are leveraging the latest security patches and improvements.

Remember to follow best practices for dependency management, including regularly checking for updates, utilizing vulnerability scanning tools, and maintaining an up-to-date inventory of your application's components. Additionally, subscribe to security mailing lists or notifications specific to the components you use to stay informed about any potential security issues.






## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'net/http'

def make_secure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  response = http.get(uri.request_uri)
  response.body
end

url = 'https://example.com'
response = make_secure_request(url)
puts response
```

In this noncompliant code, a secure request is made to example.com using Net::HTTP with SSL enabled. However, the code does not perform proper validation of the server's certificate for a host mismatch. This means that the code will accept any valid certificate, even if it does not match the expected host (example.com in this case). This can potentially lead to man-in-the-middle attacks or connections to malicious servers.

To address this security concern, it's crucial to perform proper validation of the server's certificate and ensure that it matches the expected host. Here's an example of compliant code that improves the validation of the certificate:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'net/http'
require 'openssl'

def make_secure_request(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = '/path/to/certificate.crt' # Provide the path to the trusted CA certificate
  response = http.get(uri.request_uri)
  response.body
end

url = 'https://example.com'
response = make_secure_request(url)
puts response
```


In the compliant code, the verify_mode option is set to OpenSSL::SSL::VERIFY_PEER to enforce proper certificate validation. Additionally, the ca_file option is used to specify the path to a trusted CA certificate. This CA certificate will be used to validate the server's certificate and ensure it is issued by a trusted authority and matches the expected host.


Make sure to provide the correct path to a trusted CA certificate that can properly validate the server's certificate. This may involve obtaining the CA certificate from a trusted source or using a certificate bundle provided by your operating system or security framework.

By performing proper validation of the server's certificate with host matching, you can ensure that secure connections are established only with trusted servers and mitigate the risk of man-in-the-middle attacks or connections to malicious hosts.








## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def authenticate(username, password)
  if username == 'admin' && password == 'secret'
    puts 'Authentication successful'
  else
    puts 'Authentication failed'
  end
end

# Usage
authenticate('admin', 'guess')  # Noncompliant authentication attempt
```

In this noncompliant code, the authenticate function takes a username and password as arguments and performs a simple string comparison to check if the provided credentials match the hardcoded values. This approach is insecure because it does not implement proper authentication mechanisms, such as salting, hashing, or encryption of passwords, and it uses hardcoded credentials.

To address this security concern, it's important to implement proper authentication mechanisms that follow secure practices. Here's an example of compliant code that improves the authentication process:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'bcrypt'

def authenticate(username, password)
  hashed_password = get_hashed_password(username)
  if BCrypt::Password.new(hashed_password) == password
    puts 'Authentication successful'
  else
    puts 'Authentication failed'
  end
end

def get_hashed_password(username)
  # Retrieve the hashed password associated with the username from a secure storage (e.g., database)
  # Return the hashed password
end

# Usage
authenticate('admin', 'guess')  # Compliant authentication attempt
```


In the compliant code, the authentication process is improved by using the bcrypt gem to securely hash and verify passwords. The get_hashed_password function retrieves the hashed password associated with the provided username from a secure storage, such as a database. Then, the code uses BCrypt::Password.new to create a new BCrypt::Password object from the hashed password and compares it with the provided password using the == operator. This ensures that the password is properly hashed and securely compared.


It's important to note that the compliant code only provides an example of how to improve the authentication process. The actual implementation may vary depending on the specific requirements and security practices of your application. Additionally, consider implementing other security measures like account lockouts, strong password policies, and secure password reset mechanisms to further enhance the authentication process.

Remember to follow industry-standard practices for secure authentication, such as using strong hashing algorithms, storing passwords securely, protecting against brute-force attacks, and staying informed about the latest security vulnerabilities and best practices.








## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'sinatra'

get '/login' do
  session[:user_id] = params[:user_id]
  redirect '/dashboard'
end

get '/dashboard' do
  # Access user's data based on session[:user_id]
end
```

In this noncompliant code, the /login route sets the user_id parameter as the value of the session[:user_id] variable. The problem is that this code does not generate a new session identifier upon successful login. An attacker can potentially fixate the session by obtaining a valid session ID, for example, by persuading a user to click on a specially crafted link with a predetermined session ID.

To address this security concern, it's crucial to generate a new session identifier upon successful login. Here's an example of compliant code that mitigates session fixation vulnerability:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'sinatra'
require 'securerandom'

enable :sessions

get '/login' do
  session.clear # Clear existing session data
  session[:user_id] = params[:user_id]
  session[:session_id] = SecureRandom.uuid # Generate a new session identifier
  redirect '/dashboard'
end

get '/dashboard' do
  # Access user's data based on session[:user_id]
end
```


In the compliant code, the /login route now includes session.clear to ensure any existing session data is cleared before setting the user_id and generating a new session identifier using SecureRandom.uuid. This helps prevent session fixation by discarding any existing session state and creating a new session upon successful login.

Additionally, the enable :sessions statement is used to enable session management in Sinatra.

By generating a new session identifier upon login, you mitigate the risk of session fixation attacks. This ensures that each user is assigned a unique session identifier, preventing an attacker from fixing a specific session ID and gaining unauthorized access to a user's session.

Remember to apply secure session management practices, such as using strong session identifiers, enabling secure cookies, setting appropriate session expiration times, and validating session data on subsequent requests. Regularly testing and auditing your session management implementation is also crucial to identify and address any potential vulnerabilities.






## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
source_code = params[:source_code]
eval(source_code)
```

In this noncompliant code, the source_code parameter is obtained from an untrusted source, such as user input or an external file. The code then uses the eval function to execute the contents of source_code. This approach is highly insecure as it allows arbitrary code execution, which can lead to serious security vulnerabilities, including remote code execution, information disclosure, and unauthorized access.

To address this security concern, it's crucial to avoid directly executing untrusted code using functions like eval. Instead, consider using safer alternatives that provide controlled execution environments. Here's an example of compliant code that mitigates the inclusion of functionality from an untrusted control source:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'sandbox'

source_code = params[:source_code]

sandbox = Sandbox.safe
sandbox.eval(source_code)
```


In the compliant code, the sandbox object is created using the Sandbox gem. The gem provides a controlled environment for executing untrusted code, limiting the scope of potential damage. The eval method is called on the sandbox object, which safely evaluates the source_code within the controlled environment.


By using a sandboxing mechanism or an isolated environment, you can restrict the execution of untrusted code and prevent it from accessing sensitive resources or introducing security vulnerabilities into your application. It's important to thoroughly review and understand the capabilities and limitations of the sandboxing solution you choose to ensure it aligns with your security requirements.

Remember to exercise caution when incorporating code from untrusted sources. Validate and sanitize inputs, limit access to sensitive functionality, and adhere to the principle of least privilege. Regularly update and patch your application and its dependencies to protect against known vulnerabilities.






## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
require 'open-uri'

file_url = 'http://example.com/malicious_code.rb'
file_content = open(file_url).read

# Process the downloaded file_content
```

In this noncompliant code, the open-uri library is used to download a file from a specified URL. However, the code does not perform any integrity check on the downloaded file. This means that the file's content could be modified during transit or by a malicious actor, potentially introducing security vulnerabilities or executing unauthorized code on the system.

To address this security concern, it's crucial to perform integrity checks on downloaded files to ensure their authenticity and integrity. Here's an example of compliant code that includes an integrity check:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'open-uri'
require 'digest'

file_url = 'http://example.com/malicious_code.rb'
file_content = open(file_url).read

expected_hash = '5f4dcc3b5aa765d61d8327deb882cf99' # Example expected MD5 hash

if Digest::MD5.hexdigest(file_content) == expected_hash
  # File integrity check passed
  # Process the downloaded file_content
else
  # File integrity check failed
  # Handle the error or reject the downloaded file
end
```


In the compliant code, the Digest module is used to calculate the MD5 hash of the downloaded file content using Digest::MD5.hexdigest. The calculated hash is then compared to the expected hash value. If the hashes match, the integrity check is passed, and the code proceeds to process the downloaded file content. If the hashes do not match, the integrity check fails, and appropriate error handling or rejection of the downloaded file can be implemented.


It's important to note that MD5 is used in this example for simplicity, but stronger hash algorithms like SHA-256 or SHA-3 are recommended in practice. Additionally, consider implementing secure download mechanisms, such as using HTTPS for secure transmission, verifying the authenticity of the file source, and ensuring that the server hosting the file is trusted and secure.

By performing an integrity check on downloaded files, you can verify their authenticity and protect against unauthorized modifications or tampering. This helps ensure the code you're executing or the files you're processing are from trusted and unaltered sources, reducing the risk of security vulnerabilities or malicious code execution.







## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
data = params[:serialized_data]
object = Marshal.load(data)

# Process the deserialized object
```

In this noncompliant code, the Marshal.load method is used to deserialize data obtained from the serialized_data parameter. The problem with this code is that it does not validate or sanitize the deserialized data, allowing potentially malicious or untrusted data to be executed as code. This can lead to serious security vulnerabilities, such as remote code execution or arbitrary object creation.



To address this security concern, it's crucial to implement proper validation and sanitization of deserialized data. Here's an example of compliant code that mitigates the deserialization of untrusted data:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
data = params[:serialized_data]
object = nil

begin
  object = YAML.safe_load(data, [Symbol])
rescue Psych::Exception => e
  # Handle deserialization error
  puts "Deserialization error: #{e.message}"
end

# Process the deserialized object if it was successfully loaded
if object
  # Process the deserialized object
else
  # Handle the error or reject the deserialized data
end
```


In the compliant code, the YAML.safe_load method is used instead of Marshal.load to deserialize the data. The safe_load method provides a safer alternative by allowing the specification of permitted classes and symbols during deserialization. In this example, the permitted class is limited to Symbol using [Symbol] as the second argument.

Additionally, the code includes error handling to capture any deserialization errors that may occur, such as those raised by the safe_load method. This allows for proper handling of deserialization errors and prevents potential issues, such as unexpected application crashes or information disclosure.

It's important to note that the safe_load method is just one example of a safer deserialization approach using the YAML library. Depending on your specific needs and requirements, you may choose other deserialization mechanisms or libraries that offer similar safety features.

By implementing proper validation and sanitization of deserialized data, you can mitigate the risk of executing untrusted code or malicious payloads. This helps ensure that the deserialized data is safe and only contains expected and permitted objects, reducing the risk of security vulnerabilities or unauthorized actions.







## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def transfer_funds(sender, recipient, amount)
  if sender.balance >= amount
    sender.balance -= amount
    recipient.balance += amount
    puts "Funds transferred successfully."
  else
    puts "Insufficient funds."
  end
end
```

In this noncompliant code, the transfer_funds function performs a funds transfer operation between a sender and recipient. However, the code only logs the success or failure message to the console using puts. This approach provides insufficient logging, as it does not capture important details and events that can aid in troubleshooting, auditing, or investigating security incidents.

To address this security concern, it's crucial to implement sufficient and meaningful logging in your application. Here's an example of compliant code that improves logging:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
require 'logger'

logger = Logger.new('application.log')

def transfer_funds(sender, recipient, amount)
  if sender.balance >= amount
    sender.balance -= amount
    recipient.balance += amount
    logger.info("Funds transferred: $#{amount} from #{sender.name} to #{recipient.name}")
  else
    logger.warn("Insufficient funds for transfer: $#{amount} from #{sender.name} to #{recipient.name}")
  end
end
```


In the compliant code, the Logger class from the Ruby standard library is used to create a logger instance that writes log messages to a file (application.log in this example). The info method is used to log a successful funds transfer with relevant details such as the transferred amount, sender's name, and recipient's name. In case of insufficient funds, the warn method is used to log a warning message with similar details.

By using a proper logging mechanism like Logger, you can capture important events, errors, and information within your application. Logging should include relevant details such as timestamps, user or request identifiers, actions performed, input values, and outcomes. This helps in troubleshooting issues, monitoring application behavior, detecting suspicious activities, and investigating security incidents.

Additionally, ensure that logs are protected and stored securely to prevent unauthorized access or tampering. Regularly review and analyze logs to identify anomalies, potential security threats, or unusual behavior patterns.

Remember to follow secure logging practices, such as avoiding the inclusion of sensitive information like passwords or personal data in logs, setting appropriate log levels, and using a log management system to centralize and analyze logs effectively.




## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
logger = Logger.new('application.log')

def log_user_activity(user_id, activity)
  logger.info("User #{user_id} performed activity: #{activity}")
end
```

In this noncompliant code, the log_user_activity function logs user activity by directly interpolating the user_id and activity parameters into the log message. This approach can introduce log injection vulnerabilities when the parameters contain special characters or malicious input. An attacker could potentially exploit this vulnerability to modify log entries or inject malicious content into the log file.

To address this security concern, it's crucial to properly neutralize output when incorporating user-provided data into log messages. Here's an example of compliant code that applies output neutralization:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
logger = Logger.new('application.log')

def log_user_activity(user_id, activity)
  sanitized_user_id = sanitize_output(user_id)
  sanitized_activity = sanitize_output(activity)

  logger.info("User #{sanitized_user_id} performed activity: #{sanitized_activity}")
end

def sanitize_output(input)
  # Implement output neutralization logic here
  # For example, remove or escape special characters that could be used for log injection
  sanitized_input = input.gsub(/[<>]/, '')

  # Return the sanitized input
  sanitized_input
end
```


In the compliant code, the log_user_activity function applies the sanitize_output method to the user_id and activity parameters before incorporating them into the log message. The sanitize_output method implements output neutralization logic to remove or escape special characters that could be used for log injection. In this example, the gsub method is used to remove angle brackets (< and >) from the input.

It's important to implement output neutralization logic specific to your application's requirements and the potential threats you want to mitigate. Consider using secure coding practices, such as encoding or escaping special characters, validating and limiting input values, and adhering to appropriate output formats (e.g., JSON, CSV) for structured logs.

By properly neutralizing output when logging user-provided data, you can prevent log injection vulnerabilities and ensure the integrity and security of your log entries. Regularly review and analyze your log generation and handling processes to identify and address any potential vulnerabilities or misconfigurations.








## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
def login(username, password)
  if username == 'admin' && password == 'password'
    puts 'Login successful'
  else
    puts 'Login failed'
  end
end
```


In this noncompliant code, the login function performs a basic login operation by comparing the provided username and password with hardcoded values. However, the code does not provide specific information about the cause of login failures, potentially omitting security-relevant details that could aid in identifying and addressing authentication issues or potential attacks.

To address this security concern, it's crucial to include sufficient security-relevant information when handling authentication or authorization operations. Here's an example of compliant code that includes security-relevant information:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
def login(username, password)
  if username == 'admin' && password == 'password'
    puts 'Login successful'
  else
    puts 'Login failed: Invalid username or password'
  end
end
```


In the compliant code, when a login fails, the code provides a more informative message indicating the reason for the failure: "Invalid username or password". This additional information can help users understand why the login attempt was unsuccessful and guide them to correct their credentials.



By including security-relevant information in your error messages or response messages, you provide transparency and feedback to users, allowing them to take appropriate actions. This can help prevent potential security risks such as brute-force attacks, unauthorized access attempts, or user confusion.


It's important to strike a balance between providing useful information and avoiding the disclosure of sensitive details that could aid attackers. Ensure that error messages are designed to be informative without revealing excessive information that could be exploited by malicious actors. Regularly review and update your error handling and messaging to align with best practices and address emerging security threats.











## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# Noncompliant code
logger = Logger.new('application.log')

def log_sensitive_info(username, password)
  logger.info("Login attempt - Username: #{username}, Password: #{password}")
end
```

In this noncompliant code, the log_sensitive_info function logs a login attempt with the username and password directly interpolated into the log message. Storing sensitive information such as passwords in log files can introduce serious security risks. Log files may be accessible to administrators, developers, or attackers, and the presence of sensitive information can lead to unauthorized access, disclosure, or misuse.

To address this security concern, it's crucial to avoid logging sensitive information or to take measures to properly protect and secure the logged data. Here's an example of compliant code that prevents the logging of sensitive information:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Compliant code
logger = Logger.new('application.log')

def log_login_attempt(username)
  logger.info("Login attempt - Username: #{username}")
end
```


In the compliant code, the log_login_attempt function only logs the username as opposed to the sensitive password. By excluding the password from the log message, the code avoids storing sensitive information in the log file.

It's important to adhere to secure logging practices when handling sensitive information. Here are some recommendations:

1. Avoid logging sensitive information such as passwords, credit card numbers, or personally identifiable information (PII).
2. Use log masking techniques to replace sensitive data with placeholders or redacted values.
3. Implement a log filtering mechanism to exclude sensitive information from the logs before they are written to disk or transmitted.
4. Regularly review and secure access to log files, ensuring that they are only accessible to authorized personnel.
5. Encrypt log files or store them in secure locations to protect against unauthorized access or tampering.

By avoiding the logging of sensitive information or implementing measures to protect logged data, you can maintain the confidentiality and integrity of sensitive data, reduce the risk of unauthorized access or disclosure, and comply with data protection regulations.




## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
require 'open-uri'

# Noncompliant code
def fetch_url(url)
  data = open(url).read
  # Process the fetched data
end
```

In this noncompliant code, the fetch_url function takes a URL as input and directly uses the open method from the open-uri library to read the content of the specified URL. This approach can be dangerous as it allows the attacker to manipulate the URL parameter and potentially access internal resources or perform unauthorized actions on behalf of the server.

To address this security concern, it's crucial to implement proper safeguards to prevent SSRF attacks. Here's an example of compliant code that mitigates SSRF vulnerabilities:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
require 'open-uri'
require 'uri'

# Compliant code
def fetch_url(url)
  parsed_url = URI.parse(url)
  if parsed_url.host == 'trusted-domain.com'
    data = open(url).read
    # Process the fetched data
  else
    # Handle the case of an untrusted or restricted domain
    puts 'Access to the specified domain is not allowed.'
  end
end
```

In the compliant code, the URI.parse method is used to parse the input URL and obtain the hostname. By checking the host attribute of the parsed URL against a whitelist of trusted domains (in this case, 'trusted-domain.com'), the code ensures that requests are only made to allowed destinations.

If the input URL is from an untrusted or restricted domain, the code handles the case by outputting an appropriate message or taking other necessary actions, such as logging the event, notifying administrators, or rejecting the request.

It's important to maintain a robust whitelist of trusted domains and carefully validate user input to prevent SSRF attacks. Additionally, consider implementing additional protections such as:

* Restricting the use of IP addresses and private/internal network resources.
* Implementing rate limiting or request throttling to prevent abuse.
* Monitoring and logging outgoing requests to detect and respond to suspicious or unauthorized activities.

By implementing proper input validation, domain whitelisting, and other security measures, you can significantly reduce the risk of SSRF attacks and ensure that requests are made only to trusted and intended destinations.

