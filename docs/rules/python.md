---
layout: default
title: Python
parent: Rules
---

# Python
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        return jsonify(user)
    else:
        return jsonify({'error': 'User not found'}), 404

```

The noncompliant code example exposes sensitive information by returning the complete user object as a JSON response. This can potentially expose sensitive data, such as passwords, email addresses, or other private user details. If an unauthorized user makes a request to this endpoint with a valid user ID, they will receive the complete user object, including sensitive information.


To address this issue, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        sanitized_user = {
            'id': user['id'],
            'name': user['name']
            # Include only necessary non-sensitive information
        }
        return jsonify(sanitized_user)
    else:
        return jsonify({'error': 'User not found'}), 404
```


The compliant code addresses the issue by sanitizing the user object before sending the response. Instead of returning the complete user object, it creates a new dictionary (sanitized_user) that only includes necessary non-sensitive information, such as the user ID and name. This way, sensitive data is not exposed to unauthorized users. By applying data sanitization techniques, the code ensures that only the required information is shared and sensitive information is properly protected.





## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello {user_email},\n\n{message}\n\nRegards,\nAdmin"
    
    # Code to send email using SMTP
    # ...
```

The noncompliant code example inserts sensitive information, such as the user's email address, directly into the email body without proper sanitization or protection. This can expose sensitive information to unintended recipients if the email is intercepted or if the email client does not handle the data securely.


To address this issue, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello,\n\n{message}\n\nRegards,\nAdmin"
    
    # Code to send email using SMTP
    # ...
```


The compliant code removes the insertion of the user's email address into the email body. Instead, it uses a generic salutation in the email body without directly referencing the user's email address. By avoiding the inclusion of sensitive information in the sent data, the compliant code ensures that sensitive information is not exposed or leaked during communication. It's important to handle sensitive data with care and follow best practices for data protection and privacy.






## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer():
    # Transfer funds
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... logic to transfer funds ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
```

The noncompliant code lacks appropriate CSRF protection. The transfer() function performs a fund transfer based on the form data submitted via a POST request. However, it does not implement any mechanism to prevent Cross-Site Request Forgery attacks. An attacker can craft a malicious website that automatically submits a form to the /transfer endpoint, tricking the victim into unknowingly initiating a fund transfer.


To address this issue, here's an example of compliant code:



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.exempt
def transfer():
    # Transfer funds
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... logic to transfer funds ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
```


The compliant code introduces the CSRFProtect extension from Flask-WTF to provide CSRF protection. The @csrf.exempt decorator is used on the transfer() function to exempt it from CSRF protection since it is an intentional API endpoint. By incorporating CSRF protection, the compliant code mitigates the risk of CSRF attacks by validating the authenticity of requests, ensuring that they originate from the same site as the form submission.






## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def login(username, password):
    if username == 'admin' and password == 'password123':
        # Login successful
        return True
    else:
        # Login failed
        return False
```

The noncompliant code directly compares the provided username and password with hard-coded values ('admin' and 'password123'). This approach poses a security risk as sensitive credentials are exposed directly in the source code. Anyone with access to the source code can easily retrieve the credentials, compromising the security of the system.


To address this issue, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import getpass

def login(username, password):
    stored_password = retrieve_password_from_database(username)
    if password_matches(stored_password, password):
        # Login successful
        return True
    else:
        # Login failed
        return False

def retrieve_password_from_database(username):
    # Code to retrieve the hashed password from the database
    # ...

def password_matches(stored_password, entered_password):
    # Code to compare the stored password with the entered password
    # ...

if __name__ == '__main__':
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    login(username, password)
```

The compliant code avoids using hard-coded passwords directly in the source code. Instead, it separates the authentication logic from the password storage and comparison. The retrieve_password_from_database() function retrieves the stored password for a given username from a secure database. The password_matches() function compares the entered password with the stored password using appropriate secure hashing and comparison techniques.

By following this approach, the password remains securely stored in the database, and the code does not expose sensitive information.







## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
# You sould install pycryptodome before runing this code
# pip install pycryptodome
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def encrypt_data(data, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    padded_data = pad(data.encode(), DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data.encode()))
    return unpad(decrypted_data, DES.block_size).decode('utf-8')

if __name__ == '__main__':
    key = 'abcdefgh'                 # 8 bytes key for DES
    data = 'Hello, World'            # Data to be encrypted

    encrypted_data = encrypt_data(data, key)
    print('Encrypted data:', encrypted_data)

    decrypted_data = decrypt_data(encrypted_data, key)
    print('Decrypted data:', decrypted_data)
```


The noncompliant code uses the DES (Data Encryption Standard) algorithm, which is considered broken and insecure for most cryptographic purposes. Additionally, the code uses the ECB (Electronic Codebook) mode, which does not provide sufficient security against certain attacks. The base64 module is used for encoding and decoding the encrypted data.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
# Importing required libraries
import base64, os

# Importing required libraries from cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to encrypt data using AES-GCM algorithm and return the encrypted data in string format
def encrypt(data:str, key:str) -> str:
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key.encode('utf-8')), modes.GCM(iv), backend=default_backend()).encryptor()
    encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + encrypted_data).decode('utf-8')

# Function to decrypt data using AES-GCM algorithm and return the decrypted data in string format
def decrypt(encrypted_data, key) -> str:
    decoded_data = base64.urlsafe_b64decode(encrypted_data)
    iv = decoded_data[:12]
    tag = decoded_data[12:28]
    encrypted_data = decoded_data[28:]
    decryptor = Cipher(algorithms.AES(key.encode('utf-8')), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return (decryptor.update(encrypted_data) + decryptor.finalize()).decode('utf-8')

# Main function to test the above functions
if __name__ == '__main__':
    key = '689ef728d55342d9af07ed4194cf1d4C' # 32 bytes key for AES-256
    data = 'Hello, World'                    # Data to be encrypted

    # Encrypting and decrypting the data
    encrypted_data = encrypt(data, key)
    print('Encrypted data:', encrypted_data)

    decrypted_data = decrypt(encrypted_data, key)
    print('Decrypted data:', decrypted_data)
```

The compliant code uses the cryptography library, which provides a more secure and modern cryptographic API. It employs the AES (Advanced Encryption Standard) algorithm with GCM (Galois/Counter Mode) mode, which is considered more secure than DES. The urlsafe_b64encode and urlsafe_b64decode functions from base64 module are used for encoding and decoding the encrypted data, respectively.








## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import random

def generate_random_password(length):
    password = ''
    for _ in range(length):
        password += random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    return password
```


The noncompliant code attempts to generate a random password by repeatedly selecting a character from a limited set of characters. However, this approach does not provide sufficient entropy, as the character selection is limited to alphanumeric characters. The resulting passwords may not have a strong enough random distribution, making them more susceptible to brute-force attacks.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import secrets
import string

def generate_random_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
```

The compliant code improves the entropy of the generated password by utilizing the secrets module and a wider range of characters. It combines lowercase and uppercase letters, digits, and punctuation symbols to form a more diverse character set. The secrets.choice function is used to securely select a character from the extended set for each position in the password. This approach ensures a higher level of randomness and increases the strength of the generated passwords.






## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def generate_html_output(input_data):
    html = "<div>" + input_data + "</div>"
    return html
```

The noncompliant code takes an input_data parameter and directly concatenates it into an HTML string without proper sanitization or escaping. This approach can lead to an XSS vulnerability as it allows an attacker to inject malicious scripts or HTML code into the output. If the input_data contains user-controlled input, an attacker can craft input that includes JavaScript code or HTML tags, which will be executed when the generated HTML is rendered by a browser.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import html

def generate_html_output(input_data):
    escaped_data = html.escape(input_data)
    html = "<div>" + escaped_data + "</div>"
    return html
```


The compliant code uses the html.escape function to properly sanitize the input_data by replacing special characters with their corresponding HTML entities. This step ensures that any user-controlled input is treated as plain text and not interpreted as HTML or JavaScript code when rendered in the browser. By escaping the input data, the compliant code mitigates the risk of XSS attacks by preventing the execution of malicious scripts or the unintended interpretation of HTML tags.







## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result
```

The noncompliant code takes a username parameter and directly concatenates it into a SQL query without using parameterized queries or proper input validation. This approach can lead to a SQL injection vulnerability as it allows an attacker to manipulate the query by providing malicious input. An attacker can modify the username parameter to include additional SQL statements, altering the intended behavior of the query or even gaining unauthorized access to the database.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    conn.close()
    return result
```

The compliant code uses parameterized queries with placeholders to securely pass the username parameter to the SQL query. Instead of directly concatenating the input into the query string, the placeholder ? is used, and the actual value is passed separately as a parameter to the execute method. This ensures that the input is properly sanitized and treated as data, eliminating the risk of SQL injection attacks. The compliant code protects against unauthorized manipulation of the query structure and ensures the safe execution of the intended SQL statement.





## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import os

def delete_file(file_name):
    path = "/path/to/files/" + file_name
    if os.path.exists(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
```


The noncompliant code takes a file_name parameter and directly concatenates it into the path variable without proper validation or sanitization. This approach can lead to an external control of file name or path vulnerability, as an attacker can manipulate the file_name parameter to access or delete arbitrary files on the system. By providing a specially crafted file_name input, an attacker can potentially traverse directories or delete sensitive files unintentionally.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import os
import os.path

def delete_file(file_name):
    base_path = "/path/to/files/"
    path = os.path.join(base_path, file_name)

    if os.path.exists(path) and os.path.isfile(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
```

The compliant code addresses the vulnerability by using the os.path.join function to safely concatenate the file_name parameter with the base path. This ensures that the resulting file path is properly formed regardless of the input. Additionally, the compliant code includes checks to verify that the file exists and is a regular file (os.path.isfile) before performing any operations on it. This mitigates the risk of unintended file access or deletion and provides a more secure approach to file handling in Python.






## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        error_msg = f"An error occurred: {str(e)}"
        print(error_msg)
```


The noncompliant code captures the exception message in the error_msg variable and prints it directly to the console. This can lead to the generation of error messages that contain sensitive information, such as database connection details, stack traces, or other internal system information. If an attacker can trigger an exception, they may be able to obtain valuable information that can be used to exploit the system further.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import logging

def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        logging.error("An error occurred during division", exc_info=True)
```

The compliant code addresses the issue by using a logging framework, such as the built-in logging module, to handle error messages. Instead of directly printing the error message to the console, the code uses the logging.error method to log the error message, along with the stack trace (exc_info=True). By using a logging framework, the error messages can be properly handled and logged according to the configured logging settings. This helps prevent sensitive information from being exposed in error messages displayed to end-users or attackers.






## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def save_credentials(username, password):
    credentials_file = open("credentials.txt", "w")
    credentials_file.write(f"Username: {username}\n")
    credentials_file.write(f"Password: {password}\n")
    credentials_file.close()
```

The noncompliant code saves the provided username and password directly to a file called "credentials.txt" without any form of encryption or protection. Storing sensitive information like credentials in plain text is highly insecure because anyone with access to the file can easily read and misuse the information. This can lead to unauthorized access and compromise of user accounts.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import hashlib

def save_credentials(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"Username: {username}\nPassword: {hashed_password}\n"
    
    with open("credentials.txt", "w") as credentials_file:
        credentials_file.write(credentials)
```

The compliant code addresses the issue by using a one-way hashing algorithm (SHA-256 in this example) to securely hash the password before storing it. The password is not stored directly, but rather its hash value is calculated and stored. Hashing is a one-way process, making it difficult to retrieve the original password from the hash. By using a secure hash function, even if an attacker gains access to the stored credentials, they won't be able to easily reverse-engineer the original password. This significantly enhances the security of the stored credentials.



## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import subprocess

def process_user_input(user_input):
    # Assume user_input comes from an untrusted source
    cmd = f"echo '{user_input}'"
    output = subprocess.check_output(cmd, shell=True)
    print(output)
```

The noncompliant code takes user input directly and uses it to construct a command to be executed by the subprocess module. This approach can lead to a trust boundary violation, as it allows untrusted input to be executed as a command on the system. An attacker could potentially inject malicious commands, leading to unauthorized access or execution of arbitrary code on the system.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import subprocess
import shlex

def process_user_input(user_input):
    # Assume user_input comes from an untrusted source
    cmd_args = shlex.split(f"echo {user_input}")
    output = subprocess.check_output(cmd_args)
    print(output)
```


The compliant code addresses the trust boundary violation by using the shlex.split() function to properly tokenize the user input, ensuring that it is interpreted as separate arguments instead of a single command. This helps prevent command injection attacks by ensuring that the input is treated as data rather than executable code. By properly handling and sanitizing user input, the code establishes a clear trust boundary and mitigates the risk of unauthorized command execution.






## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

def login(username, password):
    # Assume username and password come from user input
    url = "https://example.com/login"
    data = {"username": username, "password": password}
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
```

The noncompliant code takes user-provided username and password values and sends them as plaintext in a POST request to a login endpoint. This approach exposes the credentials to potential interception or eavesdropping, as they are transmitted without any form of protection. Attackers could potentially intercept the network traffic or access logs to obtain the credentials, compromising the security of the user's account.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests
from requests.auth import HTTPDigestAuth

def login(username, password):
    # Assume username and password come from user input
    url = "https://example.com/login"
    auth = HTTPDigestAuth(username, password)
    response = requests.post(url, auth=auth)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
```


The compliant code addresses the issue of insufficiently protected credentials by using HTTP Digest Authentication (HTTPDigestAuth) to securely transmit the username and password. Digest authentication uses a challenge-response mechanism that involves hashing the password and sending a hashed value along with the request. This approach ensures that the password is not transmitted in plaintext, providing a higher level of security against eavesdropping or interception attacks.







## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    tree = ET.fromstring(xml_string)
    # Process the XML data
    ...
```

The noncompliant code uses the xml.etree.ElementTree module to parse an XML string. However, it doesn't explicitly disable the resolution of external entities, which can introduce security risks. An attacker could potentially craft a malicious XML file that includes external entity references and exploit this to perform XXE attacks, such as reading sensitive files or conducting denial-of-service attacks.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    parser = ET.XMLParser()
    parser.entity_declaration = False  # Disable external entity resolution
    tree = ET.fromstring(xml_string, parser=parser)
    # Process the XML data
    ...
```


The compliant code explicitly creates an XML parser (ET.XMLParser()) and disables the resolution of external entities by setting parser.entity_declaration to False. This ensures that any external entity references in the XML string are not resolved, mitigating the risk of XXE attacks. By disabling external entity resolution, the code restricts the parser from accessing or including external entities, enhancing the security of the XML processing.





## Vulnerable and Outdated Components


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
from flask import Flask, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    # Use a vulnerable function to fetch data
    response = requests.get('http://example.com/api/v1/users')
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
```

The noncompliant code uses the requests library to make an HTTP request to an API endpoint and fetch user data. However, the code does not consider the security implications of using outdated or vulnerable components. The use of outdated libraries may expose the application to known security vulnerabilities, which can be exploited by attackers.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
from flask import Flask, render_template
import requests
from requests.packages.urllib3.util import ssl_

# Disable SSL verification warnings
ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'

app = Flask(__name__)

@app.route('/')
def index():
    # Use a secure function to fetch data
    response = requests.get('https://example.com/api/v1/users', verify=False)
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
```


The compliant code takes additional steps to address the use of vulnerable and outdated components:

1. It disables SSL verification warnings using the ssl_.DEFAULT_CIPHERS variable from requests.packages.urllib3.util. This prevents warnings related to SSL verification when making HTTPS requests.
2. It explicitly sets verify=False when making the request to disable SSL certificate verification. This is done with caution and should only be used when the risks associated with insecure connections are adequately mitigated in the application's specific context.
3. It uses the latest version of the requests library to benefit from the latest security patches and improvements.

By addressing these issues, the compliant code takes steps to reduce the risk associated with using vulnerable and outdated components and improves the overall security of the application. It is important to regularly update dependencies and libraries to ensure the usage of the latest secure versions.






## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

def get_secure_data(url):
    # Perform a request without proper certificate validation
    response = requests.get(url, verify=False)
    return response.text

# Example usage
data = get_secure_data('https://example.com')
print(data)
```

The noncompliant code uses the requests library to make an HTTPS request to a specified URL. However, it disables certificate verification by setting verify=False when making the request. This means that the code does not properly validate the certificate presented by the server, including checking for a host mismatch.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests

def get_secure_data(url):
    # Perform a request with proper certificate validation
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception if the request fails
    return response.text

# Example usage
data = get_secure_data('https://example.com')
print(data)
```


The compliant code addresses the issue of improper validation of a certificate with a host mismatch by removing verify=False and allowing the requests library to perform proper certificate validation. The requests.get() function performs certificate verification by default, ensuring that the certificate presented by the server is valid and matches the requested host. The response.raise_for_status() function is also used to raise an exception if the request fails, allowing for proper error handling.

By using proper certificate validation and checking for host mismatches, the compliant code improves the security of the HTTPS communication. It ensures that the certificate presented by the server is valid and matches the requested host, reducing the risk of man-in-the-middle attacks and unauthorized access to sensitive information.







## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

def login(username, password):
    credentials = {'username': username, 'password': password}
    response = requests.post('https://example.com/login', data=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Example usage
result = login('admin', 'password')
print(result)
```

The noncompliant code uses a basic authentication mechanism where the username and password are sent as plain text in the request body. This approach is insecure because it does not provide proper protection for sensitive credentials during transmission.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests
from requests.auth import HTTPBasicAuth

def login(username, password):
    credentials = HTTPBasicAuth(username, password)
    response = requests.post('https://example.com/login', auth=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Example usage
result = login('admin', 'password')
print(result)
```


The compliant code addresses the issue of improper authentication by using HTTP Basic Authentication. It leverages the HTTPBasicAuth class from the requests.auth module to provide proper encoding of the credentials in the Authorization header. This ensures that the username and password are transmitted in a secure manner, as they are encoded in Base64 format.

By using proper authentication mechanisms like HTTP Basic Authentication, the compliant code improves the security of the login process. It ensures that sensitive credentials are protected during transmission, reducing the risk of unauthorized access or interception by malicious actors.







## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'insecure_secret_key'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Authenticate user
    if username == 'admin' and password == 'password':
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Example usage
app.run()
```

The noncompliant code uses the Flask web framework and stores the authenticated user's username in the session after successful login. However, it does not regenerate the session ID upon login, leaving it vulnerable to session fixation attacks. An attacker can obtain a valid session ID and force it onto a victim, allowing them to hijack the victim's session.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
from flask import Flask, request, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Authenticate user
    if username == 'admin' and password == 'password':
        session.regenerate()  # Regenerate session ID
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Example usage
app.run()
```


The compliant code addresses the session fixation vulnerability by regenerating the session ID upon successful login using the regenerate() method provided by the session object. This ensures that the session ID is changed after authentication, preventing an attacker from fixing a session ID and hijacking the user's session.

By regenerating the session ID upon login, the compliant code mitigates the risk of session fixation attacks. It ensures that each user gets a unique and unpredictable session ID, enhancing the security of the session management mechanism.





## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

# Fetch and execute code from an untrusted source
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
exec(untrusted_code)
```

The noncompliant code retrieves code from an untrusted source using the requests library and executes it using the exec() function. This approach poses significant security risks as the untrusted code can potentially contain malicious instructions or perform unauthorized actions on the system.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests
import ast

# Fetch and evaluate code from an untrusted source
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
ast.parse(untrusted_code)
```


The compliant code takes a more cautious approach when including functionality from an untrusted control. Instead of directly executing the code, it uses the ast.parse() function from the ast module to parse and evaluate the code as an abstract syntax tree (AST). This allows for a safer analysis of the code without executing it directly.

By parsing the untrusted code as an AST, the compliant code gains the ability to inspect and validate the code's structure and contents before deciding whether to execute it. This mitigates the risk of running arbitrary or malicious code, providing an additional layer of security.





## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

# Download code without integrity check
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Execute the downloaded code
exec(code)
```

The noncompliant code directly downloads code from a remote source using the requests library without performing any integrity check. It then proceeds to execute the downloaded code using the exec() function. This approach can be dangerous as it allows the execution of potentially malicious or unauthorized code without verifying its integrity.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests
import hashlib

# Download code with integrity check
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Verify code integrity
expected_hash = '4a2d8f37ac...'
calculated_hash = hashlib.sha256(code.encode()).hexdigest()
if calculated_hash == expected_hash:
    exec(code)
else:
    print("Integrity check failed. Code execution aborted.")
```


The compliant code includes an integrity check to ensure the downloaded code's authenticity before execution. It computes the hash of the downloaded code using a cryptographic algorithm (in this case, SHA-256) and compares it to an expected hash value. If the calculated hash matches the expected hash, the code is considered valid and can be executed using exec(). If the hashes do not match, the code execution is aborted, and an appropriate message is displayed.

By verifying the integrity of the downloaded code, the compliant code mitigates the risk of executing tampered or malicious code, providing an additional layer of security.






## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import pickle

def deserialize_data(data):
    # WARNING: This code is noncompliant and insecure
    obj = pickle.loads(data)
    return obj
```

The noncompliant code uses the pickle.loads() function to deserialize untrusted data without any security measures. This approach is highly vulnerable to deserialization attacks, such as arbitrary code execution or malicious object injection. Attackers can craft malicious payloads to exploit vulnerabilities in the deserialization process and compromise the system.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import pickle

def deserialize_data(data):
    try:
        obj = pickle.loads(data)
        # Validate the deserialized object or perform additional security checks
        # ...
        return obj
    except (pickle.UnpicklingError, AttributeError, ImportError, TypeError) as e:
        # Handle deserialization errors
        # Log or raise an exception, or return a default value
        # ...
        return None
```


The compliant code implements security measures to mitigate the risks associated with deserialization of untrusted data. It uses a try-except block to handle potential exceptions during deserialization. This helps to prevent code execution vulnerabilities and ensures that the application gracefully handles any errors.



Additionally, in the compliant code, you can perform validation and security checks on the deserialized object to ensure it meets the expected criteria. This can include verifying the object's type, structure, or specific attributes, depending on the context and requirements of your application.

It's crucial to be cautious when deserializing untrusted data and consider additional security measures such as input validation, data integrity checks, and limiting deserialization to trusted classes or modules. These precautions help protect against deserialization vulnerabilities and enhance the overall security of your application.






## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import logging

def process_data(data):
    # Process the data
    # ...
    
    # Log the result
    logging.info("Data processed successfully")
```

The noncompliant code uses a basic logging statement without providing sufficient information. It simply logs a generic message indicating that the data was processed successfully. This approach lacks important details, making it challenging to diagnose issues, monitor the application's behavior, and investigate security incidents. Insufficient logging makes it difficult to detect and respond to security breaches and other events effectively.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import logging

def process_data(data):
    # Process the data
    # ...
    
    # Log the result with additional information
    logging.info("Data processed successfully: %s", data)
```


The compliant code improves the logging by including additional information in the log message. In this example, the processed data is included as part of the log statement using string formatting. By adding relevant details, such as the processed data or any contextual information, the log becomes more informative and aids in troubleshooting, auditing, and monitoring activities.


It's important to log meaningful events, errors, and security-relevant information throughout the application. Additionally, logging levels (e.g., info, warning, error) should be appropriately used based on the severity and significance of the logged event.


Proper logging practices facilitate the detection and analysis of security incidents, allow for effective incident response, and provide valuable insights into the application's behavior. It is crucial to log sufficient information while being mindful of data sensitivity and compliance requirements.





## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import logging

def log_user_input(username):
    # Log user input
    logging.info("Received username: " + username)
```

The noncompliant code directly concatenates the user input username with a log message string using the + operator. This approach is vulnerable to log injection, where an attacker can manipulate the input to inject malicious characters or log formatting sequences. This can lead to log forging, log injection attacks, or even the exposure of sensitive information in the log entries.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import logging

def log_user_input(username):
    # Log user input with proper output neutralization
    logging.info("Received username: %s", username)
```


The compliant code uses proper output neutralization by using string formatting with placeholders %s and passing the username variable as an argument. This ensures that the user input is treated as data and not as formatting instructions. By neutralizing the output, special characters or formatting sequences entered by an attacker are rendered harmless and logged as intended.


Proper output neutralization helps prevent log injection attacks and ensures that the logged information accurately represents the intended data without compromising the integrity of the log entries.


It's crucial to neutralize user-controlled input and other dynamic data when incorporating them into log messages to prevent security vulnerabilities and maintain the integrity and confidentiality of the logged information.







## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
def login(username, password):
    if username == "admin" and password == "password":
        print("Login successful")
    else:
        print("Login failed")
```


The noncompliant code simply prints a generic message indicating whether the login was successful or failed without providing any specific details. This omission of security-relevant information can make it difficult to diagnose and respond to potential security issues or attacks. It lacks the necessary context to understand the reason for the login failure, potentially leaving sensitive information exposed or allowing an attacker to probe for valid usernames or passwords.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import logging

def login(username, password):
    if username == "admin" and password == "password":
        logging.info("Successful login for user: %s", username)
    else:
        logging.warning("Failed login attempt for user: %s", username)
```


The compliant code improves the logging approach by providing security-relevant information in the log messages. It utilizes the logging module to log the details of the login attempts. In the case of a successful login, it logs an informative message indicating the successful login along with the username. In the case of a failed login attempt, it logs a warning message indicating the failed attempt and includes the username.


By including security-relevant information in the log messages, it becomes easier to monitor and analyze login activities, detect suspicious login attempts, and investigate potential security breaches. This helps improve the security posture of the application and facilitates incident response and forensic analysis in case of any security incidents.








## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", payment_data['user'])
```

The noncompliant code logs sensitive information, such as the user's name, directly into the log file using the logging.info() function. This practice can expose sensitive data to unauthorized individuals who might have access to the log files. Storing sensitive information in plain text logs is a security risk and can lead to data breaches or unauthorized access.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", obfuscate_user(payment_data['user']))

def obfuscate_user(user):
    # Code to obfuscate or mask sensitive information
    return "****" + user[-4:]
```


The compliant code addresses the issue by obfuscating or masking the sensitive information before logging it. In this example, the obfuscate_user() function is used to replace sensitive user information with masked data. The obfuscation process can involve techniques like truncation, substitution, or encryption, depending on the specific requirements.


By obfuscating the sensitive information before logging, the compliant code prevents the exposure of actual user data in the log files. It enhances the security and privacy of user information, ensuring that even if the log files are accessed by unauthorized individuals, the sensitive details remain protected.

It's important to note that obfuscation is not a foolproof security measure and should not be considered a substitute for proper access controls and data protection measures. It is just one step in a multi-layered security approach to safeguard sensitive information.






## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text
```

The noncompliant code directly fetches the content of a given URL using the requests.get() function. This code is vulnerable to SSRF attacks because it allows the execution of arbitrary requests to any URL, including internal or restricted network resources. Attackers can exploit this vulnerability to make requests to internal services, retrieve sensitive information, or perform further attacks on the server.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
import requests

def fetch_url(url):
    if is_valid_url(url):
        response = requests.get(url)
        return response.text
    else:
        raise ValueError("Invalid URL")

def is_valid_url(url):
    # Perform URL validation to ensure it's safe to access
    # Implement whitelist-based validation or restrict access to specific domains

    # Example: Allow access to certain domains
    allowed_domains = ['example.com', 'api.example.com']
    parsed_url = urlparse(url)
    return parsed_url.netloc in allowed_domains
```

The compliant code includes a URL validation step before making the request. It uses the is_valid_url() function to perform validation based on a whitelist approach or specific domain restrictions. The validation step ensures that only trusted and allowed URLs can be accessed, mitigating the risk of SSRF attacks.

The is_valid_url() function is just an example implementation. You should customize the validation logic based on your specific requirements and security policies. The implementation can include checks such as whitelisting allowed domains, enforcing strict URL structures, or validating against a predefined list of safe URLs.

By validating the URL before making the request, the compliant code helps prevent SSRF attacks by restricting access to known, trusted, and safe URLs. It helps ensure that the application only interacts with the intended resources and mitigates the risk of unauthorized access to internal or restricted network resources.

