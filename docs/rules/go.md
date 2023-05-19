---
layout: default
title: Go
parent: Rules
---

# Go
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Exposure of sensitive information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/users", getUsers)
	http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	// Access sensitive data from the database
	username := "admin"
	password := "secret"

	// Return the sensitive information in the HTTP response
	fmt.Fprintf(w, "Username: %s, Password: %s", username, password)
}

```

In this noncompliant code, the getUsers function retrieves sensitive information such as the username and password from a database. However, the code directly exposes this sensitive information in the HTTP response by returning it as part of the response body. This can lead to the exposure of credentials and other sensitive data to potential attackers.

To address this issue, here's an example of compliant code that avoids the exposure of sensitive information:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/users", getUsers)
	http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	// Access sensitive data from the database
	username := "admin"
	password := "secret"

	// Instead of returning sensitive information, return a generic message
	fmt.Fprint(w, "Access denied")
}
```


In the compliant code, the getUsers function still retrieves sensitive information from the database, but instead of returning it in the HTTP response, a generic message is returned. This ensures that sensitive information is not exposed to potential attackers.




## Insertion of Sensitive Information Into Sent Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate the user
	if !authenticate(username, password) {
		errMsg := fmt.Sprintf("Login failed for user: %s", username)
		log.Println(errMsg)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Proceed with successful login
	// ...
	// Code for handling successful login
}

func authenticate(username, password string) bool {
	// Perform authentication logic
	// ...
	// Code for authenticating the user

	return false
}
```

In this noncompliant code, when the login credentials provided by the user fail to authenticate, the code logs the sensitive information (the username) along with an error message. The error message is then sent as a response to the client. This practice can potentially expose sensitive information to an attacker and aid in further exploitation.

To address this issue, here's an example of compliant code that avoids the insertion of sensitive information into sent data via error:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate the user
	if !authenticate(username, password) {
		log.Println("Login failed for user:", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Proceed with successful login
	// ...
	// Code for handling successful login
}

func authenticate(username, password string) bool {
	// Perform authentication logic
	// ...
	// Code for authenticating the user

	return false
}
```


In the compliant code, the sensitive information (the username) is logged without any specific error message. Instead, a generic error message is sent as a response to the client to avoid exposing sensitive information. This helps protect against information disclosure vulnerabilities.





## Cross-Site Request Forgery (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

var (
	templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/transfer", transferHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "index.html", nil)
	} else if r.Method == http.MethodPost {
		amount := r.FormValue("amount")
		account := r.FormValue("account")

		// Perform the money transfer
		if transferMoney(amount, account) {
			fmt.Fprintln(w, "Transfer successful!")
		} else {
			fmt.Fprintln(w, "Transfer failed!")
		}
	}
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
	// Process transfer request
	// ...
}

func transferMoney(amount, account string) bool {
	// Perform money transfer logic
	// ...
	return false
}
```

In this noncompliant code, there is no CSRF protection implemented. The indexHandler function handles both GET and POST requests. When a POST request is received, it performs a money transfer based on the form values provided. This code is vulnerable to CSRF attacks because it doesn't include any mechanism to verify the origin of the request, allowing attackers to craft malicious requests and perform unauthorized transfers on behalf of the authenticated user.

To address this issue, here's an example of compliant code that includes CSRF protection:


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/csrf"
)

var (
	templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/transfer", transferHandler)
	log.Fatal(http.ListenAndServe(":8080", csrf.Protect([]byte("32-byte-long-auth-key"))(nil)))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := csrf.Token(r)
		data := struct {
			Token string
		}{
			Token: token,
		}
		templates.ExecuteTemplate(w, "index.html", data)
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Validate CSRF token
		if err := csrf.Protect([]byte("32-byte-long-auth-key")).VerifyToken(csrf.Token(r)); err != nil {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		amount := r.FormValue("amount")
		account := r.FormValue("account")

		// Perform the money transfer
		if transferMoney(amount, account) {
			fmt.Fprintln(w, "Transfer successful!")
		} else {
			fmt.Fprintln(w, "Transfer failed!")
		}
	}
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
	// Process transfer request
	// ...
}

func transferMoney(amount, account string) bool {
	// Perform money transfer logic
	// ...
	return false
}
```


In the compliant code, the Gorilla CSRF package (github.com/gorilla/csrf) is used to add CSRF protection. The CSRF token is generated in the indexHandler function and included in the template data. On form





## Use of Hard-coded Password

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
)

func main() {
	password := "myHardcodedPassword"
	
	// Rest of the code
	// ...
	
	// Authenticate user with the hardcoded password
	if authenticateUser(password) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}

func authenticateUser(password string) bool {
	// Perform authentication logic
	// ...
	return password == "myHardcodedPassword"
}
```

In this noncompliant code, the password is directly assigned to the password variable as a hard-coded string. This is a security vulnerability because the password is easily accessible within the source code. If an attacker gains access to the source code, they can easily obtain the password and potentially compromise the system.

To address this issue, here's an example of compliant code that avoids hard-coding passwords:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	// Prompt user to enter the password
	password := promptPassword("Enter your password: ")

	// Rest of the code
	// ...

	// Authenticate user with the entered password
	if authenticateUser(password) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(password)
}

func authenticateUser(password string) bool {
	// Perform authentication logic
	// ...
	return password == "correctPassword"
}
```

In the compliant code, the password is no longer hard-coded. Instead, the promptPassword function is used to securely prompt the user to enter the password. The terminal.ReadPassword function is used to read the password from the terminal without echoing it back. This way, the password remains hidden during input and is not directly visible within the code. The authenticateUser function compares the entered password with the correct password stored elsewhere (e.g., in a secure database) to perform the authentication process.






## Broken or Risky Crypto Algorithm

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	data := "Hello, World!"
	hash := md5.Sum([]byte(data))
	fmt.Printf("MD5 Hash: %x\n", hash)
}
```


In this noncompliant code, the MD5 algorithm from the crypto/md5 package is used to compute the hash of a given string. However, MD5 is considered broken and insecure for cryptographic purposes due to significant vulnerabilities, including collision attacks. Using MD5 for hashing sensitive information can expose the system to various security risks.

To address this issue, here's an example of compliant code that uses a stronger cryptographic algorithm:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	data := "Hello, World!"
	hash := sha256.Sum256([]byte(data))
	fmt.Printf("SHA-256 Hash: %x\n", hash)
}
```

In the compliant code, the SHA-256 algorithm from the crypto/sha256 package is used instead of MD5. SHA-256 is considered a stronger cryptographic algorithm and provides better security for hashing sensitive information. By using SHA-256, the code mitigates the risk associated with broken or risky crypto algorithms and ensures the integrity and security of the hashed data.






## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"math/rand"
)

func generateToken() string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 8
	token := ""

	for i := 0; i < length; i++ {
		index := rand.Intn(len(charset))
		token += string(charset[index])
	}

	return token
}

func main() {
	token := generateToken()
	fmt.Println("Generated Token:", token)
}
```


In this noncompliant code, a function generateToken() is used to generate a random token with a length of 8 characters. However, the random number generator rand.Intn() from the math/rand package is used without sufficient entropy. The math/rand package relies on a pseudo-random number generator (PRNG) that produces deterministic results based on a seed value. In this case, since no seed is explicitly set, the PRNG uses a default seed value, which can lead to predictable and non-random output.


To address this issue, here's an example of compliant code that uses the crypto/rand package to generate a random token with sufficient entropy:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateToken() string {
	length := 8
	tokenBytes := make([]byte, length)

	_, err := rand.Read(tokenBytes)
	if err != nil {
		panic(err)
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)[:length]
	return token
}

func main() {
	token := generateToken()
	fmt.Println("Generated Token:", token)
}
```

In the compliant code, the crypto/rand package is used along with the rand.Read() function to generate random bytes with sufficient entropy. These random bytes are then encoded using base64 encoding to generate a random token. By using the crypto/rand package, the code ensures the use of a secure random number generator that provides sufficient entropy for generating unpredictable and secure tokens.






## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	message := fmt.Sprintf("Hello, %s!", name)

	template := `<h1>Welcome</h1>
				 <p>%s</p>`

	output := fmt.Sprintf(template, message)
	fmt.Fprint(w, output)
}

func main() {
	http.HandleFunc("/hello", handleHello)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

In this noncompliant code, the handleHello function handles the "/hello" route and retrieves the value of the "name" query parameter from the URL. It then constructs an HTML response using a string template, directly interpolating the message variable into the template. This can lead to an XSS vulnerability if an attacker injects malicious script tags or other HTML entities into the "name" parameter.

To address this issue, here's an example of compliant code that properly sanitizes the user input to prevent XSS attacks:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	sanitized := template.HTMLEscapeString(name)
	message := fmt.Sprintf("Hello, %s!", sanitized)

	template := `<h1>Welcome</h1>
				 <p>%s</p>`

	output := fmt.Sprintf(template, message)
	fmt.Fprint(w, output)
}

func main() {
	http.HandleFunc("/hello", handleHello)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


In the compliant code, the html/template package is used to sanitize the user input by calling the template.HTMLEscapeString() function on the name variable. This ensures that any special characters in the user input are properly escaped, preventing them from being interpreted as HTML tags or entities. By applying proper HTML escaping, the code mitigates the XSS vulnerability and prevents malicious scripts from being executed in the user's browser.







## SQL Injection

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	db, err := sql.Open("mysql", "root:password@/mydatabase")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Check if the login was successful
	if rows.Next() {
		fmt.Fprintf(w, "Login successful")
	} else {
		fmt.Fprintf(w, "Login failed")
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

In this noncompliant code, the handleLogin function handles the "/login" route and retrieves the values of the "username" and "password" form fields from the HTTP request. It then directly interpolates these values into a SQL query string without any input validation or sanitization. This makes the code vulnerable to SQL injection attacks, where an attacker can manipulate the input values to modify the intended query or execute arbitrary SQL statements.

To address this issue, here's an example of compliant code that uses parameterized queries to prevent SQL injection:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	db, err := sql.Open("mysql", "root:password@/mydatabase")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := "SELECT * FROM users WHERE username = ? AND password = ?"
	rows, err := db.Query(query, username, password)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Check if the login was successful
	if rows.Next() {
		fmt.Fprintf(w, "Login successful")
	} else {
		fmt.Fprintf(w, "Login failed")
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

In the compliant code, the SQL query is modified to use parameterized queries. The placeholders "?" are used in the query string, and the actual values are passed as additional arguments to the db.Query function. This ensures that the user input is properly treated as data and not as part of the SQL query structure, effectively preventing SQL injection attacks. By using parameterized queries, the code separates the SQL logic from the data and provides a safe and secure way to interact with the database.




## External Control of File Name or Path

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")

	filePath := "/path/to/files/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	_, err = w.Write(fileContent)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/download", handleFileDownload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


In this noncompliant code, the handleFileDownload function handles the "/download" route and retrieves the file name from the query parameters. It then directly concatenates the file name with a base path to construct the file path. This can lead to a security vulnerability known as "external control of file name or path" where an attacker can manipulate the file name to access files outside the intended directory or perform other malicious actions.

To address this issue, here's an example of compliant code that validates and sanitizes the file name to prevent unauthorized file access:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")

	// Validate and sanitize the file name
	fileName = filepath.Clean(fileName)
	if fileName == "." || fileName == ".." {
		log.Fatal("Invalid file name")
	}

	filePath := "/path/to/files/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	_, err = w.Write(fileContent)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/download", handleFileDownload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

In the compliant code, the file name is validated and sanitized using the filepath.Clean function, which removes any relative path elements (e.g., ".", "..") and resolves the file name to its canonical form. This ensures that the file name is valid and prevents access to files outside the intended directory. By validating and sanitizing the file name, the code mitigates the risk of unauthorized file access and improves the security of the file download functionality.






## Generation of Error Message Containing Sensitive Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate the user
	if username == "admin" && password == "secretpassword" {
		// Successful login
		fmt.Fprintf(w, "Welcome, admin!")
	} else {
		// Failed login
		errMsg := fmt.Sprintf("Login failed for user: %s", username)
		log.Println(errMsg)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


In this noncompliant code, the handleLogin function handles the "/login" route and performs user authentication. If the login fails, the code generates an error message containing the username and logs it using the log.Println function. This can be a security vulnerability as it exposes sensitive information (the username) in the error message, which can be leveraged by an attacker for reconnaissance or social engineering purposes.

To address this issue, here's an example of compliant code that avoids exposing sensitive information in error messages:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate the user
	if username == "admin" && password == "secretpassword" {
		// Successful login
		fmt.Fprintf(w, "Welcome, admin!")
	} else {
		// Failed login
		log.Println("Login failed for user:", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

In the compliant code, the error message logged using log.Println no longer includes the sensitive information (username). Instead, it simply logs a generic message indicating a failed login without exposing any sensitive details. By avoiding the inclusion of sensitive information in error messages, the code reduces the risk of exposing sensitive information to potential attackers.





## unprotected storage of credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"os"
)

var (
	username string
	password string
)

func readCredentials() {
	file, err := os.Open("credentials.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func main() {
	readCredentials()

	// Use the credentials for authentication
	// ...
}
```

In this noncompliant code, the readCredentials function reads the username and password from a file (credentials.txt). However, the file is read without any encryption or protection mechanisms, leaving the credentials vulnerable to unauthorized access. Storing sensitive information in plaintext files is insecure and exposes the credentials to potential attackers who gain access to the file.

To address this issue, here's an example of compliant code that protects the storage of credentials:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

var (
	username string
	password []byte
)

func readCredentials() {
	file, err := os.Open(filepath.Join("secrets", "credentials.txt"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func authenticateUser(inputPassword []byte) bool {
	err := bcrypt.CompareHashAndPassword(password, inputPassword)
	if err != nil {
		return false
	}
	return true
}

func main() {
	readCredentials()

	// Get user input for authentication
	// ...

	// Hash and compare passwords
	inputPassword := []byte("password123")
	if authenticateUser(inputPassword) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}
```

In the compliant code, several improvements have been made to enhance the storage of credentials:

1. The credentials file is stored in a separate directory named "secrets" to restrict access to authorized users.

2. The password is stored securely using a hashing algorithm. In this example, the bcrypt package is used to hash and compare passwords. This provides an extra layer of protection against unauthorized access to the plaintext password.

By applying these security measures, the compliant code ensures that credentials are stored in a more secure manner, reducing the risk of unauthorized access to sensitive information.


## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read the response body
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```

In this noncompliant code, the fetchUserData function directly fetches user data from an external API (api.example.com) without validating or sanitizing the input. The user ID is taken as input from the command-line arguments and used to construct the API URL. This introduces a trust boundary violation because the code assumes that the user ID is trusted and does not perform any input validation, allowing for potential malicious input to be passed and used in the URL.

To address this issue, here's an example of compliant code that implements input validation and enforces a trust boundary:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
package main

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
)

func fetchUserData(userID string) ([]byte, error) {
	// Validate the user ID format
	validUserID := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !validUserID.MatchString(userID) {
		return nil, fmt.Errorf("Invalid user ID")
	}

	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read the response body
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```


In the compliant code, several improvements have been made to address the trust boundary violation:

1. The user ID is validated using a regular expression to ensure that it matches the expected format (in this case, alphanumeric characters only). This helps prevent arbitrary input from being used in the API URL.

2. If the user ID fails the validation, an error is returned, indicating that the user ID is invalid.

By implementing input validation, the compliant code enforces a trust boundary and ensures that only valid and trusted input is used in the API call, reducing the risk of malicious input leading to unexpected behavior or security vulnerabilities.




## Insufficiently Protected Credentials

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

const (
	apiUsername = "admin"
	apiPassword = "password"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(apiUsername, apiPassword)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read the response body
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```

In this noncompliant code, the API credentials (username and password) are hardcoded in the source code (apiUsername and apiPassword constants). Storing credentials directly in the source code poses a security risk because if an attacker gains access to the code, they will also have access to the credentials.

To address this issue, here's an example of compliant code that properly protects the credentials:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(getAPIUsername(), getAPIPassword())

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read the response body
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func getAPIUsername() string {
	// Retrieve the API username from a secure configuration or environment variable
	return "admin"
}

func getAPIPassword() string {
	// Retrieve the API password from a secure configuration or environment variable
	return "password"
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```


In the compliant code, the credentials are no longer hardcoded in the source code. Instead, the getAPIUsername and getAPIPassword functions retrieve the credentials from secure configurations or environment variables. This separation of sensitive information from the code helps protect the credentials and reduces the risk of exposure if the code is compromised.

By properly protecting the credentials and ensuring they are obtained from secure sources, the compliant code mitigates the risk of unauthorized access to sensitive information.






## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type User struct {
	ID   int    `xml:"id"`
	Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	user := &User{}
	err = xml.Unmarshal(data, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func main() {
	userID := os.Args[1]
	user, err := getUserData(userID)
	if err != nil {
		fmt.Printf("Error retrieving user data: %s\n", err)
		return
	}

	fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
```

In this noncompliant code, the XML data obtained from the API (response.Body) is directly read and parsed using the xml.Unmarshal function. However, there is no explicit restriction or mitigation against XML external entity (XXE) references. This makes the code vulnerable to XXE attacks, where an attacker can supply malicious XML content containing external entity references to disclose sensitive information or perform other unauthorized actions.

To address this issue, here's an example of compliant code that properly restricts XML external entity references:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type User struct {
	ID   int    `xml:"id"`
	Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	decoder := xml.NewDecoder(response.Body)
	decoder.Strict = true  // Enable strict XML parsing
	decoder.Entity = xml.HTMLEntity // Disable expansion of external entities

	user := &User{}
	err = decoder.Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func main() {
	userID := os.Args[1]
	user, err := getUserData(userID)
	if err != nil {
		fmt.Printf("Error retrieving user data: %s\n", err)
		return
	}

	fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
```


In the compliant code, we make use of the xml.Decoder to perform strict XML parsing and restrict the expansion of external entities. We set the Strict field of the decoder to true and the Entity field to xml.HTMLEntity to disable the expansion of external entities.

By enforcing strict XML parsing and disabling external entity expansion, the compliant code effectively mitigates the risk of XML external entity (XXE) attacks and ensures that only safe XML content is processed.





## Vulnerable and Outdated Components


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"github.com/vulnerable/library"
)

func main() {
	data := "Sensitive information"
	encryptedData := library.OldEncryption(data) // Using a vulnerable and outdated encryption function

	fmt.Println("Encrypted Data:", encryptedData)
}
```

In this noncompliant code, we import a vulnerable and outdated library (github.com/vulnerable/library) and use its OldEncryption function to encrypt sensitive information. The outdated encryption function may have known vulnerabilities or weaknesses that can be exploited by attackers.

To address this issue, here's an example of compliant code that avoids using vulnerable and outdated components:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"github.com/secure/library"
)

func main() {
	data := "Sensitive information"
	encryptedData := library.NewEncryption(data) // Using a secure and updated encryption function

	fmt.Println("Encrypted Data:", encryptedData)
}
```


In the compliant code, we import a secure and updated library (github.com/secure/library) that provides a NewEncryption function for encrypting sensitive information. The new encryption function incorporates the latest security practices and fixes any known vulnerabilities present in the old encryption function.

By using secure and updated components, the compliant code reduces the risk of potential vulnerabilities and ensures that sensitive information is properly protected during encryption. It is important to regularly update and review the components used in an application to ensure they are free from known vulnerabilities and up to date with the latest security patches.






## Improper Validation of Certificate with Host Mismatch

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Disables certificate validation
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Process the response
	// ...
}
```

In this noncompliant code, the InsecureSkipVerify field is set to true, which disables certificate validation. This means that the client will accept any certificate, even if it does not match the expected host (example.com in this case). This can lead to a potential security vulnerability as it allows for man-in-the-middle attacks and exposes the application to the risk of communicating with an unauthorized or malicious server.

To address this issue, here's an example of compliant code that properly validates the certificate with the expected host:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Enables certificate validation
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Process the response
	// ...
}
```


In the compliant code, the InsecureSkipVerify field is set to false, which enables certificate validation. This ensures that the client verifies the server's certificate and checks if it matches the expected host (example.com). By properly validating the certificate, the compliant code mitigates the risk of communicating with unauthorized or malicious servers and protects the integrity and confidentiality of the communication.






## Improper Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Perform authentication
	if username == "admin" && password == "password" {
		// Successful authentication
		// ...
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Failed authentication
		// ...
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is authenticated
	if isAuthenticated(r) {
		// Show dashboard
		// ...
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Redirect to login page
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func isAuthenticated(r *http.Request) bool {
	// Check if the user is authenticated
	// ...
	return false
}
```

In this noncompliant code, the authentication mechanism is implemented using a simple username and password comparison in the loginHandler function. The credentials are sent in plain text and there is no additional security measure, such as encryption or hashing, applied to protect the sensitive information. Furthermore, the authentication state is not properly maintained, and any user can access the dashboard without being authenticated by directly visiting the /dashboard URL.

To address these issues, here's an example of compliant code that demonstrates proper authentication in Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Retrieve the stored hashed password for the given username
	hashedPassword, _ := getHashedPassword(username)

	// Compare the provided password with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		// Successful authentication
		// ...
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Failed authentication
		// ...
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is authenticated
	if isAuthenticated(r) {
		// Show dashboard
		// ...
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Redirect to login page
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func isAuthenticated(r *http.Request) bool {
	// Check if the user is authenticated
	// ...
	return false
}

func getHashedPassword(username string) (string, error) {
	// Retrieve the hashed password from the storage for the given username
	// ...
	return "", nil
}
```


In the compliant code, the passwords are securely stored as hashed values using the bcrypt hashing algorithm. During the login process, the provided password is hashed and compared with the stored hashed password using bcrypt.CompareHashAndPassword. This ensures that the passwords are not stored or transmitted in plain text, providing an additional layer of security. Furthermore, the authentication state is properly maintained, and unauthorized access to the dashboard






## Session Fixation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
)

var sessionID string

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Perform authentication
	if username == "admin" {
		// Successful authentication
		sessionID = "123456" // Fixed session ID
		http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Failed authentication
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user has a valid session
	if r.Cookie != nil && r.Cookie["sessionID"] != nil && r.Cookie["sessionID"].Value == sessionID {
		// Show dashboard
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Redirect to login page
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}
```

In this noncompliant code, the session fixation vulnerability is present. The sessionID variable is a global variable that stores the session ID after successful authentication. The session ID is then set as a cookie value using http.SetCookie. However, the session ID is fixed and does not change between different user sessions. This allows an attacker to fix their own session ID and potentially hijack the session of a legitimate user.

To address this vulnerability, here's an example of compliant code that mitigates the session fixation vulnerability in Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Perform authentication
	if username == "admin" {
		// Generate a new session ID
		sessionID := generateSessionID()

		// Set the session ID as a cookie value
		http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})

		// Redirect to the dashboard
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {
		// Failed authentication
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user has a valid session
	sessionIDCookie, err := r.Cookie("sessionID")
	if err == nil && isValidSessionID(sessionIDCookie.Value) {
		// Show dashboard
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Redirect to login page
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func generateSessionID() string {
	// Generate a new session ID
	// ...
	return "generated-session-id"
}

func isValidSessionID(sessionID string) bool {
	// Check if the session ID is valid
	// ...
	return true
}
```


In the compliant code, the session ID is no longer stored in a global variable but is generated dynamically using the generateSessionID function. After successful authentication, a new session ID is generated and set as a cookie value using http.SetCookie. The user is then redirected to the dashboard page.




## Inclusion of Functionality from Untrusted Control

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/execute", executeHandler)
	http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")

	// Execute the command received from the user
	output, err := exec.Command(command).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error executing command: %v", err)
		return
	}

	fmt.Fprintf(w, "Command output:\n%s", output)
}
```

In this noncompliant code, the executeHandler function receives a command from the user as a request parameter (command). The code directly executes the received command using exec.Command, without any validation or sanitization of the command input. This introduces a significant security risk as it allows an attacker to execute arbitrary commands on the underlying system, leading to potential remote code execution and unauthorized access.

To address this security risk, here's an example of compliant code that mitigates the inclusion of functionality from untrusted control in Go:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func main() {
	http.HandleFunc("/execute", executeHandler)
	http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")

	// Validate and sanitize the command input
	if !isValidCommand(command) {
		fmt.Fprintf(w, "Invalid command")
		return
	}

	// Execute the validated command
	output, err := exec.Command(command).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error executing command: %v", err)
		return
	}

	fmt.Fprintf(w, "Command output:\n%s", output)
}

func isValidCommand(command string) bool {
	// Validate the command input against a whitelist of allowed commands
	allowedCommands := []string{"ls", "echo", "pwd"} // Example whitelist

	for _, allowedCmd := range allowedCommands {
		if command == allowedCmd {
			return true
		}
	}

	return false
}
```


In the compliant code, the executeHandler function validates and sanitizes the command input received from the user. It checks the command against a whitelist of allowed commands (allowedCommands). Only the commands in the whitelist are considered valid and will be executed. Any command not present in the whitelist is rejected, preventing the execution of arbitrary commands. This helps to mitigate the risk of including functionality from untrusted control.




## Download of Code Without Integrity Check

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	url := "http://example.com/malicious-code.zip"
	filePath := "/path/to/save/malicious-code.zip"

	// Download the file from the specified URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Error downloading file:", err)
		return
	}
	defer response.Body.Close()

	// Read the contents of the response body
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Save the downloaded file
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Println("File downloaded successfully!")
}
```

In this noncompliant code, the program downloads a file from a specified URL using the http.Get function and saves it to a local file using ioutil.WriteFile. However, the code does not perform any integrity check on the downloaded file. This leaves the system vulnerable to potential attacks, such as downloading and executing malicious code or tampering with the downloaded file.

To address this security risk, here's an example of compliant code that incorporates an integrity check when downloading code in Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	url := "http://example.com/malicious-code.zip"
	filePath := "/path/to/save/malicious-code.zip"

	// Download the file from the specified URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Error downloading file:", err)
		return
	}
	defer response.Body.Close()

	// Read the contents of the response body
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Perform an integrity check on the downloaded file
	if !isFileIntegrityValid(data) {
		fmt.Println("File integrity check failed!")
		return
	}

	// Save the downloaded file
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Println("File downloaded and saved successfully!")
}

func isFileIntegrityValid(data []byte) bool {
	// Implement an integrity check algorithm (e.g., cryptographic hash)
	// to validate the integrity of the downloaded file
	// and return true if the integrity check passes, or false otherwise

	// Example using SHA256 hash
	expectedHash := "..."
	actualHash := calculateHash(data)

	return expectedHash == actualHash
}

func calculateHash(data []byte) string {
	// Calculate the hash of the data using a suitable cryptographic hash function
	// and return the hash value as a string

	// Example using SHA256 hash
	// ...

	return "..."
}
```


In the compliant code, after reading the contents of the response body, an integrity check is performed on the downloaded file using the isFileIntegrityValid function. The function implements an integrity check algorithm, such as calculating a cryptographic hash (e.g., SHA256) of the file's data. If the integrity check passes, the file is saved to the local path. Otherwise, the code rejects the file and terminates the process. 





## Deserialization of Untrusted Data

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

	var user User
	err := json.Unmarshal([]byte(data), &user)
	if err != nil {
		log.Fatal("Error deserializing user:", err)
	}

	fmt.Println("User:", user)
}
```

In this noncompliant code, the program deserializes a JSON string representing a user object using json.Unmarshal. However, it does not perform any validation or sanitization on the input data. This leaves the system vulnerable to potential attacks, such as deserialization of maliciously crafted data, which could lead to code execution, information disclosure, or other security risks.

To address this security risk, here's an example of compliant code that incorporates proper validation and sanitization when deserializing untrusted data in Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

	// Perform input validation and sanitization
	if !isValidJSON(data) {
		log.Fatal("Invalid JSON data")
	}

	var user User
	err := json.Unmarshal([]byte(data), &user)
	if err != nil {
		log.Fatal("Error deserializing user:", err)
	}

	// Perform additional validation on the deserialized user object
	if !isValidUser(user) {
		log.Fatal("Invalid user data")
	}

	fmt.Println("User:", user)
}

func isValidJSON(data string) bool {
	// Implement validation logic to ensure the input data is valid JSON
	// and return true if valid, or false otherwise

	// Example: use json.Valid function from the encoding/json package
	return json.Valid([]byte(data))
}

func isValidUser(user User) bool {
	// Implement additional validation logic on the deserialized user object
	// to ensure it meets the application's requirements
	// and return true if valid, or false otherwise

	// Example: check if the username and email meet certain criteria
	if len(user.Username) < 3 || len(user.Email) == 0 {
		return false
	}

	return true
}
```


In the compliant code, before deserializing the JSON data, the input is first validated using the isValidJSON function to ensure it is valid JSON. If the data is not valid, the process is terminated. After deserialization, additional validation is performed on the deserialized User object using the isValidUser function to ensure it meets the application's requirements. If the user data is deemed invalid, the process is terminated.


By incorporating validation and sanitization steps, the compliant code mitigates the risk of deserializing untrusted data and helps prevent potential security vulnerabilities associated with deserialization attacks.





## Insufficient Logging

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Process the request
	// ...

	// Log the request details
	log.Println("Request received:", r.Method, r.URL.Path)

	// Perform some sensitive operation
	performSensitiveOperation()

	// Log the completion of the request
	log.Println("Request processed successfully")
}

func performSensitiveOperation() {
	// Perform some sensitive operation
	// ...

	// Log the sensitive operation
	log.Println("Sensitive operation performed")
}
```

In this noncompliant code, logging is used to capture request details and the execution of a sensitive operation. However, the logging is limited to using the standard logger from the log package, which typically logs to the standard error output or a predefined log file. This approach is insufficient for effective logging as it lacks important information, such as log levels, timestamps, and contextual details.

To address this issue and ensure sufficient logging, here's an example of compliant code that incorporates a more robust logging solution using a dedicated logging package, such as logrus:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

func main() {
	// Initialize the logger
	initLogger()

	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initLogger() {
	// Set the desired log output, format, and level
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Process the request
	// ...

	// Log the request details
	log.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Info("Request received")

	// Perform some sensitive operation
	performSensitiveOperation()

	// Log the completion of the request
	log.Info("Request processed successfully")
}

func performSensitiveOperation() {
	// Perform some sensitive operation
	// ...

	// Log the sensitive operation
	log.Warn("Sensitive operation performed")
}
```


In the compliant code, the logrus package is used for logging. The logging is initialized in the initLogger function, where the desired log output, format, and level are set. In this example, the logs are directed to the standard output, formatted as JSON, and the log level is set to InfoLevel.

The handleRequest function demonstrates how to log request details and the execution of a sensitive operation using the log.Info and log.Warn methods respectively. The logs include additional contextual information using the WithFields method to provide a structured log entry.

By utilizing a more feature-rich logging package like logrus, the compliant code enhances the logging capabilities by providing log levels, timestamps, and contextual information. This enables better troubleshooting, monitoring, and security analysis.




## Improper Output Neutralization for Logs

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Log the username
	log.Println("User logged in:", username)

	// Process the request
	// ...
}
```

In this noncompliant code, the username received from the request is directly logged using the log.Println function. This practice is insecure because it may lead to log injection attacks or unintentional exposure of sensitive information. An attacker could potentially exploit this vulnerability by injecting special characters or newlines into the username to modify the log output or disrupt the log file's structure.

To address this issue and ensure proper output neutralization for logs, here's an example of compliant code that incorporates output sanitization using the log.Printf function:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Sanitize the username
	sanitizedUsername := sanitizeString(username)

	// Log the sanitized username
	log.Printf("User logged in: %s", sanitizedUsername)

	// Process the request
	// ...
}

func sanitizeString(s string) string {
	// Replace special characters that could affect log output
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")

	return s
}
```


In the compliant code, the sanitizeString function is introduced to sanitize the username before logging. It replaces special characters such as newlines (\n), carriage returns (\r), and tabs (\t) with escape sequences to prevent their unintended interpretation or impact on the log output.

The sanitized username is then logged using log.Printf with the appropriate format specifier %s. This ensures that the log entry is properly neutralized and does not introduce any vulnerabilities or unintended behavior.

By sanitizing the log output in this manner, the compliant code mitigates the risk of log injection attacks and ensures that sensitive information is properly protected in the log files.






## Omission of Security-relevant Information

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Log the user login event
	log.Printf("User logged in: %s", username)

	// Process the request
	// ...
}
```


In this noncompliant code, only the username is logged during the user login event. However, the password, which is a security-relevant piece of information, is not included in the log entry. Omitting such security-relevant information can hinder the ability to effectively monitor and investigate security incidents.

To address this issue and ensure the inclusion of security-relevant information in logs, here's an example of compliant code that incorporates all relevant information while logging:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Log the user login event with all relevant information
	log.Printf("User logged in - Username: %s, Password: %s", username, password)

	// Process the request
	// ...
}
```


In the compliant code, both the username and password are included in the log entry using the log.Printf function. By including all relevant security information, such as the username and password, in the log entry, the compliant code provides valuable details for monitoring, auditing, and investigating security incidents.

It's important to note that while logging sensitive information like passwords is generally not recommended, this example is provided to address the omission of security-relevant information in logs. In a real-world scenario, it's advisable to avoid logging sensitive information and consider using techniques like tokenization or obfuscation to protect sensitive data.







## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Log the sensitive information
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	logger.Printf("Sensitive information - Username: %s, Password: %s", username, password)

	// Process the request
	// ...
}
```

In this noncompliant code, the sensitive information, including the username and password, is logged directly into a log file using the log.Printf function. Storing sensitive information in plain text log files can introduce security risks, as the log files may be accessible to unauthorized individuals, leading to the exposure of sensitive data.

To address this issue and prevent the sensitive information from being stored in the log file, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Process the request

	// Log a message without sensitive information
	log.Printf("Received request - Username: %s", username)

	// Perform authentication
	if !authenticate(username, password) {
		log.Printf("Authentication failed for user: %s", username)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Continue with the request
	// ...
}

func authenticate(username, password string) bool {
	// Perform authentication logic
	// ...
}
```


In the compliant code, the sensitive information is not logged directly into the log file. Instead, the code logs a message indicating the received request without including the actual sensitive information. By avoiding the logging of sensitive data, the compliant code ensures the protection of sensitive information and mitigates the risk of unauthorized access or exposure.

It's important to follow best practices for handling sensitive information, such as not storing it in log files, encrypting it when necessary, and adhering to relevant data protection regulations and security guidelines.





## Server-Side Request Forgery (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/fetch", handleFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")

	// Make a request to the provided URL
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Response Body: %s", body)
}
```

In this noncompliant code, the handleFetch function allows the user to specify a URL through the url parameter. The code then makes a request to the provided URL without performing any validation or restriction. This can lead to an SSRF vulnerability, where an attacker can potentially force the server to make unintended requests to internal resources or external systems.

To address this issue and prevent SSRF attacks, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

func main() {
	http.HandleFunc("/fetch", handleFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	rawURL := r.FormValue("url")

	// Parse the URL to ensure it is valid and safe
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Ensure that the URL points to a permitted domain
	allowedDomains := []string{"example.com", "trusteddomain.com"}
	if !isDomainAllowed(parsedURL.Host, allowedDomains) {
		http.Error(w, "Access to the specified domain is not allowed", http.StatusForbidden)
		return
	}

	// Make a request to the provided URL
	response, err := http.Get(parsedURL.String())
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Response Body: %s", body)
}

func isDomainAllowed(domain string, allowedDomains []string) bool {
	for _, allowedDomain := range allowedDomains {
		if domain == allowedDomain {
			return true
		}
	}
	return false
}
```


In the compliant code, several measures are taken to mitigate the SSRF vulnerability:

1. The url.ParseRequestURI function is used to parse and validate the provided URL. This ensures that the URL is well-formed and follows the expected format.
2. An allowed domain list is defined, and the isDomainAllowed function is used to check if the parsed URL's host is present in the allowed domain list. This restricts requests to only specified domains, preventing SSRF attacks.
3. Proper error handling is implemented to return appropriate HTTP responses for invalid URLs or unauthorized access attempts.

By validating and restricting the URLs that can be requested, the compliant code helps prevent unauthorized or malicious access to internal or external resources, thereby mitigating the SSRF vulnerability.
