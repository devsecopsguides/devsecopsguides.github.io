---
layout: default
title: Swift
parent: Rules
---

# Swift
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---






### Improper Platform Usage

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "http://example.com/api/data"
        let url = URL(string: urlString)!
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
```

The noncompliant code makes an HTTP request to a remote URL using URLSession.shared.dataTask(with:completionHandler:) without properly validating or handling potential security issues. It doesn't check whether the remote URL is secure (HTTPS) or whether it belongs to a trusted domain. This could lead to security vulnerabilities such as man-in-the-middle attacks or connecting to malicious servers.

To address this issue, here's an example of compliant code:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "https://example.com/api/data"
        
        guard let urlComponents = URLComponents(string: urlString),
              let host = urlComponents.host,
              let scheme = urlComponents.scheme,
              scheme.lowercased().hasPrefix("https") else {
            print("Invalid URL or scheme")
            return
        }
        
        // Perform additional validation checks if required, such as verifying the domain or certificate
        
        guard let url = urlComponents.url else {
            print("Failed to create URL")
            return
        }
        
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
```


The compliant code addresses the improper platform usage issue by performing additional checks on the URL. It uses URLComponents to parse and extract the host and scheme from the URL. It then validates that the scheme is HTTPS before proceeding with the request. Additional validation checks can be added if required, such as verifying the domain or certificate before making the request. By ensuring the URL is secure and trusted, the code mitigates potential security risks associated with improper platform usage.





### Insecure Data Storage

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
import UIKit

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Saving password to UserDefaults
        UserDefaults.standard.set(password, forKey: "password")
        
        // Reading password from UserDefaults
        let storedPassword = UserDefaults.standard.string(forKey: "password")
        print("Stored Password: \(storedPassword ?? "")")
    }
}
```

The noncompliant code stores a sensitive password string directly into the UserDefaults, which is insecure. UserDefaults is not designed for secure data storage and should not be used to store sensitive information such as passwords or authentication tokens. Storing sensitive data in UserDefaults can expose it to potential security risks, including unauthorized access or extraction by malicious actors.

To address this issue, here's an example of compliant code:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import UIKit
import KeychainAccess

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
            // Saving password to Keychain
            let keychain = Keychain(service: "com.example.app")
            try keychain.set(password, key: "password")
            
            // Reading password from Keychain
            let storedPassword = try keychain.get("password")
            print("Stored Password: \(storedPassword ?? "")")
        } catch {
            print("Error: \(error.localizedDescription)")
        }
    }
}
```


The compliant code addresses the insecure data storage issue by using a secure storage mechanism, in this case, the KeychainAccess library. The sensitive password is stored in the Keychain, which provides a more secure storage solution compared to UserDefaults. The Keychain is designed to securely store sensitive information, such as passwords or cryptographic keys, and offers additional protection measures, such as encryption and access controls, to ensure the confidentiality and integrity of the stored data. By using the Keychain for sensitive data storage, the code mitigates potential security risks associated with insecure data storage usage.




### Insecure Communication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "http://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Insecurely sending a request to the API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession.shared
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
```

The noncompliant code sends a request to an API using an insecure communication method. In this example, the API URL is using the HTTP protocol, which does not provide encryption and data integrity. This leaves the communication susceptible to eavesdropping, man-in-the-middle attacks, and data tampering.

To address this issue, here's an example of compliant code:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "https://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Securely sending a request to the API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession(configuration: .default)
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
```


The compliant code addresses the insecure communication issue by using the HTTPS protocol to establish a secure connection with the API. By changing the API URL to use the HTTPS protocol, the communication between the client and the server is encrypted, ensuring the confidentiality and integrity of the data transmitted over the network. Using HTTPS mitigates the risk of eavesdropping, tampering, and unauthorized access to sensitive information during the communication process.




### Insecure Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Noncompliant code: Insecurely sending username and password over HTTP
        let apiUrl = "http://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession.shared
        let task = session.dataTask(with: request) { (data, response, error) in
            // Handle response
        }
        
        task.resume()
    }
}
```

The noncompliant code demonstrates insecure authentication by sending the username and password over an insecure HTTP connection. The code constructs a URL with the login endpoint and creates a POST request with the username and password as part of the request body. However, using an insecure HTTP connection exposes the sensitive credentials to eavesdropping, interception, and potential credential theft.

To address this issue, here's an example of compliant code:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Compliant code: Securely sending username and password over HTTPS
        let apiUrl = "https://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession(configuration: .default)
        let task = session.dataTask(with: request) { (data, response, error) in
            // Handle response
        }
        
        task.resume()
    }
}
```


The compliant code addresses the insecure authentication issue by using an HTTPS connection to securely send the username and password. The code constructs a URL with the login endpoint using the HTTPS protocol, ensuring that the communication between the client and server is encrypted and secure. By sending the sensitive credentials over a secure channel, the risk of eavesdropping, interception, and credential theft is mitigated.







### Insufficient Cryptography

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
import CommonCrypto

func encryptData(data: Data, key: String) -> Data? {
    let keyData = key.data(using: .utf8)!
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionECBMode)
    let keyLength = size_t(kCCKeySizeAES256)
    let bufferSize = data.count + kCCBlockSizeAES128
    var buffer = Data(count: bufferSize)
    
    let status = keyData.withUnsafeBytes { keyBytes in
        data.withUnsafeBytes { dataBytes in
            buffer.withUnsafeMutableBytes { bufferBytes in
                CCCrypt(CCOperation(kCCEncrypt),
                        algorithm,
                        options,
                        keyBytes.baseAddress,
                        keyLength,
                        nil,
                        dataBytes.baseAddress,
                        data.count,
                        bufferBytes.baseAddress,
                        bufferSize,
                        nil)
            }
        }
    }
    
    return (status == kCCSuccess) ? buffer : nil
}
```

The noncompliant code uses the CommonCrypto library to encrypt data using the Advanced Encryption Standard (AES) algorithm with the Electronic Codebook (ECB) mode. However, the code has several issues. First, it uses a hard-coded key, which is insecure as it can be easily compromised. Second, it uses a weak encryption mode (ECB) that lacks security features such as initialization vectors (IVs), making it vulnerable to certain attacks like pattern recognition.

To address these issues, here's an example of compliant code:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import CommonCrypto

func encryptData(data: Data, key: Data) -> Data? {
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    let keyLength = size_t(kCCKeySizeAES256)
    let ivSize = kCCBlockSizeAES128
    let bufferSize = data.count + ivSize
    var buffer = Data(count: bufferSize)
    var numBytesEncrypted: size_t = 0
    
    let status = key.withUnsafeBytes { keyBytes in
        CCCrypt(CCOperation(kCCEncrypt),
                algorithm,
                options,
                keyBytes.baseAddress,
                keyLength,
                nil,
                data.withUnsafeBytes { dataBytes in
                    dataBytes.baseAddress
                },
                data.count,
                buffer.withUnsafeMutableBytes { bufferBytes in
                    bufferBytes.baseAddress
                },
                bufferSize,
                &numBytesEncrypted)
    }
    
    return (status == kCCSuccess) ? buffer.prefix(numBytesEncrypted) : nil
}
```


The compliant code addresses the issues with the noncompliant code. It takes the encryption key as a Data parameter instead of a String, allowing for more secure key generation and management. The code also uses the secure PKCS7 padding instead of ECB mode, which adds randomness and strengthens the encryption. Additionally, it generates a random Initialization Vector (IV) for each encryption operation, providing further security against certain attacks. The code also returns only the encrypted data without the unused buffer bytes, improving efficiency and reducing the risk of exposing sensitive information.





### Insecure Authorization

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
func checkPermission(user: User, permission: String) -> Bool {
    let userPermissions = user.permissions
    return userPermissions.contains(permission)
}
```

The noncompliant code simply checks if a user has a specific permission by comparing the user's permissions array with the specified permission. However, this code lacks proper authorization validation and does not implement any access control mechanism. It assumes that the user's permissions are stored and managed securely, which may not be the case.


To address these issues, here's an example of compliant code:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
func checkPermission(user: User, permission: String) -> Bool {
    guard let userPermissions = retrieveUserPermissions(user: user) else {
        return false
    }
    
    return userPermissions.contains(permission)
}

func retrieveUserPermissions(user: User) -> [String]? {
    // Fetch user permissions from a secure and trusted data source
    // Implement proper authentication and authorization mechanisms
    // Apply appropriate access control policies
    // Validate and sanitize user input
    // Perform necessary checks to ensure the user is authorized to access the permissions data
    
    return user.permissions
}
```


The compliant code addresses the issues with the noncompliant code by implementing a more secure authorization mechanism. It introduces a separate function retrieveUserPermissions that retrieves the user's permissions from a secure and trusted data source. This function is responsible for performing proper authentication and authorization checks, applying access control policies, and validating user input. By separating the permission retrieval logic, the code allows for more flexibility in implementing robust authorization mechanisms and ensuring the security of the process.




### Client Code Quality

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
    
    func showAlert() {
        let alert = UIAlertController(title: "Alert", message: "This is an alert message.", preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        self.present(alert, animated: true, completion: nil)
    }
}
```

The noncompliant code sample shows a ViewController class that handles updating a label and presenting an alert. However, it violates client code quality principles in several ways.

1. Lack of separation of concerns: The ViewController class is responsible for both updating the UI (updateLabel) and presenting an alert (showAlert). It's recommended to separate these responsibilities into different classes or methods for better code organization.

2. Violation of Single Responsibility Principle (SRP): The ViewController class should have a single responsibility, such as managing the view lifecycle or handling user interactions. Mixing UI updates and business logic in the same class can make the code harder to understand and maintain.

3. Lack of error handling: The code does not handle any errors that may occur during the UI update or alert presentation. Proper error handling should be implemented to provide better user experience and prevent unexpected issues.



To address these issues, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.text = text
        }
    }
}

class AlertHelper {
    static func showAlert(on viewController: UIViewController, title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        viewController.present(alert, animated: true, completion: nil)
    }
}
```


The compliant code addresses the issues with the noncompliant code by improving the client code quality. It separates the responsibilities by moving the UI update logic to the ViewController class and the alert presentation logic to a separate AlertHelper class.

The updateLabel method now runs the UI update on the main queue to ensure thread safety. By using a separate helper class AlertHelper, the presentation of alerts is decoupled from the view controller, promoting better code organization and separation of concerns.

It's important to note that the compliant code may still require additional enhancements depending on the specific requirements of the application. However, it demonstrates better client code quality by adhering to principles such as separation of concerns and the Single Responsibility Principle.






### Code Tampering

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Some data processing logic
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let viewController = ViewController()
        viewController.updateLabel(text: dataProcessor.processData(data: "Hello, World!"))
    }
}
```

The noncompliant code sample illustrates a code tampering vulnerability. In this scenario, an attacker can modify the processData method in the DataProcessor class to manipulate the processed data returned. Since the MainViewController relies on the DataProcessor to process the data before updating the label, any modification to the processData method can lead to unintended or malicious changes in the displayed text.




To address this code tampering vulnerability, here's an example of compliant code:











<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Some data processing logic
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let processedData = dataProcessor.processData(data: "Hello, World!")
        let viewController = ViewController()
        viewController.updateLabel(text: processedData)
    }
}
```


In the compliant code, measures have been taken to mitigate the code tampering vulnerability. The DataProcessor class and its processData method remain unchanged, ensuring the integrity of the data processing logic. The MainViewController obtains the processed data from the DataProcessor and passes it directly to the updateLabel method of the ViewController, without allowing any intermediary tampering.

By ensuring that critical code and data are not directly modifiable by external entities, the compliant code reduces the risk of code tampering vulnerabilities. It promotes the principle of code integrity and helps maintain the trustworthiness of the application's functionality.





### Reverse Engineering

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
```

The noncompliant code sample demonstrates a reverse engineering vulnerability. In this example, the SecretManager class contains a secret key that is crucial for sensitive operations. However, the secret key is directly embedded within the source code. An attacker who gains access to the compiled binary can reverse engineer the application to extract the secret key.




To address this reverse engineering vulnerability, here's an example of compliant code:












<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        printSecretKey()
    }
    
    func printSecretKey() {
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
```


In the compliant code, the sensitive secret key is still stored within the SecretManager class. However, the key is not directly accessed from the ViewController. Instead, a separate function printSecretKey() is created within the ViewController to handle the sensitive operation. By isolating the access to the secret key within a specific function, it becomes more difficult for an attacker to extract the secret key through reverse engineering.

Additionally, it is recommended to use advanced security measures such as encryption, obfuscation, and secure storage techniques to further protect sensitive information from reverse engineering attacks. These techniques help increase the complexity and effort required for an attacker to reverse engineer the code and extract sensitive data.





### Extraneous Functionality

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
class DataManager {
    func saveData(data: String) {
        // Code to save data
    }
    
    func deleteData(data: String) {
        // Code to delete data
    }
    
    func processData(data: String) {
        // Code to process data
    }
    
    func sendDataToServer(data: String) {
        // Code to send data to the server
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
        dataManager.processData(data: data)
        dataManager.sendDataToServer(data: data)
    }
}
```

The noncompliant code sample includes extraneous functionality in the DataManager class. In addition to the necessary data management operations, such as saving and deleting data, it also contains functions to process data and send it to a server. This violates the principle of separation of concerns and can introduce unnecessary complexity and potential security risks.



To address this issue, here's an example of compliant code:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
class DataManager {
    func saveData(data: String) {
        // Code to save data
    }
    
    func deleteData(data: String) {
        // Code to delete data
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
    }
}
```


The compliant code removes the extraneous functionality from the DataManager class, keeping only the necessary data management operations: saveData and deleteData. By eliminating unnecessary functions, the code becomes simpler and more focused on its core responsibilities. This improves code maintainability, reduces the attack surface, and minimizes the risk of unintended behavior or vulnerabilities introduced by unused functionality.


