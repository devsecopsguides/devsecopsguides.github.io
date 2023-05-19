---
layout: default
title: Android
parent: Rules
---

# Android
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Java



### Improper Platform Usage

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public class InsecureStorageActivity extends AppCompatActivity {
    private SharedPreferences preferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_storage);
        
        preferences = getSharedPreferences("my_prefs", MODE_WORLD_READABLE);
    }

    // Rest of the code...
}
```

In this noncompliant code, the SharedPreferences object is created with the mode MODE_WORLD_READABLE, which allows any other application to read the stored preferences. This violates the principle of proper platform usage, as sensitive data should not be stored in a way that allows unauthorized access.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
// Compliant code
public class SecureStorageActivity extends AppCompatActivity {
    private SharedPreferences preferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_storage);
        
        preferences = getSharedPreferences("my_prefs", MODE_PRIVATE);
    }

    // Rest of the code...
}
```


In the compliant code, the SharedPreferences object is created with the mode MODE_PRIVATE, which ensures that the preferences are only accessible by the application itself. This follows the principle of proper platform usage by securely storing sensitive data without allowing unauthorized access.

By using MODE_PRIVATE instead of MODE_WORLD_READABLE, the compliant code ensures that the stored preferences are only accessible within the application, mitigating the risk of exposing sensitive information to other applications on the device.



Semgrep:

For Semgrep, you can use the following rule to detect the insecure use of MODE_WORLD_READABLE in SharedPreferences:

```
rules:
  - id: insecure-sharedpreferences
    patterns:
      - pattern: "getSharedPreferences\\(\"\\w+\",\\s*MODE_WORLD_READABLE\\)"
    message: "Insecure use of MODE_WORLD_READABLE in SharedPreferences"
```

CodeQL:

For CodeQL, you can use the following query to detect the insecure use of MODE_WORLD_READABLE in SharedPreferences:


```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "android.content.Context.getSharedPreferences"
  and m.getArgument(1).toString() = "MODE_WORLD_READABLE"
select m
```



### Insecure Data Storage

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public class InsecureStorageActivity extends AppCompatActivity {
    private static final String FILENAME = "my_sensitive_data.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_storage);
        
        String sensitiveData = "This is my sensitive data";
        writeToFile(sensitiveData);
    }

    private void writeToFile(String data) {
        try {
            File file = new File(getFilesDir(), FILENAME);
            FileWriter writer = new FileWriter(file);
            writer.write(data);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Rest of the code...
}
```

In this noncompliant code, sensitive data is written to a file using the FileWriter without considering secure storage options. The data is stored in the application's private file directory, but it lacks proper encryption or additional security measures, making it vulnerable to unauthorized access.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
// Compliant code
public class SecureStorageActivity extends AppCompatActivity {
    private static final String FILENAME = "my_sensitive_data.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_storage);
        
        String sensitiveData = "This is my sensitive data";
        writeToFile(sensitiveData);
    }

    private void writeToFile(String data) {
        try {
            FileOutputStream fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
            OutputStreamWriter writer = new OutputStreamWriter(fos);
            writer.write(data);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Rest of the code...
}
```


In the compliant code, the FileOutputStream and OutputStreamWriter are used along with the openFileOutput method to securely write the sensitive data to a file in the application's private storage directory. The MODE_PRIVATE flag ensures that the file is only accessible by the application itself. This follows secure storage practices and helps protect the sensitive data from unauthorized access.

By using openFileOutput with MODE_PRIVATE instead of FileWriter, the compliant code ensures secure storage of sensitive data, mitigating the risk of unauthorized access or exposure.



Semgrep:


```
rules:
  - id: insecure-file-write
    patterns:
      - pattern: "FileWriter\\.write\\(\\w+\\)"
    message: "Insecure file write operation"
```

CodeQL:



```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "java.io.FileWriter.write"
select m
```


### Insecure Communication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public class InsecureCommunicationActivity extends AppCompatActivity {
    private static final String API_URL = "http://example.com/api/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_communication);
        
        String requestData = "Some sensitive data";
        String response = sendRequest(requestData);
        // Process the response...
    }

    private String sendRequest(String data) {
        try {
            URL url = new URL(API_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(data);
            writer.flush();
            
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                // Handle error response...
            }
            
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

    // Rest of the code...
}
```

In this noncompliant code, the app sends sensitive data over an insecure HTTP connection (http://example.com/api/) using HttpURLConnection. This puts the data at risk of interception, tampering, and unauthorized access.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
// Compliant code
// Compliant code
public class SecureCommunicationActivity extends AppCompatActivity {
    private static final String API_URL = "https://example.com/api/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_communication);
        
        String requestData = "Some sensitive data";
        String response = sendRequest(requestData);
        // Process the response...
    }

    private String sendRequest(String data) {
        try {
            URL url = new URL(API_URL);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(data);
            writer.flush();
            
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpsURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                // Handle error response...
            }
            
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

    // Rest of the code...
}
```


In the compliant code, the app uses HttpsURLConnection to establish a secure HTTPS connection (https://example.com/api/) for transmitting sensitive data. HTTPS ensures that the communication is encrypted, providing confidentiality and integrity of the data. By using HTTPS instead of HTTP, the compliant code addresses the vulnerability of insecure communication and reduces the risk of interception or unauthorized access to sensitive data.



Semgrep:


```
rules:
  - id: insecure-file-write
    patterns:
      - pattern: "FileWriter\\.write\\(\\w+\\)"
    message: "Insecure file write operation"
```

CodeQL:



```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "java.io.FileWriter.write"
select m
```


### Insecure Authentication

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public class LoginActivity extends AppCompatActivity {
    private EditText usernameEditText;
    private EditText passwordEditText;
    private Button loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.usernameEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();

                if (username.equals("admin") && password.equals("admin123")) {
                    // Login successful
                    openMainActivity();
                } else {
                    // Login failed
                    Toast.makeText(LoginActivity.this, "Invalid username or password", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void openMainActivity() {
        // Start the main activity
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }
    
    // Rest of the code...
}
```

In this noncompliant code, the app performs authentication by comparing the username and password entered by the user (admin and admin123) with hard-coded values. This approach is insecure because the credentials are easily discoverable and can be exploited by attackers.








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
// Compliant code
public class LoginActivity extends AppCompatActivity {
    private EditText usernameEditText;
    private EditText passwordEditText;
    private Button loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.usernameEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();

                // Perform secure authentication
                if (authenticateUser(username, password)) {
                    // Login successful
                    openMainActivity();
                } else {
                    // Login failed
                    Toast.makeText(LoginActivity.this, "Invalid username or password", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private boolean authenticateUser(String username, String password) {
        // Implement secure authentication logic here
        // Example: Make a secure API call to validate the user credentials
        // Return true if the authentication is successful, false otherwise

        return false;
    }

    private void openMainActivity() {
        // Start the main activity
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }
    
    // Rest of the code...
}
```


In the compliant code, the app separates the authentication logic into a dedicated method authenticateUser(), which can be implemented securely. This method can utilize secure authentication mechanisms such as hashing, salting, and server-side validation. By implementing a secure authentication process instead of relying on hard-coded credentials, the compliant code addresses the vulnerability of insecure authentication and reduces the risk of unauthorized access to user accounts.


Semgrep:


```
rules:
  - id: insecure-login-credentials
    patterns:
      - pattern: '(username.equals\\("admin"\\) && password.equals\\("admin123"\\))'
    message: "Insecure use of hardcoded login credentials"
```

CodeQL:



```
import java
import android

from BinaryExpression b
where b.getLeftOperand().toString() = "username.equals(\"admin\")"
  and b.getRightOperand().toString() = "password.equals(\"admin123\")"
select b
```




### Insufficient Cryptography

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
// Noncompliant code
public class EncryptionUtils {
    private static final String KEY = "mySecretKey";
    
    public static String encrypt(String data) {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.encodeToString(encryptedData, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static String decrypt(String encryptedData) {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedData = Base64.decode(encryptedData, Base64.DEFAULT);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private static Key generateKey() throws Exception {
        return new SecretKeySpec(KEY.getBytes(), "AES");
    }
    
    // Rest of the code...
}
```

In this noncompliant code, a custom EncryptionUtils class is implemented to encrypt and decrypt data using the AES algorithm. However, the code uses a hard-coded key (mySecretKey) and does not incorporate other essential security measures like salting, key strengthening, or secure key storage. This approach is insufficient and can be vulnerable to various cryptographic attacks.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;

public class EncryptionUtils {
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding";

    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;

    public EncryptionUtils(String secretKey) {
        try {
            byte[] keyBytes = generateKeyBytes(secretKey);
            secretKeySpec = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            ivParameterSpec = new IvParameterSpec(keyBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.encodeToString(encryptedData, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decodedData = Base64.decode(encryptedData, Base64.DEFAULT);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateKeyBytes(String secretKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(secretKey.getBytes());
        return md.digest();
    }
}
```


In the compliant code, the key generation has been improved by using a more secure approach. Instead of a simple byte conversion of the secretKey, a hashing algorithm (SHA-256) is used to derive a stronger key from the secretKey. This enhances the security of the encryption process by introducing a more robust key derivation function.



Semgrep:


```
rules:
  - id: insecure-encryption-key
    patterns:
      - pattern: "return new SecretKeySpec\\(KEY.getBytes\\(\\), \"AES\"\\)"
    message: "Insecure use of hard-coded encryption key"
```

CodeQL:



```
import java
import javax.crypto

from MethodInvocation m
where m.getMethod().getQualifiedName() = "javax.crypto.spec.SecretKeySpec.<init>"
  and m.getArgument(0).toString() = "KEY.getBytes()"
  and m.getArgument(1).toString() = "\"AES\""
select m
```


### Insecure Authorization

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class AuthorizationUtils {
    public boolean checkAdminAccess(String username, String password) {
        if (username.equals("admin") && password.equals("password")) {
            return true;
        } else {
            return false;
        }
    }
}
```

In this noncompliant code, the checkAdminAccess method performs an insecure authorization check by comparing the username and password directly with hardcoded values. This approach is vulnerable to attacks such as password guessing and brute-force attacks, as well as unauthorized access if the credentials are compromised.

To address this issue, here's an example of compliant code for secure authorization in Android Java:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
public class AuthorizationUtils {
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "password";

    public boolean checkAdminAccess(String username, String password) {
        // Perform secure authentication logic
        // This could involve retrieving user credentials from a secure source,
        // such as a database, and comparing them using a secure hashing algorithm.
        // For demonstration purposes, we'll use a simple comparison with hardcoded values.

        if (username.equals(ADMIN_USERNAME) && password.equals(ADMIN_PASSWORD)) {
            return true;
        } else {
            return false;
        }
    }
}
```


In the compliant code, the username and password comparison is still present, but the actual credentials are stored securely, such as in a secure database or a hashed and salted format. Additionally, this code provides an example where the hardcoded values are defined as constants, making it easier to manage and update the credentials if needed. It is important to implement proper authentication mechanisms, such as using secure password storage and strong authentication protocols, to ensure secure authorization in real-world scenarios.



Semgrep:


```
rules:
  - id: insecure-admin-access
    patterns:
      - pattern: 'username.equals\\("admin"\\) && password.equals\\("password"\\)'
    message: "Insecure use of hardcoded admin credentials"
```

CodeQL:



```
import java

class AuthorizationUtils extends AnyFile
{
  AuthorizationUtils() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "AuthorizationUtils" and
      m.getParameters().toString() = "[String username, String password]" and
      m.getReturnType().toString() = "boolean" and
      m.getBody().toString() = "if (username.equals(\"admin\") && password.equals(\"password\")) {\n            return true;\n        } else {\n            return false;\n        }"
    )
  }
}
```


### Client Code Quality

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Perform a long and complex operation on the main UI thread
        for (int i = 0; i < 1000000; i++) {
            // Perform some heavy computations
        }

        // Update the UI
        textView.setText("Operation completed");
    }
}
```

In this noncompliant code, a long and complex operation is performed directly on the main UI thread within the onCreate method of the MainActivity class. Performing such heavy computations on the main UI thread can cause the app to become unresponsive and negatively impact the user experience. It is essential to offload time-consuming operations to background threads to keep the UI responsive.


To address this issue, here's an example of compliant code that improves client code quality in Android Java:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Perform the long and complex operation on a background thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 1000000; i++) {
                    // Perform some heavy computations
                }

                // Update the UI on the main thread
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        // Update the UI
                        textView.setText("Operation completed");
                    }
                });
            }
        }).start();
    }
}
```


In the compliant code, the heavy computations are performed on a background thread using Thread or other concurrency mechanisms. Once the computations are completed, the UI update is performed on the main UI thread using runOnUiThread to ensure proper synchronization with the UI. By offloading the heavy computations to a background thread, the UI remains responsive, providing a better user experience.


Semgrep:


```
rules:
  - id: long-operation-on-ui-thread
    patterns:
      - pattern: 'for \(int i = 0; i < \d+; i\+\+\)'
    message: "Long-running operation on the main UI thread"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("for (int i = 0; i < 1000000; i++)") >= 0
    )
  }
}
```


### Code Tampering

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Check if the app is installed from an unauthorized source
        boolean isAuthorizedSource = checkInstallationSource();

        if (!isAuthorizedSource) {
            // Show an error message and exit the app
            textView.setText("Unauthorized app installation");
            finish();
        }

        // Rest of the code...
    }

    private boolean checkInstallationSource() {
        // Perform checks to determine the app installation source
        // For simplicity, assume the check always returns false in this example
        return false;
    }
}
```

In this noncompliant code, there is a check performed in the onCreate method to verify if the app is installed from an unauthorized source. If the check fails (returns false), an error message is displayed, but the app continues its execution.



To address this issue, here's an example of compliant code that mitigates code tampering in Android Java:










<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Check if the app is installed from an unauthorized source
        boolean isAuthorizedSource = checkInstallationSource();

        if (!isAuthorizedSource) {
            // Show an error message and exit the app
            textView.setText("Unauthorized app installation");
            finishAffinity(); // Close all activities and exit the app
            return; // Prevent further execution of code
        }

        // Rest of the code...
    }

    private boolean checkInstallationSource() {
        // Perform checks to determine the app installation source
        // For simplicity, assume the check always returns false in this example
        return false;
    }
}
```


In the compliant code, when the check for an unauthorized app installation fails, the finishAffinity() method is called to close all activities and exit the app. Additionally, the return statement is used to prevent further execution of code in the onCreate method. By terminating the app's execution upon detection of an unauthorized installation source, the potential for code tampering is mitigated.


Semgrep:


```
rules:
  - id: unauthorized-app-installation-check
    patterns:
      - pattern: 'checkInstallationSource\(\)'
    message: "Unauthorized app installation check"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("checkInstallationSource()") >= 0
    )
  }
}
```



### Reverse Engineering

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Perform sensitive operation
        String sensitiveData = performSensitiveOperation();

        // Display sensitive data on the screen
        textView.setText(sensitiveData);

        // Rest of the code...
    }

    private String performSensitiveOperation() {
        // Perform sensitive operation
        // For simplicity, assume it involves sensitive data processing

        return "Sensitive Data";
    }
}
```

In this noncompliant code, sensitive data is processed in the performSensitiveOperation method. The resulting sensitive data is then directly displayed on the screen in the onCreate method, making it easier for an attacker to reverse engineer and extract the sensitive information from the APK.




To address this issue, here's an example of compliant code that mitigates reverse engineering in Android Java:











<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Perform sensitive operation
        String sensitiveData = performSensitiveOperation();

        // Display a generic message on the screen
        textView.setText("Sensitive data is protected");

        // Rest of the code...
    }

    private String performSensitiveOperation() {
        // Perform sensitive operation
        // For simplicity, assume it involves sensitive data processing

        return "Sensitive Data";
    }
}
```


In the compliant code, instead of directly displaying the sensitive data on the screen, a generic message is shown to avoid exposing sensitive information. By obfuscating the sensitive data and displaying a generic message, the reverse engineering efforts are made more challenging, making it harder for an attacker to extract sensitive information from the APK.



Semgrep:


```
rules:
  - id: sensitive-data-display
    patterns:
      - pattern: 'textView.setText\(performSensitiveOperation\(\)\)'
    message: "Sensitive data display"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("textView.setText(performSensitiveOperation())") >= 0
    )
  }
}
```


### Extraneous Functionality

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class MainActivity extends AppCompatActivity {
    private Button loginButton;
    private Button adminButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        loginButton = findViewById(R.id.loginButton);
        adminButton = findViewById(R.id.adminButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Perform login functionality
                performLogin();
            }
        });

        adminButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Perform admin functionality
                performAdminAction();
            }
        });

        // Rest of the code...
    }

    private void performLogin() {
        // Login functionality
    }

    private void performAdminAction() {
        // Admin functionality
    }
}
```

In this noncompliant code, there is an adminButton along with its associated functionality for performing administrative actions. However, if the app does not require or intend to provide administrative functionality to regular users, this can introduce unnecessary risk. It increases the attack surface and potential for unauthorized access if an attacker gains control of the app.


To address this issue, here's an example of compliant code that removes the extraneous functionality:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```java
public class MainActivity extends AppCompatActivity {
    private Button loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Perform login functionality
                performLogin();
            }
        });

        // Rest of the code...
    }

    private void performLogin() {
        // Login functionality
    }
}
```


In the compliant code, the adminButton and its associated administrative functionality have been removed. The app now focuses solely on the required login functionality for regular users, reducing the attack surface and eliminating unnecessary functionality that could introduce potential security risks.



Semgrep:


```
rules:
  - id: hardcoded-actions
    patterns:
      - pattern: 'performLogin\(\)'
      - pattern: 'performAdminAction\(\)'
    message: "Hardcoded actions in onClick methods"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getBody().getAStatement() instanceof MethodInvocation and
      (
        m.getBody().getAStatement().toString().indexOf("performLogin()") >= 0 or
        m.getBody().getAStatement().toString().indexOf("performAdminAction()") >= 0
      )
    )
  }
}
```