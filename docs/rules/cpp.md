---
layout: default
title: Cpp
parent: Rules
---

# Cpp
{: .no_toc }



## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Buffer Overflow


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

int main() {
    char buffer[5];
    strcpy(buffer, "Hello, world!"); // Noncompliant code

    // Rest of the code...
}
```

In the noncompliant code, a character array buffer of size 5 is declared. The strcpy function is then used to copy a string into the buffer. However, the string "Hello, world!" requires more than 5 characters to store, causing a buffer overflow. Writing beyond the bounds of the buffer leads to undefined behavior and potential security vulnerabilities.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <cstring>

int main() {
    char buffer[20];
    strncpy(buffer, "Hello, world!", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Rest of the code...
}
```


The compliant code declares a character array buffer of size 20, providing sufficient space to store the string. The strncpy function is used to copy the string into the buffer while limiting the number of characters copied to the size of the buffer minus 1. Additionally, a null terminator is explicitly added to ensure the string is properly terminated.





Semgrep:


```
rules:
- id: buffer-overflow
  pattern: strcpy($buffer, $source)
  message: Potential buffer overflow detected
```

CodeQL:



```
import cpp

from CallExpr strcpyCall
where strcpyCall.getArgument(0).getType().toString() = "char[]"
select strcpyCall,
       "Potential buffer overflow detected" as message
```






## Null Pointer Dereference


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // handle error
    }
}

int main() {
    int* ptr = nullptr;
    foo(ptr);
    return 0;
}
```

In this example, the foo() function takes a pointer to an integer and dereferences it to set its value to 42, but it does not check if the pointer is null. If a null pointer is passed to foo(), a null pointer dereference will occur, which can cause the program to crash or exhibit undefined behavior.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // handle error
    }
}

int main() {
    int i = 0;
    int* ptr = &i;
    foo(ptr);
    return 0;
}
```


In the compliant code, the pointer is initialized to a valid address of an integer variable i using the address-of operator &. This ensures that the pointer is not null and prevents a null pointer dereference.

Alternatively, the foo() function could be modified to handle null pointers gracefully, such as returning an error code or throwing an exception. In general, it is important to always check pointers for null before dereferencing them to prevent null pointer dereferences, which can lead to crashes and security vulnerabilities.





Semgrep:


```
rules:
  - id: null-pointer-dereference
    patterns:
      - pattern: 'if \(ptr != nullptr\)'
    message: "Potential null pointer dereference"
```

CodeQL:



```
import cpp

from Function f
where f.getName() = "foo"
select f
```






## Integer Overflow/Underflow


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

int main() {
    int a = INT_MAX;
    int b = 1;
    int result = a + b;

    std::cout << "Result: " << result << std::endl;

    // Rest of the code...
}
```

In the noncompliant code, the program performs an addition operation between a and b without checking for potential integer overflow. If the value of a is already at its maximum (INT_MAX), the addition will result in undefined behavior due to integer overflow.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <limits>

int main() {
    int a = INT_MAX;
    int b = 1;

    if (a > std::numeric_limits<int>::max() - b) {
        std::cout << "Integer overflow occurred!" << std::endl;
    } else {
        int result = a + b;
        std::cout << "Result: " << result << std::endl;
    }

    // Rest of the code...
}
```


The compliant code includes a check for potential integer overflow before performing the addition. It compares the value of `a` with the maximum value of the integer type (`std::numeric_limits<int>::max()`) minus `b`. If the comparison indicates that an overflow will occur, appropriate actions can be taken to handle the overflow condition. In this example, an informative message is displayed when an overflow is detected.





Semgrep:


```
rules:
- id: integer-overflow
  pattern: |
    int a = INT_MAX;
    int b = 1;
    int result = a + b;
  message: Potential integer overflow/underflow detected
```

CodeQL:



```
import cpp

from Function main() {
  where exists(BinaryOperator addition | subtraction |
              multiplication | division |
              modulus | shift) and
              (addition.getOperandType() = int() or
              subtraction.getOperandType() = int() or
              multiplication.getOperandType() = int() or
              division.getOperandType() = int() or
              modulus.getOperandType() = int() or
              shift.getOperandType() = int())
  select addition, subtraction, multiplication, division, modulus, shift,
         "Potential integer overflow/underflow detected" as message
}
```




## Denial-of-Service (DoS)


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

void processRequest() {
    // Process the request
    // ...

    // Intentional infinite loop
    while (true) {
        // Perform some expensive operation
        // ...
    }
}

int main() {
    processRequest();

    // Rest of the code...
}
```

In the noncompliant code, the processRequest function contains an intentional infinite loop that performs an expensive operation. This can lead to a DoS vulnerability as it consumes excessive resources, such as CPU time, causing the application or system to become unresponsive.








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>

void processRequest() {
    // Process the request
    // ...
}

int main() {
    processRequest();

    // Rest of the code...
}
```


The compliant code removes the intentional infinite loop from the processRequest function, ensuring that the application does not consume excessive resources and remains responsive. By eliminating the resource-intensive operation, the compliant code mitigates the DoS vulnerability.




Semgrep:


```

```

CodeQL:



```

```







## Format String


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

int main() {
    char* user_input = nullptr;
    std::cout << "Enter your name: ";
    std::cin >> user_input;

    // Noncompliant code
    printf(user_input);

    // Rest of the code...
}
```

In the noncompliant code, the user's input is directly passed as a format string argument to the printf function. If the user input contains format specifiers, it can lead to a Format String vulnerability. An attacker can exploit this vulnerability to read or modify memory, execute arbitrary code, or crash the application.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>

int main() {
    char user_input[256];
    std::cout << "Enter your name: ";
    std::cin >> user_input;

    // Compliant code
    std::cout << user_input << std::endl;

    // Rest of the code...
}
```


The compliant code uses the std::cout stream to print the user's input, avoiding the direct use of the format string vulnerability. By using std::cout, the input is treated as a plain string and not interpreted as a format string.



Semgrep:


```
rules:
- id: format-string-vulnerability
  pattern: printf($format)
  message: Potential format string vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall printfCall
where printfCall.getTarget().hasName("printf") and
      printfCall.getArgument(0).getType().toString() = "char*"
select printfCall,
       "Potential format string vulnerability detected" as message
```




## Insecure Cryptography


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <openssl/md5.h>

std::string generateHash(const std::string& data) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)data.c_str(), data.length(), digest);

    char hexDigest[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(hexDigest + (i * 2), "%02x", digest[i]);
    }

    return std::string(hexDigest);
}

int main() {
    std::string password = "myPassword";
    std::string hashedPassword = generateHash(password);

    std::cout << "Hashed Password: " << hashedPassword << std::endl;

    // Rest of the code...
}
```

In the noncompliant code, the MD5 hashing algorithm is used to generate a hash for a password. However, MD5 is considered insecure for cryptographic purposes due to its vulnerability to collision attacks and the availability of faster and more secure hashing algorithms. Using MD5 for password hashing can expose the application to security risks.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <openssl/sha.h>

std::string generateHash(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), digest);

    char hexDigest[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hexDigest + (i * 2), "%02x", digest[i]);
    }

    return std::string(hexDigest);
}

int main() {
    std::string password = "myPassword";
    std::string hashedPassword = generateHash(password);

    std::cout << "Hashed Password: " << hashedPassword << std::endl;

    // Rest of the code...
}
```


The compliant code addresses the insecure cryptography issue by replacing the use of MD5 with the more secure SHA-256 hashing algorithm. SHA-256 is considered stronger and more resistant to collision attacks.



Semgrep:


```
rules:
- id: insecure-cryptography
  pattern: MD5($data)
  message: Insecure cryptography algorithm (MD5) detected
```

CodeQL:



```
import cpp

from FunctionCall md5Call
where md5Call.getTarget().hasQualifiedName("MD5")
select md5Call,
       "Insecure cryptography algorithm (MD5) detected" as message
```






## Memory Corruption


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

void writeToMemory(char* buffer, const char* data, size_t length) {
    strcpy(buffer, data); // Noncompliant code
    buffer[length] = '\0'; // Noncompliant code
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    writeToMemory(buffer, data, strlen(data));

    std::cout << "Buffer: " << buffer << std::endl;

    // Rest of the code...
}
```

In the noncompliant code, the writeToMemory function uses the strcpy function to copy data into a buffer without proper bounds checking. This can result in buffer overflow, leading to memory corruption. Additionally, the code attempts to write a null terminator beyond the buffer's size, causing buffer over-read and potential memory corruption.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <cstring>

void writeToMemory(char* buffer, const char* data, size_t length) {
    strncpy(buffer, data, length);
    buffer[length - 1] = '\0';
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    writeToMemory(buffer, data, sizeof(buffer));

    std::cout << "Buffer: " << buffer << std::endl;

    // Rest of the code...
}
```


The compliant code addresses the memory corruption issue by using strncpy instead of strcpy to copy data into the buffer, ensuring that the length is respected. The code also correctly sets the null terminator within the buffer's size limit.


Semgrep:


```
rules:
- id: memory-corruption
  pattern: strcpy($buffer, $data)
  message: Potential memory corruption (strcpy) detected
```

CodeQL:



```
import cpp

from FunctionCall strcpyCall
where strcpyCall.getTarget().hasName("strcpy")
select strcpyCall,
       "Potential memory corruption (strcpy) detected" as message
```





## Code Injection


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

void executeCommand(const std::string& command) {
    std::string fullCommand = "echo " + command;
    system(fullCommand.c_str()); // Noncompliant code
}

int main() {
    std::string userInput;
    std::cout << "Enter a command: ";
    std::cin >> userInput;

    executeCommand(userInput);

    // Rest of the code...
}
```

In the noncompliant code, the executeCommand function constructs a command by concatenating user input with a fixed string and then passes it to the system function. This can lead to a Code Injection vulnerability as an attacker can manipulate the user input to execute arbitrary commands on the system.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>

void executeCommand(const std::string& command) {
    std::cout << "Executing command: " << command << std::endl;
    // Execute the command using a secure method
    // ...
}

int main() {
    std::string userInput;
    std::cout << "Enter a command: ";
    std::cin >> userInput;

    executeCommand(userInput);

    // Rest of the code...
}
```


The compliant code eliminates the Code Injection vulnerability by not constructing the command string using user input and executing it with the system function. Instead, it uses a secure method to execute the command, which could involve implementing strict input validation, using an authorized command execution library, or utilizing system APIs with proper safeguards.


Semgrep:


```
rules:
- id: code-injection
  pattern: system($command)
  message: Potential code injection vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall systemCall
where systemCall.getTarget().hasName("system")
select systemCall,
       "Potential code injection vulnerability detected" as message
```




## DLL Hijacking


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <windows.h>

int main() {
    HMODULE hModule = LoadLibrary("evil.dll"); // Noncompliant code
    if (hModule != NULL) {
        // DLL loaded successfully, proceed with its usage
        // ...
    }

    // Rest of the code...
}
```

In the noncompliant code, the LoadLibrary function is used to load a DLL named "evil.dll" without specifying the full path. This can lead to a DLL Hijacking vulnerability, as an attacker can place a malicious DLL with the same name in a location where the application searches for DLLs, resulting in the execution of unauthorized code.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <windows.h>

int main() {
    std::string dllPath = "C:\\path\\to\\safe.dll";
    HMODULE hModule = LoadLibrary(dllPath.c_str());
    if (hModule != NULL) {
        // DLL loaded successfully, proceed with its usage
        // ...
    }

    // Rest of the code...
}
```


The compliant code addresses the DLL Hijacking vulnerability by specifying the full path to the DLL being loaded with the LoadLibrary function. By providing the full path, the application ensures that it loads the intended DLL and prevents the possibility of loading a malicious DLL from an unauthorized location.



Semgrep:


```
rules:
- id: dll-hijacking
  pattern: LoadLibrary($dllName)
  message: Potential DLL Hijacking vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall loadLibraryCall
where loadLibraryCall.getTarget().hasName("LoadLibrary")
select loadLibraryCall,
       "Potential DLL Hijacking vulnerability detected" as message
```





## Use After Free


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

int* createObject() {
    return new int(5);
}

int main() {
    int* ptr = createObject();
    delete ptr;
    std::cout << "Value: " << *ptr << std::endl; // Noncompliant code

    // Rest of the code...
}
```

In the noncompliant code, an object is dynamically allocated using new and assigned to the pointer ptr. Later, delete is called to deallocate the object, making the pointer ptr a dangling pointer. The noncompliant code attempts to dereference the dangling pointer by accessing the freed memory, leading to Use After Free, as the memory is no longer valid.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>

int* createObject() {
    return new int(5);
}

int main() {
    int* ptr = createObject();
    std::cout << "Value: " << *ptr << std::endl;

    delete ptr; // Deallocate the memory

    // Rest of the code...
}
```


The compliant code ensures that the pointer ptr is dereferenced before the associated memory is deallocated. After printing the value, the memory is freed using delete, preventing Use After Free vulnerabilities.


Semgrep:


```
rules:
- id: use-after-free
  pattern: "$expr"
  message: Potential use after free detected
```

CodeQL:



```
import cpp

from DestructorCall destructor
where exists(destructor.getDestructorMethod().getQualifiedName())
select destructor,
       "Potential use after free detected" as message
```






## Uninitialized Variables


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>

int main() {
    int value;
    std::cout << "Value: " << value << std::endl; // Noncompliant code

    // Rest of the code...
}
```

In the noncompliant code, the variable value is declared but not initialized. It is then used in the std::cout statement without assigning a value to it. This leads to reading uninitialized memory, resulting in undefined behavior and potential security vulnerabilities.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>

int main() {
    int value = 0; // Initialize the variable
    std::cout << "Value: " << value << std::endl;

    // Rest of the code...
}
```


The compliant code initializes the variable value to a specific value (in this case, 0) before using it. By providing an initial value, we ensure that the variable is properly initialized and avoids potential issues related to reading uninitialized memory.


Semgrep:


```
rules:
- id: uninitialized-variable
  pattern: $variable
  message: Potential uninitialized variable usage detected
```

CodeQL:



```
import cpp

from VariableAccess access
where not exists(access.getInitializer())
select access,
       "Potential uninitialized variable usage detected" as message
```





## Race Conditions


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <thread>

int balance = 100;

void withdrawMoney(int amount) {
    if (balance >= amount) {
        // Simulate some delay or expensive operation
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        balance -= amount;
        std::cout << "Withdrawal successful. Remaining balance: " << balance << std::endl;
    } else {
        std::cout << "Insufficient balance." << std::endl;
    }
}

int main() {
    std::thread t1(withdrawMoney, 50);
    std::thread t2(withdrawMoney, 70);

    t1.join();
    t2.join();

    // Rest of the code...
}
```

In the noncompliant code, two threads t1 and t2 are concurrently accessing and modifying the shared variable balance without proper synchronization. This can result in a Race Condition, where the outcome of the program becomes non-deterministic and dependent on the timing of thread execution. It can lead to inconsistent or incorrect results, such as incorrect balance updates or data corruption.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <thread>
#include <mutex>

int balance = 100;
std::mutex balanceMutex;

void withdrawMoney(int amount) {
    std::lock_guard<std::mutex> lock(balanceMutex);
    if (balance >= amount) {
        // Simulate some delay or expensive operation
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        balance -= amount;
        std::cout << "Withdrawal successful. Remaining balance: " << balance << std::endl;
    } else {
        std::cout << "Insufficient balance." << std::endl;
    }
}

int main() {
    std::thread t1(withdrawMoney, 50);
    std::thread t2(withdrawMoney, 70);

    t1.join();
    t2.join();

    // Rest of the code...
}
```


The compliant code addresses the Race Condition by introducing a mutex (balanceMutex) and using a lock guard (std::lock_guard) to ensure exclusive access to the critical section where the balance variable is modified. The mutex ensures that only one thread can access the critical section at a time, preventing concurrent modifications and guaranteeing consistent and correct results.


Semgrep:


```
rules:
- id: race-condition
  pattern: $variable = $variable $operation $value
  message: Potential race condition detected
```

CodeQL:



```
import cpp

from Assignment assignment
where exists(assignment.getTarget())
select assignment,
       "Potential race condition detected" as message
```





## Insecure File Operations


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <fstream>

void writeToFile(const std::string& data) {
    std::ofstream file("data.txt"); // Noncompliant code
    if (file.is_open()) {
        file << data;
        file.close();
    }
}

int main() {
    std::string userInput;
    std::cout << "Enter data: ";
    std::cin >> userInput;

    writeToFile(userInput);

    // Rest of the code...
}
```

In the noncompliant code, the writeToFile function writes user-supplied data to a file named "data.txt" without specifying the full path. This can lead to Insecure File Operations, as an attacker can manipulate the file location or overwrite sensitive files by controlling the current working directory or using relative paths.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <fstream>

void writeToFile(const std::string& data) {
    std::string filePath = "/path/to/data.txt"; // Specify the full path
    std::ofstream file(filePath);
    if (file.is_open()) {
        file << data;
        file.close();
    }
}

int main() {
    std::string userInput;
    std::cout << "Enter data: ";
    std::cin >> userInput;

    writeToFile(userInput);

    // Rest of the code...
}
```


The compliant code addresses Insecure File Operations by specifying the full path to the file being accessed or modified. By providing the full path, the application ensures that it performs file operations on the intended file and prevents the possibility of unauthorized access, file overwrites, or unintended data disclosure.




Semgrep:


```
rules:
- id: insecure-file-operations
  pattern: ofstream($filename)
  message: Potential insecure file operation detected
```

CodeQL:



```
import cpp

from Constructor ofstreamConstructor
where exists(ofstreamConstructor.getArgument(0))
select ofstreamConstructor,
       "Potential insecure file operation detected" as message
```





## API Hooking


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <windows.h>

typedef BOOL(WINAPI* OriginalMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

BOOL WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    // Perform malicious actions
    // ...

    // Call the original MessageBox function
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    return originalFunc(hWnd, lpText, lpCaption, uType);
}

int main() {
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    MessageBox = HookedMessageBox; // Noncompliant code

    // Rest of the code...
}
```

In the noncompliant code, API Hooking is implemented by replacing the original function pointer with a custom function, HookedMessageBox. The custom function performs malicious actions and then calls the original function. This allows an attacker to intercept and modify the behavior of the MessageBox function, potentially leading to unauthorized access or manipulation of data.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <windows.h>

typedef BOOL(WINAPI* OriginalMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

BOOL WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    // Perform additional actions before or after calling the original MessageBox function
    // ...

    // Call the original MessageBox function
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    return originalFunc(hWnd, lpText, lpCaption, uType);
}

int main() {
    // Use the original function pointer directly
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    originalFunc(NULL, "Hello", "Message", MB_OK);

    // Rest of the code...
}
```


The compliant code does not implement API Hooking. Instead, it uses the original function pointer directly to call the MessageBox function. This ensures that the original behavior of the API is maintained and prevents unauthorized interception or modification of the function.



Semgrep:


```
rules:
- id: api-hooking
  pattern: $function = $hookFunction
  message: Potential API Hooking vulnerability detected
```

CodeQL:



```
import cpp

from FunctionPointerAssignment functionPointerAssignment
where exists(functionPointerAssignment.getTarget())
and exists(functionPointerAssignment.getAssignment())
select functionPointerAssignment,
       "Potential API Hooking vulnerability detected" as message
```








## TOCTOU


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <iostream>
#include <fstream>

bool isFileWritable(const std::string& filename) {
    std::ofstream file(filename);
    return file.good(); // Noncompliant code
}

int main() {
    std::string filename = "data.txt";
    if (isFileWritable(filename)) {
        std::ofstream file(filename);
        file << "Data"; // Noncompliant code
        file.close();
        std::cout << "File written successfully." << std::endl;
    } else {
        std::cout << "File is not writable." << std::endl;
    }

    // Rest of the code...
}
```

In the noncompliant code, the function isFileWritable attempts to check if a file is writable by creating an ofstream object and checking its state. However, between the time of checking and the time of using the file, the file can be modified externally. This leads to a Time-of-Check Time-of-Use (TOCTOU) vulnerability, as the file's state can change after the check is performed but before the file is used.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <iostream>
#include <fstream>

bool isFileWritable(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

int main() {
    std::string filename = "data.txt";
    if (isFileWritable(filename)) {
        std::ofstream file(filename);
        file << "Data";
        file.close();
        std::cout << "File written successfully." << std::endl;
    } else {
        std::cout << "File is not writable." << std::endl;
    }

    // Rest of the code...
}
```


The compliant code avoids the TOCTOU vulnerability by modifying the code flow. Instead of checking if the file is writable and then performing the write operation, it directly attempts to open the file for writing. If the file is not writable, the appropriate error handling can be performed. This eliminates the window between the check and use where the file's state can change.


Semgrep:


```
rules:
- id: toctou
  pattern: |
    $check = $expr;
    $use
  message: Potential TOCTOU vulnerability detected
```

CodeQL:



```
import cpp

from Assignment assignment, MethodCall methodCall
where assignment.getTarget() = methodCall.getReturnedExpr()
  and methodCall.getName().getText() = "good"
select assignment,
       "Potential TOCTOU vulnerability detected" as message
```









