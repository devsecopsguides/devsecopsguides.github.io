---
layout: default
title: C
parent: Rules
---

# C
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Buffer Overflow

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
void copy_string(char* dest, char* src) {
  int i = 0;
  while(src[i] != '\0') {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int main() {
  char str1[6];
  char str2[10] = "example";
  copy_string(str1, str2);
  printf("%s", str1);
  return 0;
}
```

In this example, the `copy_string` function copies the contents of `src` to `dest`. However, there is no check for the length of dest, and if src is longer than dest, a buffer overflow will occur, potentially overwriting adjacent memory addresses and causing undefined behavior. In this case, str2 is 7 characters long, so the call to copy_string will overflow the buffer of str1, which has a length of only 6.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
void copy_string(char* dest, char* src, size_t dest_size) {
  int i = 0;
  while(src[i] != '\0' && i < dest_size - 1) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int main() {
  char str1[6];
  char str2[10] = "example";
  copy_string(str1, str2, sizeof(str1));
  printf("%s", str1);
  return 0;
}
```


In this compliant code, the `copy_string` function takes an additional parameter dest_size, which is the maximum size of the dest buffer. The function checks the length of src against dest_size to avoid overflowing the buffer. The sizeof operator is used to get the size of the dest buffer, so it is always passed correctly to copy_string. By using the dest_size parameter, the code ensures that it doesn't write more data than the destination buffer can hold, preventing buffer overflows.




Semgrep:


```
rules:
  - id: buffer-overflow
    patterns:
      - pattern: 'while\(src\[i\] != \'\\0\'\)'
    message: "Potential buffer overflow vulnerability"
```

CodeQL:



```
import c

from Function f
where f.getName() = "copy_string"
select f
```








## Null Pointer Dereference


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

int main() {
    int* ptr = NULL;
    *ptr = 10; // Noncompliant code

    // Rest of the code...
}
```

In the noncompliant code, a null pointer ptr is dereferenced by attempting to assign a value to the memory location it points to. This leads to a Null Pointer Dereference, as dereferencing a null pointer results in undefined behavior and potential crashes or security vulnerabilities.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

int main() {
    int value = 10;
    int* ptr = &value; // Assign the address of a valid variable

    *ptr = 20; // Valid dereference

    // Rest of the code...
}
```


The compliant code ensures that a valid memory location is accessed. In this case, the variable value is declared and its address is assigned to the pointer ptr. Dereferencing ptr after pointing to a valid variable allows for proper memory access.




Semgrep:


```
rules:
- id: null-pointer-dereference
  pattern: "*$expr"
  message: Potential null pointer dereference detected
```

CodeQL:



```
import c

from ExprDereference dereference
select dereference,
       "Potential null pointer dereference detected" as message
```






## Integer Overflow/Underflow


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

int main() {
    int a = 2147483647; // Maximum value for a signed int
    int b = 1;
    int result = a + b; // Noncompliant code

    printf("Result: %d\n", result);

    // Rest of the code...
}
```

In the noncompliant code, an integer overflow occurs when adding the maximum value for a signed integer (a) with 1 (b). The result exceeds the maximum value that can be represented by a signed int, causing undefined behavior and potentially incorrect calculations or security vulnerabilities.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <limits.h>

int main() {
    int a = INT_MAX;
    int b = 1;

    if (a <= INT_MAX - b) {
        int result = a + b;
        printf("Result: %d\n", result);
    } else {
        printf("Overflow occurred.\n");
    }

    // Rest of the code...
}
```


The compliant code checks for the potential overflow condition before performing the addition. It verifies if the result would remain within the range of representable values for a signed int by comparing a with INT_MAX - b. If the condition is true, the addition is performed, and the result is printed. Otherwise, an appropriate handling for the overflow situation can be implemented.




Semgrep:


```
rules:
- id: integer-overflow
  pattern: "$var + $expr"
  message: Potential integer overflow detected
```

CodeQL:



```
import c

from BinaryExpr addition
where addition.getOperator() = "+"
select addition,
       "Potential integer overflow detected" as message
```




## Denial-of-Service (DoS)


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

void processRequest(int length, char* request) {
    // Process the request without any validation or rate limiting
    // This code may consume excessive resources and cause a DoS condition
}

int main() {
    int length = 1000000000; // Large value to simulate a potentially malicious request
    char* request = (char*)malloc(length * sizeof(char));
    // Populate the request buffer with data

    processRequest(length, request);

    // Rest of the code...
    free(request);
}
```

In the noncompliant code, a potentially maliciously large request is created with a very high length value. The request is then passed to the processRequest function without any validation or rate limiting. This can cause the program to consume excessive resources, leading to a Denial-of-Service (DoS) condition where the system becomes unresponsive or crashes.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

void processRequest(int length, char* request) {
    // Implement appropriate request validation and rate limiting mechanisms
    // to prevent DoS attacks
    // Only process the request if it meets the defined criteria
}

int main() {
    int length = 1000000000; // Large value to simulate a potentially malicious request
    char* request = (char*)malloc(length * sizeof(char));
    // Populate the request buffer with data

    // Perform request validation and rate limiting checks before processing
    if (length <= MAX_REQUEST_LENGTH) {
        processRequest(length, request);
    } else {
        printf("Request too large. Ignoring...\n");
    }

    // Rest of the code...
    free(request);
}
```


The compliant code implements appropriate request validation and rate limiting mechanisms to prevent DoS attacks. In this example, a maximum request length (MAX_REQUEST_LENGTH) is defined, and the length of the request is checked before processing. If the length exceeds the defined limit, the request is ignored, and an appropriate message is displayed.



Semgrep:


```
rules:
- id: dos-attack
  pattern: malloc($size * sizeof($type))
  message: Potential DoS vulnerability detected
```

CodeQL:



```
import c

from CallExpr mallocCall
where mallocCall.getTarget().toString() = "malloc"
select mallocCall,
       "Potential DoS vulnerability detected" as message
```







## Format String


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

int main() {
    char name[100];
    printf("Enter your name: ");
    scanf("%s", name);

    printf(name); // Noncompliant code, format string vulnerability

    // Rest of the code...
}
```

In the noncompliant code, the user's input is directly passed to the printf function without proper format string handling. This can lead to a Format String vulnerability, where an attacker can control the format string argument and potentially exploit the program by accessing or modifying unintended memory addresses.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

int main() {
    char name[100];
    printf("Enter your name: ");
    scanf("%99s", name);

    printf("%s", name); // Compliant code, proper format string usage

    // Rest of the code...
}
```


The compliant code ensures that the user's input is properly handled by specifying the maximum field width in the scanf function to prevent buffer overflow. The user's input is then printed using the %s format specifier in the printf function, ensuring proper format string usage.


Semgrep:


```
rules:
- id: format-string-vulnerability
  pattern: "printf($expr)"
  message: Potential format string vulnerability detected
```

CodeQL:



```
import c

from CallExpr printfCall
where printfCall.getTarget().toString() = "printf"
select printfCall,
       "Potential format string vulnerability detected" as message
```




## Insecure Cryptography


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <openssl/md5.h>

void insecureHashPassword(const char* password) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)password, strlen(password), digest);
    // Insecure: using MD5 for password hashing

    // Rest of the code...
}

int main() {
    const char* password = "mysecretpassword";
    insecureHashPassword(password);

    // Rest of the code...
}
```

In the noncompliant code, the MD5 cryptographic hash function is used to hash passwords. MD5 is considered insecure for password hashing due to its vulnerability to various attacks, such as collision attacks and preimage attacks. It is important to use stronger and more secure hash algorithms for password storage.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <openssl/sha.h>

void secureHashPassword(const char* password) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), digest);
    // Secure: using SHA-256 for password hashing

    // Rest of the code...
}

int main() {
    const char* password = "mysecretpassword";
    secureHashPassword(password);

    // Rest of the code...
}
```


The compliant code replaces the use of the insecure MD5 hash function with the more secure SHA-256 hash function. SHA-256 is a stronger cryptographic algorithm suitable for password hashing and provides better security against various attacks.


Semgrep:


```
rules:
- id: insecure-cryptography
  patterns:
    - "MD5($expr)"
    - "SHA1($expr)"
  message: Potential insecure cryptography usage detected
```

CodeQL:



```
import c

from CallExpr md5Call, sha1Call
where md5Call.getTarget().toString() = "MD5"
   or sha1Call.getTarget().toString() = "SHA1"
select md5Call, sha1Call,
       "Potential insecure cryptography usage detected" as message
```






## Memory Corruption


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copyData(char* dest, const char* src, size_t size) {
    memcpy(dest, src, size);
    // Noncompliant code: potential memory corruption if size is larger than the allocated memory for dest

    // Rest of the code...
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    copyData(buffer, data, strlen(data) + 1);

    // Rest of the code...
}
```

In the noncompliant code, the copyData function uses the memcpy function to copy data from the source to the destination buffer. However, if the size of the data is larger than the allocated memory for the destination buffer, it can lead to memory corruption and unexpected behavior, including crashes or security vulnerabilities.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copyData(char* dest, const char* src, size_t size) {
    size_t destSize = sizeof(dest);  // Calculate the size of the destination buffer
    if (size > destSize) {
        // Handle the error condition appropriately (e.g., truncate, return an error code, etc.)
        return;
    }

    memcpy(dest, src, size);
    // Compliant code: ensures the size of the source data does not exceed the allocated memory for dest

    // Rest of the code...
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    copyData(buffer, data, strlen(data) + 1);

    // Rest of the code...
}
```


The compliant code introduces a check to ensure that the size of the source data does not exceed the allocated memory for the destination buffer. If the size is larger than the destination buffer's capacity, the code can handle the error condition appropriately, such as truncating the data, returning an error code, or taking other necessary actions.


Semgrep:


```
rules:
- id: memory-corruption
  pattern: memcpy($dest, $src, $size)
  message: Potential memory corruption detected
```

CodeQL:



```
import c

from CallExpr memcpyCall
where memcpyCall.getTarget().toString() = "memcpy"
select memcpyCall,
       "Potential memory corruption detected" as message
```





## Code Injection


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <stdlib.h>

void executeCommand(const char* command) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "system(\"%s\")", command);
    system(buffer);
    // Noncompliant code: potential code injection vulnerability

    // Rest of the code...
}

int main() {
    const char* userInput = "ls -la";
    executeCommand(userInput);

    // Rest of the code...
}
```

In the noncompliant code, the executeCommand function constructs a command string by directly concatenating user input with a system command. This can lead to code injection vulnerabilities, where an attacker can manipulate the input to execute arbitrary commands on the system.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <stdlib.h>

void executeCommand(const char* command) {
    // Perform appropriate input validation and sanitization
    // to ensure command integrity

    system(command);
    // Compliant code: executing the command directly without string manipulation

    // Rest of the code...
}

int main() {
    const char* userInput = "ls -la";
    executeCommand(userInput);

    // Rest of the code...
}
```


The compliant code performs input validation and sanitization to ensure the integrity of the command being executed. It avoids string manipulation and directly executes the command, reducing the risk of code injection vulnerabilities.



Semgrep:


```
rules:
- id: code-injection
  pattern: "system($expr)"
  message: Potential code injection vulnerability detected
```

CodeQL:



```
import c

from CallExpr systemCall
where systemCall.getTarget().toString() = "system"
select systemCall,
       "Potential code injection vulnerability detected" as message
```




## DLL Hijacking


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <windows.h>

void loadDLL(const char* dllName) {
    HMODULE hModule = LoadLibraryA(dllName);
    // Noncompliant code: loading a DLL without specifying the absolute path

    // Rest of the code...
}

int main() {
    const char* dllName = "mydll.dll";
    loadDLL(dllName);

    // Rest of the code...
}
```

In the noncompliant code, the loadDLL function loads a DLL using the LoadLibraryA function without specifying the absolute path of the DLL. This can lead to DLL hijacking vulnerabilities, where an attacker can place a malicious DLL with the same name in a location where the application searches, leading to the execution of unintended code.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <windows.h>
#include <stdbool.h>

bool isValidDLLPath(const char* dllPath) {
    // Perform appropriate validation to ensure the DLL path is trusted

    // Return true if the DLL path is valid, false otherwise
    return true;
}

void loadDLL(const char* dllName) {
    char dllPath[MAX_PATH];
    // Construct the absolute path to the DLL using a trusted location
    snprintf(dllPath, sizeof(dllPath), "C:\\Path\\To\\DLLs\\%s", dllName);

    if (!isValidDLLPath(dllPath)) {
        // Handle the error condition appropriately (e.g., log, return, etc.)
        return;
    }

    HMODULE hModule = LoadLibraryA(dllPath);
    // Compliant code: loading the DLL with the absolute path

    // Rest of the code...
}

int main() {
    const char* dllName = "mydll.dll";
    loadDLL(dllName);

    // Rest of the code...
}
```


The compliant code ensures the DLL is loaded using the absolute path of the DLL file. It constructs the absolute path using a trusted location and performs appropriate validation (isValidDLLPath) to ensure the DLL path is trusted before loading the DLL.


Semgrep:


```
rules:
- id: dll-hijacking
  patterns:
    - "LoadLibraryA($dllName)"
    - "LoadLibraryW($dllName)"
  message: Potential DLL hijacking vulnerability detected
```

CodeQL:



```
import cpp

from CallExpr loadLibraryCall
where loadLibraryCall.getTarget().toString() = "LoadLibraryA"
   or loadLibraryCall.getTarget().toString() = "LoadLibraryW"
select loadLibraryCall,
       "Potential DLL hijacking vulnerability detected" as message
```





## Use After Free


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdlib.h>

void useAfterFree() {
    int* ptr = (int*)malloc(sizeof(int));
    free(ptr);
    *ptr = 42;  // Noncompliant code: use after free

    // Rest of the code...
}

int main() {
    useAfterFree();

    // Rest of the code...
}
```

In the noncompliant code, the useAfterFree function allocates memory using malloc, but then immediately frees it using free. After that, it attempts to dereference the freed pointer, leading to undefined behavior and potential use after free vulnerability.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdlib.h>

void useAfterFree() {
    int* ptr = (int*)malloc(sizeof(int));
    if (ptr == NULL) {
        // Handle allocation failure appropriately (e.g., return, log, etc.)
        return;
    }

    *ptr = 42;
    // Compliant code: using the allocated memory before freeing it

    free(ptr);

    // Rest of the code...
}

int main() {
    useAfterFree();

    // Rest of the code...
}
```


The compliant code ensures that the allocated memory is used before freeing it. It performs appropriate checks for allocation failure and handles it accordingly to avoid use after free vulnerabilities.


Semgrep:


```
rules:
- id: use-after-free
  pattern: "free($expr); $expr ="
  message: Potential use after free vulnerability detected
```

CodeQL:



```
import cpp

from ExprStmt freeStmt, assignment
where freeStmt.getExpr().toString().matches("^free\\(.*\\)$")
  and assignment.toString().matches("^.* = .*")
  and assignment.getExpr().toString() = freeStmt.getExpr().toString()
select freeStmt,
       "Potential use after free vulnerability detected" as message
```






## Uninitialized Variables


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

int getValue() {
    int value;  // Noncompliant code: uninitialized variable

    // Perform some operations or calculations to initialize the value

    return value;
}

int main() {
    int result = getValue();
    printf("Result: %d\n", result);

    // Rest of the code...
}
```

In the noncompliant code, the variable value is declared but not initialized before being used in the getValue function. This can lead to undefined behavior and incorrect results when the uninitialized variable is accessed.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

int getValue() {
    int value = 0;  // Compliant code: initializing the variable

    // Perform some operations or calculations to initialize the value

    return value;
}

int main() {
    int result = getValue();
    printf("Result: %d\n", result);

    // Rest of the code...
}
```


The compliant code initializes the variable value to a known value (in this case, 0) before using it. This ensures that the variable has a defined value and prevents potential issues caused by uninitialized variables.


Semgrep:


```
rules:
- id: uninitialized-variable
  pattern: "$type $varName;"
  message: Potential uninitialized variable detected
```

CodeQL:



```
import cpp

from VariableDeclarator uninitializedVariable
where not uninitializedVariable.hasInitializer()
select uninitializedVariable,
       "Potential uninitialized variable detected" as message
```





## Race Conditions


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <pthread.h>

int counter = 0;

void* incrementCounter(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        counter++;  // Noncompliant code: race condition
    }

    return NULL;
}

int main() {
    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, incrementCounter, NULL);
    pthread_create(&thread2, NULL, incrementCounter, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Counter value: %d\n", counter);

    // Rest of the code...
}
```

In the noncompliant code, two threads are created to increment a shared counter variable. However, since the increments are not synchronized, a race condition occurs where the threads can interfere with each other, leading to unpredictable and incorrect results.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <pthread.h>

int counter = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* incrementCounter(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        pthread_mutex_lock(&mutex);  // Acquire the lock
        counter++;  // Compliant code: synchronized access to counter
        pthread_mutex_unlock(&mutex);  // Release the lock
    }

    return NULL;
}

int main() {
    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, incrementCounter, NULL);
    pthread_create(&thread2, NULL, incrementCounter, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Counter value: %d\n", counter);

    // Rest of the code...
}
```


The compliant code introduces a mutex (pthread_mutex_t) to synchronize access to the counter variable. The mutex is locked before accessing the counter and unlocked afterward, ensuring that only one thread can modify the counter at a time, eliminating the race condition.



Semgrep:


```
rules:
- id: race-condition
  pattern: |
    $lockPattern($lockVar);
    $varName $incOp
  message: Potential race condition detected
```

CodeQL:



```
import cpp

from LockExpr lockExpr, PostfixIncExpr postfixInc
where lockExpr.getLockVar().getType().toString() = "pthread_mutex_t *"
  and lockExpr.getLockPattern().toString() = "pthread_mutex_lock"
  and postfixInc.getOperand().toString() = lockExpr.getLockVar().toString()
select lockExpr,
       "Potential race condition detected" as message
```





## Insecure File Operations


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>

void readFile(const char* filename) {
    FILE* file = fopen(filename, "r");  // Noncompliant code: insecure file operation

    if (file != NULL) {
        // Read the contents of the file

        fclose(file);
    }
}

int main() {
    const char* filename = "sensitive.txt";
    readFile(filename);

    // Rest of the code...
}
```

In the noncompliant code, the readFile function uses the fopen function to open a file in read mode. However, it does not perform any validation or check for errors, which can lead to security vulnerabilities. An attacker may manipulate the filename argument to access unintended files or directories.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

void readFile(const char* filename) {
    if (filename == NULL) {
        // Handle invalid filename appropriately (e.g., return, log, etc.)
        return;
    }

    FILE* file = fopen(filename, "r");
    if (file != NULL) {
        // Read the contents of the file

        fclose(file);
    }
}

int main() {
    const char* filename = "sensitive.txt";
    readFile(filename);

    // Rest of the code...
}
```


The compliant code includes a check to ensure that the filename argument is not NULL before performing the file operation. Additionally, error handling and proper file closure are implemented to mitigate potential security risks.




Semgrep:


```
rules:
- id: insecure-file-operation
  pattern: "fopen($filename, $mode);"
  message: Potential insecure file operation detected
```

CodeQL:



```
import cpp

from CallExpr fopenCall
where fopenCall.getTarget().getName() = "fopen"
  and exists(ExceptionalControlFlow ecf |
    ecf.getAnomalyType() = "ANOMALY_UNCHECKED_RETURN_VALUE"
    and ecf.getAnomalySource() = fopenCall
  )
select fopenCall,
       "Potential insecure file operation detected" as message
```





## API Hooking


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <windows.h>

void hookFunction() {
    // Hooking code here
    // ...
}

int main() {
    // Original function code here
    // ...

    hookFunction();

    // Rest of the code...
}
```

In the noncompliant code, the hookFunction is used to modify or replace the behavior of an original function. This technique is commonly known as API hooking and is often used for malicious purposes, such as intercepting sensitive data or tampering with the system. The noncompliant code lacks proper authorization and control over the hooking process.

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>

void originalFunction() {
    // Original function code here
    // ...
}

void hookFunction() {
    // Hooking code here
    // ...
}

int main() {
    // Original function code here
    // ...

    // Call the original function
    originalFunction();

    // Rest of the code...
}
```


The compliant code separates the original function (originalFunction) and the hooking logic (hookFunction) into separate functions. Instead of directly hooking the original function, the compliant code calls the original function itself, ensuring the intended behavior and avoiding unauthorized modification.




Semgrep:


```
rules:
- id: api-hooking
  pattern: |
    $hookFunc:ident();
  message: Potential API hooking detected
```

CodeQL:



```
import cpp

from CallExpr hookFuncCall
where hookFuncCall.getTarget().getName() = "hookFunction"
select hookFuncCall,
       "Potential API hooking detected" as message
```








## TOCTOU


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void processFile(const char* filename) {
    struct stat fileStat;
    stat(filename, &fileStat);  // Time-of-Check

    // Simulate a delay between Time-of-Check and Time-of-Use
    sleep(1);

    if (S_ISREG(fileStat.st_mode)) {
        // Perform operations on regular files
        // ...
    }
}

int main() {
    const char* filename = "data.txt";
    processFile(filename);

    // Rest of the code...
}
```

In the noncompliant code, the processFile function checks the file properties using the stat function (Time-of-Check). However, there is a delay introduced using the sleep function, creating a window of opportunity for an attacker to modify or replace the file before the Time-of-Use occurs. This can lead to security vulnerabilities where the wrong file may be processed.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Compliant code:


```c
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void processFile(const char* filename) {
    struct stat fileStat;

    // Perform the Time-of-Check and Time-of-Use atomically
    if (stat(filename, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
        // Perform operations on regular files
        // ...
    }
}

int main() {
    const char* filename = "data.txt";
    processFile(filename);

    // Rest of the code...
}
```


The compliant code performs the Time-of-Check and Time-of-Use atomically within the processFile function. It checks the return value of the stat function to ensure that it was successful and then checks the file's properties. By eliminating the delay between the Time-of-Check and Time-of-Use, the compliant code mitigates the TOCTOU vulnerability.


Semgrep:


```
rules:
- id: toctou
  pattern: |
    $checkStat:stat($filename, $_);
    sleep($delay);
    if ($checkStat && S_ISREG($_.st_mode)) {
      // Vulnerable code here
      // ...
    }
  message: Potential TOCTOU vulnerability detected
```

CodeQL:



```
import cpp

from CallExpr statCall, SleepExpr sleepExpr, Expr statArg
where statCall.getTarget().getName() = "stat"
  and sleepExpr.getArgument() = $delay
  and statArg.getType().toString() = "struct stat *"
  and exists(ControlFlowNode statNode |
    statNode.asExpr() = statCall
    and exists(ControlFlowNode sleepNode |
      sleepNode.asExpr() = sleepExpr
      and sleepNode < statNode
    )
  )
  and exists(Expr fileStat |
    fileStat.getType().getName() = "struct stat"
    and exists(ControlFlowNode useNode |
      useNode.asExpr() = fileStat
      and useNode > statNode
      and useNode < sleepNode
      and useNode.(CallExpr).getTarget().getName() = "
```







