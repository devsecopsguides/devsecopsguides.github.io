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




