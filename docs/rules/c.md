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






