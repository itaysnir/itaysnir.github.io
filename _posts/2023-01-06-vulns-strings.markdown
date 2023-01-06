---
layout: post
title:  "Vulnerabilities - Strings"
date:   2023-01-06 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

Sourced from command line arguments, stdin, environment variables, files and network sockets. \
Strings aren't a built-in type in C & C++.

They are presented as sequence of `char`s, terminated by a null character. 

Their common vulnerabilities are described within CERT-C chapters 6 (arrays) and 7 (strings):
[cert-c][cert-c]. 

## ARR01-C - sizeof() on pointer paramater

```c
void clear(int array[]) {
    for (size_t i = 0; i < sizeof(array) / sizeof(array[0]); ++i)     {
        array[i] = 0;
    }
}
```

Array is passed as a parameter, so its type corresponds to `int *`. \
Therefore, `sizeof(array) == 4`, and the expression evaluates to 1, regardless of the array content. 

`sizeof` is just a static operator, evaluated during compile-time. It cannot support such cases, that requires evaluating a length of a string dynamically. \
However, `strlen` may be used to evaluate the length of a null-terminated string. 

According to `ARR01-C` spec, even the following scenario evaluates `sizeof(a)` to 4:

```c
void clear(int a[100]) {
  memset(a, 0, sizeof(a)); /* Error */
}
```

Which may seem surprising. 

A correct implementation should always pass the length of the array, along with its pointer, as parameters to the function:

```c
void clear(int a[], size_t len) {
  memset(a, 0, len * sizeof(int));
}
```

## Wide strings

Note that C supports multibyte character sets. \
It means that each character may be represented by a variable number of bytes (Unicode, UTF-8). \
Note is isn't equivalent to wide strings, which have a constant (> 1) number of bytes, for each represented character.

Usually wide-string literals are prefixed by L: `L"xyz"`.

The array elements are of type `wchar_t`. 

C strings are arrays of `char`, and modifiable, while C++ strings are `const char` array - for whom modification yields undefined behavior. 

## STR11-C - Specifying Literal String Initialization Size

The following declaration is problematic:

```c
const char s[3] = "abc";
```

While 3 bytes are allocated for the `"abc"` string, no byte is allocated for the terminating null byte. 

A better approach is to not specify the size, and let the compiler do its job. 

Note there are few exceptions:

```c
char s1[3] = { 'a', 'b', 'c' }; /* NOT a string */
char s[10] = "abc";
strcpy(&s[3], "def");  // may want to support concatanation
```

## C++ Strings

Presented by `std::basic_string`. \
`string` is a typedef of `basic_string<char>`, while `wstring` is a typedef of `basic_string<wchar_t>`. 

Many of the objects manipulated by functions declared in `<cstring>` are null terminated byte strings. 

Wide char objects can be imported via `<cwchar>`. 

## STRO4-C - Plain Character Type

3 types: `char, signed char, unsigned char`. 

It is up to the compiler to decide if the range of `char` is `signed` or `unsigned`. 

Usually, the string manipulation functions takes as an argument a `const char*` type. 

```c
char cstr[] = "char string";
signed char scstr[] = "signed char string";
unsigned char ucstr[] = "unsigned char string";

len = strlen(cstr);
len = strlen(scstr); /* warns when char is unsigned */
len = strlen(ucstr); /* warns when char is signed */
```

Note that for few cases, it may be safer to use `unsigned char` type. 

Also note that the type of a character constant is `int`. \
It leads to the surprising result, that *for all character constants, sizeof(c) == sizeof(int)*:

```c
sizeof('a') == sizeof(int) // True

char x = 'x';
sizeof('x') == sizeof(x) // False! WTF!!!
```

Unlike this surprising result, in C++ the static type of a literal character is `char`. \
Wide character literal string has type of `wchar_t`, and multicharacter literal has type `int`. \
So this vuln is C specific.

`unsigned char` has the unique property that its objects are represented using a pure binary notation. \
It means these objects have no padding bits, or trap representation. 

`wchar_t` are used for natural language character data. \
`STR00-C` states the importance of strings type compatibility. 

## Sizing Strings

Common source of runtime errors and buffer overflows. 

The C standart defines `wchar_t` as an integer type (typically UTF-16 - 2 bytes for Windows, and UTF-32 - 4 bytes for Linux). 

Example vuln:

```c
wchar_t wide_str1[] = L"0123456789";
wchar_t *wide_str2 = (wchar_t *)malloc(strlen(wide_str1) + 1);
```

`strlen` counts by a byte-granularity, until it encounters a null byte. \
Note however that *wide characters may contain null bytes*, as some of their intermediate bytes! \
It means `strlen` would return a small value, hence leading to under-allocation. 

Another example vuln:

```c
wchar_t wide_str1[] = L"0123456789";
wchar_t *wide_str3 = (wchar_t *)malloc(wcslen(wide_str1) + 1);
```

The `wcslen` function is used, to determine the amount of elements of the wide string. \
However, `malloc` should receive as an argument the total number of bytes for allocation, not the number of elements. \
Meaning, it lacks a multiplication of `sizeof(wchar_t)`.

`STR31-C` contains many more examples of common wide strings vulnerabilities:

off-by-one vuln:

```c
void copy(size_t n, char src[n], char dest[n]) {
   size_t i;
  
   for (i = 0; src[i] && (i < n); ++i) {
     dest[i] = src[i];
   }
   dest[i] = '\0';
}
```

This loop checks that `src[i]` isn't a null character, as well as copies up to `n` elements from `src` to `dest`. \

Assuming that `src` is some string with more than `n` elements, it means that the maximal value of `i` corresponds to `n-1`, so `dest` would be filled with `n` values, and `\x00` at its `n+1` entry (index `dest[n]`). 

Therefore, in case `dest` was allocated with exactly `n` bytes, it means there would be an overflow of exactly 1 byte (null) past the `dest` buffer. 

The fix is to decrease the loop iteration counter by 1. 


## Common String Manipulation Errors



[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
