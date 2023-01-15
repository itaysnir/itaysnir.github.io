---
layout: post
title:  "CERT C - Strings"
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

All of the C vulnerabilities are described within [CWE][cwe-c].

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

There are Four common string manipulation errors.

### Unbounded string copies

A classic example is the usage of `gets` function, into a fixed-length buffer. 

`MSC34-C` disallows such usage. 

Its implementation has no bound on the amount of bytes written to the `dest` buffer:

```c
char *gets(char *dest) {
  int c = getchar();
  char *p = dest;
  while (c != EOF && c != '\n') {
    *p++ = c;
    c = getchar();
  }
  *p = '\0';
  return dest;
}
```

`STR35-C` (or `CWE-120`) prohibits copy from an unbounded source to fixed-length array. 

Abit more real-world example:

```c
struct hostent *clienthp;
char hostname[MAX_LEN];

// create server socket, bind to server address and listen on socket
...

// accept client connections and process requests
int count = 0;
for (count = 0; count < MAX_CONNECTIONS; count++) {

int clientlen = sizeof(struct sockaddr_in);
int clientsocket = accept(serversocket, (struct sockaddr *)&clientaddr, &clientlen);

if (clientsocket >= 0) {
clienthp = gethostbyaddr((char*) &clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
strcpy(hostname, clienthp->h_name);
logOutput("Accepted client connection from host ", hostname);

// process client request
...
close(clientsocket);
}
}
close(serversocket);
```

In this example, `clienthp->h_name` may be longer than `MAX_LEN`, resulting with a buffer overflow. 

Moreover, `strcpy, strcat, sprintf` - all perform unboundeed copy operations.

Example:

```c
int main(int argc, char *argv[]) {
/* ... */
char prog_name[128];
strcpy(prog_name, argv[0]);
}
```

Attacker may supply `argv[0]` of his wish (usually it is the program's name, however it isn't mandatory), and cause an overflow.

A possible solution is to use the `strlen` function, and add an extra byte for the null terminator:

```c
const char * const name = argv[0] ? argv[0] : "";
char *prog_name = (char *)malloc(strlen(name) + 1);

if (prog_name != NULL) {
strcpy(prog_name, name);
}
```

Another option is to use the `strdup` function. \
This function dynamically allocates a new string, that should later on be `free`'d. 

A non-secure alternative is the usage of `sprintf`, which utilizes the `%s` format specifier. \
A null char is written at the end of the characters written. 

Abit better alternative is the `snprintf` function. \
Output chars beyond the `n-1` are discarded, and a null character is written at the end. \
It returns the number of characters that *would have been written, if n was large enough (without null byte)*, and not the amount of bytes copied! \
The null terminated output is completely written only if the returned value is up to `n-1`. \
It means that a return value of `n` means a truncation have occured. 

This leads to these surprising results:

```c
int main()
{
    char *arr = "AAAAAAAAAAAAAAAAAAAA";
    char dest[3] = {0};
    size_t n = 3;

    int ret = snprintf(dest, n, "%s", arr);
    // returns 20
    printf("retval: %d\n", ret); 
    // prints "AA", as size includes \x00, and it always writes a null byte for %s
    printf("The string is: %s\n", dest); 
    return 0;
}
```

It also means, that the following code snippet have abit non-trivial off-by-one:

```c
char arr[5] = "AAAA";
char dest[5] = {0};

int ret = snprintf(dest, strlen(arr), "%s", arr);
// returns 4, (==strlen(arr)) meaning there was a truncation
printf("retval: %d\n", ret); 
// prints "AAA", as \x00 was one of the counted 'size' bytes
printf("The string is: %s\n", dest); 
```

Note that it is very important to check the return values of this function, as it may have dynamic memory failure causes. 

`FIO04-C, FIO33-C` (`CWE-391`) states the importance of checking return value of *every* C library function.

### Off-by-ones

2 example vulns:

```c
char s1[] = "012345678";
char s2[] = "0123456789";
char *dest;
int i;

strcpy_s(s1, sizeof(s2), s2);
dest = (char *)malloc(strlen(s1));
for (i=1; i <= 11; i++) {
  dest[i] = s1[i];
  }
dest[i] = '\0';
```

Overcopy of large source buffer `s2` to `s1`, as well as under-allocation of `dest` (and accessing beyond it..).

### Null-termination errors

Can be easily occur due to `strncpy, strncat`, etc.

For example:

```c
char a[16];
char b[16];
char c[16];
strncpy(a, "0123456789abcdef", sizeof(a));
strncpy(b, "0123456789abcdef", sizeof(b));
strcpy(c, a);
```

`a` is of size 16, and a string containing 16 characters is copied to it. \
However, `strncpy` copies at most `n` characters, and does not append `\x00` afterwards if `n` have reached. \
The same holds for `b`. 

It means that `b` is contigious to `a`, so the last `strcpy` call would result by copying at least 32 bytes. 

`STR32-C` states the importance of proper null terminating strings. 

A correct common paradigm is the following:

```c
char ntbs[NTBS_SIZE];

strncpy(ntbs, source, sizeof(ntbs)-1);
ntbs[sizeof(ntbs)-1] = '\0';
```

Another cool example vuln:

```c
wchar_t *cur_msg = NULL;
size_t cur_msg_size = 1024;
size_t cur_msg_len = 0;
 
void lessen_memory_usage(void) {
  wchar_t *temp;
  size_t temp_size;
 
  /* ... */
 
  if (cur_msg != NULL) {
    temp_size = cur_msg_size / 2 + 1;
    temp = realloc(cur_msg, temp_size * sizeof(wchar_t));
    /* temp &and cur_msg may no longer be null-terminated */
    if (temp == NULL) {
      /* Handle error */
    }
 
    cur_msg = temp;
    cur_msg_size = temp_size;
    cur_msg_len = wcslen(cur_msg);
  }
}
```

The above code cuts the wide string by (about) half. \
There are no gurantess at all that post-cut, the wide string is properly null terminated. 

Instead, the following line must be added after the `cur_msg` assignment:

```c
cur_msg[temp_size - 1] = L'\x00';
```

Note the usage of `L` notation, to state a `wchar_t` element. 

### String Truncation

Usually not as bad as buffer overflow, but may lead to loss of data / logical vulns. 

For example, truncation may occur as the above solution, and under certain scenarios may lead to logical vulns.

### Non-Library String Errors 

For example, vuln string copy operation, that doesn't calls any function:

```c
int main(int argc, char *argv[]) {
  int i = 0;
  char buff[128];
  char *arg1 = argv[1];
  if (argc == 0) {
    puts("No arguments");
    return EXIT_FAILURE;
  }
  while (arg1[i] != '\0') {
    buff[i] = arg1[i];
    i++;
  }
  buff[i] = '\0';
  printf("buff = %s\n", buff);
  exit(EXIT_SUCCESS);
}
```

Clearly there is an unbounded write of `arg1`, resulting with an OOB-W to `buff`. 


## Dynamic Allocation Functions

May be prone to dynamic memory management errors. \
These includes the `getline, getdelim` functions. \
They are associated with an open file, and the program must call `free` to release the allocated buffer.

```c
char *response = NULL;
size_t len;

puts("Continue? [y] n: ");
if ((getline(&response, &len, stdin) < 0) ||
(len && response[0] == 'n')) {
  free(response);
  exit(0);
}
```

It is possible to also define a stream, that is not associated with an open file, but a memory buffer. \
The following functions are relevant for such goals:
`fmemopen, open_memstream, open_wmemstream`.

Operations on such streams are bound to a memory buffer. \
In case of `open_memstream, open_wmemstream`, the memory area may grow dynamically to perform the write operations, if needed. 

```c
char *buf;
size_t size;
FILE *stream;

stream = open_memstream(&buf, &size);
if (stream == NULL) { /* handle error */ };
fprintf(stream, "hello");
fflush(stream);
printf("buf = '%s', size = %zu\n", buf, size);
fprintf(stream, ", world");
fclose(stream);
printf("buf = '%s', size = %zu\n", buf, size);
free(buf);
```

Note - `fclose` implicitly flushes the data to the buffer. \
Moreover, `open_memstream` implicitly dynamically allocates memory for the buffer as it grows, which should eventually be `free`d. 

Note the `size` parameter holds the total size of the dynamically allocated buffer. 

## std::basic_string

One area of concern when using this class is iterators. 

References, pointers and iterators are invalidated by operations that modify the string. \
Using invalid iterator may result in a vuln. 

Example vuln:

```c++
char input[];
string email;
string::iterator loc = email.begin();
// copy into string converting ";" to " "
for (size_t i=0; i < strlen(input); i++) {
if (input[i] != ';') {
 email.insert(loc++, input[i]); // invalid iterator
}
else email.insert(loc++, ' '); // invalid iterator
}
```

After the first call to `insert`, the iterator (and also pointers and references) `loc` is actually *invalidated*, and only afterwards increased by 1. 

This results with an undefined behavior. 

The solution is simple - work with an updated iterator, as returned by `insert`:

```c++
loc = email.insert(loc, input[i]); // acquire updated iterator

++loc;
```

Usually, whenever operation references memory out of bounds, `std::out_of_range` is thrown. \
However, `std::string::operator[]` does not. 

A safer approach is using the `at()` method, which is similar to `operator[]` but does throws the exception. 

The `c_str()` method can be used to generated a null-terminated string. \
It is interesting to note, that the return value of this method is `const char *`, meaning that any attempt to `free` or `delete` the returned string is an error (which can usually be caught during compile-time). 

The same holds for modifying the returned string. \
Prefer modifying a copy of the string instead.

There are few more common errors for `basic_string` involving iterators. \
A classic example is iterating over literal string, `"TEST"`, which also implicitly iterates over the null byte. 

## String Handling Functions

### fgets

`gets` is pretty awful. 

A much better alternative is `fgets`, but we should consider its weaknesses. 

This function reads at most `n - 1` bytes from the stream, into the buffer. A `\n` is written immediately after the last read character. \
No characters are read after a `\n` or `EOF`. 

It supports reading partial line - meaning it won't pad extra bytes to reach a total of `n` written bytes. 

Note - \
User input may be truncated, if large user-input was inserted. \
We can easily detect this, by searching for `\n` character within the buffer.

### getchar

`getchar` - returns next character from the input stream. \ 
Returns `EOF` if the stream is at EOF. 

Note the return value of this function is `int`.

It is also recommended to use `feof(stdin), ferror(stdin)` after the read have completed. 

### getline, getdelim

`getline` is a specialization of `getdelim`, for delimiter of `\n`. 

This method internally uses dynamic memory allocation via `realloc` - meaning passing it a `NULL` buffer would implicitly call `malloc` under the hood, and `realloc` it as needed. \
It returns the amount of characters read. 

Note one must explicitly `free` the buffer. 

### strdup

Can be used as an alternative to `strcpy, strncpy`. 

There is no equivalent alternative to `strcat`.

This function accepts a ptr to null terminated string, and returns a ptr to a newly allocated, duplicated string. \
The allocation size is determined by the location of the first null byte occurance.

The returned ptr must be eventually `free`'d. 

### strncpy, strncat

The common "kind of" safe use of `strncpy`:

```c
strncpy(dest, source, dest_size - 1);
dest[dest_size - 1] = '\0';
```

`strncpy` does not gurantee to null terminate the destination string. \
So the programmer must ensure it is properly null terminated. 

`strncat` appends up to `n` characters from `s2` to `s1`. \
It overwrite the initial null character of `s1`, and *always* appends a null character to the result. 

The maximal number of characters post-concatenation: `strlen(s1) + n + 1` (adds `n` regular characters, and 1 null byte).

Example vuln:

```c
strncpy(record, user, MAX_STRING_LEN - 1);
strncat(record, cpw, MAX_STRING_LEN - 1)
```

The last argument to `strncat` should be the space remaining after the call to `strncpy` (actually, both functions require to specify the remaining space and not the total size of the buffer). 

Therefore, programmers must track the remaining space. 

A correct method to calculate the remaining space:

```c
strncat(dest, source, dest_size-strlen(dest)-1)
```

Another problematic aspect of these functions, is that neither of them provides a status code / report when the resulting string is truncated. 

There's another side effect, of `strncpy` filling the entire destination buffer with null bytes after the source data is exhaused. 

### strndup

Duplicates the provided string in a new block of memory, as if using `malloc`. 

Equivalent to `strdup`, but copies at most `n + 1` bytes into a new allocated memory. 

The allocated string must be reclaimed by passing the ptr to `free`. 

### memcpy, memmove

Their main errors are due to mismatched `size` parameter of the source buffer, overflowing the destination buffer.

### strlen

Its operations can be subverted, due to the weaknesses of the underlying string representation.

If the character array is not properly null terminated, it may return a large number, that could result in a vulnerability. 

## Runtime Protection 

### Input Validation

For example:

```c
char buff[100];
if (strlen(arg) >= sizeof(buff)) {
  abort();
}
strcpy(buff, arg);
/*
```

Note that if the criteria would have been `>` instead, an off-by-one vuln would occur - which results with a misproperly terminated string in this case. 

### Object Size Checking

gcc introduces the `__builtin_object_size()` function. 

By specifying `_FORTIFY_SOURCE`, gcc implicitly uses this call for any of the various buffer-manipulations functions. \ 
It adds extra runtime checks, preventing buffer overflows. 

Other mitigations, such as stack canaries, are also being used frequently.

### OS Support

For example, ASLR support:

```bash
sysctl -w kernel.randomize_va_space=2
```

## Noteable Vulns

### rlogin

Common among old unix systems.

It had an unbound copy of the `TERM` (terminal) environment variable into an array of 1024 characters, declared as local stack variable. 

```c
int uid;
long omask;
struct passwd *pw;
char *host, *p, *user, term[1024];
struct servent *sp;
…
if (!(pw = getpwuid(uid = getuid()))) {
(void)fprintf(stderr, "rlogin: unknown user id.\n");
exit(1)
}
…
(void)strcpy(term, (p = getenv("TERM")) ? p : "network");
```

An in-deptch analysis of this vuln can be found [here][rlogin-vuln].

### Kerberos V4

Network authentication protocol. 

Some serious buffer overflows were found for Kerberos 4. \
The vulnerable function is `krb_rd_req`:

```c
strcpy((char *) cmdbuf + offst, kprogdir);
cp = copy + 3 + offst;

if (auth_sys == KRB5_RECVAUTH_V4) 
{
  strcat(cmdbuf, "/v4rcp");
} 
else 
{
  strcat(cmdbuf, "/rcp");
}
if (stat((char *)cmdbuf + offst, &s) >= 0)
  strcat(cmdbuf, cp);
else
  strcpy(cmdbuf, copy);
free(copy);
```

`cmdbuf` was added an explicit nullbyte truncation, right after its first `strcpy` call:

```c
cmdbuf[sizeof(cmdbuf) - 1] = '\0';
```

Moreover, all `strcat` calls were replaced by `strncat`, up to their remaining size:

```c
strncat(cmdbuf, "/v4rcp", sizeof(cmdbuf) - 1 - strlen(cmdbuf));
```

A full description of the vulnerability can be found [here][kerberos-vuln].

### CVE-2022-0583 - Wireshark Heap OOB Read

The vulnerable code:

```c
while ((*ptr != '\n') && (*ptr != '\0') &&
      (bytes_processed < total_config_bytes) &&
      (entry_length < bufsiz))
{
...
}
```

The problem is `ptr` being referenced *prior to bounds checking*. \
It means that one extra byte past the end of the packet, may be read-accessed. 

While it doesn't seem too awful at a first glance, the heap buffer may be crafted as the last chunk within a memory page - while the successing page isn't mapped into the memory. 

In such a scenario, the process would crash - leading to a potential DOS attack.

The solution is to *check pointer bounds, prior to dereferencing it*:

```c
((bytes_processed < total_config_bytes) &&
      (entry_length < bufsiz) &&
      (*ptr != '\n') && (*ptr != '\0'))
```

[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[rlogin-vuln]: https://resources.sei.cmu.edu/library/asset-view.cfm?assetID=13161
[kerberos-vuln]: http://web.mit.edu/kerberos/www/advisories/krb4buf.txt
[wireshark-vuln]: https://gitlab.com/wireshark/wireshark/-/issues/17840
