---
layout: post
title:  "CERT C - Chapters 6, 7 - Strings"
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

## CERT C Examples

### STR02-C

Example of real vuln, from Sun Solaris TELNET daemon: 

```c
(void) execl(LOGIN_PROGRAM, "login",
  "-p",
  "-d", slavename,
  "-h", host,
  "-s", pam_svc_name,
  (AuthenticatingUser != NULL ? AuthenticatingUser :
  getenv("USER")),
  0);
```

The `USER` environment variable is an untrusted source. \
This is a classic shell injection vuln, as the arguments aren't properly sanitized. 

Assuming `login` uses the POSIX `getopt` function to parse CLI arguments, the `--` option would cause `getopt` to stop interpreting options. Meaning - putting it prior to the environment variable, would sanitize untrusted user data. 


### STR03-C

Beware of truncated strings, that may be created due to `strncpy, strncat, fgets, snprintf`. 

For example, this code may leave `a` as truncated string, without null byte:

```c
char *string_data;
char a[16];
/* ... */
strncpy(a, string_data, sizeof(a));
```

### STR06-C

The function `strtok` have surprising behavior. \
Usually, it is used for splitting a string into multiple tokens, splitted according to certain delimiter.

However, the function actually *changes* the original input string! \
On its first call, the first occurance of the delimiter within the string is swapped to a null byte. \
The function then returns a pointer to the start of the string, hence "splitting" it. \
The next calls of `strtok` would begin at the first non-delimiter character, after the fakely-placed null character. \
Note this fake-setting-of-null-bytes continues to all of the delimiters. 

Also note that `strtok` tracks the current position of the input string, by using a static pointer. \
This means that its behavior is undefined, in case it is called multiple times in the same program / within multithreaded application. This has some terrific implications. \
For example, consider a case of nested calls to `strtok`:

```c
int foo(char *input)
{
  char *dirpath = strtok(input, ":");
  while (dirpath != NULL)
  { 
    do_something_with_dir(dirpath);
    dirpath = strtok(NULL, ":");
  }
}

int main()
{
  const char *input= strtok(global_buffer, "|");
  while (input!= NULL)
  {
    foo(input);
    input = strtok(NULL, "|");
  }
}
```

While at a first glance, such a use seems completely OK, the opposite is true. \
In this case, after the first call of `foo`, the global static pointer was set by `foo`. Therefore, upon the preceding call to `strtok`, which sets `input` value towards the second iteration, it would use `input` as the search buffer, instead of the `global_buffer`. \
This means the search may be performed on a completely different string than intended!

It also means that 2+ contiguous delimiters are considered as a single delimiter (because right before `strtok` returns, it scans for the first non-delimiter character occurance). \
Moreover, delimiter bytes at the start or end of the string are ignored. \
The tokens returned by `strtok` are *always nonempty strings*. 

For example:

```c
int main()
{
    char *s = (char *)malloc(0x48);  // The string must be located within a writeable section
    memcpy(s, ",aaa;;;;bbb,", 0x48);

    printf("1 = %s\n", strtok(s, ";,"));    // prints "aaa"
    printf("2 = %s\n", strtok(NULL, ";,")); // prints "bbb"
    printf("3 = %s\n", strtok(NULL, ";,")); // prints null

    return 0;
}
```

A correct usage with `strtok` would first copy the original string to some temp buffer, on which `strtok` would be called. `strdup` can help us to do so. \
Moreover, we should always use `strtok_r`, in order to support nested calls.

Lastly, note that this function *cannot be used on constant strings / read only memory*.

A better alternative is `strspn`. 

### STR10-C

Different types of string literals should not be concatenated. \
Example vuln:

```c
wchar_t *msg = L"This message is very long, so I want to divide it "
                "into two parts.";
```

The above code causes an undefined behavior. \
The second string should also start with an `L` prefix.

### STR30-C

Do not modify string literals, as usually they are stored within the .rodata section (and should be assigned ideally only for `const char *` ptrs). 

Sometimes this kind of bug can be very subtle. \
For example, the following functions return a string literal pointer (out of a string literal input): \
`strpbrk, strrchr, strchr, strstr, memchr`.

For example: 

```c
char *str  = "string literal";
str[0] = 'S';
```

`str` actually is a local-variable pointer, located on the stack, that contains the value of some `.rodata` address. 

Using an array (`char str[]`) would fix this, as its bytes would be stored directly on the writeable stack. 

Another bad example:

```c
mkstemp("/tmp/edXXXXXX");
```

`mkstemp` actually modifies its input string. Meaning it cannot be a `const char` string. 

An alternative solution (that doesn't uses the stack), may be simply to declare the `fname` string as a `static` variable, hence storing it over the writeable data section. \
Note it is vulnerable within multithreaded applications in this way, tho. 

Finally, another real-world bad example:

```c
const char *get_dirname(const char *pathname) {
  char *slash;
  slash = strrchr(pathname, '/');
  if (slash) {
    *slash = '\0'; /* Undefined behavior */
  }
  return pathname;
}
```

While the usage of `strrchr` is fine, being a read-only function, and returning a pointer to certain offset within `pathname`, the usage of the returned `slash` as a modify-able string may write read only memory. 

### STR31-C

Gurantee the storage of the destination string has sufficient space for character data. 

For example:

```c
void copy(size_t n, char src[n], char dest[n]) {
   size_t i;
  
   for (i = 0; src[i] && (i < n); ++i) {
     dest[i] = src[i];
   }
   dest[i] = '\0';
}
```

This code has 2 major vulnerabilities:

1. OOB read - `src[i]` is being checked prior to `(i < n)`. \
It means that in case `src` first `n` bytes are all non-null-bytes, `src[n]` would be read prior to the check. \
For sophisticated attacks, this memory byte might not be mapped, therefore leading to a segmentation fault.

2. OOB write - off-by-one. \
The loop iterates a maximum of `n` times. \
After its completion, the index `i` might have the value of `n`, hence setting `dest[n] = '\0'` - causing an off-by-one write. 

This loop pattern is actually very common.

A *good* coding example, involving `snprintf`:

```c
void func(const char *name) {
  char filename[128];
  int result = snprintf(filename, sizeof(filename), "%s.txt", name);
  if (result != strlen(filename) {
    /* truncation occurred */
  }
}
```

Because `snprintf` copies up to `n` bytes, including the null-terminator, the posed check is correct. \
Note that its return value upon an unsuccessfull return, denotes the number of characters (excluding the null byte) which would have been written, if `n` was infinite. \
Therefore, the manual page recommends to check if the return value is `retval >= n`, in order to determine for truncation. \
It means another possible correct check is to verify `result < sizeof(filename)`. 

Note `snprintf` is vulnerable to overlapping source and destination buffers. 

### STR34-C

Before converting characters to large integer sizes, convert them to unsigned types. 

This is mainly because of implicit conversions to `int`, which may cause deep sign-extension issues. 

#### Tricky Assignment

```c
char *c_str;
int c;
 
c_str = bash_input.location.string;
c = EOF;
 
/* If the string doesn't exist or is empty, EOF found*/
if (c_str && *c_str) {
  c = *c_str++;
  bash_input.location.string = c_str;
}
```

The root problem is the assignment `c = *c_str++`. \
Since `c` is an `int`, and `c_str` points to a signed (by default) `char`, the assignment causes a sign extension of the small character. \
In case the character's MSb is 1, meaning `*c_str >= 0x80`, the integer conversion would add many 1's, resulting with some negative value (or large unsigned value, if the result `c` would be converted to some unsigned type).

Since the value of `EOF == -1`, upon an occurance of character byte `0xff == -1`, `c` would be assigned with the value of `EOF`!

A smarty-pants suggestion would be declaring `c_str` as an `unsigned char *`. 

Note, however, that upon an assignment from a smaller type to some large type, the smaller type is promoted to an `int` (nly if it is not representable as an int - it would be promoted to `unsigned int`). 

Meaning, even in this case - the sign extension still occurs. 

The correct solution for this case:

```c
c = (unsigned char)*c_str++;
```

Meaning, after the implicit conversion to int, case it back to an unsigned character. 

#### Tricky Indexing

```c
static const char table[UCHAR_MAX + 1] = { 'a' /* ... */ };
 
ptrdiff_t first_not_in_table(const char *c_str) {
  for (const char *s = c_str; *s; ++s) {
    if (table[(unsigned int)*s] != *s) {
      return s - c_str;
    }
  }
  return -1;
}
```

`UCHAR_MAX == 255`, meaning after pre-processing, `table` declaration is as follow:

```c
static const char table[255 + 1] = { 'a' /* ... */ };
```

Meaning 256 character entries, located within the `.data` section. 

The convertion to the array index is very tricky: `table[(unsigned int)*s]`. \
In order for the conversion `char -> unsigned int` to occur, the underlying character is first promoted to a `signed int`! \
Only then, it is converted to `unsigned int`. 

This means that a character with MSb of '1' would be converted to some huge number, hence producing an OOB-write. \
A correct implementation should only promote to `unsigned char`, instead. 

Also note the substraction `s - c_str`. \
This value is stored as a signed type, of `ptrdiff_t`. \
In case the difference between the pointed addresses is large enough, a wrap around may occur. 

### STR37-C

Arguments to character handling functions must be `unsigned char`. \
For example, methods such as `isspace, isupper, isascii` - all expects an `int` argument. \
This is because of the legacy intepreting of literal char, e.g. `'c'` as an `int`. \
It means that signed chars might get sign extended, to `int` length. 

Therefore, characters such as `0xff` would be converted to `0xffffffff == EOF`, leading to unexpected behavior. 

The following example causes unexpected behavior:

```c
size_t count_preceding_whitespace(const char *s) {
  const char *t = s;
  size_t length = strlen(s) + 1;
  while (isspace(*t) && (t - s < length)) {
    ++t;
  }
  return t - s;
} 
```

As `*t` implicitly converted, and sign-extended to an `int`. 

The solution should call `isspace((unsigned char)*t)`.


### STR38-C

Do not confuse between wide strings with narrow strings, and vice-versa. 

```c
wchar_t wide_str1[]  = L"0123456789";
wchar_t wide_str2[] =  L"0000000000";
 
strncpy(wide_str2, wide_str1, 10);
```

The above code is wrong, as `strncpy` expects a narrow string. \
A correct usage, would use `wcsncpy` instead. 

Another example:

```c
wchar_t wide_str1[] = L"0123456789";
wchar_t *wide_str2 = (wchar_t*)malloc(strlen(wide_str1) + 1);
```

The usage of `strlen` on a wide string results with a funny behavior - because multibyte chars may contain `\x00` as one of their bytes, `strlen` would stop its iteration by encountering one of these, resulting with too small value for the string actual length. 

It would lead to an under-allocation for `wide_str2`. 

Instead, `wcslen` should be used:

```c
wchar_t *wide_str2 = (wchar_t *)malloc(
    (wcslen(wide_str1) + 1) * sizeof(wchar_t));
```

### ARR30-C

Beware of out-of-bounds pointers / array subscripts. 

#### Subscript OOB

```c
enum { TABLESIZE = 100 };
 
static int table[TABLESIZE];
 
int *f(int index) {
  if (index < TABLESIZE) {
    return table + index;
  }
  return NULL;
}
```

Since `table` is actually array, it follows pointer arithmetics. \
Meaning, the actual returned value is the address corresponding to `table + 4 * index`. 

However, the possible problem, is due to the usage of signed integer. \
Meaning, `index` may be some negative value, hence returning an address prior to the `table` memory location, forming an OOB. 

#### Microsoft DCOM RPC Vuln

```c
error_status_t _RemoteActivation(
      /* ... */, WCHAR *pwszObjectName, ... ) {
   *phr = GetServerPath(
              pwszObjectName, &pwszObjectName);
    /* ... */
}
 
HRESULT GetServerPath(
  WCHAR *pwszPath, WCHAR **pwszServerPath ){
  WCHAR *pwszFinalPath = pwszPath;
  WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH_FQDN+1];
  hr = GetMachineName(pwszPath, wszMachineName);
  *pwszServerPath = pwszFinalPath;
}
 
HRESULT GetMachineName(
  WCHAR *pwszPath,
  WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH_FQDN+1])
{
  pwszServerName = wszMachineName;
  LPWSTR pwszTemp = pwszPath + 2;
  while (*pwszTemp != L'\\')
    *pwszServerName++ = *pwszTemp++;
  /* ... */
}
```

`pwszPath` is a pointer to wide string, meaning each character is represented by at least 2 bytes. \
Also note that `_RemoteActivation` actually passes a copy of the pointer as `pwszPath`, and the address *within its own stack frame* as `pwszServerPath`. \

The root vulnerability here is within `GetMachineName`. \
There are actually few bugs within this function:

1. `pwszPath` may by a null pointer. \
Also, it may be pointing to empty string - meaning the assignment `LPWSTR pwszTemp = pwszPath + 2` may trigger OOB-read. 

2. Bad pointer arithmetics, again with `LPWSTR pwszTemp = pwszPath + 2`. \
Since `pwszPath` is `WCHAR *`, this assignment actually stores the address of `(uint8_t*)pwszPath + 4`! \
Meaning, the first TWO wide character are skipped, not the first two bytes. 

3. Critical - the while loop doesn't checks for `wszMachineName` actual length, and only stops if the source string `pwszTemp` is encountered with an `'\'` wide char. \
Therefore, this loop may easily write past the buffer. 

4. Out of bounds read, for `*pwszTemp != L'\\'`, as the whole source string may not contain any `'\'` wide char.


#### Integer OVF, OOB-W, Unbound variable


```c
static int *table = NULL;
static size_t size = 0;
 
int insert_in_table(size_t pos, int value) {
  if (size < pos) {
    int *tmp;
    size = pos + 1;
    tmp = (int *)realloc(table, sizeof(*table) * size);
    if (tmp == NULL) {
      return -1;   /* Failure */
    }
    table = tmp;
  }
 
  table[pos] = value;
  return 0;
}
```

This code have few problems:

1. The assignment `size = pos + 1` may wrap around, due to an integer overflow. \
Assuming `pox = 0xffffffff > size`, it will enter the block, and wrap around. \
This would lead to `realloc` of size `0`, which means `table` would be freed (and `NULL` would return). 

On the next insertion, it would be possible to overwrite heap metadata, as `table` is now considered within some freelist. 

2. Another integer overflow, this time with:
`tmp = (int *)realloc(table, sizeof(*table) * size)`.

Because we may control `size`, the multiplication may be easily wrap around, again - leading to `realloc(ptr, 0) == free(ptr)`. 

This time tt is also possible to wrap around to some positive value, for example `realloc(ptr, 4)`. \
This should not return a null pointer, but a direct under-allocation, hence heap overflow. 

3. In case `pos == size`, the code would still perform an OOB-write! \
This is because `table[size] = value` would be issued.

4. This one is abit tricky to catch - the code first increases `size`, whether or not the `realloc` called have succeeded. \
This means that consecutive failing calls would increase `size` indefinitely. 


#### 2D OOB

A simple confusion between the dimensions indices:

```c
#define COLS 5
#define ROWS 7
static int matrix[ROWS][COLS];
 
void init_matrix(int x) {
  for (size_t i = 0; i < COLS; i++) {
    for (size_t j = 0; j < ROWS; j++) {
      matrix[i][j] = x;
    }
  }
}
```

#### Null Ptr Arithmetics

```c
char *init_block(size_t block_size, size_t offset,
                 char *data, size_t data_size) {
  char *buffer = malloc(block_size);
  if (data_size > block_size || block_size - data_size < offset) {
    /* Data won't fit in buffer, handle error */
  }
  memcpy(buffer + offset, data, data_size);
  return buffer;
}
```

This code doesn't check if the allocation has failed, but process with `buffer` anyways.

In this case, it will be assigned the value of `NULL == 0`, meaning arbitrary write is possible by controlling `offset` value. 


### ARR32-C

Beware of size arguments, especially in VLAs. \
Of course, wrap arounds can also occur within `sizeof()`. 

```c
void *func(size_t n2) {
  typedef int A[n2][N1];
 
  A *array = malloc(sizeof(A));
  if (!array) {
    /* Handle error */
    return NULL;
  }
 
  for (size_t i = 0; i != n2; ++i) {
    memset(array[i], 0, N1 * sizeof(int));
  }
 
  return array;
}
```

Most C compilers actually supports VLAs (arrays of length which is a function parameter). 

There are few problems with this code:

1. `A *array = malloc(sizeof(A))`:
A better paradigm is to avoid usage of such static types. \
Always prefer variables, for example `malloc(sizeof(*array))`. 

Note that there is an underlying integer overflow. \
Since `sizeof(A) = n2 * N1 * sizeof(int)`, this multiplication may actually wrap around, for large values of `n2`. 

2. OOB-write due to wrong indexing:
`array[i]` actually jumps by `i * sizeof(A)` bytes, instead of `i * N1 * sizeof(int)`.

### ARR36-C

Beware of comparing pointers that do not refer to the same object. 

For example:

```c
enum { SIZE = 32 };
  
void func(void) {
  int nums[SIZE];
  int end;
  int *next_num_ptr = nums;
  size_t free_elements;
 
  /* Increment next_num_ptr as array fills */
 
  free_elements = &end - next_num_ptr;
}
```

This program assumes that `nums` array is adjacent to the `end` local variable in memory. \
This isn't true, as there might be padding, or even worse - another order of the local variables withing the stack. 

A correct solution would look similar to the following:

```c
free_elements = &(nums[SIZE]) - next_num_ptr;
```

### ARR37-C

Beware of integer to pointer arithmetic operations. 

For example:

```c
struct numbers {
  short num_a, num_b, num_c;
};
 
int sum_numbers(const struct numbers *numb){
  int total = 0;
  const short *numb_ptr;
 
  for (numb_ptr = &numb->num_a;
       numb_ptr <= &numb->num_c;
       numb_ptr++) {
    total += *(numb_ptr);
  }
 
  return total;
}
 
int main(void) {
  struct numbers my_numbers = { 1, 2, 3 };
  sum_numbers(&my_numbers);
  return 0;
}
```

`numb` is a pointer towards some local stack address. \
The key problem is the increment `numb_ptr++` within the loop. \
This increment increases the pointed address by `sizeof(short)`, as this is pointers arithmetic. 

However, `struct numbers` is modifiable by the compiler, so it will be 16-bytes aligned. \
This means the compiler might add padding anywhere within the struct, so that its 3 fields aren't necessarily packed. 

A better solution would be defining the struct with contigious field:

```c
struct numbers {
  short a[3];
};
```

### ARR38-C

Beware of library functions, which may forge invalid pointers. \
There are some C functions that make changes to the arrays, taking two arguments - a pointer and length / number of elements. 

Few example functions: `fgets, memchr, strncat, strftime, setvbuf, snprintf, memset, etc`.

Vuln code examples:

#### Wide Strings Misuse

```c
static const char str[] = "Hello world";
static const wchar_t w_str[] = L"Hello world";
void func(void) {
  char buffer[32];
  wchar_t w_buffer[32];
  memcpy(buffer, str, sizeof(str)); /* Compliant */
  wmemcpy(w_buffer, w_str, sizeof(w_str)); /* Noncompliant */
}
```

The `sizeof` operator returns the real size of `w_str` within bytes. \
However, `wmemcpy` expects element count based on `wchar_t`.

A possible solution is to divide this result by `sizeof(wchar_t)`, or better - to use wide-chars dedicated function:

```c
wmemcpy(w_buffer, w_str, wcslen(w_str) + 1);
```

#### Pointer + Integer 

This code may cause easy off-by-one:

```c
void f1(size_t nchars) {
  char *p = (char *)malloc(nchars);
  /* ... */
  const size_t n = nchars + 1;
  /* ... */
  memset(p, 0, n);
}
```

Note there is a possibility of an integer overflow for `n`. 

A better example:

```c
void f2(void) {
  const size_t ARR_SIZE = 4;
  long a[ARR_SIZE];
  const size_t n = sizeof(int) * ARR_SIZE;
  void *p = a;
 
  memset(p, 0, n);
}
```

For platforms where `sizeof(int) != sizeof(long)`, an under-allocation would occur.

A better solution would be performing `n = sizeof(a)` instead.

#### Two Pointers + Integer

Especially relevant to the classic `memcpy, strncpy, memcmp, memmove, strncmp, etc`
. \ 
For these functions, the length should not be greater than any of the input buffers sizes. 

For example, the following code is buggy:

```c
void f4() {
  char p[40];
  const char *q = "Too short";
  size_t n = sizeof(p);
  memcpy(p, q, n);
}
```

As there is an OOB-read primitive, due to reading past `q`. 

#### One Pointer + Two Integers

For example, `fread, bsearch, fwrite, qsort, calloc`. \
Usually, the total size is a product of two size arguments. 

Note such functions are usually vulnerable to integer wrap-arounds. 

Example:

```c
struct obj {
  char c;
  long long i;
};
  
void func(FILE *f, struct obj *objs, size_t num_objs) {
  const size_t obj_size = 16;
  if (num_objs > (SIZE_MAX / obj_size) ||
      num_objs != fwrite(objs, obj_size, num_objs, f)) {
    /* Handle error */
  }
}
```

A problem might raise in case `sizeof(obj) != 16`, as the `num_objs` might be miscalculated.

A better paradigm is to use `sizeof(*objs)` instead. 

Another example:

```c
void f(FILE *file) {
  enum { BUFFER_SIZE = 1024 };
  wchar_t wbuf[BUFFER_SIZE];
 
  const size_t size = sizeof(*wbuf);
  const size_t nitems = sizeof(wbuf);
 
  size_t nread = fread(wbuf, size, nitems, file);
  /* ... */
}
```

This is tricky - `sizeof(*wbuf) == sizeof(wchar_t)`, while `sizeof(wbuf) == sizeof(wchar_t) * BUFFER_SIZE`. 

Therefore, the total amount of bytes read are `sizeof(wchar_t) * sizeof(wchar_t) * BUFFER_SIZE`, which may cause OOB-write. 

Another bad option is wrap-arounds. 

A possible solution is to fix `nitems = sizeof(wbuf) / size`.

### ARR39-C

Pointers arithmetics are dangerous. 

Classic example:

```c
enum { INTBUFSIZE = 80 };
 
extern int getdata(void);
int buf[INTBUFSIZE];
  
void func(void) {
  int *buf_ptr = buf;
 
  while (buf_ptr < (buf + sizeof(buf))) {
    *buf_ptr++ = getdata();
  }
}
```

`buf` is an integer array, which means it follows `int *` pointer arithmetics. \
`sizeof(buf)` returns its result in bytes, meaning `sizeof(int) * INTBUFSIZE`. 

Because of pointer arithmetcis, the actual value that is being added to `buf` is `sizeof(int) * INTBUFSIZE * sizeof(int)`! 

It means that `buf_ptr` may exceed its intended value, hence OOB-write. 

Another real world example:

```c
struct big {
  unsigned long long ull_a;
  unsigned long long ull_b;
  unsigned long long ull_c;
  int si_e;
  int si_f;
};
 
void func(void) {
  size_t skip = offsetof(struct big, ull_b);
  struct big *s = (struct big *)malloc(sizeof(struct big));
  if (s == NULL) {
    /* Handle malloc() error */
  }
 
  memset(s + skip, 0, sizeof(struct big) - skip);
  /* ... */
  free(s);
  s = NULL;
}
```

The vulnerability is caused by `s + skip`. \
Again, because of pointers arithmetics, the actual memory address that would be written to, is `s + skip * sizeof(struct big)`, not `s + skip`. 

This will cause some serius OOB-write. 

Another example:

```c
enum { WCHAR_BUF = 128 };
  
void func(void) {
  wchar_t error_msg[WCHAR_BUF];
 
  wcscpy(error_msg, L"Error: ");
  fgetws(error_msg + wcslen(error_msg) * sizeof(wchar_t),
         WCHAR_BUF - 7, stdin);
  /* ... */
}
```

Again, `error_msg` follows `wchar_t *` pointers arithmetics, and therefore the addition causes some serious OOB-write. 


[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[rlogin-vuln]: https://resources.sei.cmu.edu/library/asset-view.cfm?assetID=13161
[kerberos-vuln]: http://web.mit.edu/kerberos/www/advisories/krb4buf.txt
[wireshark-vuln]: https://gitlab.com/wireshark/wireshark/-/issues/17840
