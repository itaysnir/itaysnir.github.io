---
layout: post
title:  "CERT C - Chapter 3 - Expressions"
date:   2023-01-22 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

The common vulnerabilities are described within CERT-C chapter 3 (expressions):
[cert-c][cert-c]. 

All of the C vulnerabilities are described within [CWE][cwe-c].

## CERT C Examples

### EXP00-C 

Beware of unexpected operations precedence. \
Especially, pay attention to the unintuitive low-precedence levels of `&, |, ^, <<, >>`, compared to the comparision operators `==, !=, <, >, <=, >=`. 

Examples:

```c
x & 1 == 0 // Evaluates as x & (1 == 0) -> x & (0) -> constant 0

void* next = 0x40000000; 
(int *)next++; // evaluates to 0x40000001, not 0x40000004
```

Real world examples:

```c
/* EX1 */
#define ceil_div(x, y) (x + y - 1) / y
a = ceil_div (b & c, sizeof (int)); 
// Evaluated as: a = (b & (c + sizeof (int) - 1)) / sizeof (int);

/* EX2 */
#define ceil_div(x, y) ((x) + (y) - 1) / (y)
a = sizeof ceil_div(1, 2); 
// Evaluated as: a = sizeof ((1) + (2) - 1) / (2)
```

This is also the reason that the best way to define macros, is having parentheses wrapping both arguments (EX1) and the whole expression (EX2):

```c
#define ADD(x, y) ((x) + (y))
```

```c
uint8_t highbyte;
pos = highbyte & 63 << 8 | current->data[pos];
// Evaluated as: pos = (highbyte & 0x3F00) | etc;
// pos = etc;
```

The following example is pretty wacky:

```c
unsigned int n = 0;
std::cout << n++ << n << ++n; // prints 122!
// Evaluated as:
// operator<<(operator<<(operator<<(std::cout, n++), n), ++n)
```

In the above example, the outermost `operator<<` call have two arguments: `operator<<(operator<<(std::cout, n++), n)` and `++n`. \
The flaw is that C++ does not specifies the order of arguments evaluation. \
Even worse, the specification allows the first argument to be *partially evaluated*, then evaluate the second argument, then completing the first argument. \
This yields an UB. 

In this case, `++n` is actually first evaluated, so the value is increased by 1. Only then, `operator<<(std::cout, n++)` is called, printing 1 and increasing `n == 2`. 

### EXP02-C

Beware of short-circuit evaluation, espcially for logical operators `&&, ||`.

If the second operand contains side effects, this may yield surprising results.

```c
enum { max = 15 };
int i = /* Initialize to user-supplied value */;
 
if ( (i >= 0) && ( (i++) <= max) ) {
  /* Code */
}
```

In this case, for negative values of `i`, its value won't be incremented at all, while for non-negative, it would.

Another example:

```c
char *p = /* Initialize; may or may not be NULL */
 
if (p || (p = (char *) malloc(BUF_SIZE)) ) {
  /* Perform some computation based on p */
  free(p);
  p = NULL;
} else {
  /* Handle malloc() error */
  return;
}
```

In case `p` was initialized to some `p != NULL` value, the `malloc` call would never be performed. \

This may result with an attempt to free an invalid pointer / double-free.

### EXP03-C

Beware of structure padding. 

```c
enum { buffer_size = 50 };
 
struct buffer {
  size_t size;
  char bufferC[buffer_size];
};
 
/* ... */
 
void func(const struct buffer *buf) {
 
  /*
   * Incorrectly assumes sizeof(struct buffer) =
   * sizeof(size_t) + sizeof(bufferC)
   */
  struct buffer *buf_cpy = (struct buffer *)malloc(
    sizeof(size_t) + (buffer_size * sizeof(char) /* 1 */)
  );
 
  if (buf_cpy == NULL) {
    /* Handle malloc() error */
  }
 
  /*
   * With padding, sizeof(struct buffer) may be greater than
   * sizeof(size_t) + sizeof(buff.bufferC), causing some data 
   * to be written outside the bounds of the memory allocated.
   */
  memcpy(buf_cpy, buf, sizeof(struct buffer));
 
  /* ... */
 
  free(buf_cpy);
}
```

The above example leads to an under-allocation, due to low chunk size provided to `malloc`. \
Instead, `sizeof(*buf) / sizeof(struct buffer)` should be used. 

Note the importance of stating `struct buffer`. \
In case there was some global static buffer, named `buffer`, its own size would be placed instead.

### EXP05-C

Casting away `const` is dangerous, resulting with an UB. \
Some implementations places `const` object in a read-only region.

```c
void remove_spaces(const char *str, size_t slen) {
  char *p = (char *)str;
  size_t i;
  for (i = 0; i < slen && str[i]; i++) {
    if (str[i] != ' ') *p++ = str[i];
  }
  *p = '\0';
}
```

This func may acctually segfault, due to accessing read-only memory. \
Note that `slen` counter does not include the null byte. 

Also note that some legacy APIs does not accept a `const` argument, forcing a need to cast away the `const` qualifier. \
Moreover, some standard C funcrions returns a non-const pointers that refer to their `const` arguments. These return values are dangerous to use. \
The dangerous functions includes `memchr, strchr, strstr, strtol, etc`.

```c
extern const char s[];
char* where;
where = strchr(s, '\0'); // The returned ptr is not const. However, modifying it would lead to UB. 
```

### EXP08-C

Pay extra caution to pointers arithmetics.

Example:

```c
int buf[INTBUFSIZE];
int *buf_ptr = buf;
 
while (havedata() && buf_ptr < (buf + sizeof(buf))) {
  *buf_ptr++ = parseint(getdata());
}
```

Because `buf` is treated similar to type `int *`, its addition with `sizeof(buf)` would acctually scale by a factor of `sizeof(int)`, resulting with an OOB-write.

#### Real Vuln In OpenBSD 

```c
struct big {
  unsigned long long ull_1; /* Typically 8 bytes */
  unsigned long long ull_2; /* Typically 8 bytes */
  unsigned long long ull_3; /* Typically 8 bytes */
  int si_4; /* Typically 4 bytes */
  int si_5; /* Typically 4 bytes */
};
/* ... */
  
int f(void) {
  size_t skip = offsetof(struct big, ull_2);
  struct big *s = (struct big *)malloc(sizeof(struct big));
  if (!s) {
   return -1; /* Indicate malloc() failure */
  }
 
  memset(s + skip, 0, sizeof(struct big) - skip);
  /* ... */
  free(s);
  s = NULL;
   
  return 0;
}
```

`s + skip` is actually factored by `sizeof(struct big)`! \
This results with a significant OOB-write. 

### EXP09-C

It is a good paradigm to use `sizeof` to determine size of a type or a variable. 

```c
int f(void) { /* Assuming 32-bit pointer, 32-bit integer */
  size_t i;
  int **matrix = (int **)calloc(100, 4);
  if (matrix == NULL) {
    return -1; /* Indicate calloc() failure */
  }
 
  for (i = 0; i < 100; i++) {
    matrix[i] = (int *)calloc(i, 4);
    if (matrix[i] == NULL) {
      return -1; /* Indicate calloc() failure */
    }
  }
 return 0;
}
```

The first `calloc` correctly allocates 100 pointers, each of size 4 bytes. \
Then, the loop allocates `4 * i` bytes, and sets the result for a correctly-scaled `matrix[i]`. 

On architectures where `sizeof(int) != sizeof(ptr)`, the `matrix` is actually factored according to a ptr value, but allocates only 4 bytes. \
This results with both OOB-W and under allocations.

Note the first iteration allocates `calloc(0, 4)`, meaning a zero-length heap buffer. 

The correct solution should call:

```c
int **matrix = (int **)calloc(100, sizeof(*matrix)); // int *
// AND
matrix[i] = (int *)calloc(i, sizeof(**matrix)); // int
```

Beware of using the correct number of `*` tho.

### EXP10-C

Beware of subexpressions evaluation order. 

For example:

```c
int g;
 
int f(int i) {
  g = i;
  return i;
}
 
int main(void) {
  int x = f(1) + f(2);
  printf("g = %d\n", g);
  /* ... */
  return 0;
}
```

The functions of `f(1), f(2)` may be called at any order, meaning g might have any value of the two!

### EXP11-C

Structs with bit-fields has implementation-defined padding bits. \
The order of allocation within a strorage unit is implementation-defined: right-left or vice versa. 

Therefore, calculations that depend on the order of bits within a storage unit may produce different results on different platforms. 

For example:

```c
struct bf {
  unsigned int m1 : 8;
  unsigned int m2 : 8;
  unsigned int m3 : 8;
  unsigned int m4 : 8;
};  /* 32 bits total */
```

Therefore, `struct bf` is one storage unit, that may have two formats: `m4 m3 m2 m1, m1 m2 m3 m4`.

```c
void function() {
  struct bf data;
  unsigned char *ptr;
 
  data.m1 = 0;
  data.m2 = 0;
  data.m3 = 0;
  data.m4 = 0;
  ptr = (unsigned char *)&data;
  (*ptr)++; /* Can increment data.m1 or data.m4 */
}
```

The code above correctly sets the member's values. \
However, the increment is platform dependent. 

Another problematic aspect, is overlapping bit-fields:

```c
struct bf {
  unsigned int m1 : 6;
  unsigned int m2 : 4;
};
 
void function() {
  unsigned char *ptr;
  struct bf data;
  data.m1 = 0;
  data.m2 = 0;
  ptr = (unsigned char *)&data;
  ptr++;
  *ptr += 1; /* What does this increment? */
}
```

This code may split the bit fields to different bytes, or pack them together as much as possible. \
In case those aren't packed, `m2` is incremented by 1. \
However, in the packed case (assuming this platform places `m2` after `m1`), `m2` would be increased by 4!

This is because the first two LSbs of `m2` are located within the first byte. So incrementing the succeeding byte, would change the `3rd` lsb of `m2`. 

The solution should refer to `m2` explicitly. 

### EXP12-C

Do not ignore values returned by functions (similar to C++'s `nodiscard` qualifier).

### EXP13-C

C supports relational and equality operators associativity (left-assoc), which is an awful idea. 

This allows subtle bugs:

```c
int a = 2;
int b = 2;
int c = 2;
/* ... */
if (a < b < c) /* Misleading; likely bug */
/* ... */
if (a == b == c) /* Misleading; likely bug */
```

The expression `a < b < c` evaluates to true. \
Thats because `a < b => 0` (false), and `0 < 2`, returning true. 

Similary, `a == b => 1` (true) and `1 == 2`, returning false. 

### EXP14-C

Beware of integer promotions when performing bitwise operations on integer types smaller than int (even if they are unsigned!).

```c
uint8_t port = 0x5a;
uint8_t result_8 = ( ~port ) >> 4;
```

The above code evaluates to `0xfa` instead of `0x0a`, because initially `port` is promoted to `signed int32_t` (`int`), so the negation adds `0xfff...`. 

Correct bitwise operations should truncate back to the original type after every operation:

```c
uint8_t result_8 = (uint8_t) (~port) >> 4;
```

### EXP15-C

Beware of dump `;` placements.

```c
char* strchr(const char *str, int c) {
  for (; *str; ++str);   /* <<< forgot to remove semicolon */
    if ((unsigned char)*str == c)
      return str;
  return NULL;
}
```

### EXP16-C

Beware of comparing function pointers instead of function return values. 

Funny scenario:

```c
int do_xyz(void);
  
int f(void) {
/* ... */
  if (do_xyz) {
    return -1; /* Indicate failure */
  }
/* ... */
  return 0;
}
```

### EXP19-C

Beware of blocks not wrapped with `{, }`. 

```c
int login;
 
if (invalid_login())
  login = 0;
else
  printf("Login is valid\n");  /* Debugging line added here */
  login = 1;                   /* This line always gets executed
                               /* regardless of a valid login! */                       
```

Less trivial scenario may occur for nested conditions:

```c
int privileges;
 
if (invalid_login())
  if (allow_guests())
    privileges = GUEST;
else
  privileges = ADMINISTRATOR;
```

The `else` always matches to the *inner if*, meaning if the connection is invalid, AND not allowed guest, ADMIN would be granted. 

A severe, real world example, occurs when there are multiple statements on the same line:

```c
int a = 0;
int b = 0;
int c = 0;

if (a == 1)
    b = 2; c = 3;   // two statements on one line

printf("b=%d c=%d\n", b, c);
```

While clearly the developer didn't intended, this actually prints `b=0 c=3`! \
This example also holds for loops. 

### EXP20-C

Prefer explicit tests to determine expression. \
Meaning, prefer `if (foo() != 0)` over 
if (foo())``.

This is because some functions, such as `strcmp`, returns `true` (not 0) upon mismatch.

```c
LinkedList bannedUsers;
 
int is_banned(User usr) {
  int x = 0;
 
  Node cur_node = (bannedUsers->head);
 
  while (cur_node != NULL) {
    if(!strcmp((char *)cur_node->data, usr->name)) { // Should prefer explicit check, "==0"
      x++;
    }
    cur_node = cur_node->next;
  }
 
  return x;
}
 
void processRequest(User usr) {
  if(is_banned(usr) == 1) {  // Narrow check
    return;
  }
  serveResults();
}
```

In case a user is set as a banned user twice, the check would pass. \ This means the return value of `is_banned` should be check as `!= 0`. \

Another example:

```c
errno_t validateUser(User usr) {
  if(list_contains(allUsers, usr) == 0) {
    return 303; /* User not found error code */
  }
  if(list_contains(validUsers, usr) == 0) {
    return 304; /* Invalid user error code */
  }
 
  return 0;
}
 
void processRequest(User usr, Request request) {
  if(!validateUser(usr)) {
    return "invalid user";
  }
  else {
    serveResults();
  }
}
```

Mismatch logical error. \
Should check for `!= 0`. 

### EXP30-C

Do not rely on the order of evaluation between sequence points.

```c
void func(int i, int *b) {
  int a = i + b[++i];
  printf("%d, %d", a, i);
}
```

`i` is evaluated twice without an intervening sequence point. \
This results with an UB.

Because of the `++i` within the brackets, `a = (i+1) + b[i+1]` OR `a = i + b[i+1]`, depending on platform. 

Another, VERY common example:

```c
extern void func(int i, int j);
  
void f(int i) {
  func(i++, i);
}
```

On most platforms, this would evaluate `func(i, i)`. \
Only after the computation would end, it will increase `i`. \
However, it isn't guranteed - and `func(i+1, i), func(i+1, i+1)` might also be called.

```c
extern void c(int i, int j);
int glob;
  
int a(void) {
  return glob + 10;
}
 
int b(void) {
  glob = 42;
  return glob;
}
  
void func(void) {
  c(a(), b());
}
```

The order of `a(), b()` is not guranteed among different platforms.

### EXP32-C

Do not access `volatile` object throught non-volatile. \
Recall that this qualifier disables optimizations involving objects. 

```c
void func(void) {
  static volatile int **ipp;
  static int *ip;
  static volatile int i = 0;
 
  printf("i = %d.\n", i);
 
  ipp = &ip; /* May produce a warning diagnostic */
  ipp = (int**) &ip; /* Constraint violation; may produce a warning diagnostic */
  *ipp = &i; /* Valid */
  if (*ip != 0) { /* Valid */
    /* ... */
  }
}
```

The assignment `ipp = &ip` allows the bvalid code to reference the value of the `volatile` variable via non-volatile `ip`. \
The compiler may optimize the entire `if` block. 

### EXP33-C

Beware of reading uninitialized memory.

#### Classic Example

```c
void set_flag(int number, int *sign_flag) {
  if (NULL == sign_flag) {
    return;
  }
 
  if (number > 0) {
    *sign_flag = 1;
  } else if (number < 0) {
    *sign_flag = -1;
  }
}
 
int is_negative(int number) {
  int sign;
  set_flag(number, &sign);
  return sign < 0;
}
```

In case `number == 0`, the value would remain uninitialized, resulting with UB comparision. 

#### Uninitialized Pointer And Buffer

Another example:

```c
/* Get username and password from user, return -1 on error */
extern int do_auth(void);
enum { BUFFERSIZE = 24 }; 
void report_error(const char *msg) {
  const char *error_log;
  char buffer[BUFFERSIZE];
 
  sprintf(buffer, "Error: %s", error_log);
  printf("%s\n", buffer);
}
 
int main(void) {
  if (do_auth() == -1) {
    report_error("Unable to login");
  }
  return 0;
}
```

Note that both `error_log` and `buffer` are not initialized. \
Therefore, the previous stack frame content is read via `sprintf`. This data can actually be very long, and overflow `buffer`. \
Moreover, `printf` leaks the buffer uninitalized memory content. 

#### Uninitialized Struct

Another example, involving multi-byte string:

```c
void func(const char *mbs) {
  size_t len;
  mbstate_t state;
 
  len = mbrlen(mbs, strlen(mbs), &state);
}
```

The `mbrlen` function actually dereferences and reads its third argument. \
It is crucial that `memset` of 0 would be issued, prior to the function's call.

#### Reduced Entropy

Some Linux distributions actually uses uninitialized memory as a source of entropy. \
Note compilers may actually optimize out uninitialized variable access completely, removing it from the entropy calculation:

```c
void func(void) {
  struct timeval tv;
  unsigned long junk;
 
  gettimeofday(&tv, NULL);
  srandom((getpid() << 16) ^ tv.tv_sec ^ tv.tv_usec ^ junk);
}
```

This results with a loss of entropy. \
A better idea (although not perfect) is to use the CPU real-time clock instead. 

#### Realloc

```c
enum { OLD_SIZE = 10, NEW_SIZE = 20 };
  
int *resize_array(int *array, size_t count) {
  if (0 == count) {
    return 0;
  }
  
  int *ret = (int *)realloc(array, count * sizeof(int));
  if (!ret) {
    free(array);
    return 0;
  }
  
  return ret;
}
  
void func(void) {
  
  int *array = (int *)malloc(OLD_SIZE * sizeof(int));
  if (0 == array) {
    /* Handle error */
  }
  
  for (size_t i = 0; i < OLD_SIZE; ++i) {
    array[i] = i;
  }
  
  array = resize_array(array, NEW_SIZE);
  if (0 == array) {
    /* Handle error */
  }
  
  for (size_t i = 0; i < NEW_SIZE; ++i) {
    printf("%d ", array[i]);
  }
}
```

`func` contains an integer overflow for `malloc`'s parameter, allowing an under-allocation of zero-length buffer. Similar vuln occurs with `realloc`. \
Another vuln is a double-free for the `realloc`. We can wrap-around its second argument, making a `free(array)`, returning `NULL`, then `free(array)` once again.

Another problem is that `realloc` actually may leave the previous memory chunk, allocated by `malloc`, with its original content. 

The last vuln here, is that in case `realloc` allocates the secondary chunk on completely different memory, it may contain uninitialized values, not those set by `array[i] = i`. \
Even more severe - even if the memory isn't re-allocated, but continued, the last `NEW-OLD` bytes would be uninitialized.

### EXP34-C

Avoid null-dereferences.

#### libpng Vuln

```c
void func(png_structp png_ptr, int length, const void *user_data) {
  png_charp chunkdata;
  chunkdata = (png_charp)png_malloc(png_ptr, length + 1);
  /* ... */
  memcpy(chunkdata, user_data, length);
  /* ... */
 }
```

Note there is integer overflow for `png_malloc` second argument. \
This may result with a `NULL` returned, then accessed via the `memcpy`, causing null-deref. 

#### Unchecked Parameters And Retvals

```c
void f(const char *input_str) {
  size_t size = strlen(input_str) + 1;
  char *c_str = (char *)malloc(size);
  memcpy(c_str, input_str, size);
  /* ... */
  free(c_str);
  c_str = NULL;
  /* ... */
}
```

In the above example, allocation of `malloc` may fail. \
This isn't checked, and null-deref may occur. 

Another vuln occurs in case `input_str == NULL`. 

### EXP35-C

Beware of modifying objects with temporary lifetime. \
A non-lvalue expression, with `struct, union` type, that contains a member with an array type, is referred as "automatic storage duration", and *temporary* lifetime. \
The lifetime ends when the evaluation of the expression ends. \
Modifying such object results in UB.

Functions can return a pointer to an array, or `struct, union` that contains arrays. Do not access an array returned by function after the next sequence point, or full evaluation of the containing expression.

```c
struct X { char a[8]; };
 
struct X salutation(void) {
  struct X result = { "Hello" };
  return result;
}
 
struct X addressee(void) {
  struct X result = { "world" };
  return result;
}
 
int main(void) {
  printf("%s, %s!\n", salutation().a, addressee().a);
  return 0;
}
```

These functions returns a struct that contains an array, by value. \
Because there is no sequence point, this results in UB (`printf` may try to access the value returned by `address` in the previous sequence point). 

Another example:

```c
struct X { int a[6]; };
 
struct X addressee(void) {
  struct X result = { { 1, 2, 3, 4, 5, 6 } };
  return result;
}
 
int main(void) {
  printf("%x", ++(addressee().a[0]));
  return 0;
}
```

### EXP36-C

Beware of pointers conversions that are more strictly aligned, as the alignment of an object may be changed.

```c
void func(void) {
  char c = 'x';
  int *ip = (int *)&c; /* This can lose information */
  char *cp = (char *)ip;
 
  /* Will fail on some conforming implementations */
  assert(cp == &c);
}
```

This code casts `char` to a strictly aligned `int *ip`. Some implementations would actually advance the value of `ip`, so it would be aligned. \
Therefore, `cp != &c`. \
A possible solution is to use an intermediate object, such as `int i = c; ip = &i;`.

Another example:

```c
int *loop_function(void *v_pointer) {
  /* ... */
  return v_pointer;
}
  
void func(char *char_ptr) {
  int *int_ptr = loop_function(char_ptr);
 
  /* ... */
}
```

This code actually returns a `int *` out of `void *`. \
Because it is more strictly aligned than an object of type `char *`, small pointer modifications may occur. 

Similar example:

```c
struct foo_header {
  int len;
  /* ... */
};
  
void func(char *data, size_t offset) {
  struct foo_header *tmp;
  struct foo_header header;
 
  tmp = (struct foo_header *)(data + offset);
  memcpy(&header, tmp, sizeof(header));
 
  /* ... */
}
```

Assigning unaligned value to a pointer that references a type that needs to be aligned is UB. \
A compiler may use an inline `memcpy` that assumes aligned data, which would result with UB. 

### EXP39-C




[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
