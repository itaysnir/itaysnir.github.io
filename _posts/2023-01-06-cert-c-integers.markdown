---
layout: post
title:  "CERT C - Integers"
date:   2023-01-06 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

Their common vulnerabilities are described within CERT-C chapter 4 (integers):
[cert-c][cert-c]. 

All of the C vulnerabilities are described within [CWE][cwe-c].

## Real Wraps-Around Vulns

### Solar 2000 JPEG Parser

```c
void getComment(size_t len, char *src) {
 size_t size;
 size = len - 2;
 char *comment = (char *)malloc(size + 1);
 memcpy(comment, src, size);
return;
}
```

Since there is no sanitization at all, in case `len < 2`, `size` wraps around - and represents a very large number. 

For example, for `len == 1`, we would get `size = (unsigned int)0xffffffff`.

Again, there is no sanitization prior to the `malloc` call - meaning `malloc(size + 1)` wraps around again - to `malloc(0)` (which, for most of the implementations, does NOT return a `NULL` ptr). 

This means `memcpy` causes a simple heap overflow. 

### RUS-CERT Advisory 2002-08:02

The following pattern is a common vulnerability:

```c
p = calloc(sizeof(element_t), count);
```

Most implementations of `calloc` doesn't check if the multiplication of its arguments wraps around. \
This leads to an under-allocation, hence heap-overflow. 

### NetBSD Advisory 2000-002

```c
if (off > len - sizeof(type-name)) goto error;
```

This one is very cool: the `sizeof` operator returns a `size_t` type. 

Therefore, the experession `len - sizeof(..)` is *promoted to an unsigned integer*! 

This is not trivial at all, as we would probably assume the C standard conversion rules wouldn't automatically promote to `unsigned integer` in case of a substraction, involving an integer. \
But it does. 

It means that instead of some low negative value, the right expression evaluates to some large unsigned integer value - and the check passes. 

## Conversion Errors

Classic example, involving implicit cast:

```c
void initialize_array(int size) {
 if (size < MAX_ARRAY_SIZE) {
 array = malloc(size);
 /* initialize array */
} 
 else {
 /* handle error */
}
 }
```

For whatever bad reason, `size` is declared as an `int`. 

However, `malloc` treats its argument as a `size_t`, aka unsigned int - causing an "arbitrary long" allocation. 

## Truncation Errors

```c
int main(int argc, char *argv[]) {
 unsigned short int total;
 total = strlen(argv[1]) + strlen(argv[2]) + 1;
 char *buff = (char *)malloc(total);
 strcpy(buff, argv[1]);
 strcat(buff, argv[2]);
 /* ... */
}
```

In case the sum of the lengths exceeds `uint16_t`, a truncation occurs. \
It means `malloc` would result with an under-allocation, hence heap overflow. 

## Logic Errors

```c
int *table = NULL;
int insert_in_table(int pos, int value) {
if (!table) {
 table = (int *)malloc(sizeof(int) * 100);
}
if (pos > 99) {
 return -1;
}
table[pos] = value;
return 0;
}
```

`pos` is declared as an `int` - meaning it can have some low, negative values. 

Since there is no lower-bounds checking, an OOB write may occur, for negative `pos` values.

## CERT C Examples

### INT31-C

#### time()

The `time()` function returns `time_t`. \
The C standard requires this struct is a typedef to some *real type*, capable to represent time (`unsigned int, float, int, ...`). 

It is up to the implementor to decide the underlying type. 

This means, that the following code won't work for underlying type `unsigned int`:

```c
time_t now = time(NULL);
if (now != -1)
{
  /* continue */
}
```

A possible solution is to perform cast: `(time_t)-1`. 

#### memset()

Some C standard functinos accept arguments of type `int`, and implicitly converts it to `unsigned char OR char`. 

For example:

```c
memset(array, 4096, n);
```

In this case, 4096 is truncated to a single byte - meaning all array elements are set to 0. 

This means that the following code is vulnerable to implicit truncation, eventho the compiler won't issue any warning about this! (as this is correct `memset` signature):

```c
set_val(char* array, size_t len, int val)
{
  memset(array, val, len);
}

int main()
{
  char buffer[20] = {0};
  int val = 0;
  scanf("%d\n", &val);
  set_val(buffer, val, sizeof(buffer));
}
```

### INT32-C

#### Division Overflow

I find it pretty cool to overflow over a division, as it isn't that trivial. 

The following example contains such possible overflow:

```c
void func(signed long s_a, signed long s_b) {
  signed long result;
  if (s_b == 0) {
    /* Handle error */
  } else {
    result = s_a / s_b;
  }
  /* ... */
}
```

`s_b` is correctly sanitized, to prevent any zero-division error. 

However, recall the signed integer ranges, for example `int8_t -> [-128, +127]`. 

This means the maximal value of `s_a / s_b` in such case, is `-128 / -1 = +128`, which is out of the representation range - and therefore interpreted as `-128`!

Therefore, in the above example, the code is vulnerable to the particular case where `s_a == LONG_MIN, s_b == -1`, in which the result would be `LONG_MIN` (NEGATIVE value!)

Not trivial, and very cool vuln. 

#### Remainder

Most platforms implement the remainder operation along with the division operation in the same instruction.

Therefore, it is also susceptible to arithmetic overflow and division by zero. 

Meaning a similar vuln to the above exists here too:

```c
signed long result;
  if (s_b == 0) {
    /* Handle error */
  } else {
    result = s_a % s_b;
  }
```

Moreover, the `%` operator have some unexpected behavior - as it may return negative values!

For example, `-11 % 5 == -1`, and not 4!

Surprisingly, `11 % -5 == 1` - the negative modulu is discarded. 

Finally, `-11 % -5 == -1`, as in the first example. 


#### Shifts

Shifting by a negative number, or by more bits that exist within the operand - means a logic error.

The following code checks for both precision and negative shift count:

```c
#include <limits.h>
#include <stddef.h>
#include <inttypes.h>
  
extern size_t popcount(uintmax_t);
#define PRECISION(umax_value) popcount(umax_value)
 
void func(signed long si_a, signed long si_b) {
  signed long result;
  if ((si_a < 0) || (si_b < 0) ||
      (si_b >= PRECISION(ULONG_MAX)) {
    /* Handle error */
  } else {
    result = si_a << si_b;
  }
  /* ... */
}
```

However, it misses a check for an overflow:
`si_a > (LONG_MAX >> si_b)`.

#### Unary Negation

Resembles the division overflow. 

In case the operand equals to the minimum negative value of a signed integer type, an overflow occurs:

```c
void func(signed long s_a) {
  signed long result = -s_a;
  /* ... */
}
```

As `-(LONG_MIN) == LONG_MAX + 1`, which is out of the representation range. 

### INT01-C

The following code have some non trivial vuln:

```c
char *copy(size_t n, const char *c_str) {
  int i;
  char *p;
 
  if (n == 0) {
    /* Handle unreasonable object size error */
  }
  p = (char *)malloc(n);
  if (p == NULL) {
    return NULL; /* Indicate malloc failure */
  }
  for ( i = 0; i < n; ++i ) {
    p[i] = *c_str++;
  }
  return p;
}
```

This is a very common practice to declare an index within a for loop as a `signed int`, regardless of its actual meaning (index, in this case).

According to CERT, there is an overflow here, for cases where `n > INT_MAX`. \
However, it isn't exactly accurate. 

Note the comparison `i < n`. \
Because this is signed and unsigned comparsion, the compiler usually treats this as a signed (as opposed to arithmetics, where usually signed integers are promoted). 

This means that after `i = INT_MAX` is increased once again, it wraps around to `INT_MIN`, and the signed comparision succeeds - resulting withn an infinite loop!

It is important to note such cases, where comparing between integers of different types. 



[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
