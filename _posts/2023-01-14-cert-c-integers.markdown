---
layout: post
title:  "CERT C - Chapter 4 - Integers"
date:   2023-01-14 19:59:43 +0300
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

## Evaluation Order Errors

It is pretty common paradigm to use the `++` operator. \
However, it might be pretty risky, as surprising behavior might occur.

For example:

```c
void my_func(int a, int b){
    printf("a=%d b=%d\n",a , b);
}

int a = 1, b = 1;
my_func(a++, b++);
```

The reader might be surprised to see that `a=1 b=1` would be printed, instead of `a=2 b=2`. 

This is because aftermost `++` operator is evaluated only AFTER the expression evaluation have completed. 

A straightforward operator is the preceding `++` operator, for example `++a`. \
It first increments the integer number, and only then evaluates the whole expression. 

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

#### Index Type Mismatch

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

According to CERT, there is an OOB-write, for cases where `n >= INT_MAX`. 

Note the comparison `i < n`. \
Because this is signed and unsigned `int` operands, the compiler promotes this comparision to an unsigned compare. 

This means that after `i = INT_MAX` is increased once again, it wraps around to `INT_MIN`, which is evaluated as `INT_MAX + 1`, since this is an unsigned comparision. \
However, note that `i` is declared as a signed int. Thefore - there is an under-access for `p`, resulting within an OOB write!

It is important to note such cases, where comparing between integers of different types. 

A subtle point we should consider, is the integer type size. \
For cases where the underlying types cannot be promoted to `int, unsigned int` (or themselves being `int, uint`), the following code *stops*:

```c
unsigned int max = INT_MAX + 1;

int main()
{
signed int i = 0;

for (i = 0 ; i < max ; ++i)
{
    printf("i=0x%08x max=0x%08x\n", i, max);
}

return 0;
}
```

This means that `signed int i` have successfully "reached" the unsigned value of `INT_MAX + 1`! \
As explained, this is because of the comparision being an unsigned comparision, so `i` is treated as an `unsigned int`. 

However, we should recall that for smaller types, the comparision may promote integers to be `signed int`, even if one of the operands is of an `unsigned` type:

```c
unsigned char max = CHAR_MAX + 1;

int main()
{
signed char i = 0;

for (i = 0 ; i < max ; ++i)
{
    printf("i=0x%08x max=0x%08x\n", i, max);
}

return 0;
}
```

The above code does NOT stop, resulting with an infinite loop - unlike the `int` case!

The reason behind this is integer promotions. \
In order to perform the arithmetic operator `<`, both `i, max` are being promoted to `int` - as it can fully represent their range. 

This results with a *signed comparision*, where `max == 0x00000080`, and `i` wraps around after it reaches `CHAR_MAX`: \
`0x0000007f -> 0xffffff80`, so the loop continues. 

Not a trivial behavior at all. 

#### Implicit Truncation

The following code isn't a trivial vuln either:

```c
void *alloc(unsigned int blocksize) {
  return malloc(blocksize);
}
 
int read_counted_string(int fd) {
  unsigned long length;
  unsigned char *data;
 
  if (read_integer_from_network(fd, &length) < 0) {
    return -1;
  }
 
  data = (unsigned char*)alloc(length);
  if (data == NULL) {
    return -1;  /* Indicate failure */
  }
 
  if (read_network_data(fd, data, length) < 0) {
    free(data);
    return -1;
  }
  data[length-1] = '\0';
 
  /* ... */
  free( data);
  return 0;
}
```

Assuming `unsigned long length` is of 8 bytes, the `read_integer_from_network` has a wrong check - as an error occurs in case the amount of read bytes are `< 8`, not only a wrong return value of `< 0`. 

There is also implicit assumption that `sizeof(size_t) == sizeof(unsigned int) == sizeof(unsigned long)`, which is usually correct tho. \
For platforms that satify `sizeof(long) > sizeof(int)`, `length` would be truncated. 

Also, `read_network_data` doesn't check if the return value is `< length`, but only `< 0`. 

Lastly, `data[length-1] = '\0'` overwrites the last read byte (in case `length` bytes were read). 

Note that in case `length == 0`, `alloc` would allocate a zero-length buffer, `read_network_data` won't read anything, and the `\0` assignment would cause OOB-write. 

### INT02-C

#### Integer Promotions

When an operation is performed on integer types that are smaller than `int`, they are promoted. 

If all values of the original type can be represented as an `int`, it will be converted to an `int`. Otherwise - to an `unsigned int`. 

These promotions are applied for function arguments, and operators of `+, -, *, /, ~, <<, >>`.

For example:

```c
char c1, c2;
c1 = c1 + c2;
```

The type of `c1 + c2` is promoted to an `int`, and than truncated back to a `char`. 

Thanks to these promotions, correctness is preserved, even in presence of intermediate values overflows:

```c
signed char cresult, c1, c2, c3;
c1 = 100;
c2 = 3;
c3 = 4;
cresult = c1 * c2 / c3;
```

#### Integer Comparision

A funny example:

```c
int si = -1;
unsigned int ui = 1;
printf("%d\n", si < ui);
```

The above code snippet prints a "0", meaning `false`!

That is because the comparision is promoted to unsigned comparision - `si` is evaluated as `0xffffffff`, while `ui == 0x00000001`. 


#### Small Integers Bitwise Operations

Another cool example caused by performing bitwise operations, on small integer values. 

Note that the bug resides eventho these are `unsigned` integers!

```c
uint8_t port = 0x5a;
uint8_t result_8 = ( ~port ) >> 4;
```

We would expect the result of `0x0a`, in case these operations are performed only on 8-bit integers. 

However, `~port` is implicitly converted to an integer, hence the negation adds 6 '1's within its MSbs. 

The result: `result_8 == 0xfa`!

A possible solution is to explicitly trunc the negated value:

```c
uint8_t result_8 = (uint8_t) (~port) >> 4;
```

#### Wacky Promotions

```c
unsigned short x = 45000, y = 50000;
unsigned int z = x * y;
```

The bug raises on platforms where shorts are 2 bytes, and ints are 4 bytes.

Since each of the `unsigned shorts` may be represented by an `int`, they are promoted into a signed `int`. 

The result cannot be represented within the signed integer range, so an overflow occurs - leading to undefined behavior, meaning the result may differ on every platform. 

More of this issue can be found [here][wacky-promotion].

### INT04-C

#### Heartbleed

```c
int dtls1_process_heartbeat(SSL *s) {         
  unsigned char *p = &s->s3->rrec.data[0], *pl;
  unsigned short hbtype;
  unsigned int payload;
  unsigned int padding = 16; /* Use minimum padding */
 
  /* Read type and payload length first */
  hbtype = *p++;
  n2s(p, payload);
  pl = p;
 
  /* ... More code ... */
 
  if (hbtype == TLS1_HB_REQUEST) {
    unsigned char *buffer, *bp;
    int r;
 
    /* Allocate memory for the response, size is 1 byte
     * message type, plus 2 bytes payload length, plus
     * payload, plus padding
     */
    buffer = OPENSSL_malloc(1 + 2 + payload + padding);
    bp = buffer;
 
    /* Enter response type, length and copy payload */
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload, bp);
    memcpy(bp, pl, payload);
 
    /* ... More code ... */
  }
  /* ... More code ... */
}
```

The vulnerability is a classic integer overflow, that leads to `OPENSSL_malloc` under-allocation, hence heap overflow.

### INT09-C

Becareful of enums redefinition.

Enum values are assigned with an initial value (0 if un-specified), and increment by one for each new element.

Therefore, the following enum definition causes duplication:

```c
enum Color { red=4, orange, yellow, green, blue, indigo=6, violet };
 
const char* color_name(enum Color col) {
  switch (col) {
  case red: return "red";
  case orange: return "orange";
  case yellow: return "yellow";
  case green: return "green";
  case blue: return "blue";
  case indigo: return "indigo";   /* Error: duplicate label (yellow) */
  case violet: return "violet";   /* Error: duplicate label (green) */
  }
}
```

### INT10-C

Surprisingly, the `%` operator may yield negative values. 

Therefore, the following code contains OOB-write:

```c
int insert(int index, int *list, int size, int value) {
  if (size != 0) {
    index = (index + 1) % size;
    list[index] = value;
    return index;
  }
  else {
    return -1;
  }
}
```

### INT12-C

It is possible to define plain int bit-fields:

```c
struct {
  int a: 8;
} bits = {255};
```

This issue resembles the signess problem of plain `char`. \
It is up to the implementation to derive whether this integer is `signed int` or an `unsigned int`. 

Therefore, the following code may print either `-1 OR +255`, depending on the platform:

```c
int main(void) {
  printf("bits.a = %d.\n", bits.a);
  return 0;
}
```

A better practice is to explicitly state the signess of the bitfield integer.


### INT13-C

Bitwise operators should ONLY be used on unsigned operands. 

That is because signed operands may trigger arithmetic operations - sign extension of 1's for negative values, violating correctness.

For example:

```c
int rc = 0;
int stringify = 0x80000000;
char buf[sizeof("256")];
rc = snprintf(buf, sizeof(buf), "%u", stringify >> 24);
if (rc == -1 || rc >= sizeof(buf)) {
  /* Handle error */
}
```

The problem with this code is `stringify >> 24`: because this is a signed integer, the shift operation is arithmetic, meaning the MSB of `1` propagates, meaning the expression evaluates to `0xffffff80`.

It means that the resulting string, "4294967168", would be larger than `buf`, and truncation would occur. 


### INT14-C

bit manipulations and arithmetic manipulations shouldn't be performed on the same variable. 

```c
unsigned int x = 50;
x += (x << 2) + 1;
```

While it is still correct for `unsigned int`, in the general integer type case - the behavior is implementation defined. 

### INT16-C

*Signed integers* representation (two's, one's complement) is implementation defined.

This means the following code won't work correctly for all one's comp. implementations:

```c
int value = ...;
if (value & 0x1 != 0) {
    /* Take action if value is odd */
  }
```

A correct way is to use the `%` operator, or to just use the bitwise operators on an `unsigned integers`. 

### INT18-C

In case of comparision to larger size integer, the smaller size operand should be explicitly casted to the larger size.

#### Classic Integer Overflow

For example, on archs where `size_t, int` are 32-bit, and `long long` is 64-bit:

```c
enum { BLOCK_HEADER_SIZE = 16 };
 
void *AllocateBlock(size_t length) {
  struct memBlock *mBlock;
 
  if (length + BLOCK_HEADER_SIZE > (unsigned long long)SIZE_MAX)
    return NULL;
  mBlock = (struct memBlock *)malloc(
    length + BLOCK_HEADER_SIZE
  );
  if (!mBlock) { return NULL; }
  /* Fill in block header and return data portion */
 
  return mBlock;
}
```

Since `type(length) = size_t`, and `type(BLOCK_HEADER_SIZE) = int`, their addition is an `unsigned int`, 32 bit. 

The result is comparted to 64-bit `unsigned long long`. 

Therefore, an overflow may occur within the 32-bit result, so the check would pass, and `malloc` would perform under-allocation.

A possible fix:

```c
if ((unsigned long long)length + BLOCK_HEADER_SIZE > SIZE_MAX) {
    return NULL;
  }
```

So by promoting `length` to 64-bit value, we eliminate the possibility of overflow. 

#### Larger Type Integer Overflow

Another, very cool vuln. \
I find this very surprising, as this code produces no compilation warnings at all, even under `-Wall`:

```c
void *AllocBlocks(size_t cBlocks) {
  if (cBlocks == 0) { return NULL; }
  unsigned long long alloc = cBlocks * 16;
  return (alloc < UINT_MAX) ? malloc(cBlocks * 16) : NULL;
}
```

For archs where sizes of `size_t, unsigned long long` are both 8 bytes, there is a clear integer overflow under the multiplication. 

The major surprising problem is for archs where `size_t` is 4 bytes. \
`cBlocks * 16` may overflow. In such case, `alloc` would contain the *overflowed 32-bit value, NOT the correct 64-bit value!*

A possible solution is to add an explicit cast of `(unsigned long long)cBlocks` during multiplication. 

#### size_t Signed Comparision

```c
void func(wchar_t *pwcs, const char *restrict s, size_t n) {
  size_t count_modified = mbstowcs(pwcs, s, n);
  if (count_modified == -1) {
    /* Handle error */
  }
}
```

The evaluation of negative number comparision depends on `size_t` implementation. \
A better paradigm is to explicitly cast `(size_t)-1`. 

#### Signed Integer Conversion Overflow

The following code is tricky:

```c
uint64_t i = 1 << 31;
printf("0x%llx", i);
```

Because the `1` literal implicitly treated as a signed integer, aka `int`, `1<<31` evaluates to `int` too. 

However, bitwise operations are risky to perform on signed integers, due to the two's complement arithmetics. 

`1 << 31 == 0x8000000 == MIN_INT`, as its MSb is 1. \
In order to store this value within an 64-bit variable, a sign-extension is performed, thus filling the leftmost 32 bits with 1's. \
This sign-extended number, which has the same (signed) value of `MIN_INT`, is stored as an `uint64_t`. 

Therefore, the surprising string `0xffffffff80000000` is printed!

The root cause of this mayhem is performing bitwise operations on a signed integer. \
This case is particular risky, as literal numbers have implicit type of `int` by default. 

An elegant fix is possible via explicit `unsigned int, uint64_t` type casting, or by using `1U` literal. 


#### C Is Completely Wrecked

As a *completely wrecked example, that does not triggers any compilation warnings*, I've added a small twick to the above snippet:

```c
uint64_t i = (uint8_t)1 << 31;
printf("0x%llx", i);
```

Both right expression and left expression are `unsigned` types. \
However, even in this case - a bug occurs, and `0xffffffff80000000` is printed!

But how?

Recall integer types promotions. \
Upon issuing binary operators, such as shifts - the compiler would promote small types up to `int` (if they can reside within its range) or `unsigned int` if they couldn't. \
It can *ONLY promote types up to these sizes*, no more (`long long`, for example).

This means that `(uint8_t)1 << 31` is promoted to `int` type, as it is representable by 4 bytes. \
Note this promotion actually makes a lose of the "unsigness" - hence treating the MSb as the one of `signed int`. \
Like before, that results with a sign extension of 1's, because this is a signed type - and we get the error.

Note this bug does not occur for casts of `unsigned int, uint64_t` - because there is no implicit `int` promotion. 

Amazing. \
Thats exactly why I love C so much!


[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[wacky-promotion]: https://cryptoservices.github.io/fde/2018/11/30/undefined-behavior.html
