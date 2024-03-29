---
layout: post
title:  "CERT C - Chapter 5 - Floating Point"
date:   2023-01-21 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

The common vulnerabilities are described within CERT-C chapter 5 (floating point):
[cert-c][cert-c]. 

All of the C vulnerabilities are described within [CWE][cwe-c].

## CERT C Examples

### FLP00-C

Floating point numbers has its own  limitations, described by the `IEEE 754` standard. 

It is prone to errors associated with rounding. 

For example:

```c
int main(void) {
  float f = 1.0f / 3.0f;
  printf("Float is %.50f\n", f);
  return 0;
}
```

The precision should be 50 decimal places. \
However, for 64-bit Linux, GCC, the printed value is `0.33333334326744079589843750000000000000000000000000 != 1/3`

For Windows, the precision is even worse. 

Even worse - comparisions may fail, depending on the compiler optimization level:

```c
double a = 3.0;
double b = 7.0;
double c = a / b;
 
if (c == a / b) {
  printf("Comparison succeeds\n");
} else {
  printf("Unexpected result\n");
}
```

For GCC with `-O1` or highter, the comparision succeeds. \
However, with optimizations turned off, this code prints `Unexpected result`.

The reason is that Linux uses an internal extended precision mode, of the x87 FPU on IA-32 machines, to achieve increased accuracy. \
When the result is stored within c, the FPU automatically rounds the result to fit into a `double`. \
Then, the value read back from the stack memory, `c`, is now compared unequally to the internal FPU representation - which has extended precision. 

The highter compiler optimizations eliminates the need to store `c` within the memory, so all computation happens within the FPU, as extended precision. 

A possible solution is to check that the difference between two floats, is lower than `__FLT_EPSILON__`. 


### FLP01-C

Rearranging floating point expressions is dangerous. 

Because of roundoff error, the regular associative rules do not apply. 

```c
double x, y, z;
/* ... */
x = (x * y) * z; /* not equivalent to x *= y * z; */
z = (x - y) + y ; /* not equivalent to z = x; */
z = x + x * y; /* not equivalent to z = x * (1.0 + y); */
y = x / 5.0; /* not equivalent to y = x * 0.2; */
```

### FLP02-C

Avoid floating point operations when precise computation is needed.

Vuln example:

```c
/* Returns the mean value of the array */
float mean(float array[], int size) {
  float total = 0.0;
  size_t i;
  for (i = 0; i < size; i++) {
    total += array[i];
    printf("array[%zu] = %f and total is %f\n", i, array[i], total);
  }
  if (size != 0)
    return total / size;
  else
    return 0.0;
}
 
enum { array_size = 10 };
float array_value = 10.1;
 
int main(void) {
  float array[array_size];
  float avg;
  size_t i;
  for (i = 0; i < array_size; i++) {
    array[i] = array_value;
  }
 
  avg = mean( array, array_size);
  printf("mean is %f\n", avg);
  if (avg == array[0]) {
    printf("array[0] is the mean\n");
  } else {
    printf("array[0] is not the mean\n");
  }
  return 0;
}
```

Because of imprecision of floating point arithmetics, the computed mean does not match. 

Prefer using integers as much as possible, and cast to a `float` in case of a division.

### FLP03-C

Floating point division by zero results in UB, while most implementations do not treat it as a terminal error - meaning only a silent error (as opposed to integers division).

The correct way to determine if a FP exception has occured is to use the `fenv.h` library. 

```c
void fpOper_noErrorChecking(void) {
  /* ... */
  double a = 1e-40, b, c = 0.1;
  float x = 0, y;
  /* Inexact and underflows */
  y = a;
  /* Divide-by-zero operation */
  b = y / x;
  /* Inexact (loss of precision) */
  c = sin(30) * a;
  /* ... */
}
```

Within the above code, FP operations are performed without any errors checking. 

A compliant solution uses the following methodology:

```c
int fpeRaised;
  /* ... */
 
  feclearexcept(FE_ALL_EXCEPT);
  /* Store a into y is inexact and underflows: */
  y = a;
  fpeRaised = fetestexcept(FE_ALL_EXCEPT);
  /* fpeRaised has FE_INEXACT and FE_UNDERFLOW */
 
  feclearexcept(FE_ALL_EXCEPT);
 
  /* Divide-by-zero operation */
  b = y / x;
  fpeRaised = fetestexcept(FE_ALL_EXCEPT);
  /* fpeRaised has FE_DIVBYZERO */
 
  feclearexcept(FE_ALL_EXCEPT);
 
  c = sin(30) * a;
  fpeRaised = fetestexcept(FE_ALL_EXCEPT);
  /* fpeRaised has FE_INEXACT */
 
  feclearexcept(FE_ALL_EXCEPT);
```

The Windows equivalent for this, is via `_clearfp()` call. \
Another option is the SEH, which may handle floating point exceptions too. 

### FLP04-C

FPs can take two classes of exceptional values: `infinity, NaN`. 

Moreover, the expression `Nan == Nan` evaluates to `false`, as any comparision with `NaN` returns false!

Formatted input functions, such as `scanf`, accepts the values of `INF, INFINITY, NAN` as valid inputs, for the `%f` specifier. 

`math.h` provides `isinf, isnan` to detect these special cases. 

```c
float currentBalance; /* User's cash balance */
void doDeposit() {
  float val;
 
  scanf("%f", &val);
 
  if(val >= MAX_VALUE - currentBalance) {
    /* Handle range error */
  }
 
  currentBalance += val;
}
```

Since `val` can have the value of `INF, NAN` - all calculations using these values would be invalid, crashing the program and enabling DoS. 

In this case, `val == nan -> currentBalance == nan`, possibly destroying other data.

This wacky rule have some surprising implications. 
For example, inspect the following code:

```c
float a = 1.0 / 0.0; // inf
float b = 0.0 / 0.0; // -nan
float c = -0.0 / 0.0;// -nan
float d = -b;        // nan 

if (b != b)
{
  printf("OMG, how?\n");  // executed
}
```

Moreover, according to IEEE-754 floating point encoding, we may actually forge a `INF, NAN` (both silent + exception triggering versions) out of an integer representation. 

We just have to set the bits carefully, according to the [specs][ieee-754]:

```c
bool is_authorized(float *a, float *b)
{
    if (*a != *b)
    {
        return true;
    }

    return false;
}

uint32_t dec = 0x7fC00000; // Encodes to non-silent NAN

if (is_authorized(&dec, &dec))
{
  printf("WTF? how did you do this?\n"); 
}
```

Very cool, and not trivial at all. 

### FLP05-C

Beware of denormalized numbers.

For IEEE-754 (the common FP standard), floats are encoded by 1 sign bit, 8 exponent bits, and 23 mantissa bits. 

doubles are encoded by 1 sign bit, 11 exponent bits, and 52 mantissa bits.

Their calculation: `(-1)^S * M * 2^E`. \ 
The leading 1 is implied, and left out. \
These numbers are called *normalized numbers*. 

Using mantissa bits extends the possible range of exponents. \
Because these bits no longer serve bits of precision, but as part of the exponent, the total precision of extremely small numbers is less than usual - also referred as *denormalized numbers*

```c
float x = 1/3.0;
printf("Original    : %e\n", x); // 3.333333e-01
x = x * 7e-45;
printf("Denormalized: %e\n", x); // 2.802597e-45
x = x / 7e-45;
printf("Restored    : %e\n", x); // 4.003710e-01
```

### FLP07-C

Cast the return value of a function that returns a floating point type. 

The representation of floating point values may have wider range or precision than implied by the return type. \
A cast may be used to remove this extra range and precision. 

```c
float f(float x) {
  return x * 0.1f;
}
 
float g(float x) {
  return x * 0.1;
}
```

`0.1` is interpreted as a literal `double`, while `0.1f` interpreted as literal `float`. 

This means `f()` may return a value wider than `float` (as the representation may have wider range / precision than implied by the type), but `g()` is not (as it is implicitly converted to a `float`). 

```c
float calc_percentage(float value) {
  return value * 0.1f;
}
 
void float_routine(void) {
  float value = 99.0f;
  long double percentage;
 
  percentage = calc_percentage(value);
}
```

In this example, the literal constant `0.1f` may be stored within a range / precision that is greated than that of `float`. 

Therefore, the result `value * 0.1f` may also have a wider range or precision, greater than that of `float`. 

As a result, `calc_percentage` may return a value that is more precise than expected, and may lead to inconsistency execution. 

A correct solution is to cast the return expression:

```c
return (float)(value * 0.1f);
``` 

Which forces the expected precision. 

A good paradigm is to perform a cast for every return expression, in order to remove the extra range and precision. 

### FLP30-C

Beware of using floats as loop counters. \
To gain a large dynamic range, floats maintain fixed number of precision bits (mantissa) and exp, which limits the number of significant digits represented. 

For example, because of inaccurate representation of `0.1f` (which requires infinite mantissa size), the following loop may be evaluated only 9 times:

```c
void func(void) {
  for (float x = 0.1f; x <= 1.0f; x += 0.1f) {
    /* Loop may iterate 9 or 10 times */
  }
}
```

In case the `<=` operator would be switched to exact comparision, `!=`, the above would result with an infinite loop.

Another example occurs for large floating point numbers, where the increment amount is too small to change its value, given its precision:

```c
void func(void) {
  for (float x = 100000001.0f; x <= 100000010.0f; x += 1.0f) {
    /* Loop may not terminate */
  }
}
```

### FLP32-C

It is a good paradigm to prevent input range errors, in functions like `sqrt, pow, sin, log` from the `math.h` library.

For example, the following code may result with an UB in case of a negative `x`:

```c
void func(double x) {
  double result;
  result = sqrt(x);
}
```

Another example, is a range error, that might occur for an extremely large magnitude:

```c
void func(double x) {
  double result;
  result = sinh(x);
}
```

Moreover, another domain error, this time caused by negative `x` + non-integer `y`, or both `x==0, y==0`:

```c
void func(double x, double y) {
  double result;
  result = pow(x, y);
}
```

Note that the result may not be representable as a `double`.

### FLP34-C

Beware of floats conversions, and smaller precision in particular. 

When a `float` is converted to an integer type, the fractional part is truncated toward zero. 

When a value of integer type is converted to `float`, if the value can be represented exactly as a `float`, it is unchanged. \
However, if it is in a range of representable numbers, but not representable, the result is the nearest higher / lower (platform dependent) `float`. \
If the value is outside of the representable range, UB. \
These rules also apply to `float` and `double` conversions. 

Note that on platforms following IEEE 754, signed `INF` is supported, so any value is always representable. 

For example:

```c
void func(double d_a, long double big_d) {
  double d_b = (float)big_d;
  float f_a = (float)d_a;
  float f_b = (float)big_d;
}
```

This may cause truncated values, that are outside of the range of the destination types. 


### FLP36-C

Conversions from int to floats can lead to loss of precision. 

This is because the maximum number represented by a float is:
`1.99999 * M`, where the mantissa have a maximal value of `2^21` for 32-bit `floats`, or `2^52` for `double`.

For example, the following yields inaccurate result:

```c
int main(void) {
  long int big = 1234567890L;
  float approx = big;
  printf("%ld\n", (big - (long int)approx));
  return 0;
}
```

Note that even for an `int32_t`, which has the exact size of `float`, for large numbers loss of precision occurs.

### FLP37-C

Unlike integers, the equivalence of floating point values *is not encoded solely by the bit pattern used to represent the value*. \
For example, the values of `-0.0` and `0.0` are encoded differently, but will compare as equivalent. 

Similary, two `NAN` floating point values will not compare as equal, despite the bit patterns being identical. 

While comparing with `!=, ==` operation may yield surprising results, it is preferred over stuff such as `memcmp` (but generally `<=` operators are better, yet still in-accurate). 


[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[ieee-754]: https://en.wikipedia.org/wiki/NaN
