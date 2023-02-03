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

Their common vulnerabilities are described within CERT-C chapter 5 (floating point):
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
Because these bits no longer serve bits of precision, the total precision of extremely small numbers is less than usual - also referred as *denormalized numbers*

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




[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[ieee-754]: https://en.wikipedia.org/wiki/NaN
