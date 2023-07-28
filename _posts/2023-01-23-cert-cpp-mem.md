---
layout: post
title:  "CERT C++ - Chapter 3 - Memory"
date:   2023-01-23 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

The common vulnerabilities are described within CERT-C++ chapter 6 (memory):
[cert-cpp][cert-cpp]. 

All of the C vulnerabilities are described within [CWE][cwe-c].

## CERT C++ Examples

### MEM50-CPP

Beware of UAFs.

#### Dump Example

```cpp
struct S {
  void f();
};
  
void g() noexcept(false) {
  S *s = new S;
  // ...
  delete s;
  // ...
  s->f();
}
```

`s->f()` is accessed after releasing the object. UAF. \
Note that `g` is denoted as `noexcept(false)`, meaning explicitly it can throw in case of an allocation exception. 

#### std::unique_ptr

```cpp
int main(int argc, const char *argv[]) {
  const char *s = "";
  if (argc > 1) {
    enum { BufferSize = 32 };
    try {
      std::unique_ptr<char[]> buff(new char[BufferSize]);
      std::memset(buff.get(), 0, BufferSize);
      // ...
      s = std::strncpy(buff.get(), argv[1], BufferSize - 1);
    } catch (std::bad_alloc &) {
      // Handle error
    }
  }
 
  std::cout << s << std::endl;
}
```

This vuln here isn't trivial. The string buffer is correctly copied, as well as null-terminated. 

Note `s = std::strncpy()`. The retval if a `const char*`, pointing towards the destination buffer, meaning `buff.get()`. \
Once exiting the `try` block, the smart pointer's dtor would kick in, de-allocating the buffer. \
This means the last line, reading `s` content, is actually performing an UAF-read.

We may declare this smart ptr in the outer scope:

```cpp
int main(int argc, const char *argv[]) {
  std::unique_ptr<char[]> buff;
  const char *s = "";
 
  if (argc > 1) {
    enum { BufferSize = 32 };
    try {
      buff.reset(new char[BufferSize]);
      std::memset(buff.get(), 0, BufferSize);
      // ...
      s = std::strncpy(buff.get(), argv[1], BufferSize - 1);
    } catch (std::bad_alloc &) {
      // Handle error
    }
  }
 
  std::cout << s << std::endl;
```

Note that in this case, we have to use `std::unique_ptr::reset` to replace the managed object (which was previously uninitialized). 

#### std::string::c_str

```cpp
std::string str_func();
void display_string(const char *);
  
void f() {
  const char *str = str_func().c_str();
  display_string(str);  /* Undefined behavior */
}
```

Because the returned `std::string` is a managed object, it gets destructed after the assignment line. \
This is because `c_str` is *being called on a temporary string object*! At the end of the assignment, this string would be destroyed, yields in UB when accessing it for display.

#### Zero Allocation

```cpp
void f() noexcept(false) {
  unsigned char *ptr = static_cast<unsigned char *>(::operator new(0));
  *ptr = 0;
  // ...
  ::operator delete(ptr);
}
```

Writing to such pointer, that returned from a zero-length allocation, is UB (some implementations may even point it right towards the next chunk).

### MEM51-CPP

Make sure to deallocate stuff properly.

#### Placement new()

The idea is an operator that only constructs, without allocation. 

```cpp
struct S {
  S() { std::cout << "S::S()" << std::endl; }
  ~S() { std::cout << "S::~S()" << std::endl; }
};
 
void f() {
  alignas(struct S) char space[sizeof(struct S)];
  S *s1 = new (&space) S;
 
  // ...
 
  delete s1;
}
```

No need to `delete`, as it deallocates memory that is stored on the stack, and not returned by a `new` call.

#### Uninitialized delete

```cpp
void f() {
  int *i1, *i2;
  try {
    i1 = new int;
    i2 = new int;
  } catch (std::bad_alloc &) {
    delete i1;
    delete i2;
  }
}
```

In case the first allocation fails, it would call `delete i2`, eventho `i2` isn't initialized.

Unlike `free(0)`, `delete` of an uninitialized pointer results in UB.

The correct solution is to initialized both of them to `nullptr`, so that `delete nullptr` would be called, which is completely valid. 

#### Double-Free + Copy CTOR

```cpp
struct P {};
 
class C {
  P *p;
   
public:
  C(P *p) : p(p) {}
  ~C() { delete p; } 
   
  void f() {}
};
 
void g(C c) {
  c.f();
}
 
void h() {
  P *p = new P;
  C c(p);
  g(c);
}
```

`C` dtor calls `delete p`, which is completely risky, as it isn't the scope where `p` is allocated. 

The problem with this, is that both `h()` scope has `C c`, and another copy is constructed within `g()`. \
This means the DTOR would actually be called twice! first within `g`, and then within `h`. 

A correct solution should pass `g(C &c)`, meaning a reference, as well as delete the copy constructors explicitly. 

#### Array new[]

```cpp
void f() {
  int *array = new int[10];
  // ...
  delete array;
}
```

Mismatch, should use `delete[]` (gah..)

#### malloc()

```cpp

#include <cstdlib>
void f() {
  int *i = static_cast<int *>(std::malloc(sizeof(int)));
  // ...
  delete i;
}
```

`malloc` should be `free`d, not `delete`d. 

#### new

```cpp
struct S {
  ~S();
};
 
void f() {
  S *s = new S();
  // ...
  std::free(s);
}
```

The exact opposite case, should call `delete` here instead of `free`. 

#### Class new

Classes may define their own `new, delete` operators. 

```cpp
struct S {
  static void *operator new(std::size_t size) noexcept(true) {
    return std::malloc(size);
  }
   
  static void operator delete(void *ptr) noexcept(true) {
    std::free(ptr);
  }
};
 
void f() {
  S *s = new S;
  ::delete s;
}
```

This bug is subtle: operator `delete` is used from the global scope, instead of the new wrapper `S::delete s`, or simply `delete s` (which evaluates to operator delete). 

#### std::unique_ptr + Array

```cpp
struct S {};
 
void f() {
  std::unique_ptr<S> s{new S[10]};
}
```

This kind of uptr initialization actually performs two allocations - one for the `unique_ptr` data, and another for the object. \
While this isn't performant, it is OK. 

However, when `std::unique_ptr` is destroyed, *its default deleter calls delete, instead of delete[]*! Thats because the uptr is defined as `<S>` instead of `<S[]>`!

Always prefer using `std::make_unique`:

```cpp
std::unique_ptr<S[]> s = std::make_unique<S[]>(10);
```

That way the uptr holds an array of objects, instead of ptr to a single object. 

### MEM52-CPP

Detect memory allocation errors, e.g., `std::bad_alloc`. \
By default, `new` throws an exception instead of returning a `nullptr`. 

Moreover, it can throw `std::bad_array_new_length : std::_bad_alloc`, in case a negative / huge size argument is passed to array `new`. 

#### noexcept shit

```cpp
void f(const int *array, std::size_t size) noexcept {
  int *copy = new int[size];
  std::memcpy(copy, array, size * sizeof(*copy));
  // ...
  delete [] copy;
}
```

In case allocation fails, exception is thrown. However the `noexcept` kills the program.

An idea is to add `std::nothrow` to the `new` operator, or to delete the `noexcept`.

#### Leaking Arguments

```cpp
struct A { /* ... */ };
struct B { /* ... */ }; 
  
void g(A *, B *);
void f() {
  g(new A, new B);
}
```

Assuming deterministic build order, in case `A` has built, and `B` throws - memory leakeage occurs, and `A` won't be freed. 

Instead, prefer using smart pointers, both should be initiated via `std::make_unique<A/B>()`, or to just use references for automatic storage duration variables. 

### MEM53-CPP

Beware of manual initializations. 

#### Sole Allocation

```cpp
struct S {
  S();
   
  void f();
};
 
void g() {
  S *s = static_cast<S *>(std::malloc(sizeof(S)));
  
  s->f();
  
  std::free(s);
}
```

In this code, the CTOR of the object is never called. The object is only allocated, not constructed. 

This means `s->f()` results in UB. 

#### Container Allocator

```cpp
template <typename T, typename Alloc = std::allocator<T>>
class Container {
  T *underlyingStorage;
  size_t numElements;
   
  void copy_elements(T *from, T *to, size_t count);
   
public:
  void reserve(size_t count) {
    if (count > numElements) {
      Alloc alloc;
      T *p = alloc.allocate(count); // Throws on failure
      try {
        copy_elements(underlyingStorage, p, numElements);
      } catch (...) {
        alloc.deallocate(p, count);
        throw;
      }
      underlyingStorage = p;
    }
    numElements = count;
  }
   
  T &operator[](size_t idx) { return underlyingStorage[idx]; }
  const T &operator[](size_t idx) const { return underlyingStorage[idx]; }
};
```

In case `alloc.allocate` fails, exception is thrown. \
Note that the allocation and the initialization phases are splitted. 

There are two problems:

1. Only `numElements` are copied, while `p` was allocated according to `count`. \
This may lead to overflow / under-copy, depending on the allocator implementation of `count` (is it bytes? elements? bits?). \
More accurately - `copy_elements` manually constructs `numElements`, instead of `count` elements. \
It means the rest will only be allocated, not CTOR'ed, and referencing them via `[]` would result in UB.

Meaning, it should add this:

```cpp
for (size_t i = numElements; i < count; ++i) {
          alloc.construct(&p[i]);
        }
```

2. The objects `underlyingStorage` and `p` might be polymorphic. \
It means copying the underlying memory may corrupt inner metadata, such as `vptrs, vbases`. 

### MEM54-CPP

Regular `new` returns a correctly-aligned object. \
Placement new should provided with properly aligned pointers, otherwise it won't return a correctly-aligned object. 

```cpp
void f() {
  short s;
  long *lp = ::new (&s) long;
}
```

The above code contains an address that is aligned to `short`, but requires an alignment of `long`. Resulting in UB.

A tricky example:

```cpp
void f() {
  char c; // Used elsewhere in the function
  unsigned char buffer[sizeof(long)];
  long *lp = ::new (buffer) long;
  
  // ...
}
```

`buffer` has the alignment of `char`, while the inplace-new requires an alignment of `long`. UB.

A solution is to use `alignas(long)` declaration, or `std::aligned_storage`.

### MEM55-CPP

Beware of replacing memory allocation functions. 

```cpp
void *operator new(std::size_t size) {
  extern void *alloc_mem(std::size_t); // Implemented elsewhere; may return nullptr
  return alloc_mem(size);
}
  
void operator delete(void *ptr) noexcept; // Defined elsewhere
void operator delete(void *ptr, std::size_t) noexcept; // Defined elsewhere
```

If the custom allocator fails to allocate the requested amount of mem, the replacement function returns `nullptr` instead of throwing an exception, as desired by the specification. \
This breaks all functions that rely on `std::bad_alloc`, hence attempting to null-deref. 


### MEM56-CPP

Beware of storing an already-owned pointer in another smart pointer! \
Calling `std::unique_ptr::release()` will relinquish ownership of the managed pointer. Moreover, DTOR, move assignment, `std::unique_ptr::reset` would also relinquish the ownership, but would also destruct the managed pointer value. 

`std::shared_ptr` allows multiple smart pointer objects to manage the same pointer value. Subsequent smart pointer objects are related to the original smart pointer, the one that owns the underlying pointer value. \
If `std::shared_ptr` is copied to another `std::shared_ptr` object via copy assignment, they are *related*. \
Calling `std::shared_ptr` CTOR out of the managed pointer value of the owner `shared_ptr` does not makes them related! `std::shared_ptr(a.get())`.

It is very risky to create unrelated smart pointers to the same object, as calling `reset` or destructing the object may yield UAF. 

```cpp
void f() {
  int *i = new int;
  std::shared_ptr<int> p1(i);
  std::shared_ptr<int> p2(i);
}
```

Two unrelated smart pointers are constructed. \
This results with a double-free vuln!

The correct solution:

```cpp
std::shared_ptr<int> p1 = std::make_shared<int>();std::shared_ptr<int> p2(p1);
```

Another, very cool example:

```cpp
struct B {
  virtual ~B() = default; // Polymorphic object
  // ...
};
struct D : B {};
 
void g(std::shared_ptr<D> derived);
 
void f() {
  std::shared_ptr<B> poly(new D);
  // ...
  g(std::shared_ptr<D>(dynamic_cast<D *>(poly.get())));
  // Any use of poly will now result in accessing freed memory.
}
```

The vuln occurs because `g`'s argument is initialized as dynamic cast of the underlying ptr, `poly.get()`, instead of just `poly`. 

Therefore, the copy of the `shared_ptr` actually treated as the secondary owner of the `new D` pointer, and again results with a double-free.

Last example:

```cpp
struct S {
  std::shared_ptr<S> g() { return std::shared_ptr<S>(this); }   
};
 
void f() {
  std::shared_ptr<S> s1 = std::make_shared<S>();
  // ...
  std::shared_ptr<S> s2 = s1->g();
}
```

As before, two unrelated smart shared pointers are constructed, causing double-free.

### MEM57-CPP

Avoid using default operator new for over-aligned types.

The `new` operator gurantees aligned returned address, corresponding to the allocation size. 

Moreover, in C++ arrays allocation may take more amount of storage, also referred as an *overhead*, and known as `array cookie`. \
That is because arrays deallocation requires hint `cookie` for `delete[]` to work properly. This number of elements hint is also required for stack unwinding mechanism. 

Can read more here: [cookie][cookie].

```cpp
struct alignas(32) Vector {
  char elems[32];
};
 
Vector *f() {
  Vector *pv = new Vector;
  return pv;
}
```

`struct Vector` is defined as over-aligned type, as it uses custom `alignas` specifier. 

However, `new` wishes to allocate about `>=36` bytes, as it also stores a cookie. \
This results with an address that is 36-bytes aligned, instead of 32-bytes aligned!

These over-aligned types are popular among SIMD instructions, that requires 128 / 256 bits for the various `xmm` registers, otherwise causing a trap. 

A good solution in this case, would be overriding the `new` operator with an `std::aligned_alloc`, with an alignment corresponding to the allocation size. 


[cert-cpp]: https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682
[cwe-c]: https://cwe.mitre.org/data/slices/658.html
[cookie]: https://pvs-studio.com/fr/blog/posts/cpp/0973/
