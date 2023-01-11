---
layout: post
title:  "Vulns - Dynamic Memory"
date:   2023-01-09 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

The C specification provides 4 memory allocation functions, all are widely available on multiple platforms.

CERT C chapter 8 describes the secure coding guidelines for dynamic memory. \
It can be found [here][cert-c].


### malloc

`malloc(size_t size)` - allocates `size` bytes, returns ptr to the allocated memory chunk. 

The pointer is always aligned. 

For example, the `glibc - 64 bit` implementation of `malloc` allocates `align16(size + 8)` bytes - extra 8 for the header, and alignment of 16. 

It means that the optimum chunk size for "as tight as possible" allocations, is one that satisfies `size % 16 == 8`, for example `0x38`.

Note that the allocated memory *is not initialized to known value* - meaning if a chunk is being reused, old data might be reused.

### aligned_alloc

`aligned_alloc(size_t alignment, size_t size)` - generalization of `malloc`, that lets the user align memory as he wishes, not only to 16 bytes. 

Usually it may come handy by aligning to cache-lines / pages granularity.

Note that the value of `size` must be an integer multiple of `alignment` - otherwise *undefined behavior occurs*. 

### realloc

`realloc(void *p, size_t size)` - can change the size of an allocated memory block, pointed to by `p`, to a new size - `size`. 

There are many caveats with this function. 

newly allocated memory will be uninitialized. Content will be unchanged up to the `min(old_sz, new_sz)`, with the exception of `new_sz == 0`. 

If the memory request cannot be made successfully, the old memory is left intact. 

If `p == NULL`, the call is equivalent to `malloc(size)`.

If `size == 0`, the call is equivalent to `free(p)`! \
This may be very surprising, and lead to unexpected UAF / double free vulns. 

Moreover, sometimes memory chunks cannot be increased - as there is an allocated succeeding chunk after them. \
In such cases, `realloc` implicitly `free`s the old chunk, and copies its content to a newly-allocated chunk at another region. \
This may leave old memory on the heap (as it isn't `memset`'ed), and more importantly - invalidates any of the pointers to the original chunk! 

### calloc

`calloc(size_t nmemb, size_t size)` - allocates a total of `nmemb * size` bytes (must verify it does not wraps-around the maximal integer value), and returns pointer to allocated memory. \
This time, the content of the chunk is initialized to contain `\x00` bytes. 

All memory allocation functions returns a `NULL` ptr in case of fail - which should be checked prior dereferencing. 

### free

`free(void *p)` - Used for deallocation. \
Note that `free(NULL)` is completely fine, and no operation is performed in such case. 

## Alignment

As mentioned, `aligned_alloc` can be used for alignned allocations. 

The alignment of certain object may be found via `alignof`. 

The main issue with allocating strictly aligned memory is reallocation. \
If `realloc` is called on a pointer returned from `aligned_alloc`, there is no gurantee of an alignment stricter than the normal alignment. 

`MEM36-C` explains this issue. \
For example:

```c
size_t resize = 1024;
  size_t alignment = 4096;
  int *ptr;
  int *ptr1;
   
  if (NULL == (ptr = (int *)aligned_alloc(alignment, sizeof(int)))) {
    /* Handle error */
  }
 
  if (NULL == (ptr1 = (int *)realloc(ptr, resize))) {
    /* Handle error */
  }
```

Because `resize > sizeof(int)`, `realloc` allocates new chunk, which may start from a different memory address (in case there is a succeeding chunk). 

In that case, the newly allocated chunk may not be aligned anymore. 

The guideline recommends not using `realloc` at all, for allocations involving alignment constraints. 

Memory should be manually re-`aligned-alloc`'ed, `memcpy`'d, and `free`'d. 

## alloca

Allocates memory within the stack. \
Automatically freed when the function returns, should *not* be called within `free`.

Often implemented as `inline`, with *only a signle instruction to adjust $rsp*. \
It means it does not return a `NULL` upon error, and can make allocations that exceeds the stack's bounds. 

This macro should be avoided. It may easily exhaust the stack memory, for large allocations.

A better alternative that some compilers supports, are variable-length-arrays (VLAs). \
These are arrays, having `size` initialized as a runtime variable, instead of a constant integer:

```c
int f (size_t size)
{
    char vla[size];
}
```

The allocated buffer lifetime is its declaration scope. \
Note that jumpion to another block / embedded block *prior to the declaration*, should not allocate the buffer (in most compilers). 

If `size` is a signed, negative integer - undefined behavior occurs. 

Moreover, for extremely large values, allocations may exceed the bounds of the stack - and even wrap around the virtual address space. \
This can be useful in order to overwrite program data (recall that the stack grows downwards tho). 

Therefore, sanitazion of VLA arguments are very important. 

`ARR32-C` describes this issue. 

Note that `sizeof` operator on a VLA returns its real size. \
This kind of surprised me, as im used to think on `sizeof` as a fully compile-time mechanism. 

## Common Memory Management Errors

### Initialization Errors



[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c
