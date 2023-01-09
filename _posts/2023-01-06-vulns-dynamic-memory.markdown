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

