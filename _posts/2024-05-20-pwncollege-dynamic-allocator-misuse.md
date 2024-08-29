---
layout: post
title:  "Pwn College - Tcache Exploitation"
date:   2024-05-20 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Over the years, there were many heap exploitation techniques developed. Most of them can be found [here][heap-techniques] (there are other obscure techniques, not mentioned there). \
This module deals with a subset of techniques, only involving the tcache. 

## Background

One approach of dynamically allocating memory is `mmap`. While it does allows dynamic allocation and deallocation for regions that surivves across functions (unlike the stack), the allocation size is inflexible, and requires kernel involvment for every call. \
A smarter solution is to write a library, that allocates a large chunk of memory (`brk`, not `mmap`, but also allocates large amout of memory), and manage the small chunks of it, based on demand. 

Current dynamic allocator of Linux usermode is `ptmalloc2`, for its kernel - `kmalloc` (slab allocator), for FreeBSD it is `jemalloc` (which used in Android), for Windows - `Segment Heap, NT Heap`, for Chrome - `PartitionAlloc`. 

It is good to mention that the heap **HAVE NO RELATION** to the heap data structure. \
The heap provides the basic API of `malloc, free`, as well as more fancy stuff, such as `realloc, calloc` and others (`aligned_alloc`). 

Recall `ptmalloc` doesn't uses `mmap` but `brk`. \
`brk(addr)` expands the end of the data segment up to `addr`, while `sbrk(NULL)` returns the end, and `sbrk(delta)` increments the end by `delta` bytes. `ptmalloc` simply slices bytes off the data segment for small allocations, and uses `mmap` for very large allocations.

### Detection

We can detect some dynamic memory issues via `valgrind`. Also, glibc itself has some hardening techniques, in the cost of performance - `MALLOC_CHECK`, `MALLOC_PERTURB`, `MALLOC_MMAP_THRESHOLD` (making ALL allocations being done via `mmap`, lol). 

### Tcache

Recall all allocated chunks contains metadata member before them, of `0x10` bytes long (on 64-bit platforms). Moreover, allocations are always aligned to `0x10`. Hence, if we would allocate `0x1c` bytes (28 bytes), we would actually allocate chunk of size `align(0x2c,10) = 0x30` bytes. \
There are separate tcache bins for every chunk sizes, by multiple of the alignment `0x10`. 

24:15


## Challenge 1

I've set `pwndbg` environment for all challenges from now on.








[heap-techniques]: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/

