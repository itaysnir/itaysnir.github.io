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

If the smallbins couldn't perform the allocation (`> 1024 bytes`), we'd consolidate the fastbins and try to perform the allocation from there. \
But how can we consolidate, if fastbins doesn't sets the `P` bit? We'd go through all fastbins, and clear the corresponding `P` bit, which would allow consolidation of fastbins to occur. \
By doing so, we'd prevent fragmentation of small chunks within the fastbins. \
This consolidation of fastbins can occur not only by `malloc(>1024)`, but also when `free` occurs - if a chunk is freed around `~65 KB` in size. \
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




[shellphish]: https://github.com/shellphish/how2heap
[glibc-all-in-one]: https://github.com/matrix1001/glibc-all-in-one
