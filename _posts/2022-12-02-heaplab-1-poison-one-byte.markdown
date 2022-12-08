---
layout: post
title:  "HeapLAB 1 - Poison One Byte"
date:   2022-12-08 20:02:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Remaindering

This is the term for splitting one free chunk down into two, then allocating one of those parts, and the other one returned to a freelist.

For example, consider a case where only `smallbin[0x300]` contains an available free chunk. \
A `malloc(0x98)` (allocation of chunk size `0x100`) would unlink the `0x300` chunk from its freelist, split a `0x100` chunk off it, link the `remainder` of size `0x200` into the *head of the unsortedbin*, and allocate the `0x100` chunk.

### Trigger

Remaindering can occur at one of three points during `malloc` execution:

1. During allocations from the `largebins`

2. During `binmap search`

3. From a `last remainder` during `unsortedbin scanning`


### binmap

This is a bitmap representing which arena's bins may be occupied. 

The binamp resides near the end of an arena.

During binmap search, `malloc` uses the binmap to find the *next* largest, occupied bin, with respect to the *requested chunk size*. \
It then remainders the last chunk in that bin (tail). 

When a chunk isn't large enough to be remaindered by a request, and leave behind at least a minimum-size chunk (which is `0x20`), this leads to `exhausting`. 

For example, if the arena only has `0x90` chunk, requesting `0x80` will exhaust that chunk, because `0x10 < MINSIZE = 0x20`, so it would allocate the *whole 0x90 chunk*. \
This is one of the few times it is possible `malloc` would return an un-expected size. 

Note this is a lazy bitmap implementation, meaning the bit of certain bin is cleared only when `malloc` attempts to allocate from an empty bin, during `binmap search` and fails. 

The bit of bin on the `binmap` is enabled when a chunk is sorted into it, during an `unsortedbin scan`. 


### last remainder

If a chunk was remainded during a binmap search, and the request size was within a smallbin range, the arena's `last_remainder` is set. 

This is just a pointer to the last chunk to get remainded. 

It works in conjunction with the unsortedbin: during an unsortedbin search for a small chunk, if the search gets to the last chunk in the unsortedbin, and that chunk is the `last_remainder` chunk, than it will be remaindered again, the `last_remainder` would be updated, and the allocation would return. 

For example:

```python
chunk_A = malloc(0x198)   # allocates 0x200 size chunk
chunk_B = malloc(0x18)    # prevent consolidation with top chunk

free(chunk_A)             # now chunk_A is within the unsortedbin

chunk_C = malloc(0xf8)    # allocate 0x100 size chunk.        
```

The request to allocate `0x100` size chunk involved searching the unsortedbin, hence sorting the `0x200` chunk towards `smallbin[0x200]`. \ 
Then, via a `binmap search` the chunk was remainded, and returned the free chunk to the unsortedbin head. \
This `0x100` free chunk is now the `last_remainder` chunk. 


