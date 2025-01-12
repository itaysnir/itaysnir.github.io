---
layout: post
title:  "Pwnable.tw - Re-alloc"
date:   2025-01-12 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Re-alloc 

```bash
$ checksec ./re-alloc
[*] '/home/itay/projects/pwnable_tw/re-alloc/re-alloc'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    Stripped:   No

$ file ./re-alloc
./re-alloc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=14ee078dfdcc34a92545f829c718d7acb853945b, for GNU/Linux 3.2.0, not stripped
```

64-bit binary. 

## Debug

We're given libc-2.29, which isn't too old:

```bash
$ strings libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.
Compiled by GNU CC version 8.3.0.
```

I've install the corresponding debian package:

```bash
cd glibc-all-in-one
mkdir -p libs/2.29-0ubuntu2_amd64/
cd debs
wget https://launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428/+files/libc6_2.29-0ubuntu2_amd64.deb
cd ..
./extract debs/libc6_2.29-0ubuntu2_amd64.deb libs/2.29-0ubuntu2_amd64/
```

And used `patchelf` to mimic the remote environment precisely. 

## Overview

Menu-based challenge. Having the options of `alloc, realloc, free, exit`.

1. `read_long` - the main routine to parse numbers off the user. Its implementation is interesting - reading `0x10` bytes to buffer of size `0x18`, having a check that the read amount isn't larger than the buffer's size - `0x11`. Also notice that this buffer isn't initialized to `0`, hence, the rest of the bytes aren't guranteed to contain nullified values. This might mean that the preceding `atoll` call might leak stack values, by parsing them as part of the number. 

2. The fact that `read_long` uses `atoll` might hint we can also store there some non-number string, which would still get parsed properly.

3. Within `allocate`, the return value of `index = read_long` (and size) are checked. In particuler, if these are high values, such as pointers, the program would terminate. Hence, `read_long` won't be able to serve as a stack leak primitive (`rfree, realloc` also performs these checks).

4. `allocate` - verifies that the requested `index` is either `0` or `1`, and that the pointer slot within the global `heap` address isn't initialized. If that's the case, requests the `size` of the allocation (must be below `0x78`, probably to fall within the fastbins & tcache), and **performs the allocation using `realloc(NULL, size)`**. By reading the documentation, it should be equal to `malloc(size)`. What would `malloc(0)` do?

5. Vuln - the returned chunk isn't initialized. Hence, it may still contain uninitialized values, if we'd send less than `size` bytes. 

6. Vuln - OOB-W of a single null byte. Notice that `ptr[size] = '\0'` is being issued, hence - writing a byte past the buffer's end, writing a total of `size + 1` bytes.

7. `rfree` - frees the pointers using `realloc(ptr, 0)`, and nullifies the `heap` global slot to prevent UAF. Seems as there are no vulns here.

8. `reallocate` - performs `realloc` of the desired size and heap slot. It then stores the return value within a global heap slot, reading the input to there. This time, without truncating the buffer with OOB-W of `\x00`. 

9. Vuln - `reallocate` may receive `size == 0`, which in this case, triggers `realloc(ptr, 0) == free(ptr)`. Notice that the retval is checked to be non-NULL (where the retval in this case is actually NULL). However, in this case, the function returns before assigning the pointer within the global `heap` slot. Hence, the slot still contains the chunk's pointer, but this time - it is already freed. We can reissue the same routine, or `rfree`, to cause double-free. 

Indeed, while performing point (9), I've got the following error:

```bash
free(): double free detected in tcache 2
```

Meaning there's tcache enabled. 


## Exploitation

So we have 2 major bugs - 1 byte heap overflow of `\x00`, and double-free. \
My goto approach is using the double free, such that we'd be able to overwrite content of a chunk within the tcachebin freelist. 

### Write Primitive

By overwriting the tcache chunk's `next` pointer to an address of our wish, we can obtain arbitrary-alloc primitive, which is easily tranlated to an arbitrary write. \
Interestingly, even after perfoming the `free(a), free(b), free(a)` trick, double free was still detected. \
By reading `glibc-2.29` sources, I've seen that in case the key (the next ptr after `next`) matches `tcache_perthread_struct`, ALL tcachebin would be traversed over, so the above trick wouldn't work. However, if we can corrupt this value, we'd be good. **The off-by-one vuln, potentially writing the size class of a freed chunk, may come very handy**:

```bash
pwndbg> x/20gx 0x31686250
0x31686250:     0x0000000000000000      0x0000000000000021
0x31686260:     0x4141414141414141      0x4141414141414141
0x31686270:     0x4141414141414141      0x0000000000000000
0x31686280:     0x4141414141414141      0x4141414141414141
0x31686290:     0x4141414141414141      0x0000000000020c00
0x316862a0:     0x0000000000000000      0x0000000000000000
```

Such a technique is called `House of Poortho`. However, it seems to be valuable only in cases where the size isn't `0`, but we can perform a size mismatch. For example, shrunk `0x120` to `0x100`. This is not the case. \
Another option i've tried, is to try and avoid using the tcache - and use the fastbins instead. However we're very limited, only for 2 allocations at once. Hence, it won't be trivial. 

At this point I've concluded the challenge must involve the `realloc(ptr, 0)` vuln. Since `free` of this chunk seems to be causing a trap as glibc-2.29 mitigates this well, we have only one other option - calling `realloc` on the already freed chunk! 

**Q: How the heck would `realloc` on a freed chunk behave?**

Well, if the size would be `0` - just as `free`, hence we'd encounter the same problem as before. \
**However, in case the size isn't `0`, `realloc` checks if the desired requested size corresponds to the chunk's size (within the metadata), and if so - simply returns the given pointer as-is!**
This feature is amazing - because `realloc` design doesn't considers the wrecked case of given freed ptr parameter, calling `realloc` on freed chunk with its adequate size is "no-op" - and returns its valid pointer, without touching any freelist. 

Within the challenge, it allows us to write content directly to the freed tcache chunk, **while still keeping it inside the tcache freelist**. 


