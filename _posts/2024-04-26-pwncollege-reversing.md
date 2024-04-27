---
layout: post
title:  "Pwn College - Reverse Engineering"
date:   2024-04-26 19:59:48 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module involves breaking simple RE crackmes. 

It doesn't resembles real-world RE challenges at all, but there are still cool insights we can learn from here.  

## Tips

For blackbox research, `ltrace, strace, strings` would be our close friends. 

For whitebox research, watchpoints (memory-breakpoints) are our friends. Notice we are limited to only 4 debug registers within x86, and the target addresses must be aligned to the debugged amount (1, 2, 4 or 8 bytes). 

In order to debug a whole memory region, we must invoke it with valgrind as follow:

```bash
# Start program
valgrind --vgdb=full --vgdb-error=0 ./binary
# Connect gdb
target remote ...
awatch (char[100]) *0x3003000
```

## Challenge 6

Upon opening the binary in IDA, we would see lots of ida-macros being used. \
Their full list is defined here: [ida-macros][ida-macros].

This means the binary switches the first two bytes, switches all of the bytes, and finally switches `buf[5]` and `buf[9]`. 

## Challenge 7

```python
def do_xor(xs, ys):
    return [xs[i] ^ ys[i%len(ys)] for i in range(len(xs))]


def do_reverse(s):
    return s[::-1]


def do_parity_xor(s, even_k, odd_k):
    return [s[i] ^ even_k if i % 2 == 0 else s[i] ^ odd_k for i in range(len(s))]


def do_switch(s, idx1, idx2):
    s[idx1], s[idx2] = s[idx2], s[idx1]
    return s

# Retrieve via IDA's edit → export data
payload = bytearray.fromhex('a0 a0 a1 a1 a3 a3 a5 a5 a6 a8 a9 a9 aa aa ab ab ae b5 b7 b7 b8 b8 b9 b9 b9 b9 ba ba ba bc bc be be be bf bf bf')

payload_1 = bytearray(do_switch(payload, 14, 31))
print(payload_1)

payload_2 = bytearray(do_xor(payload_1, [0xcf]))
print(payload_2)

payload_3 = bytearray(do_switch(payload_2, 3, 23))

payload_4 = bytearray(do_reverse(payload_3))
print(payload_4)

with open('/home/hacker/my_payload.txt', 'wb') as f:
    f.write(payload_4)
```

## Challenge 9

Simply change 0x2639 - 0x263e to:
```bash
48 31 c0 90 90
# Equivalent to:
xor rax, rax; 
nop; 
nop;
```

## Challenge 12

An emulator of custom architecture is presented. \
Just put a breakpoint at the decryption point:

```bash
b *main-0x1b7d+0x2107

pwn unhex 350308304b994a60 | /challenge/babyrev_level12.0
```

## Challenge 14

A completely stripped binary. Cool trick to set a breakpoint:

```bash
tbreak __libc_start_main
tbreak *__libc_start_main-0x6048+0x207c
r
```

Another (better) option, is to retrieve `$rdi` value upon `__libc_start_main` bp was hit - as it contains the loaded `main` address. 


## Updated Challenges

They’ve added more challenges in the middle, such as obfuscated code. \
Therefore, challenges numbers have changed.

## Challenge 20

The program initially expects us to send 0x14 key bytes, and stores them within `mem[0x30]`. \
Every byte is being mangled with some different byte, as given by the `IMM c = bla` command. \
We should parse all such instructions, to retrieve the mangling key. 

Finally, the resulting buffer (which is located at `mem[0x30]`) is compared to a secret key, located at `mem[0x87]`.

An automated approach:

```python
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
from itertools import islice

def batched(iterable, n):
    "Batch data into tuples of length n. The last batch may be shorter."
    # batched('ABCDEFG', 3) --> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    it = iter(iterable)
    while (batch := tuple(islice(it, n))):
        yield batch

BINARY = '/challenge/babyrev_level20.1'
GDB_SCRIPT= '''
tbreak __libc_start_main
commands
print("breaking address")
b *$rdi-0x1d3a+0x1ca1
end

c
'''

@dataclass
class Opcodes:
    STM = b''
    IMM = 0x02
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b''

# These are subject to change
reg_index = 2
opcode_index = 1
value_index = 0


def gen_license(vm_code, vm_code_length, vm_mem):
    with open(BINARY, 'rb') as f:
        program_binary = f.read()

    code = program_binary[vm_code: vm_code + vm_code_length]
    memory = program_binary[vm_mem: vm_mem + 0x300]
    instructions = list(batched(code, 3))
    for i in range(len(instructions)):
        if instructions[i][opcode_index] == Opcodes.IMM and \
           instructions[i][opcode_index] == instructions[i + 1][opcode_index] and \
           instructions[i][opcode_index] == instructions[i + 2][opcode_index] and \
           instructions[i][opcode_index] == instructions[i + 3][opcode_index]:
           input_addr = instructions[i][value_index]
           key_addr = instructions[i+1][value_index]
           key_length = instructions[i+2][value_index]
           print(f'input_addr:{input_addr} key_addr:{key_addr} key_length:{key_length}')
           break
    
    expected_key = memory[key_addr: key_addr + key_length]
    print(f'expected_key:{expected_key}')

    for a in enumerate(instructions):
        print(a)

    mangled_key = b''
    # We might want to change the start index: 5 / 42
    for i in range (42, len(instructions), 5):
        key = instructions[i][value_index]
        mangled_key += key.to_bytes(1, 'little') 
        if len(mangled_key) >= key_length:
            break
    
    print(f'mangled_key:{mangled_key}')

    gen_license = b''
    for i in range(key_length):
        license_byte = (expected_key[i] - mangled_key[i]) & 0xff
        gen_license += license_byte.to_bytes(1, 'little')
        
    
    print(f'license:{gen_license}')

    return gen_license


def exploit():
    p = process(BINARY, close_fds=False)
    # p = gdb.debug(BINARY, close_fds=False, gdbscript=GDB_SCRIPT)

    my_license = gen_license(vm_code=0x3020, vm_code_length=0x1da, vm_mem=0x3200)

    p.send(my_license)
    p.interactive()

exploit()
```

## Challenge 21

Send dedicated emulator code:

```python
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
from itertools import islice


BINARY = '/challenge/babyrev_level21.0'
GDB_SCRIPT= '''
tbreak __libc_start_main
commands
print("breaking address")
b *$rdi-0x1d3a+0x1ca1
end
c


'''

@dataclass
class Regs:
    a = b'\x10'
    b = b'\x40'
    c = b'\x01'
    d = b'\x04'
    s = b'\x20'
    i = b'\x08'
    f = b'\x02'


@dataclass
class Opcodes:
    STM = b''
    IMM = b'\x01'
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b'\x10'


@dataclass
class Syscalls:
    OPEN = b'\x04'
    READ_CODE = b''
    READ_MEM = b'\x08'
    WRITE_MEM = b'\x01'
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

def open_file(file_addr):
    buffer = b''
    buffer += write_register(register=Regs.a, value=file_addr)
    buffer += write_register(register=Regs.b, value=2)  # O_RDWR
    buffer += write_register(register=Regs.c, value=0)  # mode, Irrelevant
    buffer += syscall(Syscalls.OPEN, out_reg=Regs.a)
    return buffer

def read_to_memory(fd, offset, count):
    buffer = b''
    buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.READ_MEM, out_reg=Regs.a)
    return buffer

def write_stdout_from_memory(offset, count):
    buffer = b''
    buffer += write_register(Regs.a, value=1)  # stdout
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.WRITE_MEM, out_reg=Regs.a)
    return buffer


def exploit():
    p = process(BINARY, close_fds=False)
    # p = gdb.debug(BINARY, close_fds=False, gdbscript=GDB_SCRIPT)

    FLAG_PATH = b'/flag'
    flag_addr = 0
    buf = b''
    buf += read_to_memory(fd=0, offset=flag_addr, count=len(FLAG_PATH))
    buf += open_file(file_addr=flag_addr)
    buf += read_to_memory(fd=3, offset=0, count=0xff)
    buf += write_stdout_from_memory(offset=0, count=0xff)
    buf += b'\x42' * (0x300 - len(buf))

    p.send(buf)
    p.send(FLAG_PATH)

    p.interactive()

exploit()
```

## Challenge 22

Like the above, but this time all of the `dataclasses` values are randomized, according to a seed that is dependent on the secret flag! \
Hence, we won't be able to debug it with gdb and retrieve the correct values. 

The approach I've took here, is to semi-bruteforce at multiple phases. \
In particular, hitting `sys_exit(exit_code)` would leak us information about the system by resulting our controlled `exit_code`. 

Automated approach (extremely ugly code):

```python
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
import time
from itertools import islice


BINARY = '/challenge/babyrev_level22.1'
GDB_SCRIPT= '''
tbreak __libc_start_main
commands
print("breaking address")
b *$rdi-0x1d3a+0x1ca1
end
c
'''

@dataclass
class Regs:
    a = b''
    b = b''
    c = b''
    d = b''
    s = b''
    i = b''
    f = b''

@dataclass
class Opcodes:
    STM = b''
    IMM = b''
    ADD = b''
    CMP = b''
    JMP = b''
    LDM = b''
    STK = b''
    SYSCALL = b''

@dataclass
class Syscalls:
    OPEN = b''
    READ_CODE = b''
    READ_MEM = b''
    WRITE_MEM = b''
    SLEEP = b''
    EXIT = b''


def instruction(opcode, reg1, reg2):
    return reg2 + opcode + reg1

def compare(reg1, reg2):
    buffer = b''
    buffer += instruction(Opcodes.CMP, reg1, reg2)
    return buffer

def syscall(number, out_reg):
    return instruction(Opcodes.SYSCALL, number, out_reg)
    
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

def open_file(file_addr):
    buffer = b''
    buffer += write_register(register=Regs.a, value=file_addr)
    buffer += write_register(register=Regs.b, value=2)  # O_RDWR
    buffer += write_register(register=Regs.c, value=0)  # mode, Irrelevant
    buffer += syscall(Syscalls.OPEN, out_reg=Regs.a)
    return buffer

def read_to_memory(fd, offset, count):
    buffer = b''
    buffer += write_register(Regs.a, value=fd)
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.READ_MEM, out_reg=Regs.a)
    return buffer

def write_stdout_from_memory(offset, count):
    buffer = b''
    buffer += write_register(Regs.a, value=1)  # stdout
    buffer += write_register(Regs.b, value=offset)
    buffer += write_register(Regs.c, value=count)
    buffer += syscall(Syscalls.WRITE_MEM, out_reg=Regs.a)
    return buffer

def try_all_opcodes(reg1, reg2):
    exit_result = []
    current_opcode = 1
    while current_opcode <= 0x80:
        p = process(BINARY)
        debug_buf = instruction(current_opcode.to_bytes(1, 'little'), reg1, reg2)
        debug_buf += b'\x41' * (0x300 - len(debug_buf))
        p.send(debug_buf)
        time.sleep(0.06)
        exit_code = p.poll()
        exit_result.append(exit_code)
        current_opcode *= 2
    return exit_result

def try_all_opcodes_and_do_syscall(reg1, reg2, sys_opcode, sys_num):
    exit_result = []
    current_opcode = 1
    while current_opcode <= 0x80:
        p = process(BINARY)
        debug_buf = instruction(current_opcode.to_bytes(1, 'little'), reg1, reg2)
        debug_buf += instruction(sys_opcode, sys_num, reg1)  # save to a register we know must exist
        debug_buf += b'\x41' * (0x300 - len(debug_buf))
        p.send(debug_buf)
        time.sleep(0.06)
        exit_code = p.poll()
        exit_result.append(exit_code)
        current_opcode *= 2
    return exit_result 

def get_sys_read_and_reg_c():
    # Idea - reg_a = read(0, mem[0], 0xff); exit(reg_a).
    # We'd send 0xfd bytes of invalid characters - 0x42. If the program terminated successfully, thats a hit
    write_amount = 0xfd
    sys_read_candidate = 1
    expected_exit_code = 0
    while sys_read_candidate <= 0x80:
        if sys_read_candidate.to_bytes(1, 'little') == Syscalls.EXIT:
            sys_read_candidate *= 2
            continue
        reg_c_candidate = 1
        while reg_c_candidate <= 0x80:
            if reg_c_candidate.to_bytes(1, 'little') == Regs.a:
                reg_c_candidate *= 2
                continue
            p = process(BINARY)
            debug_buf = instruction(Opcodes.IMM, Regs.a, b'\x00')  # read from stdin
            debug_buf += instruction(Opcodes.IMM, reg_c_candidate.to_bytes(1, 'little'), write_amount.to_bytes(1, 'little'))  # set read amount to 0xff bytes
            debug_buf += instruction(Opcodes.SYSCALL, sys_read_candidate.to_bytes(1, 'little'), Regs.a)  # save to a register we know must exist
            debug_buf += instruction(Opcodes.SYSCALL, Syscalls.EXIT, Regs.a)  # retrieve the return code, should be \xfd - as this is the return value of the read. 
            debug_buf += b'\x41' * (0x300 - len(debug_buf))
            p.send(debug_buf)
            p.send(b'\x42' * write_amount)
            time.sleep(0.06)
            exit_code = p.poll()
            if exit_code == write_amount:
                return sys_read_candidate, reg_c_candidate
                
            reg_c_candidate *= 2
        sys_read_candidate *= 2


def get_sys_write_and_reg_b():
    # Idea - reg_a = write(1, mem[b], 0xfc); exit(reg_a).
    # We'd send 0xfc bytes of invalid characters - 0x42. If the program terminated successfully, thats a hit
    candidates = []
    write_amount = 0xfd
    sys_write_candidate = 1
    expected_exit_code = 0
    while sys_write_candidate <= 0x80:
        if sys_write_candidate.to_bytes(1, 'little') == Syscalls.EXIT or sys_write_candidate.to_bytes(1, 'little') == Syscalls.READ_MEM:
            sys_write_candidate *= 2
            continue
        reg_b_candidate = 1
        while reg_b_candidate <= 0x80:
            p = process(BINARY)
            debug_buf = instruction(Opcodes.IMM, Regs.a, b'\x01')  # write to stdout
            debug_buf += instruction(Opcodes.IMM, reg_b_candidate.to_bytes(1, 'little'), write_amount.to_bytes(1, 'little'))  # set write amount
            debug_buf += instruction(Opcodes.SYSCALL, sys_write_candidate.to_bytes(1, 'little'), Regs.a)  # save to a register we know must exist
            debug_buf += instruction(Opcodes.SYSCALL, Syscalls.EXIT, Regs.a)  # retrieve the return code, should be the write amount - as this is the return value of the syscall. 
            debug_buf += b'\x41' * (0x300 - len(debug_buf))
            p.send(debug_buf)
            p.send(b'\x42' * write_amount)
            time.sleep(0.06)
            exit_code = p.poll()
            if exit_code == write_amount:
                candidates.append(sys_write_candidate)
            reg_b_candidate *= 2
        sys_write_candidate *= 2
    return candidates

def exploit():
    sys_index = None
    current_reg_1 = 1
    while current_reg_1 <= 0x80:
        exit_codes = try_all_opcodes(current_reg_1.to_bytes(1, 'little'), current_reg_1.to_bytes(1, 'little'))
        try:
            sys_index = exit_codes.index(0)
            sys_exit_value = current_reg_1
        except Exception:
            pass
        current_reg_1 *= 2

    syscall_val = 2 ** sys_index
    Opcodes.SYSCALL = syscall_val.to_bytes(1, 'little')
    Syscalls.EXIT = sys_exit_value.to_bytes(1, 'little')
    # Opcodes.SYSCALL = b'\x80'
    # Syscalls.EXIT = b'\x08'
    print(f'syscall opcode:{Opcodes.SYSCALL} sys_exit:{Syscalls.EXIT}')

    current_reg_1 = 1
    expected_exit_code = 7
    while current_reg_1 <= 0x80:
        exit_codes = try_all_opcodes_and_do_syscall(current_reg_1.to_bytes(1, 'little'), expected_exit_code.to_bytes(1, 'little'), Opcodes.SYSCALL, Syscalls.EXIT)
        try:
            imm_index = exit_codes.index(expected_exit_code)
            reg_a_value = current_reg_1
        except Exception:
            pass
        current_reg_1 *= 2
    imm_val = 2 ** imm_index
    Opcodes.IMM = imm_val.to_bytes(1, 'little')
    Regs.a = reg_a_value.to_bytes(1, 'little')
    # Opcodes.IMM = b'\x08'
    # Regs.a = b'\x01'
    print(f'imm opcode:{Opcodes.IMM} reg_a:{Regs.a}')

    sys_read, reg_c = get_sys_read_and_reg_c()
    Syscalls.READ_MEM = sys_read.to_bytes(1, 'little')
    Regs.c = reg_c.to_bytes(1, 'little')
    print(f'sys_read_reg_c:{(sys_read, reg_c)}')

    sys_write_candidates = get_sys_write_and_reg_b()
    print(f'sys_write candidates:{sys_write_candidates}')

    for sys_write in sys_write_candidates:
        write_candidate  = sys_write.to_bytes(1, 'little')
        if write_candidate == Syscalls.READ_MEM or write_candidate == Syscalls.EXIT:
            continue
        Syscalls.WRITE_MEM = write_candidate
        print(f'sys_write attempt:{Syscalls.WRITE_MEM}')
        sys_open_candidate = 1
        while sys_open_candidate <= 0x80:
            Syscalls.OPEN = sys_open_candidate.to_bytes(1, 'little')
            reg_b_candidate = 1
            while reg_b_candidate <= 0x80:
                Regs.b = reg_b_candidate.to_bytes(1, 'little')
                p = process(BINARY)
                FLAG_PATH = b'/flag'
                flag_addr = 0
                buf = b''
                buf += read_to_memory(fd=0, offset=flag_addr, count=len(FLAG_PATH))
                buf += open_file(file_addr=flag_addr)
                buf += read_to_memory(fd=4, offset=0, count=0xff)
                buf += write_stdout_from_memory(offset=0, count=0xff)
                buf += b'\x43' * (0x300 - len(buf))
                p.send(buf)
                p.send(FLAG_PATH)
                time.sleep(0.1)
                exit_code = p.poll()
                print(f'flag exit_code:{exit_code}')
                p.recvuntil(b'input your yancode:')
                p.recvuntil(b'Good luck!')
                flag_candidate = p.recv()
                print(f'flag_candidate:{flag_candidate} len:{len(flag_candidate)}')
                if len(flag_candidate) >= 4095:
                    print(f'extra flag candidate:{p.recv()}')
                reg_b_candidate *= 2
            sys_open_candidate *= 2
exploit()
```

[ida-macros]: https://github.com/nihilus/hexrays_tools/blob/master/code/defs.h
