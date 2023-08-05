---
---
layout: post
title:  "ROP Emporium - ret2win"
date:   2023-08-05 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Introduction

Lately I've decided that my next current goal is to gain deeper exploitation knowledge, regarding ARM and MIPS architectures. And whats better than learning by hands?
The ROP Emporium platform offers 8 exploitation challenges, for `x86, x64, ARMv5, mips`. 
Lets do them all!

## Tools
To find ROP gadgets, my regular go-to tool is `ropper`. \
Just in case it might miss few gadgets here and there, I would also use `ROPGadget` (which is abit more recommended for ARM architecture). \
`pwntools` is mandatory for such challenges.

As a debugger, I'd use `pwndbg`. \
It has great integration with `pwntools`, which can automate debugging tasks by running `gdb` from a pythonic script. 

`checksec` is good to learn the challenge's mitigations settings. `rabin2` is also an option.

## Tips

1. Note that for stripped binaries, external functions (that are being imported by the binary) names may be resolved from their shared objects:

```bash
nm -u <binary>  # list external functions
rabin2 -qs <binary> | grep -ve imp -e ' 0 '  # try to list internal functions
```

2. The ROP Emporium challenges contains a `usefulGadgets` symbol, which marks the address of added gadgets to the binary. 

3. In order to find strings (avoid using `strings` binary):

```bash
rabin2 -z split
```

4. Make sure the stack is 16-Byte aligned before `call` instruction.

5. When debugging with GDB, calling `system` with invalid string may start `/usr/bin/bash`. 
   This works specifically within a debugger, not the remote target. 
   
6. Use `ltrace` to track library calls. 

## x86

```bash
$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped

$ checksec ret2win32
[*] '/home/itay/projects/rop_emporium/rop_emporium_all_challenges/ret2win32/ret2win32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

This challenge reads 56 bytes into 32 stack buffer, via `read` call. \
A function named `ret2win` prints the flag, and located within `0x804862c`. 

The amount of needed garbage bytes is 44:

```bash
$ sudo dmesg -C
$ echo `python -c 'print("A"*44 + "B" * 4)'` | ./ret2win32
$ sudo dmesg
[ 4285.835462] show_signal_msg: 7 callbacks suppressed
[ 4285.836441] ret2win32[32818]: segfault at 42424242 ip 0000000042424242 sp 00000000ff9c0940 error 14 in libc.so.6[f7c00000+20000]
[ 4285.836884] Code: Unable to access opcode bytes at RIP 0x42424218.
```

The exploit for x86 is simple (would use it as a skeleton for most of the challenges):
[solution][script-x86]

## x64

For x64, mostly the padding is being changed (now to 40 bytes), as well as usage of 8-byte addresses. \
However, while executing the adapted exploit, the goal flag function was indeed hit, but crashed upon the call for `system(""/bin/cat flag")`.

After some quick research, I've found out it was due to mis-aligned `rsp` value:

```bash
(gdb) x/10i $rip
=> 0x400769 <ret2win+19>:       call   0x400560 <system@plt>
   0x40076e <ret2win+24>:       nop
   0x40076f <ret2win+25>:       pop    rbp
   0x400770 <ret2win+26>:       ret
   0x400771:    cs nop WORD PTR [rax+rax*1+0x0]
   0x40077b:    nop    DWORD PTR [rax+rax*1+0x0]
   0x400780 <__libc_csu_init>:  push   r15
   0x400782 <__libc_csu_init+2>:        push   r14
   0x400784 <__libc_csu_init+4>:        mov    r15,rdx
   0x400787 <__libc_csu_init+7>:        push   r13
(gdb) p $rsp
$1 = (void *) 0x7fff7801efa8
```

Originally, I've jumped to the start of `ret2win == 0x400756`. \
However, I can simply skip over the new frame opening `push rbp, mov rbp, rsp` and just jump directly to printing the flag, e.g `0x400764`. \
That way, by avoiding the extra push, the stack should be aligned correctly. 

[solution][script-x64]

[script-x86]: https://github.com/itaysnir/ROP-Emporium-Solutions/blob/main/ret2win/x86/exploit.py
[script-x64]: https://github.com/itaysnir/ROP-Emporium-Solutions/blob/main/ret2win/x64/exploit.py

