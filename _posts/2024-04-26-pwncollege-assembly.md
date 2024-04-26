---
layout: post
title:  "Pwn College - Assembly"
date:   2024-04-26 19:59:46 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module teaches basics of `x86-64`. \
I've added solutions for selected challenges.

## Setup

Disassemble:

```bash
objdump -d asm -M intel
```

Create shellcode without overhead:

```bash
gcc -nostdlib asm.s -o asm
objcopy -O binary -j .text ./asm ./asm_bytes
```

Template of the input `asm.s` file:

```bash
.globl _start
_start:
.intel_syntax noprefix
mov rdi, 0x1337
```

Challenges template using `pwntools`:

```python
import pwn
from glob import glob
pwn.context.arch = 'amd64'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')
assembly = """
mov rdi, 0x1337
"""
with pwn.process(glob("/challenge/embr*")) as p:
  pwn.info(p.readrepeat(1))
  p.send(pwn.asm(assembly))
  pwn.info(p.readrepeat(1))
```

## Challenge 1

```bash
cat asm_bytes | /challenge/embryoasm_level1
```

## Challenge 6

Registers `rdi` and `rsi` have dedicated 8-bit registers: `dil` and `sil`. 

## Challenge 17

```bash
.globl _start
_start:
.intel_syntax noprefix
jmp short .+0x53
.rept 0x51
nop
.endr
mov rdi, [rsp]
mov rbx, 0x403000
```

A much simpler approach is via labels, which `pwntools` assembly supports by default. 

Good to know - when it comes to jumps, there are 3 types:

relative \
absolute \
indirect (via register / memory location content)

For relative jumps, the count is calculated from the END of the jump instruction. \
Moreover, there are 3 types of relative jumps:

short (1 byte indicating the jump count, -128 +127) \
near (2 bytes indicating the jump, -65536, +65535) \
far (4 bytes indicating the jump) - Note this allows jumping to a different segment selector, aka different CS (code segment selector) value. 

*Some very important stuff i’ve learned from this challenge:*

1. Within intel, `jmp 0xBLABLA` instruction is ALWAYS an absolute jump. \
However, during the assembling of the instruction, it is transformed to relative jump behind the scenes. \
Therefore, in order to make a real absolute address jump, that wont get relocated, a use of register or a memory location is required.

```bash
mov rax, 0x403000
jmp rax
```

2. A cool thing to know about is the ‘dot’ addressing. \
Relative jumps are usually relative to the END of the command. \
In our case, it means `jmp 0x51`. However, simply jmp 
For conventient, we can state relative address corresponding to the START of the instruction as follow:

```bash
jmp short .+0x53
```

Note the instruction is 2 bytes long (short jmp), and both ‘dot’ and '+' are mandatory. \
The assembly encoding will fix the right offset, so that it will be calculated corresponding to the end of the instruction address.

3. Repeat specifier:

```bash
.rept <count>
nop
.endr
```

## Challenge 20

```bash
.globl _start
_start:
.intel_syntax noprefix
xor rax, rax
xor rbx, rbx
xor rdx, rdx
init:
    cmp rbx, rsi
    je final
    xor rax, rax
    mov eax, dword ptr [rdi+4*rbx]
    add rdx, rax
    inc rbx
    jmp init
final:
    mov rax, rdx
    xor rdx, rdx
    div rsi
```

For unsigned division, use `div`. Make sure to zero-out `rdx` prior to this.

For signed division, use `idiv`, with `cdq` prior to this. 

Also note that the divisor (`rsi`) should be of the same type of the dividend (`rax`) , e.g. NOT `esi`!

finally, note I’ve stored intermediate values via `eax`, and accumulated them in `rdx`. 

## Challenge 22

```bash
str_lower:                                                 
    push rbp
    mov rbp, rsp
    xor rax, rax
    cmp rdi, 0
    je done_l

calc_l:
    mov bl, byte ptr[rdi]
    cmp bl, 0
    je done_l
    cmp bl, 90
    jg calc_fin

    mov r13, rax
    mov rcx, rdi
    xor rdi, rdi
    mov dil, bl
    mov r12, 0x403000
    call r12
    mov byte ptr[rcx], al
    mov rdi, rcx
    mov rax, r13

    inc rax

calc_fin:
    inc rdi
    jmp calc_l

done_l:
    mov rsp, rbp
    pop rbp
    ret
```

## Challenge 23

```bash
most_common_byte:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx

calc_1:
    cmp rcx, rsi
    je calc_1_done
    xor rbx, rbx
    mov bl, byte ptr[rdi + rcx]

    mov r12, rbp
    sub r12, rbx
    inc byte ptr[r12]

    inc rcx
    jmp calc_1


calc_1_done:
    xor rbx, rbx
    xor rcx, rcx

calc_2:
    cmp rbx, 0xff
    jg done_l

    mov r12, rbp
    sub r12, rbx
    cmp byte ptr[r12], cl
    jle calc_2_done
    mov cl, byte ptr[r12]
    mov al, bl

calc_2_done:
    inc rbx
    jmp calc_2

done_l:
    add rsp, 0x200
    mov rsp, rbp
    pop rbp
    ret
```
