---
layout: post
title:  "Pwn College - Assembly"
date:   2024-04-26 19:59:44 +0300
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
Relative jumps are usually relative to the END of the command. 
In our case, it means jmp 0x51.  However, simply jmp 
For conventient, we can state relative address corresponding to the START of the instruction as follow:
