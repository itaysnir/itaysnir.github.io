---
layout: post
title: "Pwn College - AArch64"
date: 2024-05-26 19:59:45 +0300
categories: jekyll update
---

**Contents**

- TOC
  {:toc}

## Overview

Up to ARMv7, only ARM32 instruction set was supported. It was based on ARMV7-A profile, used mostly in mobile devices and embedded.
Since ARMv8, A32(ARM-32), T32(Thumb) A64(AArch-64) are supported. \
Notice that aarch64 is fixed length 32-bit instruction set, and the 64 refers to the user of the instruction by the execution state (registers, for example), not to the size of the instruction in memory. \
In addition to the major ISA addition, 31 general-purpose registers are supported (64-bit wide), instead of previous 16 (32-bit wide). Moreover, ARMv8 introduces multiple exception levels (`EL0 - EL3`), as well as the Trustzone, and HW-based virtualization. \
For this module, I will mainly focus on `ARMv8`, and `AArch-64` in particular. \
Notice the ARM architecture defines several profiles, each targeting specific use cases - `ARMv8-A` (the most widely used - application, for general purpose application processors such as mobiles and servers. Allows features such as HW virtualization, TrustZone, AArch64 ISA), `ARMv8-R` (real-time profile, doesn't supports AArch64 ISA but only 32-bit operations), and `ARMv8-M` (microcontrollers, also doesn't supports AArch64).

I've used the following documentations: [A Profile docs][arm-a-docs], [AArch64 ISA][aarch64-instruction-set], [AArch64 Instructions][aarch64-instructions] .

### Thumb Mode

Exists only in ARM32, and refers to a 16-bit instruction set, T32. \
The motivation behind this, is mainly optimiziation of space and performance, and instruction-cache in particular.
The ARM processor can dynamically switch between the modes at runtime by using the LSb (T-bit) in the `CPSR` register. There are few special 32-bit instructions that were added to thumb-2 (extension), introduced in ARMv5.

### registers

31-general purpose regs. To refer to the whole 64-bit: `X0..X30`, and 32-bit: `W0..W30` (4 LSBs). \
For example:

```bash
ADD W0, W1, W2
ADD X0, X1, X2
```

Cool note - when a `W` register is written, top 32-bits are zeroed. \
In addition to general purpose regs, there's a separate 32 registers set for floating point and vector operations.
These regs are 128-bit, and can be accessed in several ways:

```bash
B0  # 8
H0  # 16
S0  # 32
D0  # 64
Q0  # 128
```

For example, floating point addition:

```bash
FADD D0, D1, D2
```

In addition, these regs may be referred as `V` registers - a vector.
In this case, it can be treated to contain multiple independent values, instead of single value, allowing vectorized operations:

```bash
FADD V0.2D, V1.2D, V2.2D
```

Which means each of the registers `Q0, Q1, Q1` are treated as `2 * D` separate registers, hence performing a vectorized operation of 64-bit add.

#### Other registers

Zero registers: `XZR, WZR`. Always read as `0`, ignore writes. \
Stack: `SP`, base address for loads and stores. Notice ARMv8-A has multiple stack pointers, each associated with a specific exception level. \
Link register: `LR`, also used as `X30`. To return from exceptions, `ELR_ELx` are used. \
Program counter: `PC` isn't a register in AArch64. However, we can read the current PC as follows:

```bash
ADR Xd, .
```

`ADR` calculates the address of a label, in this case `.`, and stores it within a register. \
Notice, in A32 and T32 `PC, SP` are general purpose registers - not in A64.

System registers: configure the processor, such as MMU. \
They cannot be used directly, but they can be read and written back:

```bash
# Read from system register
MRS        Xd, <system register>
# Write to system register
MSR        <system register>, Xn
```

System register names ends with `_ELx` (exception level - specifying the minimum necessary privilege).

### Data Processing

Operand 1 of an instruction would always be a register. \
Operand 2 will be either register of a constant. \
We can add `S` to an instruction, to set flags. For example, `ADDS` instead of `ADD`. \

`MOV` moves a constant or register. `MVN` moves the NOT.
Both of them only requires a single input operand:

```bash
MOV       X0, #1
```

Notice the `MOV` instruction only works for up to 16-bit immediates. \
There are similar operations for floating points, prefixed with an `F`, such as `FDIV`. \
For bit operations, `BFI` (bit field insertion) may be helpful, taking bits from source to dest. 
`UBFX` extracts a bit field. `RBIT, REV16` can reverse bit or byte order. 
Moreover, we can perform signed extension using `SXTx`, and unsigned extension using `UXTx`. Notice - `x` denotes the extension's granularity. For example, `SXTH` takes the bottom 2 bytes and sign-extends the register. 
We can add saturation to the instruction's suffix, to cause the result to use saturating arithmetic:

```bash
# Sign-extends assumed 16-bit value in W1
SXTH  W8, W1
# Adds 16-bit values, treating the result as saturated 16-bit
ADD   W0, W8, W0, SXTH
```

Regarding bit shifts, we can perform logical shifts using `lsl, lsr`. 

Two types of vector processing are available, NEON (advanced SIMD) and SVE. 

### Loads and stores

Handling with memory operations. Unlike x86, memory addresses cannot be accessed directly, but only using registers. 

```bash
LDR<Sign><Size>   <Destination>, [<address>]

STR<Size>         <Source>, [<address>]
```

For loads, the size is denoted by the register. For stores, we may use `STRH` to denote storage of 16-bit, for example. 
Moreover, we can use sign extension, for example `LDRSB`. \
A cool note is that we can use offsets for addressing:

```bash
LDR W0, [X1, #12]
```

Hence, reading 4-byt value from address `*(x1 + 12)`. \
Interestignly, there's a "pre-index" mode, denoted by `!`:

```bash
LDR W0, [X1, #12]!
```

Which is the same as above, but also updates the register. In this case, `x1` would be updated to `x1 + 12`. \
There's also a post indexing mode:

```bash
LDR W0, [X1], #12
```

Which first retrieves the content off `x1`, and then updates `x1`. 
This is popular for popping off the stack. 

A cool feature of ARM is dealing with pairs, which transfers two registers. 

```bash
# Load [X0] to W3, [X0 + 4] to W7
LDP        W3, W7, [X0]
# Store D0 to [X4], D1 to [X4 + 8]
STP        D0, D1, [X4]       
# Push X0 and X1 to the stack, writing at [SP - 16], [SP - 16 + 8], and updating SP value
STP        X0, X1, [SP, #-16]!
# Pop X0 and X1 off the stack, reading from [SP], and updating SP += 16
LDP        X0, X1, [SP], #16
```

**A critical note in AArch64, is that SP must be 128-bit aligned (0x10 byte)**. \
Another interesting note, is that there are special instructions for `memcpy, memset` operations - `CPYx, SETx`. 

### Control Flow

Unconditional jump: `B <label>`, and `BR` (jump with register). \
Notice - the label jump is a PC-relative direct jump, limited to an offset ranging from `+- 128MB`. No such limitation for `BR`, which jumps to an absolute address within a register. \
Conditional jumps: simply `B.<cond> <label>`. This time, the offset is limited to `+-1MB`. 
The condition is checked against the ALU flags stored in the `PSTATE` register. May be set within a previous `CMP` instruction. \
Another interesting instructions are `CBZ, CBNZ`, which allows performing both comparision (to zero) and jumping to the label if needed, at the same time. 
`TBZ, TBNZ` are similar variants, but also allows specifying a particular bit offset for the comparision. \
The possible conditional jump suffixes may be found [here][conditional-jump-suffix]

### Function calls

Adding `L` to the `B, BR` instructions turns them into a branch with link. 
This means the return address is written into `LR == X30` as part of the branch. 
The `RET` instruction performs indirect jump to the address in the link register. \
The procedure call standard:

1. Parameters passed in `X0..X7`. Further arguments are passed on the stack

2. Return values in `X0..X1`

3. All registers from `X0-X15` are corruptible registers. 

4. Registers `X19..X28` are callee-saved registers. Hence, they must be saved on the stack, and then restore them from the stack. 

5. Registers `X8(XR), X16(IP0), X17(IP1), X18(PR), X29(FR), X30(LR)` are special. `XR` is the indirect result register. For example, to support a function that returns a struct, the memory for the struct would be allocated by the caller, and `XR` is a pointer to the memory allocated by the caller. `IPx` are intra-procedure-call corruptible registers (may be corrupted even between the call time and first function execution), used by linkers to insert small pieces of code between caller and callees, for example - for branch range extension (as it is very limited in A64). 

### Syscalls

Performed by `SVC` for supervisor call, exception targeting `EL1`. \
`HVC` for hypervisor call, targeting `EL2`, used by the OS (kernel) to call the hypervisor. \
`SMC` - secure monitor call, targets `EL3`, used by either the OS or the hypervisor to call the `EL3` firmware (not available at `EL0`).


## Challenge 1

```python
#!/bin/python
from pwn import *

context.arch = 'aarch64'
BINARY = '/challenge/run'
GDB_SCRIPT= '''
c
'''

def main():
    asm_bytes = asm('''
        MOV x1, #0x1337
    '''
    )

    log.info(f'asm_bytes: {asm_bytes} len: {len(asm_bytes)}')

    with process('/challenge/run') as p:
        p.send(asm_bytes)
        p.stdin.close()
        p.interactive()

if __name__ == '__main__':
    main()
```

## Challenge 2

We now want to load 4-byte immediate value into a register. \
We can do so using `movk`, which loads a value with a specific bitshift, retaining all other bytes.

```bash
asm_bytes = asm('''
    mov x1, #0xbeef
    movk x1, #0xdead, lsl 16
'''
)
```

## Challenge 3

```bash
asm_bytes = asm('''
    mul x3, x0, x1
    add x3, x3, x2
    mov x0, x3
'''
)
```

## Challenge 4

Same as above, but a single instruction. `MADD`.

```bash
asm_bytes = asm('''
    madd x0, x0, x1, x2
'''
)
```

## Challenge 5

Modulu - cannot be done in a single instruction. 

```bash
asm_bytes = asm('''
    udiv    x8, x0, x1
    msub    x0, x8, x1, x0
    '''
```

## Challenge 6

Retrieve 4'th byte:

```bash
 asm_bytes = asm('''
    lsl x0, x0, 32
    lsr x0, x0, 56
    '''
    )
```

## Challenge 7

Read from memory, perform operation, and store back. 

```bash
asm_bytes = asm('''
    mov x0, #0x4000
    movk x0, #0x4000, lsl 16
    movk x0, #0x1337, lsl 32

    mov x1, #0x4008
    movk x1, #0x4000, lsl 16
    movk x1, #0x1337, lsl 32

    ldr x0, [x0]
    ldr x1, [x1]
    add x2, x0, x1

    mov x3, #0x4010
    movk x3, #0x4000, lsl 16
    movk x3, #0x1337, lsl 32
    str x2, [x3]
    '''
    )
```

## Challenge 8

Memcpy of 0x10 bytes:

```bash
asm_bytes = asm('''
    mov x0, #0x4000
    movk x0, #0x40, lsl 16
    ldp x1, x2, [x0]
    stp x1, x2, [x0, #0x10]
    '''
    )
```

## Challenge 9

We'd like to push/pop qwords off the stack. 

```bash
asm_bytes = asm('''
    ldp x1, x2, [sp], #0x10
    ldp x3, x4, [sp], #0x10
    ldp x5, x6, [sp], #0x10
    ldp x7, x8, [sp], #0x10
    
    add x1, x1, x2
    add x3, x3, x4
    add x5, x5, x6
    add x7, x7, x8

    add x1, x1, x3
    add x5, x5, x7
    add x1, x1, x5

    mov x2, #8
    udiv x0, x1, x2
    str x0, [sp, #-0x10]!
    '''
    )
```

## Challenge 10

Swap register values, using 2 instructions. \
We can do so using the memory, by storing a pair in the opposite direction, and loading them. 

```bash
asm_bytes = asm('''
    stp x1, x0, [sp, #-0x10]!
    ldp x0, x1, [sp]
    '''
    )
```

## Challenge 11

Loop over an array, and compute its sum. 

```bash
asm_bytes = asm('''
    mov x2, xzr
    mov x3, xzr
    loop:
    cmp x2, x1
    b.ge done
        ldr x4, [x0]
        add x3, x3, x4

        add x0, x0, #8
        add x2, x2, #1
        b loop
    done:
        mov x0, x3
    '''
    )
```

## Challenge 12

Now do it with only 6 instructions.

```bash
asm_bytes = asm('''
    loop:
    ldr x3, [x0], #8
    add x4, x4, x3
    add x2, x2, #1
    cmp x2, x1
    b.ne loop

    done:   
    mov x0, x4
    '''
    )
```

## Challenge 13

Relative, absolute jumps. \
Only trick is to consider the relative jump is performed relative to the end of the jump instruction address, not its start. 
Hence, we'd need to subtract `4` bytes. 

```bash
asm_bytes = asm('''
    b start
    .rept 0x40 - 4
    .byte 0x61
    .endr

    start:
    ldr x1, [sp]
    mov x2, #0x3000
    movk x2, #0x40, lsl 16
    br x2
    '''
    )
```

## Challenge 14

Average function. Usually, would have similar pattern:

```bash
# Stores previous FR, LR, on the stack.
# The stack pointer is decremented, to create a new frame.
stp x29, x30, [sp, #-0x30]!
# Set new frame pointer
mov x29, sp
# Now pushes stuff to the stack, creating locals
# This increments the sp value. 
# Finally, epilogue:
# Restore FR, LR
ldp x29, x30, [sp], #0x30
# Return to LR
ret
```

And the solution (notice, it takes time to execute, and also works without the assembly directives):

```bash
asm_bytes = asm('''
    .global calc_avg
    .type calc_avg, %function
    
    calc_avg:
    stp x29, x30, [sp, #-0x30]!
    mov x29, sp

    loop:
    ldr x3, [x0], #8
    add x4, x4, x3
    add x2, x2, #1
    cmp x2, x1
    b.ne loop
    done:   
    udiv x0, x4, x1

    ldp x29, x30, [sp], #0x30
    ret
    '''
    )
```

## Challenge 15

fib function. \
This one is abit tricky. 
The main caveat, is that we have to keep in mind that some of the registers may be corrupted in between calls. Hence, we'd have to use the stack frame to store intermediate values:

```bash
 asm_bytes = asm('''
 fib:
    stp x29, x30, [sp, #-0x10]!
    mov x29, sp
    sub sp, sp, 0x10
    stp x0, x2, [sp, #0]
   
    cmp x0, #1
    ble epilogue

    sub x0, x0, #1
    bl fib
    mov x2, x0
    str x2, [sp, #8]

    ldr x0, [sp, #0]
    sub x0, x0, #2
    bl fib

    ldr x2, [sp, #8]
    add x0, x0, x2

    b epilogue
    
epilogue:
    add sp, sp, 0x10
    ldp x29, x30, [sp], #0x10
    ret
    '''
)
```

## Conclusion

Cool module, basic must-knows within AArch64, not challenging at all. 


[arm-a-docs]: https://www.arm.com/architecture/learn-the-architecture/a-profile
[aarch64-instruction-set]: https://developer.arm.com/documentation/102374/0101/Overview
[aarch64-instructions]: https://developer.arm.com/documentation/ddi0602/2024-12/?lang=en 
[conditional-jump-suffix]: https://developer.arm.com/documentation/dui0801/d/dom1359731161338
