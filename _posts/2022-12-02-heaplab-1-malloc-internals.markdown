---
layout: post
title:  "HeapLAB 1 - Malloc Internals"
date:   2022-12-02 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General GLIBC Note

The glibc `.so` usually can be found under `/lib/x86_64-linux-gnu/libc.so.6`. 

It can be easily found by issuing:

```bash
ldd /bin/ls
```

Note this path is usually a symlink, pointing towards the exact version of libc.

The exact libc version can be found by either executing `ldd --version`, or running `./libc.so.6` (which would also print the generating compiler version).

## Pwndbg Note

`pwndbg` is extremely useful for heap exploitation. 
With DWARF debug symbols, it can also display the source code along with the analysis. 

In order to display only the source code panel, issue:

```bash
set context-sections code
```

And the source would be printed by issuing `context`

The different mapped memory regions (such as heap) can be seen via `vmmap`.

Issue `n` (next) to navigate to the next line, stepping over a function call. 

Issue `vis` (vis_heap_chunks) to display the state of the heap chunks. \
Pwndbg shows the different chunks types with different colors, which is extremely convenient. 

## Malloc Internals

### Dynamic Memory

`malloc` provides dynamic memory to running process.

It consists of arenas, multiple heaps and chunks. \
Arenas are structs, used to administrate heaps. 

`malloc` uses the arenas and the heaps in order to transact chunks of memory to a process.


### Malloc Call

Analysing `void *a = malloc(9)` : 

```bash
pwndbg> vis
0x602000        0x0000000000000000      0x0000000000000021      ........!.......
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000020fe1      ................         <-- Top chunk
pwndbg> p a
$1 = (void *) 0x602010
```

Note there were actually 32 allocated bytes - 8 bytes for the header, and 24 bytes data. \
This is because the minimal size of `malloc()` is actually 24-bytes data chunk. \
Note this even holds for `malloc(0)`! \ 
`malloc(24)` would allocate exactly 24-bytes of data (+8 bytes header).

### Chunk Size

The first 8 bytes represents the `size` field of the chunk. 
It contains the total number of bytes (including the header) that make up the chunk. 

The allocated chunk size is 32 bytes, however we see the registered size is acctually 0x21. \
That is because of allocations being made on 16-byte granularity. 

Therefore, the least significant nibble isn't interpreted as part of the size. Instead, it represents `flags`. 

### Chunk Flags

The lsb (0x1) inidicates `prev_inuse` flag.\
This flag means the previous chunk (located in lower memory than the current chunk) is allocated (used) by the program. 

If this is clear, the previous chunk is free. 

Note the first chunk's `prev_inuse` flag is always set (as it have no previous chunk). 

The second bit (0x2) represents `IS_MMAPPED` - inidicates whether this chunk was allocated via `mmap` call (instead of `malloc`). 

The third bit (0x4) represents `NON_MAIN_ARENA`. When set indicates this chunk does not belong to the main arena (arena of the main thread of execution). 

### Top Chunk

Also referred as *the wilderness*, is the last chunk on the heap. \
On my example, it contains the value of `0x0000000000020fe1`. 

This is the size field of the top chunk.

By issuing `vmmap`, we can see the total size of the heap is `0x21000` bytes. \
`malloc` treats the remaining, usused, memory of the heap memory as a single large chunk - the top chunk (highest address). 

It means `malloc` may tear down a heap memory from the top chunk, assign its metadata field, and returns a pointer towards the user data memory. 

In case there is no enough available memory at the top chunk, `malloc` call may extend the heap mapped memory region, hence enlarging the top chunk. 

Note that most versions of glibc does not perform any integrity checks on the value of the top chunk's `size` - allowing attacking such as *House of Force*.

### Hole

There appears to be a "hole" at the first 8 bytes on the heap. This is because malloc assumes the metadata starts 16 bytes before the user data. 
