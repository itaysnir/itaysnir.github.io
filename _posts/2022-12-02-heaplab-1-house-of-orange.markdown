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

This technique consists of 3 stages. 

## File Stream Exploitation

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

## Unsortedbin Attack

### Chunk Fates

The `free` function may directly populate the `fastbins` (if the chunk size is below `0x80`), the `top_chunk` (if it is adjacent / consolidates with an adjacent chunk), the `unsortedbin` (if its not within the first two options) or the `tcachebin`. 

However, there are two more bins (`smallbins, largebins`) that *arent populated directly by the free() function*.

In fact, chunks may move from the `unsortedbin` to these two bins through a process known as *sorting*. \
This procedure may trigger during calls to `malloc()`!

### Smallbins

Doubly-linked, circular freelists. \
There are 62 smallbins - from size `0x20 to 0x3f0` (overlapping `fastbins` sizes). 

Their methodology is FIFO (like the `unsortedbin`, new chunk registered to the head, allocations are made from tail).

Like the `fastbins`, each bin contains chunks of the same size. 

### Largebins

Doubly-linked, circular freelists. \
However, each bin contains *range of sizes*, instead of a specific size. 

They operate differently, using a `skiplist`. 

### Unsortedbin Scanning

Sorting moves free chunks from the `unsortedbin` into the `small/largebins`. 

Issued once malloc searches an `unsortedbin` while trying to serve a request. 

Note: allocations from the `unsortedbin` are *exact fit*, meaning that by requesting `0x90` size chunk, it will only return `0x90` size chunk - even if larger ones are available. 

During the search for a matching chunk, Malloc sorts the not-adquate chunks from the `unsortedbin` to their respective `smallbin / largebin`. 

For example, requesting chunk `0x90` from the following `unsortedbin` (when the `0x90` bins are empty): `[0x100, 0x90, 0x400, 0x230]`, malloc will start searching the `unsortedbin` from back to front (as allocations are being started from the tail).

It will sort `0x230` to its smallbin, `0x400` to its largebin, and allocate the `0x90` chunk, as it is an exact fit. The chunk `0x100` remaines at the unsortedbin. 

There is exception to the exact-fit - called `last remainder`. 

Note that upon unlinking a chunk from the `unsortedbin` this way, it actually can perform an optimization, called *partial unlink*. \
Because the victim chunk is always the tail of the bin, partially unlinking is made by :

```c
(victim->bk)->fd = unsortedbin_head  // victim removed from the forward list
unsortedbin_head->bk = victim->bk  // victim removed from the backward list
```

Unlike the unlink macro / partial unlinks from the smallbins, unsortedbin partial unlinks are not subject to any integrity check. 

The idea is to overwrite `victim->bk`, then trigger partial unlink, writing the address of the unsortedbin to any arbitrary address we choose (see the first line of the C code above). \
Remember that the `victim->fd` is completely ignored within this partial unlinking, hence it may contain any arbitrary value we wish. 

The key note here, is that after unlinking the victim chunk, `unsorted_head->bk`, aka the tail of the unsortedbin, is the attacker data. \
It means that after sorting the victim chunk (in case it wasnt an exact fit), it will continue to search for chunks from this address. \
Therefore, usually it is easier to just perform an exact allocation to trigger the unlink. 

Example of overwriting arbitrary address (the heap first quadword) to the unsortedbin_head.

Initially, the following arena layout was made:

```bash
pwndbg> dq &main_arena 40
00007fb871b10b20     0000000100000000 0000000000000000
00007fb871b10b30     0000000000000000 0000000000000000
00007fb871b10b40     0000000000000000 0000000000000000
00007fb871b10b50     0000000000000000 0000000000000000
00007fb871b10b60     0000000000000000 0000000000000000
00007fb871b10b70     0000000000000000 0000000000758000
00007fb871b10b80     0000000000000000 00007fb871b10b78
00007fb871b10b90     00007fb871b10b78 00007fb871b10b88
00007fb871b10ba0     00007fb871b10b88 00007fb871b10b98
```

The top chunk ptr is stored at `0x00007fb871b10b78`. 
Moreover, `unsortedbin fd` and `unsortedbin bk`, both initially points toward `0x00007fb871b10b78`. 

After executing the unlink:

```bash
pwndbg> vis

0x2205000       0x00007f8abe9b1b78      0x0000000000000091      x...............  <-- unsortedbin[all][0]
0x2205010       0x0000000000000000      0x0000000002204ff0      .........O .....
0x2205020       0x0000000000000000      0x0000000000000000      ................
0x2205030       0x0000000000000000      0x0000000000000000      ................

pwndbg> dq &main_arena 20
00007f8abe9b1b20     0000000100000000 0000000000000000
00007f8abe9b1b30     0000000000000000 0000000000000000
00007f8abe9b1b40     0000000000000000 0000000000000000
00007f8abe9b1b50     0000000000000000 0000000000000000
00007f8abe9b1b60     0000000000000000 0000000000000000
00007f8abe9b1b70     0000000000000000 00000000022050b0
00007f8abe9b1b80     0000000000000000 0000000002205000
00007f8abe9b1b90     0000000002204ff0 00007f8abe9b1b88
00007f8abe9b1ba0     00007f8abe9b1b88 00007f8abe9b1b98
00007f8abe9b1bb0     00007f8abe9b1b98 00007f8abe9b1ba8
```

Meaning the first heap quadword was overwritten with the value of the unsortedbin fake chunk, that starts at `0x00007f8abe9b1b78`. 

This fake unsortedbin head chunk `fd = 0x00007f8abe9b1b88` was changed to `0x2205000`, and its `bk` was changed to `0x2204ff0` (because of the partial unlink, as I chose `victim->bk = heap - 16`). \
Note that the fake chunk `fd` was changed only because the length of the linked list was 1. \
In case there were more elements within the unsortedbin, its `fd` would remain being pointed to them. 

POC:

```python
# Request 2 chunks.
chunk_A = malloc(0x88)
# Guards against consolidation with the top chunk
chunk_B = malloc(0x18)

# Free "chunk_A".
free(chunk_A)

# Overwrite the bk of the unsorted victim chunk
new_bk = heap - 0x10
edit(chunk_A, p64(0) + p64(new_bk))

# Trigger the unsorted chunk unlink by allocating it
malloc(0x88)
```

So in short - the unsortedbin attack allows writing the address of the unsortedbin head (which is a arena address) toward an arbitrary memory address. 

Therefore, it is especially useful in order to leak an arena's address - which is a libc address in the case of `main_arena`. 


