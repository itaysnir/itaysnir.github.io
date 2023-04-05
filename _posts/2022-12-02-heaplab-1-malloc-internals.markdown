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
Pwndbg shows the different chunks types with different colors, which is extremely convenient. \
Another great command for learning about the heap's layout is `heap`. 


## Dynamic Memory

`malloc` provides dynamic memory to running process.

It consists of arenas, multiple heaps and chunks. \
Arenas are structs, used to administrate heaps. 

`malloc` uses the arenas and the heaps in order to transact chunks of memory to a process.


## Malloc Call

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

## Prev Size, Chunk Size

The first 8 bytes represents the `prev_size`. Meaning - the size of the previous chunk, *in case it isn't allocated!* (was freed). 

The second 8 bytes, `0x0000000000000021`, represents the `size` field of the chunk. \
It contains the total number of bytes (including the chunk header) that make up the chunk. 

The allocated chunk size is 32 bytes, however we see the registered size is acctually 0x21. \
That is because of allocations being made on 16-byte granularity. 

Therefore, the least significant nibble isn't interpreted as part of the size. \
Instead, it represents `flags`. 

## Chunk Flags

The lsb (0x1) inidicates `prev_inuse` flag.\
This flag means the previous chunk (located in lower memory than the current chunk) is allocated (used) by the program. 

If this is clear, the previous chunk is free. 

Note the first chunk's `prev_inuse` flag is always set (as it have no previous chunk). 

The second bit (0x2) represents `IS_MMAPPED` - inidicates whether this chunk was allocated via `mmap` call (instead of `malloc`). 

The third bit (0x4) represents `NON_MAIN_ARENA`. When set indicates this chunk does not belong to the main arena (arena of the main thread of execution). 

## Top Chunk

Also referred as *the wilderness*, is the last chunk on the heap. \
On my example, it contains the value of `0x0000000000020fe1`. 

This is the size field of the top chunk.

By issuing `vmmap`, we can see the total size of the heap is `0x21000` bytes. \
`malloc` treats the remaining, usused, memory of the heap memory as a single large chunk - the top chunk (highest address). 

It means `malloc` may tear down a heap memory from the top chunk, assign its metadata field, and returns a pointer towards the user data memory. 

In case there is no enough available memory at the top chunk, `malloc` call may extend the heap mapped memory region, hence enlarging the top chunk. 

Note that most versions of glibc does not perform any integrity checks on the value of the top chunk's `size` - allowing attacking such as *House of Force*.

## Heaps

Heaps can be created, extended, trimmed or destroyed. \
They are administrated by the `arena` structure, where their administration is different depending on whether they belong to the `main arena` or not. 

Heaps for non-main arena are created via the `new_heap()` function. \
They are created with a fixed size, which can be changed via the `grow_heap()` and `shrink_heap()` functions. They can be deleted via the `delete_heap()` macro, wrapped by `heap_trim()`.

The main arena heaps are changed via the `brk` syscall. 


## free()

Chunks can be in one of two states: *allocated* or *free*. 

The goal `free` is to recycle the memory that was being used by the chunk.

From malloc's view, once a chunk is unallocated, it is linked into *one of several free lists, called bins*.

The following struct represents an unallocated chunk generic struct:

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk, if it is free. */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;                /* double links -- used only if this chunk is free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if this chunk is free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```

It is important to understand, that the various fields of `malloc_chunk` have different meanings for allocated and unallocated chunks. 

Both allocated and unallocated chunks, always starts with 16 bytes: of `prev_size` and `size`. 

However, for allocated chunk, at the offset of `fd` - the `user_data` lays. \
Equivalently, once a chunk is freed, the first 8 bytes of the chunk's user data is repurposed as a forward pointer, `fd`. 

The 2nd quadword repurposed as a backward pointer, `bk`. 

Important notes:

1. All bins: `unsortedbins, smallbins, largebins, fastbins, tcachebins` use the `fd` ptr. 

2. Only doubly linked lists, `unsortedbins, smallbins` use the `bk` ptr. 

3. Only `largebins` use `fd_nextsize` and `bk_nextsize`. 

4. Some bins support consolidation (coalescing) of chunks. \
In such cases, the last quadword of a free chunk's userdata repurposed as a `prev_size` field of the next chunk. 

This field presence is accompanied by clearing the next chunk's `PREV_INUSE` bit - meaning it exists only for unallocated chunks. 

5. All of the above means that when a chunk is freed, up to 5 quadwords (`fd, bk, fd_nextsize, bk_nextsize, prev_size`) of its user data are repurposed as malloc metadata - and in the case of `prev_size` - becomes a part of the succeeding chunk. 

6. GLIBC ver `> 2.29` introduces tcache double-free mitigation. \
In such case, the 2nd quadword of free chunks (`bk`) at the `tcachebin` get repurposed as `key` field. \
There is no uses for `bk, fd_nextsize, bk_nextsize, prev_size` within the `tcachebin`.


## fastbins

One type of bins are the `fastbins` freelists (`bin == list` within malloc's maintainers dictionary).

Fast - because the process of recycling chunks from these freelists is fast.

The fastbins are `singly linked, non-circular` freelists. 

Each fastbin holds free chunks of a *specific size*. 

They follow LIFO methodology - meaning freeing a chunk into a fastbin links it into the `head` of that fastbin, and would be the first chunk to be allocated. 

Important note - free chunks are linked towards the `fastbin` only if their `tcachebin` is full, therefore the `fastbin` searches are performed after a `tcachebin` search. 

### Demo

`pwndbg` allows viewing the fastbins easily, via the `fastbins` command:

```bash
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

Meaning there are 7 "default conditions" fastbins - each corresponds to a different unallocated chunk size (can be increased by `mallopt()` - which modifies `global_max_fast`). 

Lets say i've allocated 3 chunks, each is of 24-bytes user content (32-byte including the header):

```c
void* a = malloc(1);
void* b = malloc(1);
void* c = malloc(1);
```


```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000021      ........!.......
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000021      ........!.......
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000021      ........!.......
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000020fa1      ................    <-- Top chunk
```

Upon calling `free` on the first allocated chunk:

```c
free(a);
```

The layout of the heap wasn't changed at all (as can be seen via `vis`), however `pwndbg` notes the first chunk is now part of the 0x20 bin of the fastbins:

```bash
pwndbg> fastbins
fastbins
0x20: 0x602000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

This information is retrieved from the `main arena` of this heap.

By executing:

```c
free(b);
free(c);
```

The following heap layout is obtained (each freed chunk is replaced to the head of the fastbin):

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][2]
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][1]
0x602030        0x0000000000602000      0x0000000000000000      . `.............
0x602040        0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][0]
0x602050        0x0000000000602020      0x0000000000000000        `.............
0x602060        0x0000000000000000      0x0000000000020fa1      ................         <-- Top chunk
pwndbg> fastbins
fastbins
0x20: 0x602040 —▸ 0x602020 —▸ 0x602000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

Note that `prev_inuse` bit is still set! This is because fastbins are the exception for this bit usage. 


## Arenas

malloc administrates process heaps via arenas, described by the `malloc_state` struct. 

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);
  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];
  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;
  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;
  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;
  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;
  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */

  INTERNAL_SIZE_T attached_threads;
  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

typedef struct malloc_state *mstate;
```

One (non-main) arena may administrate multiple heaps. 

For every time a *thread* issues a call for `malloc`, a new arena and heap are being initialized for its use. \
There is, however, a limit of the number of arenas - depending on the number of cores. 

New arenas are created by calling `_int_new_arena()`, and initialized via `malloc_init_state()`. 

Each arena contains the *heads* of each of the mentioned freelists - enabling access to each of the freed chunks.


### Main Arena

The main thread gets a special arena - the `main arena` - which resides within the libc data section.  

By default, `pwndbg` is configured to parse the main arena information - hence displaying the freelists associated with the main arena. 

There are few commands `pwndbg` supports, related to arenas:

```bash
pwndbg> pwndbg arena
arena                Print the contents of an arena, default to the current thread's arena.
arenas               List this process's arenas.
bins                 Print the contents of all an arena's bins and a thread's tcache, default to the current thread's arena and tcache.
fastbins             Print the contents of an arena's fastbins, default to the current thread's arena.
largebins            Print the contents of an arena's largebins, default to the current thread's arena.
smallbins            Print the contents of an arena's smallbins, default to the current thread's arena.
top_chunk            Print relevant information about an arena's top chunk, default to current thread's arena.
unsortedbin          Print the contents of an arena's unsortedbin, default to the current thread's arena.
vis_heap_chunks      Visualize chunks on a heap, default to the current arena's active heap.
```

There is actually a symbol, exported by glibc: the `main_arena`.

Parsing its content:

```bash
pwndbg> x/20gx &main_arena
0x7ffff7dd0b60 <main_arena>:    0x0000000000000000      0x0000000000000001
0x7ffff7dd0b70 <main_arena+16>: 0x0000000000602000      0x0000000000000000
0x7ffff7dd0b80 <main_arena+32>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b90 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0ba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bc0 <main_arena+96>: 0x0000000000602060      0x0000000000000000
0x7ffff7dd0bd0 <main_arena+112>:        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0
0x7ffff7dd0be0 <main_arena+128>:        0x00007ffff7dd0bd0      0x00007ffff7dd0bd0
0x7ffff7dd0bf0 <main_arena+144>:        0x00007ffff7dd0be0      0x00007ffff7dd0be0
```

The first quadword of the arena (`0x0000000000000000`) stores the `libc_mutex` as well as `flags` for the arena. \
Each malloc call locks an arena's mutex before requesting heap memory from it.

The second quadword of the arena (`0x0000000000000001`) is a boolean, indicates the `fastbins` aren't empty. \
This field present in glibc `> 2.27`, prior versions had it as part of the `flags` field. 

Afterwards, an array of the head pointers towards the fastbins is located. \
`0x0000000000602000` is a pointer towards the header chunk of the `fastbin[0x20]`. 

After the `fastbins` array, a pointer towards the top chunk is presented (`0x0000000000602060`). \
There is only one top chunk per arena. \
Requests would be served by the top chunk only if there are no other adequate bins within this arena. \
In case it is too small (`< mmap_threshold`), malloc attempts to grow the heap via `sysmalloc` - to extend the top chunk. \
In case that fails, a *new heap is allocated - and becomes the top chunk of that arena*. \
The remaining memory in the old top chunk is freed. \
Malloc keeps track of the remaining top chunk memory using its `size` field only (the core idea behind `House of Force`). 

## Unlinking

When calling `free` on a chunk size that corresponds to a `fastbin`, it have no impact on the surrounding chunks. \
Meaning - the heap content remains exactly the same (even the `PREV_INUSE` flag, doesn't hold for `fastbins`). 

However, upon freeing an `unsortedbin` size chunk, the heap layout changes.

Usually `partial unlink` refers to `unsortedbin, smallbin` unlinking, where `full unlink`refers to `largebin, bitmap search` unlink. 

Assume the following code:

```c
void* a = malloc(0x88);
void* b = malloc(0x88);
free(b);
```

Before `free`:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000000      0x0000000000000091      ................
0x6020a0        0x0000000000000000      0x0000000000000000      ................
0x6020b0        0x0000000000000000      0x0000000000000000      ................
0x6020c0        0x0000000000000000      0x0000000000000000      ................
0x6020d0        0x0000000000000000      0x0000000000000000      ................
0x6020e0        0x0000000000000000      0x0000000000000000      ................
0x6020f0        0x0000000000000000      0x0000000000000000      ................
0x602100        0x0000000000000000      0x0000000000000000      ................
0x602110        0x0000000000000000      0x0000000000000000      ................
0x602120        0x0000000000000000      0x0000000000020ee1      ................         <-- Top chunk
```

After `free`:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................
0x602010        0x0000000000000000      0x0000000000000000      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000000      0x0000000000020f71      ........q.......         <-- Top chunk
```

Meaning the `b` chunk was completely coalesced to the `top chunk`!

The following rule holds:

*In case a chunk adjacent to the top chunk is freed, and it does not qualify for any fastbin, it will be coalesced to the top chunk*

Indeed, we can see the `unsortedbin` remained empty upon `free(b)`. 

### unsortedbin

There is only *one* `unsortedbin` per arena. \
This is a doubly-linked (uses `fd, bk` ptrs), circular list, that *holds chunks of any size*. 

Therefore, the `main_arena` only contains two pointers of the `unsortedbin`: `unsortedbin_fd, unsortedbin_bk`.

Freed chunks are registered within the `unsortedbin` head. \
Unlike `fastbins`, allocations are being made from the *tail* of the bin. 

In case we would `free` a non-top-chunk-adjacent `unsortedbin` chunk, few heap changes would occur:

1. The `PREV_INUSE` flag of the succeeding chunk is cleared.

2. The last quadword of the freed chunk `user_data`, now repurposed as the `PREV_SIZE` field of the succeeding chunk. 

3. The `fd, bk` ptrs of the freed chunks are set.

Note: upon freeing the first `unsortedbin` chunk, its `fd, bk` ptrs would point towards a *fake chunk* on the main arena (where its `PREV_SIZE` field repurposed as the `top_chunk` ptr).

This fake chunk's `fd, bk` ptrs are initialized to point toward the freed unsorted chunk:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000091      ................         <-- unsortedbin[all][0]
0x602010        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0      ................
0x602020        0x0000000000000000      0x0000000000000000      ................

pwndbg> x/20gx &main_arena
0x7ffff7dd0b60 <main_arena>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd0b70 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b80 <main_arena+32>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0b90 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0ba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7ffff7dd0bc0 <main_arena+96>: 0x0000000000602140      0x0000000000000000
0x7ffff7dd0bd0 <main_arena+112>:        0x0000000000602000      0x0000000000602000
```

### Consolidation

Upon freeing the two chunks allocated above, a *coalescing* is being made - hence creating a large, freed hole within the heap:

```bash
pwndbg> vis

0x602000        0x0000000000000000      0x0000000000000121      ........!.......         <-- unsortedbin[all][0]
0x602010        0x00007ffff7dd0bc0      0x00007ffff7dd0bc0      ................
0x602020        0x0000000000000000      0x0000000000000000      ................
0x602030        0x0000000000000000      0x0000000000000000      ................
0x602040        0x0000000000000000      0x0000000000000000      ................
0x602050        0x0000000000000000      0x0000000000000000      ................
0x602060        0x0000000000000000      0x0000000000000000      ................
0x602070        0x0000000000000000      0x0000000000000000      ................
0x602080        0x0000000000000000      0x0000000000000000      ................
0x602090        0x0000000000000090      0x0000000000000090      ................
0x6020a0        0x0000000000000000      0x0000000000000000      ................
0x6020b0        0x0000000000000000      0x0000000000000000      ................
0x6020c0        0x0000000000000000      0x0000000000000000      ................
0x6020d0        0x0000000000000000      0x0000000000000000      ................
0x6020e0        0x0000000000000000      0x0000000000000000      ................
0x6020f0        0x0000000000000000      0x0000000000000000      ................
0x602100        0x0000000000000000      0x0000000000000000      ................
0x602110        0x0000000000000000      0x0000000000000000      ................
0x602120        0x0000000000000120      0x0000000000000020       ....... .......
0x602130        0x0000000000000000      0x0000000000000000      ................
0x602140        0x0000000000000000      0x0000000000020ec1      ................         <-- Top chunk
```

Key notes:

1. The succeeding fast chunk, whose size field was `0x21`, have turned off the `PREV_INUSE` bit. \
Moreover, its `PREV_SIZE` field has been set to `0x120`. 

2. The `fd, bk` ptrs of the freed chunks weren't set. \
Moreover, the `fd, bk` ptrs of the first freed chunk weren't changed at all. The `unsortedbin` wasn't changed. 

3. The size of the first freed chunk was increased from `0x91` to `0x121`

The consolidation algorithm:

1. Checks whether either adjacent chunk is available for consolidation, via the `PREV_INUSE` flags. \
In case this bit is on, it means consolidation with the previous chunk is possible. Malloc would find this chunk, via the `PREV_SIZE` field of the current chunk. \
In case this bit is off, it looks forward *two chunks*, using their `SIZE` fields, and checks the `PREV_INUSE` flag of the succeeding chunk next chunk (as this is the only way to know if the *SUCCEEDING* chunk is in use).

2. In case a consolidation candidate was found, it must remove the candidate from which ever freelist theyre already linked to. Otherwise, the chunk may get linked twiced. 

3. Malloc calculates the new large chunk size, and updates its `size` and `prev_size` fields. 

4. The new consolidated chunk is linked to the `unsortedbin`.

Note that multiple consolidations may occur with a single `free` call. \
For example, consolidating a preceding chunk, creating a large chunk that may be consolidated with the `top_chunk`, would result with a double consolidation.

The advantage of doubly-linked lists, is the fast unlinking algorithmm (which finds the preceding chunk in `O(1), read chunk->bk`), which cannot be performed on a singly-linked lists. 
