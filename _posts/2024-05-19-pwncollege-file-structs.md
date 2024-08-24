---
layout: post
title:  "Pwn College - File Struct Exploits"
date:   2024-05-19 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Recall how file descriptors work. \
An `fd` is just an entry within the `process file table` in the kernel. The `process file table` entries contains pointers to the kernel's `global file table`, which aggregates all open files within the system. An entry within the `global file table` contains the `file struct`, as well as `inode ptr`, `offset` (where in the file we're currently accessing) and more. \
Every time we would issue `read, write` operations, a context switch would be performed, and all of the above dereference chain would be triggered - non trivial amount of work. 

File streams are a libc optimization mechanism. The most notable API - `fopen, fread, fwrite`. Instead of working on `fd`s, they operate on file streams. \
The idea is instead of issuing lots of `read` or `write` syscalls, use an intermediate userspace buffer. This buffer is usually of fixed size (`~0x1000` bytes), allocated on the heap during the call to `fopen`. By doing so, instead of performing `read` syscall for every `0x20` bytes, we can do a single read syscall that would read `0x1000` bytes into the intermediate buffer, returning `0x20` bytes for every `fread` request. 

Part of its implementation, can be found under `struct_FILE.h`:

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
  ...
}
```

`flags` denotes whether the file was opened to read, write or both. 

`_IO_buf_base, _IO_buf_end` - related to the heap's allocated intermediate buffer. They store the start and end of this allocation. 

For the rest of the pointers, `_base` denotes the beggining of a region (read / write), `_end` the end of a region, and `_ptr` the current location we're working with. 

When we call `fread`, the program actually accesses the intermediate buffer. \
For the first read request, the buffer gets filled with about `0x1000` bytes. \
Both `_read_ptr, _read_base` are initially pointing to `_buf_base`, while `_read_end` to `_buf_end`. \
For every `fread` request, `_read_ptr` would be incremented. \
At some point, we would reach the end of the file - `_read_end`, which may be less than `_buf_end` in case the file size isn't aligned to the allocated interemediate buffer size. \
`fwrite` operates in a similar manner. Just recall the bytes stored within `_write_base` up to `_write_ptr` actually denotes the bytes **to-be-written** into the file. Only once the intermediate buffer would be filled, or a `flush` operation would be requested, the bytes would be actually written to the file.

## Arbitrary R/W




