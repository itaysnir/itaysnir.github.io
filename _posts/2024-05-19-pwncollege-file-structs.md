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
  int _fileno;
}
```

`_fileno` denotes the underlying open file descriptor. 

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

First, we'd have to set the `flags` values to allow read or write operations. This includes setting the `_IO_MAGIC = 0xFBAD0000`, and the correct operation flag, whether `_IO_NO_READS` or `_IO_NO_WRITES`. \
Also notice there's `_IO_UNBUFFERED` magic, which would bypass R/W operations within the intermediate buffer.

### Arbitrary Write - Reading from stream to Arbitrary Memory

May be abit confusing, `read` is actually operation that writes data **into** memory. Hence, allows a write primitive. 

The idea is simple. We would trick the stream to "think" it have reached the read buffer end, hence needs to fetch another chunk into the intermediate buffer. \
By corrupting the interemediate buffer pointers, the data read from the stream would be written to memory of our wish. 

Requirements:

1. Adequate `flag` value

2. `read_ptr = read_end`

3. `buf_base = target_addr`

4. `buf_end = buf_base + length`

5. `buf_end - buf_base >= requested_bytes_to_read`

Clarification - `buf_end - buf_base` actually denotes the size of the intermediate buffer. Since streams reads chunks by filling the intermediate buffer, this size denotes the actual amount of bytes that would be read. \
Moreover, `requested_bytes_to_read` are the actual number of bytes requsted by the program's `fread` call. In case this amount would've been larger than the intermediate buffer size, one of two bad scenarios would be happening:

1. The intermediate buffer woulv'e been re-allocated

2. The destination buffer wouldv'e been written-on multiple times, overwriting itself. For example, for a buffer of length 0x20 and `fread` request of `0x30` bytes, the buffer would be filled, copied to the real destination, and filled with the rest of `0x10` bytes. This would destroy our write primitive. 

That's why it is important to make sure the size of the intermediate buffer is for sure larger than the requested size by the commercial stream function. 

Notice - **ALL** of the requirements can be supplied by simply setting all pointers to `NULL`, while pointing `buf_base` to target and `buf_end` to `target + target_length`. \
This is because libc does simple checks, such as `read_ptr == read_end` (which is satisfied in the case of both `NULL`..)

### Arbitrary Read - Writing from Arbitrary Memory to Stream

The idea is to put the stream into a state where it thinks it must flush the intermediate buffer. \
We would trick the `write` ptrs to our leak, hence it would be flushed into the stream. 

Requirements: 

1. Adequate `flags` for writing 

2. `write_base` as the memory to be leaked

3. `write_ptr` as `write_base + length`, where `length` is the amount of bytes we'd like to leak

4. `read_end == write_base` - libc constraint to cause flush. 

5. `buf_end - buf_base` >= `requested_bytes_to_write`. 

Notice - next bytes would be written right past the `write_ptr`. We would have to cause multiple writes in order to fill the buffer, and trigger the flush. 

We can achieve the arbitrary read primitive by setting all pointers to `NULL`, except for the `write_base, read_end` to point towards our leak, and `write_end` to its end. \


### Pwntools - FileStructure

Pwntools exports a convenient way to exploit file streams. \
We can generate `fp = FileStructure()` object, which would represent the native `struct FILE` of our desired platform (mostly, we would like to set `context.arch = 'amd64'`). \
We can set values manually, for example by using `fp.flags = 0xfbad0000`. \
We can also retrieve the bytes representing this object by calling `bytes(fp)`. 

Moreover, pwntools exports the ability to perform the R/W operations on the stream. For example, by calling `fp.read(target, targetLength)`, a file object with the appropriate values for the underlying pointers would be returned, such that the WRITE primitive would occur on the `target`. Notice `targetLength` must be larger than the amount of bytes requsted by `fread`, as it actually represents the size of the intermediate buffer. 

Another interesting feature of Pwntools is `FileStructure.struntil()` - which generates a `fp` object until certain members. \
May come handy, incase our primitive is a linear heap overwrite, and we don't like to overwrite other members, such as `_lock`. 








