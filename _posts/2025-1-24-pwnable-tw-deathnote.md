---
layout: post
title:  "Pwnable.tw - deathnote"
date:   2025-01-24 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## deathnote 

```bash
checksec death_note
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

3. The menu option is read via `read_int`. It ontains a vuln, as the buffer the number is read into isn't initialized. This means that `atoi` may return a value, partially based on uninitiallized bytes - potentailly leaking information. However, since we don't receive the return value (simply `Invalid choice` is being printed), it cannot serve as an information disclosure. Still, we may store there interesting buffers that would get parsed properly, such as `atoi("1;/bin/sh\x00")`. 

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

### Idea 1 - Heap Shellcode

My initial idea is very simple, and doesn't requires leakage, nor `show_note, del_note` handlers - but only one allocation. \
Using the OOB-Write primitive of `add_note`, overwrite the GOT entry of `exit / free / .fini_array[0]` with our `strdup`'ed name buffer. By doing so, code execution would be redirected into our chunk within the heap, but since the binary is non-NX - this is fine. From there, we would just need to write alphanumeric shellcode as the name (maximum of `0x50` bytes) and win. \
However, after playing abit with the binary I've realized that the non-NX only applies to the stack, not the heap. Hence, we'd probably like to store our shellcode somewhere on the stack. 

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
Notice that it actually performs a read of `*(addr)` of our wish - which means that it does a deref of the requested address, and reads from there. We can easily leak heap and libc addresses, for example by reading the `.bss stdout` pointer (which derefs libc, hence would leak the file stream content itself), or reading `plt` entries, for example:

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
As of heap pointers, we can use the tcache to perform leaks. \
Notice we cannot use the untruncated string vuln to perform leak, as right after the `name` buffer, the canary resides (which contains a nullbyte within its LSB). 

