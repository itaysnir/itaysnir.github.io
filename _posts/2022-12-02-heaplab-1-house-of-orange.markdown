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


