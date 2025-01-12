---
layout: post
title:  "Pwnable.tw - Re-alloc"
date:   2025-01-12 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Re-alloc 

```bash
$ checksec ./re-alloc
[*] '/home/itay/projects/pwnable_tw/re-alloc/re-alloc'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    Stripped:   No

$ file ./re-alloc
./re-alloc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=14ee078dfdcc34a92545f829c718d7acb853945b, for GNU/Linux 3.2.0, not stripped
```

64-bit binary. 

## Debug

We're given libc-2.29, which isn't too old:

```bash
$ strings libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.
Compiled by GNU CC version 8.3.0.
```

I've install the corresponding debian package:

```bash
cd glibc-all-in-one
mkdir -p libs/2.29-0ubuntu2_amd64/
cd debs
wget https://launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428/+files/libc6_2.29-0ubuntu2_amd64.deb
cd ..
./extract debs/libc6_2.29-0ubuntu2_amd64.deb libs/2.29-0ubuntu2_amd64/
```

And used `patchelf` to mimic the remote environment precisely. 

## Overview

Menu-based challenge. Having the options of `alloc, realloc, free, exit`.



