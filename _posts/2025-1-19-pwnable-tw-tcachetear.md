---
layout: post
title:  "Pwnable.tw - Tcache Tear"
date:   2025-01-19 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Tcache Tear 

```bash
$ checksec ./tcache_tear
[*] '/home/itay/projects/pwnable_tw/tcache_tear/tcache_tear'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled

$ file ./tcache_tear
./tcache_tear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a273b72984b37439fd6e9a64e86d1c2131948f32, stripped

$ strings libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Compiled by GNU CC version 7.3.0.
```

Cool, 64-bit binary, with almost all mitigations enabled, glibc 2.27. \
This glibc version is pretty old, hence I expect only basic tcache mitigations. 

## Debug

I've downloaded the dbian package, extracted it using glibc-all-in-one, and patched the binary via `patchelf`. 

```bash
wget https://launchpad.net/~adconrad/+archive/ubuntu/staging/+build/14768180/+files/libc6_2.27-3ubuntu1_amd64.deb .
```

## Overview

