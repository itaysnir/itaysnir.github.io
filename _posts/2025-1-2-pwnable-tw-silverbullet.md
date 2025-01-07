---
layout: post
title:  "Pwnable.tw - Silver Bullet"
date:   2025-01-2 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Silver Bullet

```bash
$ checksec ./silver_bullet
[*] '/home/itay/projects/pwnable_tw/silver_bullet/silver_bullet'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    Stripped:   No

$ file ./silver_bullet
./silver_bullet: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=8c95d92edf8bf47b6c9c450e882b7142bf656a92, not stripped
```

## Overview



