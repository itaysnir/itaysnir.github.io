---
layout: post
title:  "HeapLAB 1 - House of Force"
date:   2022-12-02 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General GLIBC Note

The glibc `.so` usually can be found under `/lib/x86_64-linux-gnu/libc.so.6`. 

It can be easily found by issuing:

```bash
ldd /bin/ls
```

Note this path is usually a symlink, pointing towards the exact version of libc.

The exact libc version can be found by either executing `ldd --version`, or running `./libc.so.6` (which would also print the generating compiler version).

## House of Force


