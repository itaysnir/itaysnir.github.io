---
layout: post
title:  "IO Uring Notes"
date:   2022-09-10 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Basics

## Installing liburing
Luckily, the authors of io_uring also created a user - libary, `liburing.h`. 
Since it isn't exported by the kernel, we have to install it manually.

The README file under `/tools/io_uring` (on the kernel tree) states the installation procedure:
```bash
git clone git://git.kernel.dk/liburing
make install
```

This will download and compile liburing. 
Now liburing.so is symlinked towards /usr/lib, and can be used for your C programs :)


## Awesome resources
1. [io uring examples][io-uring-examples]

[io-uring-examples]: https://unixism.net/2020/04/io-uring-by-example-article-series/

