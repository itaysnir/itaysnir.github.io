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
In order to support SGL (scatter-gather-list) operations, linux introduces the readv() and writev() syscalls. 
These syscalls takes a `struct iovec` array ptr, as well as its length. 

Each `struct iovec` represents a single buffer.
```C
struct iovec {
    void *iov_base;
    size_t iov_len;
}
```
Example usage:

```C
struct iovec *iovecs;
iovecs = malloc(sizeof(struct iovec) * count);
for (int i = 0 ; i < count ; i++)
{
    void *buf;
    posix_memalign(&buf, alignment, size);  // Allocate heap memory
    iovecs[i].iov_base = buf;
    iovecs[i].iov_len = size;
}

readv(file_fd, iovecs, count); // Read from the file into the allocated buffers
```


## Installing liburing
Luckily, the authors of io_uring also created a user - libary, `liburing.h`. 
Since it isn't exported by the kernel, we have to install it manually.

The README file under `/tools/io_uring` (on the kernel tree) states the installation procedure, along with extra examples:
```bash
git clone git://git.kernel.dk/liburing
make install
```

This will download and compile liburing. 
Now `liburing.so` is symlinked towards `/usr/lib`, and can be used for your C programs :)


## Awesome resources
1. [io uring examples][io-uring-examples]

[io-uring-examples]: https://unixism.net/2020/04/io-uring-by-example-article-series/

