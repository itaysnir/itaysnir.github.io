---
layout: post
title:  "IO Uring Notes"
date:   2022-09-10 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Linux Vectorized IO Syscall API
### readv(), writev()
In order to support SGL (scatter-gather-list) operations, linux introduces the readv() and writev() syscalls. 
These syscalls takes a ptr towards `struct iovec` array, as well as the `struct iovec` count. 

Each `struct iovec` represents a single buffer.
```c
struct iovec {
    void *iov_base;
    size_t iov_len;
}
```
Example usage:

```c
uint32_t count = 10;
uint32_t alignment = sysconf(_SC_PAGESIZE);
uint32_t size = 4 * sysconf(_SC_PAGESIZE); 

struct iovec *iovecs;
iovecs = malloc(sizeof(struct iovec) * count);
for (int i = 0 ; i < count ; i++)
{
    void *buf;
    posix_memalign(&buf, alignment, size);  // Allocates heap memory
    iovecs[i].iov_base = buf;
    iovecs[i].iov_len = size;
}

readv(file_fd, iovecs, count); // Read from the file into the allocated buffers
```

We can think of it this way - each of the `struct iovec` represents a different size "bucket". 
Upon read, the first "bucket" (iovec[0]) is being filled, up to its size- given by iovec[0].iov_len. 
Only after the first bucked was completely filled, the second bucket is being filled, and so on. 

While this sequential IO is very easy to grasp, for multithreaded applications it might be problematic. 

### preadv(), pwritev()
Another interesting syscall is `preadv()`. This is a combination of `readv()` and `pread`. 
Recall - `pread` syscall takes an additional `offset` parameter, Which is especially useful for multithreaded programs. How exactly this extra parameter allows MT?
By diving into the inner implementation of file descriptors in linux, we can see the following:
```c
//
// include/linux/fs.h
//

struct file {
        mode_t f_mode;
        dev_t  f_rdev;
        off_t  f_pos;            // each opened file has its own offset
        unsigned short f_flags;
        unsigned short f_count;
        unsigned short f_reada;
        struct inode * f_inode;
        struct file_operations * f_op;
};
```

As documented, *each opened file* has its own offset! 
Therefore, if multiple threads issue `read()` calls simultaneously, the `f_pos` field of the single opened file gets frenzikly-wrecked.  
`pread()`, on the other hand, allows multiple threads to read from the same fd, without being affected by the `f_pos` changes being made by other threads. 

As a side note - even more sophisticated schemes exists, such as `gread()` for [GPU-fs][GPU-fs]. Internally, it utilizes `pread()` calls. 
This, however, outside of the scope of this post. 

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
[GPU-fs]: https://github.com/gpufs/gpufs
