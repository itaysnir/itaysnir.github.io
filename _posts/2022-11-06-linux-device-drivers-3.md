---
layout: post
title:  "Linux Device Drivers Chapter 3 - Char Drivers"
date:   2022-10-16 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview 

We will design a simple character driver, based on the `scull` char driver.

It will serve as a template for real drivers. 

The following [link][ldd3-github] contains updated examples from the book.

## Scull - Design

The following devices would be implemented:

`scull0` to `scull3`, each contains global (shared among all fds that have opened the device) and persistent (remains after close + reopen) memory arenas. 

`scullpipe0` to `scullpipe3`, serves as FIFO devices that act like pipes. \
One process writes to the device, and the other one reads its content. 

`scullsingle, scullpriv, sculluid, scullwuid` - similar to `scull0`, but with some limitations. 

## Majors and Minors

### Internal Representation

Recall that the major number identifies the driver associated with the device, and the minor number identifies the particular device. 

The `dev_t` type, as defined in `linux/types.h`, holds the device numbers. \
It may be created via `MKDEV(int major, int minor)`. \
The major and minor numbers should be obtained via dedicated macros, such as `MAJOR(dev_t dev)`. 

### Allocation of Device Numbers

The function `register_chrdev_region(dev_t first, unsigned int count, char *name)`, as declared in `linux/fs.h` statically allocates `count` minor numbers, starting from `MINOR(first)`. \
Note that for large allocation, it may spill over to the next major number. \
Among common devices, it is very popular to see statically assigned majors, which can be found under `Documentation/devices.txt`. \
Note that statically assigning major numbers is a bad paradigm - as there might be conflicts while deploying multiple drivers of different vendors. 

Another approach is dynamic allocation of these numbers - as sometimes the designed major number is only available during runtime. \
`alloc_chrdev_region(dev_t *dev, unsigned int firstminor, unsigned int count, char *name)` does this job, by using `dev` as an output parameter that holds the first allocated `dev_t`. \
Note that devices nodes cannot be created in advance in this case, because the major numbers may vary. \
Therefore, to load such driver, `insmod` invocation should also read `/proc/devices`, in order to obtain the special files majors. 

A cool hybrid approach utilizes the kernel module's parameters in order to allow both static and dynamic allocation:

```c
int scull_major =   0;
int scull_minor =   0;
module_param(scull_major, int, S_IRUGO);
module_param(scull_minor, int, S_IRUGO);

if (scull_major) {
		dev = MKDEV(scull_major, scull_minor);
		result = register_chrdev_region(dev, scull_nr_devs, "scull");
	} else {
		result = alloc_chrdev_region(&dev, scull_minor, scull_nr_devs,
				"scull");
		scull_major = MAJOR(dev);
	}
```

The cleanup function of the module should free the allocated numbers, via `unregister_chrdev_region`. 

## Important Structs

These involve `file_operations, file, inode`. 

### struct file_operations

`file_operations` is a struct of the operations handlers of the device. \
Note that some parameters uses the `__user` annotation to denote userspace buffers, that cannot be directly accessed by the kernel. \
For example, `ssize_t (*aio_read)(struct kiocb *, char __user *, size_t, loff_t)` - which performs an async read to the user's buffer. 

The `struct module *owner` field is used in order to prevent unloading of the module, while its operations are in use. \
For 99% of the cases, it should be initialized to `THIS_MODULE`.

Note that it is common to use tagged initialization of structs:

```c
struct file_operations scull_fops = {
 .owner = THIS_MODULE,
 .llseek = scull_llseek,
 .read = scull_read,
 .write = scull_write,
 .ioctl = scull_ioctl,
 .open = scull_open,
 .release = scull_release,
};
```

As it allows reordering of the structure members, and in some cases may yield better performance (for example by placing popular pointers in the same cache line). 

### struct file

Represents an open file, not specific to device drivers. \
We are particulary interested in the following fields:

`f_mode` - identifies the file I/O type - read, write or both. May be useful for permission checking during `open, ioctl` handlers. \
`f_pos` - the current I/O position. `read, write` handlers should update this position. \
`f_flags` - the permission + options flags, as defined in `linux/fcntl.h`, such as `O_RDONLY, O_NONBLOCK`. The driver should check if non-blocking operation has been requested. \
`f_op` - pointer to the `file_operations` associated with this file. It may be changed during runtime. \
`private_data` - driver specific data. \
`f_dentry` - the associated directory entry with the file. Usually drivers don't care about this. Note that the `struct inode` should be accessed via `filp->f_dentry->d_inode`.  

### struct inode

Internally represents files, different from the `file` structure that represents an **open** fd. 

`dev_t i_rdev` contains the actual device number. \
`struct cdev *i_cdev` contains the internal representation of the character device. 

## Char Device Registration

A char device is represented by `struct cdev`. \
It may be allocated as a standalone struct at runtime: 

```c
struct cdev *my_cdev = cdev_alloc( );
my_cdev->ops = &my_fops;
```

Or we may just embed it to an already existing `struct cdev`:

```c
void cdev_init(struct cdev *cdev, struct file_operations *fops);
```

Post initialization, we can tell the kernel the device is ready via:

```c
int cdev_add(struct cdev *dev, dev_t num, unsigned int count);
```

Usually we would call it with `count=1`, and adding the devices within a loop. 

Note it is common for a driver to define its own dedicated device struct, that would wrap an `struct cdev`, which serves as the interface driver<->kernel:

```c
struct scull_dev {
 struct scull_qset *data; /* Pointer to first quantum set */
 int quantum; /* the current quantum size */
 int qset; /* the current array size */
 unsigned long size; /* amount of data stored here */
 unsigned int access_key; /* used by sculluid and scullpriv */
 struct semaphore sem; /* mutual exclusion semaphore */
 struct cdev cdev; /* Char device structure */
};
```

## readv, writev

These handlers are pretty interesting, as they implement vectorized operations via `struct iovec`, as defined in `linux/uio.h`:

```c
struct iovec
{
  void __user *iov_base;
  __kernel_size_t iov_len;
};
```

In case those handlers are set to `NULL` within the fops, the kernel automatically implements these syscalls via multiple calls to `read, write` handlers. 


[ldd3-github]: https://github.com/martinezjavier/ldd3
