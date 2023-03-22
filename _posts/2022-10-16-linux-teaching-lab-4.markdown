---
layout: post
title:  "Linux Kernel Lab 4 - Character Device Drivers"
date:   2022-10-16 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Hardware devices may be accessed by the user via special files, located under `/dev`, along with syscalls such as `open, read, write, close, mmap`, etc. \
The OS redirects these syscalls to their corresponding handlers, as defined by the device driver. \
The driver is usually a kernel module, that interacts with the hardware device. 

Character device drivers are managing relatively slow devices, with small amount of data. \
Usually there are no frequent `seek` queries towards the device data, as the data access is usually sequential on these devices (for example, keyboard, mouse, serial ports). \
The operations (e.g `read`) are performed byte by byte. 

The linux kernel offers a dedicated API for character device drivers, where system calls go directly to the driver (unlike block devices). 

## Majors And Minors

Devices has a unique fixed identifier associated with them. \
It consists of two parts: major and minor. \
The major stands for the device type (such as SCSI disk / IDE / Serial port, etc), and the second part identifies the device (first disk, second serial port, etc). 

The major identifies the **driver**, while the minor identifies each physical device served by the driver. 

For example:

```bash
$ ls -la /dev/sda* /dev/ttyS?
brw-rw---- 1 root disk    8,  0 Mar 10 00:32 /dev/sda
brw-rw---- 1 root disk    8,  1 Mar 10 00:32 /dev/sda1
brw-rw---- 1 root disk    8,  2 Mar 10 00:32 /dev/sda2
brw-rw---- 1 root disk    8,  3 Mar 10 00:32 /dev/sda3
crw-rw---- 1 root dialout 4, 64 Mar 10 00:32 /dev/ttyS0
crw-rw---- 1 root dialout 4, 65 Mar 10 00:32 /dev/ttyS1
crw-rw---- 1 root dialout 4, 66 Mar 10 00:32 /dev/ttyS2
crw-rw---- 1 root dialout 4, 67 Mar 10 00:32 /dev/ttyS3
crw-rw---- 1 root dialout 4, 68 Mar 10 00:32 /dev/ttyS4
crw-rw---- 1 root dialout 4, 69 Mar 10 00:32 /dev/ttyS5
crw-rw---- 1 root dialout 4, 70 Mar 10 00:32 /dev/ttyS6
crw-rw---- 1 root dialout 4, 71 Mar 10 00:32 /dev/ttyS7
crw-rw---- 1 root dialout 4, 72 Mar 10 00:32 /dev/ttyS8
crw-rw---- 1 root dialout 4, 73 Mar 10 00:32 /dev/ttyS9
```

### /dev/sda

We can see the `sda` is a block device, associated with major number `8`. \
Disk drivers have a major number of `8`, which assigns them as a SCSI block devices (hence `sd`). \
Hard drives that would previously be designated as `hd[a-z]` (usually means the old ATA subsystem) are now referred to as `sd[a-z]`, which is the most used way to refer to hard disks. \
Note that SCSI stands for *small computer system interface* - and is a smart bus (controlled by microprocessor) that allows adding up to 15 devices to the computer (HDAs, USB, printers, etc). 

Moreover, the `sda` driver has 4 "devices", having minors of `0-3`. \
Note  those aren't physical devices - they represent the partition number (there are up to 15 partitions per disk). \
If an another disk device would be presented, it will have the prefix `sdb`, and so on. 

We can learn more about the partition tables of devices via `fdisk`:

```bash
$ sudo fdisk -l 
Disk /dev/sda: 60 GiB, 64424509440 bytes, 125829120 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 8DD30760-4E1B-4E6C-95FB-F4D72B38D1CD

Device       Start       End   Sectors  Size Type
/dev/sda1     2048      4095      2048    1M BIOS boot
/dev/sda2     4096   1054719   1050624  513M EFI System
/dev/sda3  1054720 125827071 124772352 59.5G Linux filesystem
```

Cool - we can see the size of each partition (within sectors) and its type. 

The next command is `lsblk`, which displays the partitions in a tree-topology:

```bash
$ lsblk
sda      8:0    0    60G  0 disk
├─sda1   8:1    0     1M  0 part
├─sda2   8:2    0   513M  0 part /boot/efi
└─sda3   8:3    0  59.5G  0 part /var/snap/firefox/common/host-hunspell
```

### /dev/ttyS

The second type of devices we can see, are `ttyS` devices. \
There are 3 types of `tty` drivers: console, serial port and pty. \
The `console, pty` drivers are implemented, and probably the only ones needed of these types. \
Therefore, new `tty` drivers are usually serial port devices (such as `ttyUSB`).

The `/proc/tty/drivers` file represents the loaded `tty` drivers in the kernel:

```bash
$ cat /proc/tty/drivers
/dev/tty             /dev/tty        5       0 system:/dev/tty
/dev/console         /dev/console    5       1 system:console
/dev/ptmx            /dev/ptmx       5       2 system
/dev/vc/0            /dev/vc/0       4       0 system:vtmaster
dbc_serial           /dev/ttyDBC   240 0-63 serial
ttyprintk            /dev/ttyprintk   5       3 console
max310x              /dev/ttyMAX   204 209-224 serial
serial               /dev/ttyS       4 64-111 serial
pty_slave            /dev/pts      136 0-1048575 pty:slave
pty_master           /dev/ptm      128 0-1048575 pty:master
unknown              /dev/tty        4 1-63 console
```

We can see that `ttyS` stands for a `serial` tty driver, having major number of `4`. \
Particular information about some specific driver may be found under `/proc/tty/driver/`, as well as `/sys/class/tty/`:

```bash
$ ls -la /sys/class/tty/ttyS?
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS0 -> ../../devices/pnp0/00:05/tty/ttyS0
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS1 -> ../../devices/platform/serial8250/tty/ttyS1
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS2 -> ../../devices/platform/serial8250/tty/ttyS2
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS3 -> ../../devices/platform/serial8250/tty/ttyS3
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS4 -> ../../devices/platform/serial8250/tty/ttyS4
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS5 -> ../../devices/platform/serial8250/tty/ttyS5
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS6 -> ../../devices/platform/serial8250/tty/ttyS6
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS7 -> ../../devices/platform/serial8250/tty/ttyS7
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS8 -> ../../devices/platform/serial8250/tty/ttyS8
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS9 -> ../../devices/platform/serial8250/tty/ttyS9
```

The driver tells the kernel the locations of the physical device associated with the tty device, by creating a symlink back to them. 

Moreover, by looking at `/proc/devices`, we can see the mapping of major number and relevant drivers, for all devices installed within the system. 

To send text to a terminal, we may redirect stdout of some CLI program to the appropriate special serial port (`ttyS`) file:

```bash
echo noder0 > /dev/ttyS0
echo noder1 > /dev/ttyS1
```

Each `ttyS` device is mapped to a different I/O address (bus-physical / PCI address) and IRQs. \
The `setserial` command shows this mapping:

```bash
$ sudo setserial -g /dev/ttyS0
/dev/ttyS0, UART: 16550A, Port: 0x03f8, IRQ: 4
```

Note that a `tty` is an abstraction for serial IO, for program that runs on a terminal (for example, it understands using backspace keys to erase characters before the program "sees" them). \
Serial device is a driver for real hardware, such as UART. \
It understands bit rates, parity, control lines, interrupts. 

Pseudo terminals have no physical connector on the PC, and are used to emulate serial port (they have no IO address, nor IRQ). \
If someone connects via telnet / ssh over the network, they may connect to a pseudo terminal port, such as `/dev/ptyp2`. \
Pseudo terminals come in pairs: the `pty` stands for the master controlling the terminal, and `tty` is the slave. \
They stand for the same port, but the slave is used by the network program, where the master is used by the userspace application. \
Modern unix doesn't use this approach, but uses a `pty master`, which is `/dev/ptmx`, which can supply a `pty` on demand. 

`/dev/tty` is the controlling terminal for the current process. \
By using `ps -a`, we can see the process <-> tty mapping:

```bash
$ ps -a 
 PID TTY          TIME CMD
   1339 tty2     00:00:00 gnome-session-b
   2783 pts/0    00:00:00 tmux: client
   4558 pts/2    00:00:00 ps
```

Note that `/dev/tty` stands for the current terminal that is now used:

```bash
$ tty
/dev/pts/1
```

In linux, the PC monitor is called console, and it has several special files - `ttyN`, which are called virtual terminals. \
Upon logging in, the console is set to `tty1`. We can switch to other virtual terminals using `ALT+F2` (for `tty2`). \
`tty0` is an alias for the current virtual terminal, and its where messages from the system are sent. 

Extra reading: [link1][ttyS], [link2][ttyS2], [link3][ttyS3], [link4][ttyS4], [link5][devices]. 

## Making New Device

We can create a new device (and type), via `mknod`:

```bash
mknod /dev/my_char_dev c 42 0
mknod /dev/my_block_dev b 240 0
```

## Char Devices - Structs

A character device is represented by `struct cdev`. \
The driver operations implementation utilizes three core structs: `struct file_operations, struct file, struct inode`. 

### struct file_operations

The character drivers receives **unaltered** system calls, issued by the users over device-type files. \
Implementation of the driver means an implementation of system calls, specific to files: `open, close, read, write, mmap, lseek`. \

The `file_operations` struct, under `linux/fs.h`, describes these operations:

```c
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    [...]
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    [...]
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    [...]
}
```

Note the system call signature differs from the driver's implementation (as the OS simplifies the driver implementation). \
These routines receive as parameters two structs: `file, inode`, which identifies the device type file.

### struct inode, struct file

`inode` represents a file from the FS view, and uniquely identifies it. \
It contains the size, rights, timestamps of the file. 

`file` also represents a file, but "closer" to the user's point of view. \
It conntains the file's `inode`, filename, opening attributes, position, etc. \
All open files at a given time, have an associated `file` struct. 

The inode is used to determine the major and minor of the device, and the file determines the flags with which the file was opened, as well as save and access private data. 

```c
struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep_links, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
	enum rw_hint		f_write_hint;
	atomic_long_t		f_count;
	unsigned int 		f_flags;
	fmode_t			f_mode;
	struct mutex		f_pos_lock;
	loff_t			f_pos;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct list_head	f_ep_links;
	struct list_head	f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
	errseq_t		f_wb_err;
	errseq_t		f_sb_err; /* for syncfs */
} __randomize_layout
```

The `file` struct contains `f_mode`, which stands for read / write. \
`f_flags` - which specifies the opening flags (`O_RDONLY, O_NONBLOCK`, etc). \
`f_op` - pointer to the `struct file_operations`. \
`private_data` - pointer that can be used to store device-specific data. The memory location should be assigned by the programmer. \
`f_pos` - the offset within the file. \
`f_inode` - the underlying inode. 

```c
struct inode {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;

#ifdef CONFIG_SECURITY
	void			*i_security;
#endif

	/* Stat data, not accessed from path walking */
	unsigned long		i_ino;
	/*
	 * Filesystems may only read i_nlink directly.  They shall use the
	 * following functions for modification:
	 *
	 *    (set|clear|inc|drop)_nlink
	 *    inode_(inc|dec)_link_count
	 */
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t			i_rdev;
	loff_t			i_size;
	struct timespec64	i_atime;
	struct timespec64	i_mtime;
	struct timespec64	i_ctime;
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	unsigned short          i_bytes;
	u8			i_blkbits;
	u8			i_write_hint;
	blkcnt_t		i_blocks;

#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t		i_size_seqcount;
#endif

	/* Misc */
	unsigned long		i_state;
	struct rw_semaphore	i_rwsem;

	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	unsigned long		dirtied_time_when;

	struct hlist_node	i_hash;
	struct list_head	i_io_list;	/* backing dev IO list */
#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback	*i_wb;		/* the associated cgroup wb */

	/* foreign inode detection, see wbc_detach_inode() */
	int			i_wb_frn_winner;
	u16			i_wb_frn_avg_time;
	u16			i_wb_frn_history;
#endif
	struct list_head	i_lru;		/* inode LRU list */
	struct list_head	i_sb_list;
	struct list_head	i_wb_list;	/* backing dev writeback list */
	union {
		struct hlist_head	i_dentry;
		struct rcu_head		i_rcu;
	};
	atomic64_t		i_version;
	atomic64_t		i_sequence; /* see futex */
	atomic_t		i_count;
	atomic_t		i_dio_count;
	atomic_t		i_writecount;
#if defined(CONFIG_IMA) || defined(CONFIG_FILE_LOCKING)
	atomic_t		i_readcount; /* struct files open RO */
#endif
	union {
		const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context	*i_flctx;
	struct address_space	i_data;
	struct list_head	i_devices;
	union {
		struct pipe_inode_info	*i_pipe;
		struct block_device	*i_bdev;
		struct cdev		*i_cdev;
		char			*i_link;
		unsigned		i_dir_seq;
	};

	__u32			i_generation;
  ...

	void			*i_private; /* fs or device private pointer */
} __randomize_layout;
```

In addition to many other members, it contains a union of `i_cdev, i_bdev`, which are pointers to structures that defines the device. \
These pointers can be used to infer the major and minor numbers of the device. 

## Operations Implementation

Usually upon implementing a driver, we would create a struct that contains the device information used in the module, such as the `struct cdev` of the device. 

```c
struct my_device_data {
    struct cdev cdev;
    /* my data starts here */
    //...
};

static int my_open(struct inode *inode, struct file *file)
{
    struct my_device_data *my_data;

    my_data = container_of(inode->i_cdev, struct my_device_data, cdev);

    file->private_data = my_data;
    //...
}
```

Note how `file->private_data` is used to store the associated data. 

## Registration, Unregistration of Character Devices

The `dev_t` keeps the major and minor identifiers of the device. \
It can be obtained via `MKDEV` macro, and being used within the (un)register functions:

```c
#include <linux/fs.h>

int register_chrdev_region(dev_t first, unsigned int count, char *name);
void unregister_chrdev_region(dev_t first, unsigned int count);
```

These functions stands for static assignment of the device identifiers. \ 
`count` stands for the amount of the allocated devices (total number of minors). \
Note a dynamic approach is also recommended, which can be used via `alloc_chrdev_region`. 

For example, the following allocates `my_minor_count` devices, starting with `my_major, my_first_minor`:

```c
err = register_chrdev_region(MKDEV(my_major, my_first_minor), my_minor_count,
                             "my_device_driver");
```

After assigning identifiers to the device, `cdev_init` should be called in order to initialize the device. \
Moreover, the kernel would have to be notified via `cdev_add` (once the device is ready to receive calls):

```c
#include <linux/cdev.h>

void cdev_init(struct cdev *cdev, struct file_operations *fops);
int cdev_add(struct cdev *dev, dev_t num, unsigned int count);
void cdev_del(struct cdev *dev);
```

Note `cdev_init, cdev_add` should be called for each device (minor):

```c
struct my_device_data {
    struct cdev cdev;
    /* my data starts here */
    //...
};

struct my_device_data devs[MY_MAX_MINORS];

err = register_chrdev_region(MKDEV(MY_MAJOR, 0), MY_MAX_MINORS,
                                 "my_device_driver");

    for(i = 0; i < MY_MAX_MINORS; i++) {
        /* initialize devs[i] fields */
        cdev_init(&devs[i].cdev, &my_fops);
        cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
    }
```

Note how `cdev_init` takes a `struct file_operations`, and allocates a `struct cdev` to be stored within `devs[i].cdev`. \
The mapping between `struct cdev` and its `dev_t` is done via `cdev_add`. 

## Process Address Space

The driver often has to access userspace data. \
Userspace pointer cannot be directly accessed, as there might not be any mapping for it within the page table. \
Moreover, it rises some serious security issues. 

Instead, userspace adata may be accessed via:

```c
#include <asm/uaccess.h>

put_user(type val, type *address);
get_user(type val, type *address);
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
```

The first 2 are macros. \
`put_user` writes `val` within address `address`, `get_user` reads it into `val`. 

`copy_to_user` copies `n` bytes from kernel buffer `from` into userspace buffer `to`. \
`copy_from_user` is similar.

Note the usage of `__user` to denote a userspace pointer. 

## Open & Release

`open` performs initialization of a device, and fills it with specific data (incase its the first `open` call).\
`release` is similar - releases the device-specific data, and closes the device if it is the last call of `close`. 

For example:

```c
static int my_open(struct inode *inode, struct file *file)
{
    struct my_device_data *my_data =
             container_of(inode->i_cdev, struct my_device_data, cdev);

    /* validate access to device */
    file->private_data = my_data;
}
```

Access control is a crucial problem for the `open` function. \
Sometimes multiple `open` calls on the device are not allowed (until `release` is issued). \
We may block, return `-EBUSY`, or just close the device in such case.

## Read & Write

These functions transfers data between the device and the user-space. 

Example of `read` operation, copying a kernel buffer towards the user buffer:

```c
static int my_read(struct file *file, char __user *user_buffer,
                   size_t size, loff_t *offset)
{
    struct my_device_data *my_data = (struct my_device_data *) file->private_data;
    ssize_t len = min(my_data->size - *offset, size);

    if (len <= 0)
        return 0;

    /* read data from my_data->buffer to user buffer */
    if (copy_to_user(user_buffer, my_data->buffer + *offset, len))
        return -EFAULT;

    *offset += len;
    return len;
}
```

Note the driver uses some internal buffer, allocated somewhere else (for example, `open`), of fixed-length. \
Moreover, `read` may return less than the desired `size`. 

The `write` operation is similar, but uses `copy_from_user` to write from the user buffer towards the driver's internal buffer. 

## ioctl

The driver may implement an `ioctl` function, so physical device control commands are possible. 

Its signature:

```c
static long my_ioctl (struct file *file, unsigned int cmd, unsigned long arg);
```

The `ioctl` receives a `cmd` argument from user-space, which identifies the request, and `arg` is its value. \
In case a buffer is involved with the command, `arg` would be a pointer to it. 

In order to generate `ioctl` command codes, it is recommended to use the `_IOC` macro: 

```c
#include <asm/ioctl.h>

#define MY_IOCTL_IN _IOC(_IOC_WRITE, 'k', 1, sizeof(my_ioctl_data))

static long my_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
    struct my_device_data *my_data =
         (struct my_device_data*) file->private_data;
    my_ioctl_data mid;

    switch(cmd) {
    case MY_IOCTL_IN:
        if( copy_from_user(&mid, (my_ioctl_data *) arg,
                           sizeof(my_ioctl_data)) )
            return -EFAULT;

        /* process data and execute command */

        break;
    default:
        return -ENOTTY;
    }

    return 0;
}
```

## Waiting Queues

Sometimes we would like a kernel thread to wait for an operation to finish, without using polling.

A waiting queue supports sleep-wakeup. \
This is a list of processes that are waitinf for a specific event. 

A queue is of type `wait_queue_head_t`. \
The following routines are useful for dealing with queues:

```c
#include <linux/wait.h>

DECLARE_WAIT_QUEUE_HEAD(wq_name);
// Initialize queue at compile time

void init_waitqueue_head(wait_queue_head_t *q);
// Initialize queue at runtime

int wait_event(wait_queue_head_t q, int condition);
// Adds current thread to the queue while the condition is false. 
// State is TASK_UNINTERRUPTIBLE.
// Calls the sched to schedule a new thread. Wakes up upon another thread calling wake_up

int wait_event_interruptible(wait_queue_head_t q, int condition);
// state is TASK_INTERRUPTIBLE

int wait_event_timeout(wait_queue_head_t q, int condition, int timeout);
// Same, but also have a maximum timeout for waiting

int wait_event_interruptible_timeout(wait_queue_head_t q, int condition, int timeout);

void wake_up(wait_queue_head_t *q);
// Puts all threads of the queue whose state is TASK_INTERRUPTIBLE or TASK_UNINTERRUPTIBLE to TASK_RUNNING.
// Removes them from the queue

void wake_up_interruptible(wait_queue_head_t *q);
// Wakes up only threads of TASK_INTERRUPTIBLE state
```

For example:

```c
#include <linux/sched.h>

wait_queue_head_t wq;
int flag = 0;

init_waitqueue_head(&wq);
wait_event_interruptible(wq, flag != 0);  // waiting

/* Another thread */
flag = 1 ;
wake_up_interruptible (&wq);
```

## Exercise 0

Note `generic_ro_fops` is defined within `linux/fs.h`, following an implementation at `fs/read_write.c`:

```c
extern const struct file_operations generic_ro_fops;

const struct file_operations generic_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};
```

It is used within few filesystem implementations, as the handler to regular files (example from `fs/efs/inode.c`): 

```c
switch (inode->i_mode & S_IFMT) {
		case S_IFDIR: 
			inode->i_op = &efs_dir_inode_operations; 
			inode->i_fop = &efs_dir_operations; 
			break;
		case S_IFREG:
			inode->i_fop = &generic_ro_fops;
			inode->i_data.a_ops = &efs_aops;
			break;
```

Moreover, `vfs_read` is declared within `linux/fs.h` and defined within `fs/read_write.c`:

```c
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}
```

`FMODE_READ` states `file` was opened with read permissions. \
`FMODE_CAN_READ` denotes that the `file` has an `f_op->read` handler associated with it. \
`access_ok` verifies that the user pointer is valid. \
It is defined within `arch/x86/include/asm/uaccess.h`:

```c
#define access_ok(addr, size)					\
({									\
	WARN_ON_IN_IRQ();						\
	likely(!__range_not_ok(addr, size, TASK_SIZE_MAX));		\
})
```

So this macro does a simple range-based verification for the pointer's integrity. \
Note `copy_from_user` implicitly uses this check. 

Moreover, `rw_verify_area` is declared within `fs/internal.h`. \
This function calls `security_file_permissions`, which verifies the file has the desired permissions. 

Afterwards, the `read` handler is called. \
Note `f_ops->read` is issued upon `read(2)` and related syscalls, while `read_iter` is a possibly async read, with `iov_iter` as its desination (which supports several chunks of user-data, see [here][iov_iter]). We can think of it as a wrapper to `iovec`. 

Finally, `fsnotify_access` is called - which notifies the notify subsystem that the file was accessed (read). \
`add_rchar` have something to do with the IO_ACCOUNTING of the current process (number of I/O bytes this task have caused). \
`inc_syscr` is similar, and accounts the number of syscalls this task have caused. 

## Exercises 1

We can generate the desired device via `mknod`:

```bash
mknod /dev/so2_cdev c 42 0
```

And indeed we can see the new generated device under `/dev` (same applies to `udev` daemon usage). \
Note the device is not displayed under `/proc/devices`. 

Next, I've implemented `so2_cdev_init`, which is the static function `module_init` calls. \
This function registers a device region corresponding to the device's major, and allocates desired amount of minors:

```c
static int so2_cdev_init(void)
{
    int err;
    int i;

    pr_info("Entering init..");

    err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);
    if (err != 0)
    {
        return err;
    }

    pr_info("Module:%s Major:%d Minors:%d registration succeeded",
            MODULE_NAME,
            MY_MAJOR,
            NUM_MINORS);

    for (i = 0; i < NUM_MINORS; i++) {
        cdev_init(&devs[i].cdev, &so2_fops);
        cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
    }

    return 0;
}


static void so2_cdev_exit(void)
{
    int i;

    pr_info("Entering exit..");

    for (i = 0; i < NUM_MINORS; i++) {
        cdev_del(&devs[i].cdev);
    }

    unregister_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS);
    pr_info("Major:%d Minors:%d unregistration succeeded",
            MY_MAJOR,
            NUM_MINORS);
}
```

Note that devices initiated by kernel modules do not appear in `/dev`, but only in `/proc/devices`. \
If this is required, we should add a call to `device_create` within the module.

Upon loading and unloading the module, we can see `so2_cdev` is appended/removed to/from the `/proc_devices` list. 

## Exercise 2

I've created a fake device at `major==42` via `mknod`, and inserted the module. \
Surprisingly, it worked. \
I assume the collision occurs only if both devices are located under `/proc/devices`. 

By changing `MY_MAJOR -> 4`, the following error occured:

```bash
$ insmod so2_cdev.ko
insmod: can't insert 'so2_cdev.ko': Device or resource busy

$ echo $?
16
```

And indeed, this error code stands for `EBUSY`, as both `tty, ttyS` are already using this major number. 

## Exercise 3

I've implemented `open, release` of the driver, and added them towards the `struct file_operations`:

```c
static int so2_cdev_open(struct inode *inode, struct file *file)
{
    struct so2_device_data *data;

    pr_info("Device is open!");

    data = container_of(inode->i_cdev, struct so2_device_data, cdev);
    file->private_data = data;

    if (atomic_cmpxchg(&data->is_open, 0, 1))
    {
        return -EBUSY;
    }

    set_current_state(TASK_INTERRUPTIBLE);
    schedule_timeout(10 * HZ);

    return 0;
}

so2_cdev_release(struct inode *inode, struct file *file)
{
#ifndef EXTRA
    struct so2_device_data *data;
#endif

    pr_info("Device have released!");

#ifndef EXTRA
    data = (struct so2_device_data *) file->private_data;
    atomic_set(&data.is_open, 0);
#endif
    return 0;
}
```

I've inserted the module, and runned `so2_cdev_test n` (the user program) to read from the device. \
After scheduling of 10 seconds, the following error is displayed:

```bash
read: Invalid argument
Device is open!  # Debug information
```

As there is no implemented read handler. 

## Exercise 4

I've added an `atomic_t is_open` variable, for each device of the driver. \
This value is initialized upon the module load, and compared for every `open` operation (which may set it to `true`). \
A `release` operation sets this variable to `false`. 

Note the character device struct is retrieved from `inode->i_cdev`. \

Upon attempting to open (while some other `open` request is scheduled to sleep), the following error is displayed:

```bash
open: Device or resource busy
```

## Exercise 5 - read operation

In order to support `read` operation, each device would maintain a dedicated inner buffer within its private device data. 

I've initialized this buffer using `memset` and `memcpy`, as exported by `linux/string.h`. 

Moreover, the read handler uses `copy_to_user` in order to write from the kernel buffer into the user's buffer. \
Note this function actually returns the number of bytes NOT copied, meaning 0 denotes a success. 

```c
static ssize_t
so2_cdev_read(struct file *file,
        char __user *user_buffer,
        size_t size, loff_t *offset)
{
    struct so2_device_data *data =
        (struct so2_device_data *) file->private_data;
    size_t to_read;

    pr_info("Entering read. offset:%lld size:%u\n", *offset, size);

    to_read = min((size_t)(sizeof(data->buffer) - *offset), size);
    if (copy_to_user(user_buffer, data->buffer + *offset, to_read) != 0)
    {
        pr_info("Read failed\n");
        return -EFAULT;
    }

    *offset += to_read;

    return to_read;
}
```

Note that by taking the `min`, an kernel OOB-read vuln is fixed. \
The user may provide **arbitrary values** for `offset` and `size`. 

In case `*offset` value would be somewhere within the kernel buffer (`0 < *offset < 4096`), and `size` would be some value greater than the leftover space (for example, the full size of the buffer) - memory beyond `data->buffer` would be copied towards userspace. \
Note that userspace overflow is possible, but it is the user's role to supply large enough buffer. 

Note there is still an integer overflow, as large enough `offset` may wrap around the result, hence produces some huge copy. \
The kernel build system actually warns about this, and requiring an explicit cast to `size_t`. 

Also note that the `read` syscall ends only upon returning a value of `0` (meaning no bytes were copied, and no error have occured). \
Thats why in case of returning some constant, un-updated value, a `cat /dev/so2_cdev` would never halt. \
Thats why `to_read` has to be calculated dynamically, based on the `offset` and supplied `size` paramters:

```bash
Device is open!
Entering read. offset:0 size:4096
hello
Entering read. offset:4096 size:4096
```

Meaning `size` is the constant supplied request, issued by the user. \
`offset` is updated dynamically, based on the offset within the file. 

## Exercise 6 - write operation

Similar to above, now using `copy_from_user`. 

```c
static ssize_t
so2_cdev_write(struct file *file,
        const char __user *user_buffer,
        size_t size, loff_t *offset)
{
    struct so2_device_data *data =
        (struct so2_device_data *) file->private_data;

    pr_info("Entering write. offset:%lld size:%u\n", *offset, size);

    if (copy_from_user(data->buffer + *offset, user_buffer, size) != 0)
    {
        pr_info("write failed");
        return -EFAULT;
    }

    *offset += size;

    return size;
}
```

Upon writing a userspace buffer, its size is calculated dynamically:

```bash
$ echo "noderneder!" > /dev/so2_cdev
Device have released!
Device is open!
Entering write. offset:0 size:12

$ cat /dev/so2_cdev
Device have released!
Device is open!
Entering read. offset:0 size:4096
noderneder!
Entering read. offset:4096 size:4096
```

## Exercise 7 - ioctl operation

Long ago, there used to be a single "Big kernel lock" for synchronizing the kernel. \
In case old compatability is required, `file_operations` contains `compat_ioctl` member. \

The member `unlocked_ioctl` would be used for modern kernels tho.

Note the ioctl codes are defined as following, via `_IOC`:

```c
#include <asm/ioctl.h>

#define BUFFER_SIZE     256

#define MY_IOCTL_PRINT      _IOC(_IOC_NONE,  'k', 1, 0)
#define MY_IOCTL_SET_BUFFER _IOC(_IOC_WRITE, 'k', 2, BUFFER_SIZE)
#define MY_IOCTL_GET_BUFFER _IOC(_IOC_READ,  'k', 3, BUFFER_SIZE)
#define MY_IOCTL_DOWN       _IOC(_IOC_NONE,  'k', 4, 0)
#define MY_IOCTL_UP     _IOC(_IOC_NONE,  'k', 5, 0)
```

I've added few simple switch-cases for the `ioctl` handler commands:

```c
static long
so2_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct so2_device_data *data =
        (struct so2_device_data *) file->private_data;
    int ret = 0;
    int remains;

    switch (cmd) {
        case MY_IOCTL_PRINT:
            pr_info("%s\n", IOCTL_MESSAGE);
            break;
        case MY_IOCTL_SET_BUFFER:
            if (copy_from_user(data->buffer, (const void __user *)arg, BUFFER_SIZE) != 0)
            {
                pr_info("ioctl: SET_BUFFER failed\n");
                return -EFAULT;
            }
            break;

        case MY_IOCTL_GET_BUFFER:
            if (copy_to_user((void __user *)arg, data->buffer, BUFFER_SIZE) != 0)
            {
                pr_info("ioctl: GET_BUFFER failed\n");
                return -EFAULT;
            }
            break;
    default:
        ret = -EINVAL;
    }

    return ret;
}
```




[ttyS]: https://tldp.org/HOWTO/Serial-HOWTO-10.html
[ttyS2]: https://www.mit.edu/afs.new/athena/system/rhlinux/redhat-6.2-docs/HOWTOS/other-formats/html/Text-Terminal-HOWTO-html/Text-Terminal-HOWTO-6.html
[ttyS3]: https://www.oreilly.com/library/view/linux-device-drivers/0596005903/ch18.html
[ttyS4]: https://www.linux.it/~rubini/docs/serial/serial.html
[devices]: https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
[iov_iter]: https://lwn.net/Articles/625077/
