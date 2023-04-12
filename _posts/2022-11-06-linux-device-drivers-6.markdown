---
layout: post
title:  "Linux Device Drivers Chapter 6 - Advanced Char Drivers"
date:   2022-10-16 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## ioctl

Hardware control via the device driver. 

Most `ioctl` implementations consist of big switch statement, according to the requested `cmd`. 

### Capabilities and Restricted Operations

Usually the driver is not involved in permissions checking. \
Sometimes, even in case any user is granted R/W permissions to the device, control operations should still be denied. \
The driver must perform additional checks in such cases. 

Linux kernel provides flexible permissions system, called *capabilities*. \
The kernel uses capabilities exclusively for permissions mangement, and exports 2 syscalls: `capget, capset`. 

The full system capabilities set may be found under `linux/capability.h`. Few examples: \
`CAP_NET_ADMIN` - allows performing network tasks, such as configuring network interfaces. \ 
`CAP_SYS_MODULE` - allows loading /unloading of kernel modules. \
`CAP_DACT_OVERRIDE` - allows override the permissions of files and directories. 

Capability check operations are performed via `capable` function, as defined in `linux/sched.h`. 

## Device Control Without ioctl

May be accomplished by writing control sequences directly to the device. \
For example, for console drivers - which allows writing of escape sequences in order to change the default color. 

Note that this is also a drawback - as it adds constraints to the device. \
For example, for TTY drivers - in case of printing a binary file towards the console, non-ascii character may be printed, and some sequences may be interpreted as control-sequences of the TTY driver - and corrupt the console session. 

## Sleeping

In order to support blocking I/O, the driver may want to put certain processes to sleep, until some event is accomplished (for example, read buffer contains some content, write buffer isn't full, etc).

Notice that processes that are put to sleep must not hold `spinlock, seqlock, RCU lock`, and must be able to receive interrupts. \
Moreover, after a process wakes up - it must check that the waited event is still valid (which isn't guranteed in case another process was also waked up).

The method `wait_event_interruptible` does exactly this. \
In case the sleep was interrupted by some signal, a nonzero return value is obtained, and the driver should return `-ERESTARTSYS`. 

Some other process / interrupt handler have to wake up the slept process. \
It can be done via `wake_up`, and `wake_up_interruptible` (which wakes up only the interruptible processes within the waiting queue). \
It is a good practice to match between `wait_event_*` and `wake_up_*`. 


## Blocking, Non Blocking Operations

Basically - decide when to put a process to sleep. \
In case of blocking operation, the following implementation adheres the standard semantics:

1. If process calls `read` but no data is available, the process sleeps. \
As soon as data arives and data is returned to call (even if less than the requested `count`), the process is awakened. 

2. If process calls `write` and there is no space in the buffer, the process sleeps. \
Note that this waiting queue is **different** than the one used for reading. 
When there is some free space in the output buffer, the proecss is awakened and `write` succeeds, although only partial write may be performed. 

Nonblocking operations return immediately, enabling data polling. \
Note that even `open` may be a blocking operation - for example when opening a FIFO for reading, while it has no writers. Another example is accessing a disk file, and waiting for pending lock.

### Scullpipe - Blocking Read

Usually, when data arrives the hardware issues an interrupt, and the driver awakens waiting processes. 

However, within a pipe driver the writer processes are waking up the sleeping processes, and via versa. 

The following struct serves as the driver's internal metadata component (`filp->private_data`):

```c
struct scull_pipe {
        wait_queue_head_t inq, outq;       /* read and write queues */
        char *buffer, *end;                /* begin of buf, end of buf */
        int buffersize;                    /* used in pointer arithmetic */
        char *rp, *wp;                     /* where to read, where to write */
        int nreaders, nwriters;            /* number of openings for r/w */
        struct fasync_struct *async_queue; /* asynchronous readers */
        struct mutex lock;              /* mutual exclusion mutex */
        struct cdev cdev;                  /* Char device structure */
};
```

Note it contains two waiting queues, and a single buffer. 

The read operation starts with a `mutex_lock` call, to prevent data races on the shared buffer:

```c
struct scull_pipe *dev = filp->private_data;

if (mutex_lock_interruptible(&dev->lock))
	return -ERESTARTSYS;
```

In case there is no available data, the lock is released. \
For a blocking operation, the process that had issued the read call is put to sleep, until there is pending data. \
Note that right after the process has awakened, it must reacquire the lock:

```c
while (dev->rp == dev->wp) { /* nothing to read */
		mutex_unlock(&dev->lock); /* release the lock */
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		PDEBUG("\"%s\" reading: going to sleep\n", current->comm);
		if (wait_event_interruptible(dev->inq, (dev->rp != dev->wp)))
			return -ERESTARTSYS; /* signal: tell the fs layer to handle it */
		/* otherwise loop, but first reacquire the lock */
		if (mutex_lock_interruptible(&dev->lock))
			return -ERESTARTSYS;
	}
```

In case there is data, it would be copied towards the user buffer. The read pointer would be updated:

```c
if (dev->wp > dev->rp)
	count = min(count, (size_t)(dev->wp - dev->rp));
else /* the write pointer has wrapped, return data up to dev->end */
	count = min(count, (size_t)(dev->end - dev->rp));
if (copy_to_user(buf, dev->rp, count)) {
	mutex_unlock (&dev->lock);
	return -EFAULT;
}

dev->rp += count;
if (dev->rp == dev->end)
	dev->rp = dev->buffer; /* wrapped */
mutex_unlock (&dev->lock);
```

After the whole read operation have completed, and **the device lock have been released**, we may wake up any pending writers, and return the amount of bytes read:

```c
wake_up_interruptible(&dev->outq);
PDEBUG("\"%s\" did read %li bytes\n",current->comm, (long)count);
return count;
```

### Advanced Sleeping

According to `linux/wait.h`, the struct behind `wait_queue_head_t` is actually simple:

```c
struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;
```

When putting a process to sleep, we first have to allocate and initialize a `wait_queue_entry`, and add the process to its proper waiting queue. \
Then, the process state is marked as sleeping. \
We can find the task states under `linux/sched.h`. \
The states `TASK_INTERRUPTIBLE` and `TASK_UNINTERRUPTIBLE` indicates that a process is asleep. 

Usually we won't need to manipulate the process state directly. \
However, it is possible via `set_current_state()`. \
Note that changing the current state of a process does not put it to sleep. \
It does change the way the scheduler treats the process, however the process may still run on the processor, and needs to be yielded. 

Note `wait_event_interruptible` internally calls `___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0, schedule())`. \
It stands for the following macro:

```c
#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)		\
({										\
	__label__ __out;							\
	struct wait_queue_entry __wq_entry;					\
	long __ret = ret;	/* explicit shadow */				\
										\
	init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0);	\
	for (;;) {								\
		long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
										\
		if (condition)							\
			break;							\
										\
		if (___wait_is_interruptible(state) && __int) {			\
			__ret = __int;						\
			goto __out;						\
		}								\
										\
		cmd;								\
	}									\
	finish_wait(&wq_head, &__wq_entry);					\
__out:	__ret;									\
})
```

This means that as long as `condition` does not met, the loop continues, and `schedule()` is called, in order to reschedule another process and yield the CPU. \
Note how rescheduling occurs only after the condition check is performed. \
Moreover, check of the condition is performed only after the process state is changed, via `prepare_to_wait_event` (which internally calls `set_current_state`). 

Finally, `finish_wait` does the cleanup - it is called after the condition is finally met, and sets the process state back to `TASK_RUNNING`, and removes the process from the waiting queue. 

Note Linux supports exclusive waits - only waking up a single process that waits within the waiting queue. \
This may really improve contention problems.

When wqe has `WQ_FLAG_EXCLUSIVE` (each wqe has a `flags` member), it is added to the **end** of the waiting queue. Regular processes are added to the beginning. \
Moreover, `wake_up` stops after waking the first exclusive process. 

### Advanced Waking-Up

The actual behavior that results when a process is awakened is actually controlled by an handler, `wait_queue_func_t func`, within the wqe. 

The default handler, `autoremove_wake_function`, sets the process into a runnable state, and might perform context switch to that process. 

Usually we won't need to modify this member within the driver, unless we would like to exploit it :)

## poll & select Implementation

Whenever user application calls `poll, select, epoll_ctl`, the kernel invokes the associated `poll` method handler of the underlying file operations. \
It uses an internal struct, `poll_table`, which is a linked list of memory pages containing `struct poll_table_entry`s. \
Each `poll_table_entry` holds the `struct file, wait_queue_head_t, wait_queue_t` which would be passed to `poll_wait`. 

If no driver indicates that I/O may be performed without blocking, the `poll` call simply sleeps until at least one waiting queue wakes up. 

After any driver being polled indicates that I/O is possible, the `poll_table` argument is set to `NULL`. This also true in case the user application calls `poll` with `timeout==0`. 

After `poll` call completes, the `poll_table` is deallocated, and all previous queue entries are removed from the table. 

In case of an application that involves dealing with thousands of fds, setting up and tearing down this struct between every I/O operation is expesive. \
`epoll` set up the internal struct once, and uses it many times.

For more information about this, see `linux/poll.h`, and `fs/select.c`. 

## Async Notification - Userland

Can be very useful in some scenarios. \
For example, process executing a loop, waiting for data from some peripheral device. \
With async notification, the application may receive a signal whenever data becomes available - and does not need to use any polling. 

To do so, user process has to specify itself as the owner of the underlying file. \
This can be done via `fcntl(F_SETOWN)`, which stores the `current` pid within `filp->f_owner`. \ 
That way, the kernel knows who to notify. \
Then, the process have to call `fcntl(F_SETFL, FASYNC)` to enable async notification. \
Whenever new data arrives, the file can request delivery of dedicated signal, `SIGIO`, which would be sent to the owner process. 

```c
signal(SIGIO, &input_handler); /* dummy sample; sigaction( ) is better */
fcntl(STDIN_FILENO, F_SETOWN, getpid( ));
oflags = fcntl(STDIN_FILENO, F_GETFL);
fcntl(STDIN_FILENO, F_SETFL, oflags | FASYNC);
```

Usually async capability is available only for sockets and ttys. 

## Async Notification - Kerneland

From the kernel's point of view, the following main stages occur:

1. `F_SETOWN` sets `filp->owner = pid`. 

2. `F_SETFL` with `FASYNC` issues the driver's `fasync` file operations handler. \
It notifies the driver of the change. 

3. When data arrives, all processes registered for async notification are sent a `SIGIO`. 

Note how the latter 2 steps requres maintaining a data structure to keep track of different async readers. \
Note that the kernel already offers such general purpose implementations, via `linux/fs.h` and `fasync_struct`. \
The driver should call `fasync_helper` - which adds or removes entries from the list of interested processes, and `kill_fasync` - which signals the interested processes when data arrives. 

For example:

```c
static int scull_p_fasync(int fd, struct file *filp, int mode)
{
 struct scull_pipe *dev = filp->private_data;
 return fasync_helper(fd, filp, mode, &dev->async_queue);
}
...
/* Within write-handler, whenever data is available - notify */
if (dev->async_queue)
 kill_fasync(&dev->async_queue, SIGIO, POLL_IN);
...
/* Within release-handler, remove this filp from the list of async notified filp's */
scull_p_fasync(-1, filp, 0);
```

Note the similarity between async notification and waiting queues. \
The only difference is notifying `struct file` (which is then used to retrieve `f_owner`), instead of `task_struct`s. 

## Access Control

Sometimes only one authorized user should be allowed to open the device at a time. \
Sometimes we would like more sophisticated schemes. 

Notice that usually we won't use the brute-force way, e.g. to permit a device to be opened by only one process at a time. 

Another option is restricting access to a single user at a time, which can open multiple processes. \
This can be accomplished easily by adding more checks during `open`, preceding the regular open checks. \
It requires an open counter, as well as the `uid` of the device owner - which would be placed via the device driver dedicated struct.

```c
struct scull_dev *dev = &scull_u_device; /* device information */

spin_lock(&scull_u_lock);
if (scull_u_count && 
    (scull_u_owner != current_uid().val) &&  /* allow user */
    (scull_u_owner != current_euid().val) && /* allow whoever did su */
	!capable(CAP_DAC_OVERRIDE)) { /* still allow root */
	    spin_unlock(&scull_u_lock);
	    return -EBUSY;   /* -EPERM would confuse the user */
    }

if (scull_u_count == 0)
	scull_u_owner = current_uid().val; /* grab it */

scull_u_count++;
spin_unlock(&scull_u_lock);
```

Note the usage of a dedicated spinlock. 


