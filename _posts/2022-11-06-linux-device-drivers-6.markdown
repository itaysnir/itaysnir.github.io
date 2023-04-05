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


