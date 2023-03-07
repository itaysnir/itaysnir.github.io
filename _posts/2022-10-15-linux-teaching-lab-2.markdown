---
layout: post
title:  "Linux Teaching Lab 1 - Kernel API"
date:   2022-10-15 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This lab contains concepts and basic functions, required for Linux kernel programming.

Kernel programming is based on a totally new and independent API that is unrelated to the user-space API. 


## General

### Memory

There are 4 memory types: physical, virtual from kernel-space, virtual from user-space, and resident (accessed pages are *gurantee* to present in physical memory). 

Virtual memory of process's address space may not be considered as resident, as pages may be swapped out, or simply not present in the physical memory (due to demand paging). 

The memory of the kernel address space can be resident, depending on its segments: \
Both `data, code` of a module and `kstack` of a process are resident. \
Dynamic memory (`kmalloc, vmalloc`), may or may not be resident, depending on how it was allocated. 

Working with resident memory is easy, as it can always be accessed. \
However, non-resident memory can only be accessed from certain contexts, such as from the process context. \
It cannot be accessed from the context of an interrupt. 

Moreover, the virtual memory of a process cannot be accessed directly by the kernel. \
In case a driver is required to access a buffer from user-space, it must use special features to do so. 

Lastly, the `kstack` size if fixed and limited - 4KB in Linux (unlike the dynamically growing stack of a single thread application). 

### Execution Contexts

Kernel execution can be distinguished to two context: process context (for example, due to syscall or running kernel thread), and interrupt context (handle device interrupt / deferrable action).

Some kernel APi calls may block the current process execution, such as semaphore / waiting for a condition. \
The process is put into `WAITING` state, and other process is `RUNNING`. \
In case an interrupt context calls function that leads to current process suspension, there may be unpredictable results, as there is no `current` process. 

### Locking

Linux supports SMP systems with multiple processors and kernel preemptivity. \
This means access to global vars must be synced with spinlock primitives or blocking primitives. \
However, blocking primitives cannot be used in an interrupt context, so the only solution in this case are spinlocks. 

Note that the code within the critical region protected by a spinlock is not allowed to suspend `current`. \
The CPU won't be released except for the case of an interrupt. 

### Preemptivity

Linux uses preemptive kernels. \
Note the difference between preemptive multitasking and kernel: \
The notion of preemptive multitasking refers to the OS forcefully interrupts a process **running in user-space** when its quantum expires (and therefore able able to run another process). 

A preemptive kernel can interrupt a process **running in kernel-mode**.

This means when we share resources between two portions of kernel code, we need to protect ourselves with sync - **even in the case of a single processor**!


## Linux Kernel API

### Convention Indicating Errors

Same convention as UNIX programming:

```c
if (alloc_memory() != 0)
    return -ENOMEM;

if (user_parameter_valid() != 0)
    return -EINVAL;
```

The full errors list and their explanations can be found under `includes/asm-generic/errno-base.h` and `errno.h`. 

### Strings

The usual functions `strcpy, strncpy, strncat, strncmp, memmove` etc - are all provided within `include/linux/string.h`. \
These kernel variants are implemented within `lib/string.c`. 

### printk

Equivalent to `printf`, defined within `include/linux/printk.h`. 
It allows setting the logging level of the call. 

We can use the help functions, such as `pr_info`, to call `printk` with predefined logging level. 

### Memory Allocation

Important: **only resident memory can be allocated**, using `kmalloc`. \
This means memory allocated via `kmalloc` call is guranteed to be within the physical memory. 

```c
#include <linux/slab.h>

string = kmalloc (string_len + 1, GFP_KERNEL);
if (!string) {
    //report error: -ENOMEM;
}
```

The function returns a pointer to a memory area that can be directly used in the kernel. \
`GFP_KERNEL` may cause the current process to be suspended, so it cannot be used within an interrupt context. \
`GFP_ATOMIC` gurantees the function does not suspend the current process. Can be used anytime.

Memory can be de-allocated via `kfree`, which does not suspends the current process, and can be called from any context. 

### Lists



