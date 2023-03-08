---
layout: post
title:  "Linux Kernel Lab 2 - Kernel API"
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

Linux kernel provides unified way for defining and using linked lists - `struct list_head`, defined within `linux/list.h`:

```c
struct list_head {
    struct list_head *next, *prev;
};
```

The structure we want to consider as a list node should contain this struct. \
For example:

```c
struct task_struct {
    ...
    struct list_head children;
    ...
};
```

The most frequently-used routines for lists: 

`LIST_HEAD(name)` - declares and statically-initializes the first node of the list:  

```c
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
```

`INIT_LIST_HEAD()` - initializes the head of a list. \
Used when dynamic allocation is made:

```c
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	WRITE_ONCE(list->prev, list);
}
```

Note the usage of `WRITE_ONCE` is mandatory when dealing with the list head. \
Its main usage is to prevent the compiler from merging / refetching reads and writes. The [following][write-once] article describes its motivation. \
In short, this ensures atomic writes, that are mandatory for the `head` of the list. 

`list_add(new, head)` - adds `new` after `head`:

```c
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	if (!__list_add_valid(new, prev, next))
		return;

	next->prev = new;
	new->next = next;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}
```

`list_del(entry)` is similar to the above - but deletes the item `entry`. 

`list_entry` returns the struct for specific entry. \
This is a simple wrapper for the `container_of` macro. 

`list_for_each(pos, head)` - iterates over the list, starting from `head`, via `pos`:

```c
#define list_for_each(pos, head) \
	for (pos = (head)->next; !list_is_head(pos, (head)); pos = pos->next)
```

`list_for_each_safe` - variant that uses `n` as temporary cursor, used to delete an item from the list.

For example:

```c
#include <linux/slab.h>
#include <linux/list.h>

struct pid_list {
    pid_t pid;
    struct list_head list;
};

LIST_HEAD(my_list);

static int del_pid(pid_t pid)
{
    struct list_head *i, *tmp;
    struct pid_list *ple;

    list_for_each_safe(i, tmp, &my_list) {
        ple = list_entry(i, struct pid_list, list);
        if (ple->pid == pid) {
            list_del(i);
            kfree(ple);
            return 0;
        }
    }

    return -EINVAL;
}
```

### Spinlock

Spinlocks are implemented via `spinlock_t`, as defined within `linux/spinlock.h`. \
Example usage:

```c
#include <linux/spinlock.h>

DEFINE_SPINLOCK(lock1);
spinlock_t lock2;

spin_lock_init(&lock2);

spin_lock(&lock1);
/* critical region */
spin_unlock(&lock1);

spin_lock(&lock2);
/* critical region */
spin_unlock(&lock2);
```

Note `DEFINE_SPINLOCK` both declares and initializes the spinlock. 

Moreover, read-write spinlocks, `rwlock_t`, can be used:

```c
DEFINE_RWLOCK(lock);

struct pid_list {
    pid_t pid;
    struct list_head list;
};

/* read */
read_lock(&lock);
    list_for_each(i, lh) {
        struct pid_list *pl = list_entry(i, struct pid_list, list);
        if (pl->pid == pid) {
            read_unlock(&lock);
            return 1;
        }
    }
    read_unlock(&lock);

/* write */
write_lock(&lock);
list_add(&pl->list, lh);
write_unlock(&lock);
```

Extra reading about [volatile][volatile].

### Mutex

Variable of type `struct mutext`, as defined in `linux/mutex.h`. \
It has very similar API to spinlocks:

```c
#include <linux/mutex.h>

/* functions for mutex initialization */
void mutex_init(struct mutex *mutex);
DEFINE_MUTEX(name);

/* functions for mutex acquire */
void mutex_lock(struct mutex *mutex);

/* functions for mutex release */
void mutex_unlock(struct mutex *mutex);
```

Unlike spinlocks, these operations can only be used in process context, not kernel-interrupt. \
This mechanism is a sleep-wakeup, unlike the spinlock's polling. 

### Atomic Variables

In order to sync access to a simple variable, such as counter, `atomic_t`, as defined in `asm/atomic.h`, may be used:

```c
#include <asm/atomic.h>

void atomic_set(atomic_t *v, int i);
int atomic_read(atomic_t *v);
void atomic_add(int i, atomic_t *v);
int atomic_inc_and_test(atomic_t *v);
int atomic_cmpxchg(atomic_t *v, int old, int new);
```

Note the atomic variable holds an integer value. 

There are also atomic bitwise operations, as defined in `asm/bitops.h`. 

## Exercise 0 - Intro

`container_of` takes a pointer to some struct's member, and returns the address of the containing struct. 

`offset_of` returns the offset of certain member within a struct:

```c
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
```

It does a cool trick - casts the address `0` into pointer towards `TYPE`, and returns the "address" of offset `MEMBER`, starting from the base address 0. 


## Exercise 1 - Memory Allocation

The following code stands for the `module_init` handler:

```c
static int mem_init(void)
{
    size_t i;

    mem = kmalloc(4096 * sizeof(*mem), GFP_KERNEL);
    if (mem == NULL)
        goto err_mem;

    pr_info("chars: ");
    for (i = 0; i < 4096; i++) {
        if (isalpha(mem[i]))
            printk("%c ", mem[i]);
    }
    pr_info("\n");

    return 0;

err_mem:
    return -1;
}
```

This code allocates 4096 bytes of uninitialized memory, `mem`, and traverses the allocated content. \
The memory is allocated via `GFP_KERNEL`, which means the calling context is allowed to sleep (as this operation is not atomic). 

The `module_exit` handler simply `kfree`s the allocated buffer. 

Upon inserting the kernel module, lots of `'Z'` characters are being printed to the screen. 

## Exercise 2 - Sleeping in Atomic Context

Initially, we are given the following code:

```c
spinlock_t lock;
spin_lock_init(&lock);

set_current_state(TASK_INTERRUPTIBLE);
/* Try to sleep for 5 seconds. */
schedule_timeout(5 * HZ);
```

`lock` is being initialized, the current running process state is set to `INTERRUPTIBLE`, and the module execution is paused for 5 seconds. \
Upon inserting this module, no bug is occured. 

However, upon creating the following critial section:

```c
spin_lock(&lock);

set_current_state(TASK_INTERRUPTIBLE);
schedule_timeout(5 * HZ);

spin_unlock(&lock);
```

An error occurs, and stack trace is printed:

```bash
BUG: scheduling while atomic: insmod/238/0x00000002
1 lock held by insmod/238:
 #0: cc777d98 (&lock){+.+.}-{2:2}, at: sched_spin_init+0x32/0x90 [sched_spin]
Modules linked in: sched_spin(O+)
CPU: 0 PID: 238 Comm: insmod Tainted: G           O      5.10.14+ #1

Call Trace:
 dump_stack+0x6d/0x8b
 __schedule_bug.cold+0x6e/0x81
 __schedule+0x5f7/0x760
 ? __mod_timer+0x198/0x340
 schedule+0x56/0xd0
 ? 0xd0870000
 schedule_timeout+0xaa/0x1c0
 ? trace_raw_output_hrtimer_start+0xa0/0xa0
 sched_spin_init+0x61/0x90 [sched_spin]
 ? sched_spin_init+0x32/0x90 [sched_spin]
 do_one_initcall+0x57/0x2d0
 ? rcu_read_lock_sched_held+0x41/0x70
 ? kmem_cache_alloc_trace+0x2be/0x330
 ? do_init_module+0x1f/0x230
 do_init_module+0x4e/0x230
 load_module+0x2368/0x2920
 ? sched_clock_cpu+0x145/0x160
 ? find_held_lock+0x29/0x90
 __ia32_sys_init_module+0xe5/0x120
 do_int80_syscall_32+0x2c/0x40
 entry_INT80_32+0xf7/0xf7
EIP: 0x44902cc2
...
=============================
WARNING: suspicious RCU usage
5.10.14+ #1 Tainted: G        W  O
-----------------------------
include/trace/events/initcall.h:48 suspicious rcu_dereference_check() usage!
```

Linux kernel forbiddens sleeping while holding a lock. \
Because while entering the critical section a `spinlock_t` is held, we may not perform sleep operation while holding it. \
We've done so, and a kernel taint occurs.

## Exercise 3 - Kernel Memory

The goal of this exercise is to implement a system process monitor, recording each process and its scheduling time. 

I've implemented the following function to allocate a `task_info`:

```c
struct task_info {
    pid_t pid;
    unsigned long timestamp;
};

static struct task_info *task_info_alloc(int pid)
{
    struct task_info *ti;

    ti = kmalloc(sizeof(*ti), GFP_KERNEL);
    if (ti == NULL)
    {
        pr_info("Allocation failure\n");
        return NULL;
    }

    ti->pid = pid;
    ti->timestamp = jiffies;

    return ti;
}
```

I've also created a function that allocates desired `task_info`s, for few `pids` - current, parent, and next processes (within the process list):

```c
static int memory_init(void)
{
    struct task_struct* p = current;
    ti1 = task_info_alloc(p->pid);

    ti2 = task_info_alloc(p->real_parent->pid);

    ti3 = task_info_alloc(next_task(p)->pid);

    ti4 = task_info_alloc(next_task(next_task(p))->pid);

    return 0;
}
```

Note this function have some potential null-dereferences vulnerabilities. 

Finally, I've implemented a print routine of the various fields, and free'd the allocated memory chunks:

```c
static void memory_exit(void)
{
    pr_info("PID:%d Time:%lu", ti1->pid, ti1->timestamp);
    pr_info("PID:%d Time:%lu", ti2->pid, ti2->timestamp);
    pr_info("PID:%d Time:%lu", ti3->pid, ti3->timestamp);
    pr_info("PID:%d Time:%lu", ti4->pid, ti4->timestamp);

    kfree(ti1);
    kfree(ti2);
    kfree(ti3);
    kfree(ti4);
}
```

The following output is printed:

```bash
PID:227 Time:4294913356
PID:214 Time:4294913356
PID:0 Time:4294913356
```

Note there is no parent for `PID 0` (the scheduler). 

## Exercise 4 - Kernel Lists

Like the prior exercise, but this time instead of using 4 global variables, we would use a kernel-api list. \
The only global variable is `list_head head`. 

Elements are being added as follows:

```c
static void task_info_add_to_list(int pid)
{
    struct task_info *ti;
    ti = task_info_alloc(pid);
    if (ti == NULL)
    {
        return;
    }

    list_add(&ti->list, &head);
}
```

Note how `list_add` takes the member `list_head` of the node to be inserted. 

The linked list is printed via:

```c
static void task_info_print_list(const char *msg)
{
    struct list_head *p;
    struct task_info *ti;

    pr_info("%s: [ ", msg);
    list_for_each(p, &head) {
        ti = list_entry(p, struct task_info, list);
        pr_info("(%d, %lu) ", ti->pid, ti->timestamp);
    }
    pr_info("]\n");
}
```

Note how `ti` is crafted out of the `list_head` member `p`, via `list_entry` (which is simply a wrapper to `container_of`). 

Finally, the list is freed:

```c
static void task_info_purge_list(void)
{
    struct list_head *p, *q;
    struct task_info *ti;

    list_for_each_safe(p, q, &head) {
        ti = list_entry(p, struct task_info, list);
        list_del(p);
        kfree(ti);
    }
}
```

Note the usage of the safe variant. \
This is required while traversing and removing elements from a list. 

Output:

```bash
before exiting: [
(1, 4294922168)
(0, 4294922168)
(213, 4294922168)
(230, 4294922168)
]
```

## Exercise 5 - Kernel Lists + Process Handling

In addition to prior exercise, we add an atomic `count` field for each of the nodes. 

The following function checks if a node is already presented within the linked list:

```c
static struct task_info *task_info_find_pid(int pid)
{
    struct list_head *p;
    struct task_info *ti;

    list_for_each(p, &head) {
        ti = list_entry(p, struct task_info, list);
        if (ti->pid == pid)
        {
            return ti;
        }
    }

    return NULL;
}
```

In order to ensure there is at least one element in the list, I've added the following:

```c
ti = list_entry(head.next, struct task_info, list);
atomic_set(&ti->count, 5);
```

## Exercise 6 + 7 - Sync'ed List

Added `rwlock_t` support. \
This part contains two modules, with one of them exporting core functions to the other. 

The full code of the sync module:

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched/signal.h>

MODULE_DESCRIPTION("Full list processing with synchronization");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

struct task_info {
    pid_t pid;
    unsigned long timestamp;
    atomic_t count;
    struct list_head list;
};

static struct list_head head;
static DEFINE_RWLOCK(lock);

static struct task_info *task_info_alloc(int pid)
{
    struct task_info *ti;

    ti = kmalloc(sizeof(*ti), GFP_KERNEL);
    if (ti == NULL)
        return NULL;
    ti->pid = pid;
    ti->timestamp = jiffies;
    atomic_set(&ti->count, 0);

    return ti;
}

static struct task_info *task_info_find_pid(int pid)
{
    struct list_head *p;
    struct task_info *ti;

    list_for_each(p, &head) {
        ti = list_entry(p, struct task_info, list);
        if (ti->pid == pid) {
            return ti;
        }
    }

    return NULL;
}

static void task_info_add_to_list(int pid)
{
    struct task_info *ti;

    write_lock(&lock);
    ti = task_info_find_pid(pid);
    if (ti != NULL) {
        ti->timestamp = jiffies;
        atomic_inc(&ti->count);
        /* Very important: do not forget to unlock! */
        write_unlock(&lock);
        return;
    }
    write_unlock(&lock);

    ti = task_info_alloc(pid);
    write_lock(&lock);
    list_add(&ti->list, &head);
    write_unlock(&lock);
}

void task_info_add_for_current(void)
{
    task_info_add_to_list(current->pid);
    task_info_add_to_list(current->parent->pid);
    task_info_add_to_list(next_task(current)->pid);
    task_info_add_to_list(next_task(next_task(current))->pid);
}
EXPORT_SYMBOL(task_info_add_for_current);


void task_info_print_list(const char *msg)
{
    struct list_head *p;
    struct task_info *ti;

    pr_info("%s: [ ", msg);

    read_lock(&lock);
    list_for_each(p, &head) {
        ti = list_entry(p, struct task_info, list);
        pr_info("(%d, %lu) ", ti->pid, ti->timestamp);
    }
    read_unlock(&lock);
    pr_info("]\n");
}
EXPORT_SYMBOL(task_info_print_list);

void task_info_remove_expired(void)
{
    struct list_head *p, *q;
    struct task_info *ti;

    write_lock(&lock);
    list_for_each_safe(p, q, &head) {
        ti = list_entry(p, struct task_info, list);
        if (jiffies - ti->timestamp > 3 * HZ && atomic_read(&ti->count) < 5) {
            list_del(p);
            kfree(ti);
        }
    }
    write_unlock(&lock);
}
EXPORT_SYMBOL(task_info_remove_expired);

static void task_info_purge_list(void)
{
    struct list_head *p, *q;
    struct task_info *ti;

    write_lock(&lock);
    list_for_each_safe(p, q, &head) {
        ti = list_entry(p, struct task_info, list);
        list_del(p);
        kfree(ti);
    }
    write_unlock(&lock);
}

static int list_sync_init(void)
{
    INIT_LIST_HEAD(&head);

    task_info_add_for_current();
    task_info_print_list("after first add");

    set_current_state(TASK_INTERRUPTIBLE);
    schedule_timeout(5 * HZ);

    return 0;
}

static void list_sync_exit(void)
{
    struct task_info *ti;
    // ti = list_entry(head.prev, struct task_info, list);
    // atomic_set(&ti->count, 10);
    task_info_remove_expired();
    task_info_print_list("after removing expired");
    task_info_purge_list();
}

module_init(list_sync_init);
module_exit(list_sync_exit);
```

Note the importance of `write_unlock()` before any `return` branch within the code. 

After loading module-6, I've seen `/proc/kallsyms` contains the exported functions. \
For example:

```bash
d0872091 r __kstrtab_task_info_remove_expired   [list_sync]
d08720aa r __kstrtabns_task_info_remove_expired [list_sync]
d0872054 r __ksymtab_task_info_remove_expired   [list_sync]
d0871100 T task_info_remove_expired     [list_sync]
```

We can see that there were actually 4 entries added: one for each section of `kstrtab, ksymtab, kstrtabns` and the function itself.

Moreover, while executing `lsmod`, we can see the `list_sync` refcount is incremented by 1, due to `list_test` using it:

```bash
list_test 16384 0 - Live 0xd0841000 (O)
list_sync 16384 1 list_test, Live 0xd0869000 (O)
```

Also note that the unloading order must be first unload-test, then unload-sync, as module-test is dependent on the sync module. \
Indeed, if we would try to do so, `Resource temporarily unavailable` would be printed.

[write-once]: https://stackoverflow.com/questions/34988277/write-once-in-linux-kernel-lists
[volatile]: https://blog.regehr.org/archives/28
