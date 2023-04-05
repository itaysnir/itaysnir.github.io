---
layout: post
title:  "Linux Kernel Lab 2 - Kernel Modules"
date:   2022-10-12 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview
Kernel Modules are object files, that can extend the kernel functionality at runtime. \
Device drivers are used as kernel modules. 

This lab focuses on modern linux kernel modules API. 

## Modules Structure
Modules must include the following headers:
```c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
```

As well as defining module-specific information:
```c
MODULE_DESCRIPTION("My kernel module");
MODULE_AUTHOR("Me");
MODULE_LICENSE("GPL");
```

The entry and exit methods are `module_init` and `module_exit`, which takes as a single argument a static method. 

## Compile Modules
Kernel modules compilation is different than regular programs compilation (different headers, not linked to libs, must be compiled as the kernel itself). 
Therefore, a `Kbuild` file is being used. This file is similar to regular `makefiles`, but there are few key differences.

### Kbuild

#### General
The suffix of the targets in Kbuild, determines their use: \
m (module) - states a target for kernel module (obj-m), meaning a `.ko` compilation result. \
y (yes) - states a target for object files as built-in (obj-y, part of the kernel itself), or linked to a module (modulename-y). 

Objects listed with obj-m are used as modules, or combined in a `built-in.a` archive. 

It is cool to know - the kernel's config file entries are used as this suffix. \
For example, stating `CONFIG_BTRFS_FS=y` links `btrfs.o` to the kernel binary object, due to the following line of the BTRFS makefile (Kbuild):

```bash
obj-$(CONFIG_BTRFS_FS) := btrfs.o
```

`obj-y` is actually a list of lists of the built-in objects of the kernel. \
All of these files are then merged into one archive (via `$(AR)`), the `built-in.a` file, which is eventually linked to `vmlinux` (by `scripts/link-vmlinux.sh`). 

On the other hand, `obj-m` is a list of object files that are built as kernel modules. \
Meaning, it runs `$(LD)` on each element in the list. 

A more detailed doc can be found under [linux makefiles][linux-makefiles]. 

#### Simple Examples

Compile a single `.ko`, named `supermodule.ko`. \
This module links `module-a.o, module-b.o`:

```bash
EXTRA_CFLAGS = -Wall -g

obj-m        = supermodule.o
supermodule-y = module-a.o module-b.o
```

Note `obj-m` states a kernel module, whereas `supermodule-y` states statically linking `module-a.o , module-b.o` into `supermodule.o`. \
`obj-y` states a compilation within the kernel itself.

## Helper Methods
The method `pr_debug` allows logging messages.
These messages are recorded comperhensively under `/var/log/syslog`, as well as in `/var/log/dmesg` (can be seen via `dmesg` call). \
Note - it is stored at a specially reserved memory area for logging, It is then extracted via a dedicated logging daemon, `syslogd`. 


## Static Kernel Debugging
1. `dmesg` is a friend. use it. \
Most of the time, wer'e interested on the first generated oops, and its code (R / W oops). \
The generated message contains the stack content, backtrace, and the `IP` value, at which the oops have occured.

2. We can easily parse the instruction which generated the oops, by using `objdump -dSl` (both source code and assembly display). \
The trick is to find the loaded address of the module, VMA (runtime address, as opposed to load address, LMA), via: `cat /proc/modules`:

```bash
# sudo cat /proc/modules
oops 1280 1 - Loading 0xc89d4000
netconsole 8352 0 - Live 0xc89ad000
```

Then, we can parse the compiled kernel module while fixing its loading address:

```bash
objdump -dS --adjust-vma=<module_start_from_procfs> <module.ko>
```

3. Using `addr2line`: this binary takes a kernel object file, and offset which generated the oops. \
It returns the equivalent source-code line that triggered the oops. 

4. Interact with serial port via `minicom` (similar to `screen`). 
- For real embedded hardware, it is common to use `/dev/ttyS0`. Another option is to use `/dev/ttyUSB`. 
- For lab VM, a `/dev/pts/X` entry is generated. We can connect this virtual serial port via `minicom -D /dev/pts/X`.

5. Logging kernel messages over the network via the kernel module `netconsole`. \
Useful if there are no serial ports available / disk doesnt work / terminal doesn't respond. 

Example config (`debugged_machine`, `debugger_machine`):

```bash
modprobe netconsole netconsole=6666@192.168.191.130/eth0,6000@192.168.191.1/00:50:56:c0:00:08
```

So the host machine can display messages via:
`nc -ulp 6000`

Or via `syslogd`. 

6. The most common method of them all - `printk`. 

Note that it also takes a log level macro, which may be found under `linux/kern_levels.h`. \
This allows routing the messages to different outputs. 

```bash
KERN_EMERG = 0
KERN_ALERT = 1
...
KERN_DEBUG = 7
```

In order to display `printk` messages in userspace, its log level must be higher than `console_loglevel`. \
Therefore, the following will enable all messages to be shown at userspace: `echo 8 > /proc/sys/kernel/printk`

The log files under `/var/log` keeps its information between system restarts. \
These files are populated by the `syslogd` and `klogd` kernel daemons. \
If both of these daemons are enabled, *all* incoming kernel messages will be routed towards `/var/log/kern.log`. 

A simple alternative is the `/var/log/debug` file, which is populated only due to printk messages, stated with `KERN_DEBUG` log level. 

The following macro may become handy to use:

```c
#define PRINT_DEBUG \
       printk (KERN_DEBUG "[% s]: FUNC:% s: LINE:% d \ n", __FILE__,
               __FUNCTION__, __LINE__)
```

To delete previous log messages: 

```bash
`cat /dev/null > /var/log/debug`  	# From log file
dmesg -c 							# Messages from the dmesg command
```


## Dynamic Kernel Debugging

### dyndbg

The following [link][dyndbg-link] contains the documentation.
It is possible to use [debugfs][debugfs] to configure debug options. 
```bash
mount -t debugfs none /debug
cat /debug/dynamic_debug/control  # display existing message filters
echo 'file svcsock.c line 1603-1605 +p' > /debug/dynamic_debug/control  # enable message from source file, for specific lines
echo 'func svc_tcp_accept +p' > /debug/dynamic_debug/control  # messages from specific functions

Flags:
+p  # actviates pr_debug()
+f  # includes func name
+l  # includes line number
+m  # includes module name
+t  # includes thread id
```

### KDB

Performs live debugging and monitoring. Can be used in parallel with GDB.

Activate GDB over serial port:

```bash
echo hvc0 > /sys/module/kgdboc/parameters/kgdboc
echo g > /proc/sysrq-trigger  # Force the kernel to enter KDB, or ctrl+O g in the terminal
```
KDB allows printing backtraces, dump trace logs, inserting hardware breakpoints, and modifying memory. \
See `help` within KDB shell. 

```bash
bph my_var dataw  # HW-bp on write access to my_var
```

### Remote GDB

Probably the easiest method. 

Qemu sets up a gdb server, that we can connect to debug a "guest" OS. \
We can connect to it via `gdb -ex "target remote:1234"`.

Moreover, it is recommended to set the number of CPUs to 1. \
A more detailed explanation can be found here: [link][kernel-gdb] and [link2][kernel-debug]

## Exercise 0 - Intro

### module_init, module_exit

By browsing [LXR][bootlin-link], I've found the definitions of `module_init` and `module_exit` at `include/linux/module.h`.

Note it has different compilation results, based on whether or not the driver was compiled as a separare module, or a kernel built-in:

```c
/* These are either module local, or the kernel's dummy ones. */
extern int init_module(void);
extern void cleanup_module(void);

#ifndef MODULE
/**
 * module_init() - driver initialization entry point
 * @x: function to be run at kernel boot time or module insertion
 *
 * module_init() will either be called during do_initcalls() (if
 * builtin) or at module insertion time (if a module).  There can only
 * be one per module.
 */
#define module_init(x)	__initcall(x);

/**
 * module_exit() - driver exit entry point
 * @x: function to be run when driver is removed
 *
 * module_exit() will wrap the driver clean-up code
 * with cleanup_module() when used with rmmod when
 * the driver is a module.  If the driver is statically
 * compiled into the kernel, module_exit() has no effect.
 * There can only be one per module.
 */
#define module_exit(x)	__exitcall(x);

#else /* MODULE */
...

/* Each module must use one module_init(). */
#define module_init(initfn)					\
	static inline initcall_t __maybe_unused __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __copy(initfn)			\
		__attribute__((alias(#initfn)));		\
	___ADDRESSABLE(init_module, __initdata);

/* This is only required if you want to be unloadable. */
#define module_exit(exitfn)					\
	static inline exitcall_t __maybe_unused __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __copy(exitfn)		\
		__attribute__((alias(#exitfn)));		\
	___ADDRESSABLE(cleanup_module, __exitdata);

#endif
```

In case the driver wasn't compiled as a separate module, but as a kernel builtin, `module_init` is simply appended to the kernel's `__initcall` list, which would be all called at boot time at `do_initcalls`. 

On the other hand, if the driver was compiled as a module, we can see `module_init` actually wraps a *new definition* for `init_module`. \
Recall that `init_module, cleanup_module` are the old-fashion way for defining ctor and dtor module functions. 

We can clearly see that `module_init, module_exit` avoids the overhead of manually `#define-ing` these for our module, and implicitly handles both cases - whether the driver is standalone module or a kernel-builtin. 

### ignore_loglevel

By browsing `kernel/printk/printk.c`, I've found `ignore_loglevel` definition:

```c
static bool __read_mostly ignore_loglevel;
```

That is a kernel global variable, that is usually being read. 

Usually printk functions are associated with a `log-level`, for example `DEBUG, CRITICAL`, etc. \
By setting this variable to `true`, all kernel messages would be printed to the console. 

In case this variable is `true`, `suppress_message_printing()` would always return `false`, so `console_emit_next_record` would emit a message. 

Note that `ignore_loglevel` is also a printk (which is a builtin module) parameter:

```c
early_param("ignore_loglevel", ignore_loglevel_setup);
module_param(ignore_loglevel, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ignore_loglevel,
		 "ignore loglevel setting (prints all kernel messages to the console)");
```

The above code adds `ignore_loglevel` as an `early_param` for the kernel (usually used for the kernel command line, see [here][early-params] for more info about early_params), and also as a `module_param`. \
This macro allows passing arguments to a module, hence controlling the value of `ignore_loglevel` during runtime.

We can do so while inserting the module - `insmod` fills the variable with any commandline arguments that are given, like `./insmod itay-module.ko itay_mod_param=1`. 

Users may also change it dynamically via `/sys/module/printk/parameters/ignore_loglevel`.

## Exercise 1 - Kernel module

Compiled the kernel module, and started the VM. 

By executing `dmesg, lsmod`, We can see that initially there are no loaded modules. \

Right after executing `insmod hello_mod.ko`, the string `"Hello!"` was printed, along with two new entries displayed by `dmesg`:

```bash
hello_mod: loading out-of-tree module taints kernel.
Hello!
```

By executing `rmmod hello_mod.ko`, I've teared-down the module. \
`dmesg` now displayed `"Goodbye!"`.

## Execise 2 - Printk

Note that messages were displayed directly towards the VM console, eventho they were declared as `DEBUG` messages:

```c
static int my_hello_init(void)
{
    pr_debug("Hello!\n");
    return 0;
}

static void hello_exit(void)
{
    pr_debug("Goodbye!\n");
}
```

I assume this is because of the `ignore_loglevel` value. \
By reading `/sys/module/printk/parameters/ignore_loglevel`, the value of `N` was printed - meaning it was not configured. 

Another option is to rewrite the desired level to `/proc/sys/kernel/printk`. This allows setting the current `console_loglevel` values. \
It contains 4 values: 

```bash
# cat /proc/sys/kernel/printk
15      4       1       7
```

Those values stands for the current, default, minimum and boot-time-default log levels. 

By setting the current level to 0 via `echo 0 > printk`, loading messages were not displayed on console anymore, but were displayed via `dmesg`. 

## Exercise 3 - Error

Upon compiling this module, many errors are printed. \
By carefully reading those, we can see that there is a missing kernel header - `linux/module.h`.

After adding this, the module was compiled successfully. 

## Exercise 4 - Sub-modules

In order for multi modules compilation, I've wrote the following short Kbuild file:

```bash
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable

# TODO: add rules to create a multi object module
obj-m = multi-mod.o
multi-mod-y = mod1.o mod2.o
```

Now `multi-mod.ko` was created, and works properly. 

Note `mod1.c` declares `static int` variables on its scope. \
Those variables are only accessible to this module. 

In case "global" variable would like to be used (for example, by other modules or by core-kernel), `EXPORT_SYMBOL(var)` should've been used on the exporting module, and `extern int var` on the importing module. \
The following page describes the various variable scopes possibilities: [kernel-vars][kernel-vars]

## Exercise 5 - Kernel oops

This module contains a null-dereference bug:

```c
static int my_oops_init(void)
{
    char *p = 0;

    pr_info("before init\n");
    *p = 'a';
    pr_info("after init\n");

    return 0;
}
```

In order to generate debug information, I've added the `-g` flag within the Kbuild file:

```bash
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable -g

obj-m = oops_mod.o
```

Upon loading the module, the kernel *was not* crashed. \
However, the following error was printed to the console:

```bash
oops_mod: loading out-of-tree module taints kernel.
before init
BUG: kernel NULL pointer dereference, address: 00000000
#PF: supervisor write access in kernel mode
#PF: error_code(0x0002) - not-present page
*pde = 00000000
Oops: 0002 [#1] SMP
CPU: 0 PID: 227 Comm: insmod Tainted: G           O      5.10.14+ #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
EIP: my_oops_init+0xd/0x22 [oops_mod]
Code: Unable to access opcode bytes at RIP 0xd085afe3.
EAX: 0000000b EBX: 00000000 ECX: cfdc9d4c EDX: 01000000
ESI: d085b000 EDI: 00000002 EBP: cb6cddb8 ESP: cb6cddb4
DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068 EFLAGS: 00000286
CR0: 80050033 CR2: d085afe3 CR3: 0bfe2000 CR4: 00000690
Call Trace:
 do_one_initcall+0x57/0x2d0
 ? rcu_read_lock_sched_held+0x41/0x70
 ? kmem_cache_alloc_trace+0x2be/0x330
 ? do_init_module+0x1f/0x230
 do_init_module+0x4e/0x230
 load_module+0x2368/0x2920
 ? sched_clock_cpu+0x25/0x160
 ? find_held_lock+0x29/0x90
 __ia32_sys_init_module+0xe5/0x120
 do_int80_syscall_32+0x2c/0x40
 entry_INT80_32+0xf7/0xf7
EIP: 0x44902cc2
Code: 06 89 8a 84 01 00 00 c3 55 57 56 53 8b 6c 24 2c 8b 7c 24 28 8b 74 24 24 8b 54 24 20 8b 4c 24 1c 8b 5c 24 18 8b 44 24 14 cd0
EAX: ffffffda EBX: 0a08d050 ECX: 000096d8 EDX: 0a08d008
ESI: 00000000 EDI: bff8a21c EBP: 00000000 ESP: bff8a07c
DS: 007b ES: 007b FS: 0000 GS: 0033 SS: 007b EFLAGS: 00000206
Modules linked in: oops_mod(O+)
CR2: 0000000000000000
---[ end trace ccf3788f35b47ab6 ]---
EIP: my_oops_init+0xd/0x22 [oops_mod]
Code: Unable to access opcode bytes at RIP 0xd085afe3.
EAX: 0000000b EBX: 00000000 ECX: cfdc9d4c EDX: 01000000
ESI: d085b000 EDI: 00000002 EBP: cb6cddb8 ESP: cb6cddb4
DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068 EFLAGS: 00000286
CR0: 80050033 CR2: d085afe3 CR3: 0bfe2000 CR4: 00000690
Killed
```

According to the stack trace, the oops happened at `RIP=0xd085afe3`. 

By reading `/proc/modules`, we can see the kernel module virtual load address, as well as its size:

```bash
oops_mod 20480 1 - Loading 0xd085b000 (O+)
```

We can see even more detailed information by inspecting `/sys/module/<name>/sections/`. 

Note the module cannot be unloaded, as `rmmod` does not decreases the reference count of the buggy modules.

## Exercise 6 - Module Params

By inspecting `cmd_mod.c`, we can see the module defines a module parameter as follows:

```c
static char *str = "the worm";
module_param(str, charp, 0000);
MODULE_PARM_DESC(str, "A simple string");
```

Module parameters are supported by `<moduleparam.h>`. \
The parameter `str` is defined as a `char ptr`, with default permissions of `0000`. \
The permissions are relevant for the file under `/sys/module/cmd_mod/parameters/str`, in case dynamic change of its values are needed (and not only at the module's loading time). 

A short description is added, which can be displayed via the `modinfo` command. 

We can load the module with parameters via `insmod cmd_mod.ko str="noder"`. \
The variable will be initialized before the init function call. 

We can simply call `insmod cmd_mod.ko str="Noder"` to set the module param value, prior to the `module_init` call. 

## Exercise 7 - Proc Info

We want to add code to display the PID and executable name for the current process. 

Recall that a process is described by `struct task_struct`. \
The pointer to the structure of the current running process is given by the `current` variable, which is of type `struct task_struct*`. \
It is actually a macro, for the `get_current()` function, defined within `linux/sched.h`. 

I've added the following code to the kernel module:

```c
struct task_struct *p = current;

pid_t pid = p->pid;
char *name = p->comm;

pr_info("PID=%d NAME=%s\n", pid, name);
```

And the following output is printed:

```bash
# insmod list_proc.ko
PID=226 NAME=insmod
# rmmod list_proc.ko
PID=227 NAME=rmmod
```

## Extra 1 - KDB

The file `hello_kdb.c` creates a `proc` entry via `proc_create`, and sets up its `struct proc_ops`. \
It uses `seq_file` to define some of the handlers, such as `single_open`. \
This scheme allows easy implementation of virtual files, as can be learned [here][seq-files] and [here][seq-files-2].

```c
static int hello_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "Hello proc!\n");
    return 0;
}

static int hello_proc_open(struct inode *inode, struct  file *file) {
    return single_open(file, hello_proc_show, NULL);
}

static int edit_write(struct file *file, const char *buffer,
        size_t count, loff_t *data)
{
    kdb_write_address += 1;
    return count;
}

static const struct proc_ops edit_proc_ops = {
    .proc_open  = hello_proc_open,
    .proc_read  = seq_read,
    .proc_write = edit_write,
    .proc_lseek = seq_lseek,
    .proc_release   = single_release,
};
```

Note the `.proc_open` handler must be created. \
It may wrap `seq_open`, or `single_open` and provide a single-function show handler, such as `hello_proc_show`. \
Also note that default behavior for a seq file may be provided. 

Upon opening both files, an `hello` greeting is printed. \
Moreover, writing to the `hello_bug` proc file causes a kernel-taint, as explicit call to `panic` is being issued. 


## Extra 2 - PS Module

Updating the module created at exercise 7, to display information about all of the processes in the system. 

The [following page][process-list] describes the Linux kernel implementation of the process list. \
A circular doubly linked list links all of the existing process descriptors (`task_struct`) - the process list. \
The `prev_task` and `next_task` fields are used to implement the list. \
The head of the list is called `init_task`, which is the ancestor of all processes - `process 0, swapper`.

Process descriptor can be inserted / removed from the list via `set_links, remove_links`. 

A useful macro is called `for_each_process`, which scans the whole process list:

```c
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
```

It is defined within `linux/sched/signal.h`, and should be explicitly included.

My module contains the following snippet:

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
// Required for task_struct + for_each_process macro
#include <linux/sched.h>
#include <linux/sched/signal.h>

static int my_proc_init(void)
{
    struct task_struct *p = current;

    pid_t pid = p->pid;
    char *name = p->comm;
    /* TODO: print current process pid and its name */

    pr_info("PID=%d NAME=%s\n", pid, name);

    /* TODO: print the pid and name of all processes */
    for_each_process(p) {
        pid = p->pid;
        name = p->comm;

        pr_info("PID=%d NAME=%s\n", pid, name);
    }

    return 0;
}
```

And I got the following result on the VM:

```bash
# insmod list_proc.ko
PID=239 NAME=insmod
PID=1 NAME=init
PID=2 NAME=kthreadd
PID=3 NAME=rcu_gp
PID=4 NAME=rcu_par_gp
PID=5 NAME=kworker/0:0
PID=6 NAME=kworker/0:0H
PID=7 NAME=kworker/u2:0
PID=8 NAME=mm_percpu_wq
PID=9 NAME=ksoftirqd/0
PID=10 NAME=rcu_sched
PID=11 NAME=migration/0
PID=12 NAME=cpuhp/0
PID=13 NAME=kdevtmpfs
PID=14 NAME=netns
PID=15 NAME=oom_reaper
PID=16 NAME=writeback
PID=38 NAME=kblockd
PID=39 NAME=kworker/0:1
PID=40 NAME=kworker/0:1H
PID=41 NAME=kswapd0
PID=42 NAME=cifsiod
PID=43 NAME=smb3decryptd
PID=44 NAME=cifsfileinfoput
PID=45 NAME=cifsoplockd
PID=47 NAME=acpi_thermal_pm
PID=48 NAME=kworker/u2:1
PID=50 NAME=kworker/0:2
PID=52 NAME=khvcd
PID=53 NAME=ipv6_addrconf
PID=54 NAME=kmemleak
PID=55 NAME=jbd2/vda-8
PID=56 NAME=ext4-rsv-conver
PID=194 NAME=udhcpc
PID=205 NAME=syslogd
PID=208 NAME=klogd
PID=214 NAME=getty
PID=215 NAME=sh
PID=216 NAME=getty
PID=217 NAME=getty
PID=218 NAME=getty
PID=219 NAME=getty
PID=222 NAME=kworker/u2:2
PID=223 NAME=kworker/u2:3
PID=233 NAME=start_getty
PID=234 NAME=start_getty
PID=235 NAME=login
PID=236 NAME=login
PID=239 NAME=insmod
```

Cool - the output seems identical to the `ps` command!

## Extra 3 - Memory Info

We want to develop a kernel module that displays the virtual memory mappings for the current process. 

Recall `task_struct` describes a single task. \
It contains two members of type `mm_struct *`: `mm, active_mm`. Note `active_mm` is relevant for kernel-threads support, and saves the `mm` of the previous running process. \
This struct is defined within `linux/mm_types.h`. \
It describes a whole **memory address space** of a process / thread. 

Cool to know - `mm_users` serves as the minor ref count for this address space. For example, for 2 threads `mm_users` is equal to 2, and `mm_count` equals to 1. \
Once `mm_users` reaches 0, the `mm_count` is decremented by 1 - which frees the `mm_struct` upon reaching 0. \
The free operation is done by `free_mm` macro, which returns the struct towards the `mm_cachep` slab via `kmem_cache_free`. 

Moreover, kernel threads do not have a process address space, and therefore no associated `mm_struct`. \
However, they still need some data - such as page tables, in order to access the kernel memory. Therefore, they simply use the `mm_struct` of the previous running process, as the kernel memory mapping is shared among all of the processes. 

For kernel 5.10, `mm_struct` has a linked-list pointer of structs `vm_area_struct`, called `mmap`, but it was changed on modern kernel. \
This struct describes a single virtual memory area, by the fields `vm_start, vm_end`. \
It also has a pointer for its associated `mm_struct`, as well as a pointer towards the next vm area, `vm_next`. \
The `vm_flags` member describes the permissions of the memory area. 

[extra-reading][vm-area].

I've added the following to my module, in order to parse the `current` process memory sections:

```c
struct task_struct *p = current;
struct mm_struct *m = p->mm;
struct vm_area_struct *vmem = m->mmap;

while (vmem != NULL)
{
    unsigned long start = vmem->vm_start;
    unsigned long end = vmem->vm_end;
    pr_info("START=0x%lx END=0x%lx\n", start, end);
    vmem = vmem->vm_next;
}
```

The following output is yield:

```bash
START=0x8048000 END=0x80c2000
START=0x80c2000 END=0x80c3000
START=0x80c3000 END=0x80c4000
START=0x80c4000 END=0x80c6000
START=0x91c2000 END=0x91e3000
START=0x4480c000 END=0x4482e000
START=0x4482e000 END=0x4482f000
START=0x4482f000 END=0x44830000
START=0x44832000 END=0x449a9000
START=0x449a9000 END=0x449ab000
START=0x449ab000 END=0x449ac000
START=0x449ac000 END=0x449af000
START=0x449b1000 END=0x44a09000
START=0x44a09000 END=0x44a0a000
START=0x44a0a000 END=0x44a0b000
START=0xb7fd1000 END=0xb7fd3000
START=0xb7fd3000 END=0xb7fd7000
START=0xb7fd7000 END=0xb7fd9000
START=0xbfb95000 END=0xbfbb6000
```

As we can see, the `insmod` user process loads at `0x8048000`. \
Moreover, we can see the mapped kernel addresses on the userspace program. 

## Extra 4 - Dyndbg

Enables dynamic debugging. \
Reduces the amount of messages displayed, leaving only those relevant for debugging. 

While compiling the kernel, `CONFIG_DYNAMIC_DEBUG` should be enabled. \
This allows configuring `pr_debug, dev_dbg, print_hex_dump_debug` per call. 

Messages can be filtered using the `/sys/kernel/debug/dynamic_debug/control` file, from the `debugfs`. 

Debugfs is a filesystem used as kernel&user space interface to configure differnt debug options. 

This task mounts a `debugfs` file system under `/debug`. 

Examples of specific debug messages enabling:

```bash
echo 'file svcsock.c line 1603 +p' > /debug/dynamic_debug/control
echo 'func svc_tcp_accept +p' > /debug/dynamic_debug/control
echo 'module noder +p' > /debug/dynamic_debug/control
```

Note that `p` activates the `pr_debug` call.



[linux-makefiles]: https://docs.kernel.org/kbuild/makefiles.html?highlight=kbuild
[dyndbg-link]: https://www.kernel.org/doc/html/v4.15/admin-guide/dynamic-debug-howto.html
[debugfs]: https://www.opensourceforu.com/2010/10/debugging-linux-kernel-with-debugfs/
[bootlin-link]: https://elixir.bootlin.com/linux/latest/source
[early-params]: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2011-July/002709.html
[kernel-gdb]: https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html#debugging-the-kernel-with-gdb
[kernel-debug]: https://www.cnblogs.com/bsauce/p/11634162.html
[process-list]: https://www.halolinux.us/kernel-reference/the-process-list.html
[vm-area]: http://books.gigatux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html
[kernel-vars]: https://stackoverflow.com/questions/43895817/how-to-use-a-variable-from-another-c-file-in-linux-kernel
[seq-files]: https://www.kernel.org/doc/html/v5.8/filesystems/seq_file.html
[seq-files-2]: https://kernelnewbies.org/Documents/SeqFileHowTo
