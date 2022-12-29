---
layout: post
title:  "Linux Teaching Lab 1 - Kernel Modules"
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
For example, stating `CONFIG_BTRFS_FS=y` links `btrfs.o` to the kernel, due to the following line of the BTRFS makefile (Kbuild):

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
These messages are recorded comperhensively under `/var/log/syslog`, as well as in `/var/log/dmesg` (can be seen via `dmesg` call). 
Note - it is stored at a specially reserved memory area for logging. It is then extracted via a dedicated logging daemon, `syslog`. 


## Static Kernel Debugging
1. `dmesg` is a friend. use it. 
Most of the time, wer'e interested on the first generated oops, and its code (R / W oops). The generated message contains the stack content, backtrace, and the `IP` value, at which the oops have occured.

2. We can easily parse the instruction which generated the oops, by using `objdump -dSl` (both source code and assembly display). 
The trick is to find the VMA (runtime address, as opposed to load address, LMA) of the kernel module, via: `cat /proc/modules`. 
Then, easy parsing of the kernel module as follow:
```bash
objdump -dS --adjust-vma=<module_start_from_procfs> <module.ko>
```

3. Using `addr2line`: this binary takes a kernel object file, and offset which generated the oops. It returns the equivalent source-code line. 

4. Interact with serial port via `minicom` (similar to `screen`). 
- For real embedded hardware, it is common to use `/dev/ttyS0`. Another option is to use `/dev/ttyUSB`. 
- For lab VM, a `/dev/pts/X` entry is generated. We can connect this virtual serial port via `minicom -D /dev/pts/X`.

5. Logging kernel messages over the network via the kernel module `netconsole`. 
Useful if there are no serial ports available / disk doesnt work / terminal doesnt respond. 
Example config (`debugged_machine`, `debugger_machine`):
```bash
modprobe netconsole netconsole=6666@192.168.191.130/eth0,6000@192.168.191.1/00:50:56:c0:00:08
```

So the host machine can display messages via:
`nc -ulp 6000`

Or via `syslogd`. 

6. Most useful - `printk`. 
It also takes a log level macro, which may be found under `linux/kern_levels.h`. This allows routing the messages to different outputs. 

```bash
KERN_EMERG = 0
...
KERN_DEBUG = 7
```

In order to display `printk` messages in userspace, its log level must be higher than `console_loglevel`. 
Therefore, the following will enable all messages to be shown at userspace:
`echo 8 > /proc/sys/kernel/printk`

The log files under `/var/log` keep its information between system restarts. 
These files are populated by `syslogd` and `klogd` - kernel daemons. 
If both of these daemons are enabled, all incoming kernel messages will be routed towards `/var/log/kern.log`. 

A simple alternative is the `/var/log/debug` file, which is populated only due to printk messages, stated with `KERN_DEBUG` log level. 

The following macro may become handy to use:
```c
#define PRINT_DEBUG \
       printk (KERN_DEBUG "[% s]: FUNC:% s: LINE:% d \ n", __FILE__,
               __FUNCTION__, __LINE__)
```

To delete previous log messages:
`cat /dev/null > /var/log/debug`


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

echo g > /proc/sysrq-trigger  # force the kernel to enter KDB, or ctrl+O g in the terminal
```
KDB allows printing backtraces, dump trace logs, inserting hardware breakpoints, and modifying memory. See `help` within KDB shell. 
```bash
bph my_var dataw  # HW-bp on write access to my_var
```

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

In case the driver wasn't compiled as a separate module, but as a kernel builtin, `module_init` is simply equivalent to the kernel's `__initcall`. 

On the other hand, if the driver was compiled as a module, we can see `module_init` actually wraps a *new definition* for `init_module`. \
Recall that `init_module, cleanup_module` are the old-fashion way for defining ctor and dtor module functions. 

We can clearly see that `module_init, module_exit` avoids the overhead of manually `#define-ing` these for our module, and implicitly handles both cases - whether the driver is standalone module or a kernel-builtin. 

### ignore_loglevel

By browsing `kernel/printk/printk.c`, I've found `ignore_loglevel` definition:

```c
static bool __read_mostly ignore_loglevel;
```

That is a kernel global variable, usually being read. 

Usually printk functions are associated with a `log-level`, for example `DEBUG, CRITICAL`, etc. \
By settings this variable to `true`, all kernel messages would be printed to the console. 

In case this variable is `true`, `suppress_message_printing()` would always return `false`, so `console_emit_next_record` would emit a message. 

Note that `ignore_loglevel` is also a printk module parameter:

```c
early_param("ignore_loglevel", ignore_loglevel_setup);
module_param(ignore_loglevel, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ignore_loglevel,
		 "ignore loglevel setting (prints all kernel messages to the console)");

```

The above code adds `ignore_loglevel` as an `early_param` for the kernel (usually used for the kernel command line, see [here][early-params] for more info about early_params), and also as a `module_param`. \
This macro allows passing arguments to a module. \
At runtime, `insmod` fills the variable with any commandline arguments that are given, like `./insmod itay-module.ko itay_mod_param=1`. 

It means that users may change it dynamically via `/sys/module/printk/parameters/ignore_loglevel`.


[linux-makefiles]: https://docs.kernel.org/kbuild/makefiles.html?highlight=kbuild
[dyndbg-link]: https://www.kernel.org/doc/html/v4.15/admin-guide/dynamic-debug-howto.html
[debugfs]: https://www.opensourceforu.com/2010/10/debugging-linux-kernel-with-debugfs/
[bootlin-link]: https://elixir.bootlin.com/linux/latest/source
[early-params]: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2011-July/002709.html
