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
Kernel Modules are object files, that can extend the kernel functionality at runtime. 
Device drivers are used as kernel modules. 

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
The suffix of the targets in Kbuild, determines their use:
m - states a target for kernel module (obj-m).
y - states a target for object files as built-in (obj-y), part of the kernel itself. 

Objects listed with obj- are used as modules, or combined in a `built-in.a` archive for the specifir directory. 


It is cool to know - the kernel's config file entries are used as this suffix. For example, stating `CONFIG_BTRFS_FS = y` links `btrfs.o` to the kernel, due to the following line of the BTRFS makefile (Kbuild):
```bash
obj-$(CONFIG_BTRFS_FS) := btrfs.o
```

`obj-y` is actually a list of lists of the built-in objects of the kernel. 
All of these files are then merged into one archive (via `$(AR)`), the `built-in.a` file, which is eventually linked to `vmlinux` (by `scripts/link-vmlinux.sh`). 

On the other hand, `obj-m` is a list of object files that are built as kernel modules. Meaning, it runs `$(LD)` on each element in the list. 

A more detailed doc can be found under [linux makefiles][linux-makefiles]. 


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


[linux-makefiles]: https://docs.kernel.org/kbuild/makefiles.html?highlight=kbuild
[dyndbg-link]: https://www.kernel.org/doc/html/v4.15/admin-guide/dynamic-debug-howto.html
[debugfs]: https://www.opensourceforu.com/2010/10/debugging-linux-kernel-with-debugfs/
