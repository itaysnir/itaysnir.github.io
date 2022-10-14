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


[linux-makefiles]: https://docs.kernel.org/kbuild/makefiles.html?highlight=kbuild