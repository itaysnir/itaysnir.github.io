---
layout: post
title:  "Linux Teaching Lab 0 - Introduction"
date:   2022-10-12 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Lab 0 - Infrastructure

Clone [linux teaching labs][linux-teaching-labs] to your workspace. 
The task files are located under `linux/tools/labs`. 

To solve tasks, we build the drivers by issuing:
```bash
make clean  # cleans old modules sources
LABS=kernel_modules make skels  # creates skeleton drivers sources for the kernel_modules lab. Stored under the skels/ dir. 
make build  # builds the driver sources
make copy  # copies the drivers to the VM. 
```

Start the vm:
```bash
make boot  # without console, add QEMU_DISPLAY=gtk otherwise
minicom -D serial.pts  # connect to the VM
```

Attaching debugger to the VM kernel:
`make gdb`

## Cscope

Create a cscope database in the linux tree:
`make ARCH=x86 COMPILED_SOURCE=1 cscope`
Note: using the `COMPILED_SOURCE` flag, ensures that only symbols that has been used in the compile process will be indexed. So make sure to run it only after the kernel was compiled. 

After configuring the default vimrc cscope configuration:
use `CTRL-\ g` to jump to the symbol's definition
use `CTRL-\ s` to jump to the symbol's usages
`F5, F6` to move between multiple results
use `CTRL-o` to return to the previous location
use `:cclose` to close the results panel (should just add F7 as macro)

## Debugging

### GDB
For local debugging, the kernel image `vmlinux` can be used. 
This is especially useful if the kernel was compiled with `-g` flag, and only for static analysis.

It is possible to inspect the kernel state via `/proc/kcore`. Since this virtual file represents the physical memory of the system, it can be used for dynamic debugging of the kernel.
`gdb --quiet ~/src/linux/vmlinux /proc/kcore`

In order to generate a stack trace, add `dump_stack()` call in the wanted code section. 


[linux-teaching-labs]: https://github.com/linux-kernel-labs/linux
