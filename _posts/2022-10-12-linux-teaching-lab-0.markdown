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
1. use `CTRL-\ g` to jump to the symbol's definition
2. use `CTRL-\ s` to jump to the symbol's usages
3. `F5, F6` to move between multiple results
4. use `CTRL-o` to return to the previous location
5. use `:cclose` to close the results panel (should just add F7 as macro)

## Debugging

### GDB
For local debugging, the kernel image `vmlinux` can be used. 
This is especially useful if the kernel was compiled with `-g` flag, and only for static analysis.

It is possible to inspect the kernel state via `/proc/kcore`. Since this virtual file represents the physical memory of the system, it can be used for dynamic debugging of the kernel.
`gdb --nx --quiet ~/src/linux/vmlinux /proc/kcore`
Note: `--nx` is used for vanilla gdb invocation.

In order to generate a stack trace, add `dump_stack()` call in your wanted code section. 

## Adding virtual disk image

Download an extra disk image:
`wget http://elf.cs.pub.ro/so2/res/laboratoare/mydisk.img`
By issuing `file`, we can see this is a BTRFS file system image. 

To add this filesystem to our virtual machine, add the following line to qemu's options within the makefile:
`-drive file=mydisk.img,if=virtio,format=raw \`
Note - `vda` is the root partition, `vdb` and `vdc` are `disk1` and `disk2`, respectively. 

Since the VM uses devtmpfs, our new filesystem can be found under `/dev/vdd`. 

Mount the filesystem (make sure the kernel has compiled with BTRFS enabled):
```bash
mkdir -p /meow
mount /dev/vdd /meow
```


[linux-teaching-labs]: https://github.com/linux-kernel-labs/linux
