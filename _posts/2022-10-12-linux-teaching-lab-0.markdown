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

## Exercise - Adding virtual disk image

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

Since the kernel wasn't configured to support BTRFS filesystems, we can easily twick it via `make menuconfig` (add Btrfs as a builtin within the kernel). 
Recompile the kernel to apply changes.
Now mounting should be done successfully.

## Exercise - Remote GDB Debugging
Qemu allows to open a gdbserver on the emulated machine, by 
specifing the flag `-gdb protocol::port`.
Alternatively, `-s` will listen on tcp port 1234. 

As an example of dynamic debugging, we want to hook the handler of the sys_access syscall. 

We can find its address by searching the generated symbols file of the kernel, `System.map`:
`cat System.map | grep -i sys_access`
Its resulting address is `0xc11a9c70`. 

Now we can hook this address via gdb, and issue `ls` command on the VM. Since the `access` syscall retrives the user's permissions for a given file, eventually it will be called when we issue `ls`. 

Indeed, the breakpoint was hit, and the following backtrace is generated:
```bash
(gdb) bt
#0  __ia32_sys_access (regs=0xce99bfb4) at fs/open.c:482
#1  0xc171e86c in do_syscall_32_irqs_on (nr=<optimized out>, regs=0xce99bfb4)
    at arch/x86/entry/common.c:77
#2  do_int80_syscall_32 (regs=0xce99bfb4) at arch/x86/entry/common.c:94
#3  0xc172bccb in entry_INT80_32 () at arch/x86/entry/entry_32.S:1059
```

To display the content and address of the `jiffies` variable, issue `x/gx &jiffies`

## Exercise - Cscope
In order to generate cscope index, navigate to the kernel source tree and issue `make cscope`. 

To search for a symbol, issue `:cs f g <SYMBOL>`
Another option is landing the cursor on our desired symbol name, and issue `CTRL + \ + g` to find it. 

To swap between the recent search and previous one, issue `CTRL + o` or `CTRL + i`. 

It is highly recommended to create a macro for `:copen` and `:cclose`. 

To exit all windows at once, issue `:wqa`

[linux-teaching-labs]: https://github.com/linux-kernel-labs/linux
