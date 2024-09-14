---
layout: post
title:  "Pwn College - Kernel Security"
date:   2024-05-23 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

## Background

Recall some resources are only available for the kernel. For example, setting the value of `MSR_LSTAR` (register that contains the kernel address of the syscall table) via `wrmsr, rdmsr`, or the value of `cr3` - which contains the page table address. \
The current CPU privilege level is stored within the `cs` register 3 lowest bits. Do not be confused with `uid` privileges - while root (uid 0) means a total userspace privileges (OS-level security), it doesn't means a process running with root uid can overwrite kernel memory. Only execution context running with CPL of 0 (ring 0), as tracked by the CPU, is able to do so. \
For example, for every `syscall` instruction, CPL is changed to `0`, control flow jumps to `MSR_LSTAR`, and RA is stored in `rcx` (not stack, as it might be a shared region with other threads). Return is being done via `sysret`. Regarding memory mappings, userspace processes have their VA mapped at low addresses. The kernel has its own VA space, located in high addresses and mapped for all processes (yet only accessible from CPL 0). \
The Linux kernel is monolithic kernel. This means that a single binary unifies all OS-level tasks, and drivers are libaries that are loaded to this binary. In particular, drivers are NOT userspace components that request operations by the kernel. This means that upon finding a driver vulnerability, the kernel may be compromised. \
Our attack vector would usually be an arbitrary code execution within userspace, and our goal - a LPE. 

### Environment

We'd work on a VM. We need: Compiler, kernel, userspace FS, and emulator (qemu). Pwncollege environemnt setup can be found [here][pwnkernel]. Moreover, `/home/ctf/pwn/kernel` is mounted to the host home directory. \
In terms of debugging - the kernel was compiled with debug symbols, and KASLR is disabled for most challenges. We'd compile most of our userspace programs with `-static -nostdlib`. Since `qemu` was launched with `-s`, it opens a gdbserver port at `1234`, meaning we'd be able to debug the kernel from regular host gdb invocation: `gdb -nx vmlinux` (usually we won't like to use `pwndbg` or `gef`), and issue the following:

```bash
target remote :1234
```

Interestingly, upon kernel debugging, we can set a breakpoint on userspace addresses - and they would hit anytime a userspace process reaches that address. Moreover, now instead of `si` simply passes `syscall` instruction, which is the userspace behavior, upon hitting `si` - it would actually launch us back to the kernel. Notice that also every userspace process have its corresponding kernel stack, which is loaded by the start of the `syscall` instruction handler. \
There are 2 main ways to retrieve kernel symbol's address:

1. From the kernel binary image (`objdump` for example)

2. From `/proc/kallsyms`, including those of loaded kernel modules! Need root access (or leak) tho.

The following links may also come handy: [link1][setup1], [link2][setup2], [link3][setup3]


### Kernel Modules




[pwnkernel]: https://github.com/pwncollege/pwnkernel/tree/main
[setup1]: https://scoding.de/linux-kernel-exploitation-environment
[setup2]: https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/
[setup3]: https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
