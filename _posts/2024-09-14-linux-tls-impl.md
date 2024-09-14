---
layout: post
title:  "Linux TLS Implementation Internals"
date:   2024-09-14 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This page is a short research I've performed, in order to gain more in-depth knowledge regarding TLS, having the end goal of usermode exploitation. \
It is mostly based on this [great paper][tls-impl] as well as dynamic debugging via `pwndbg`. 

## Userspace Interaction

Recall `pwndbg` is an amazing tool, that contains many useful and non-trivial features. In particular, for `x86-32` linux, the `gs` segment register points to the entry within the `GDT` (and sometimes `LDT`, depends on its LSb) within the kernel, that contains the address of the thread-local storage. For `x86-64`, `fs` is the relevant segment register. \
The command `fsbase` actually fetches the TLS address of a thread. I found it fascinating - how does it retrieves an address that resides within the kernel? \
By reading its [sources][pwndbg-source], we can learn it actually calls `ptrace` on the target thread, with the special value of `request = PTRACE_ARCH_PRCTL`, and having a `which == ARCH_GET_FS == 0x1003` (or `GS == 0x1004`). \
`ptrace` manpage is udder shit (I'm sorry, but this is probably the worst manpage in Linux. To be pair, `arch_prctl` doesn't documents `ptrace` too), and doesn't even documents this request type exists. However, by reading the kernel's sources, we can see its implementation within `ptrace.c` is just a basic wrapper for `do_arch_prctl_64` syscall:

```c
#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
	case PTRACE_GET_THREAD_AREA:
		if ((int) addr < 0)
			return -EIO;
		ret = do_get_thread_area(child, addr,
					(struct user_desc __user *)data);
		break;

	case PTRACE_SET_THREAD_AREA:
		if ((int) addr < 0)
			return -EIO;
		ret = do_set_thread_area(child, addr,
					(struct user_desc __user *)data, 0);
		break;
#endif

#ifdef CONFIG_X86_64
		/* normal 64bit interface to access TLS data.
		   Works just like arch_prctl, except that the arguments
		   are reversed. */
	case PTRACE_ARCH_PRCTL:
		ret = do_arch_prctl_64(child, data, addr);
		break;
#endif

	default:
		ret = ptrace_request(child, request, addr, data);
		break;
```

This means that there are actually 3 undocumented requests types: `PTRACE_ARCH_PRCTL(x64)`, `PTRACE_GET_THREAD_AREA`, and `PTRACE_SET_THREAD_AREA`. Each of them is just a wrapper around their corresponding syscall's internal handler! \
It is worth mentioning that `arch_prctl` is a specific extension for either `x86, x64` archs only. Hence, different architectures should have their own implementation to retrieve the thread-local address. 

## Memory Layout

I've created a simple multithreaded program:

```c
void* thread_main(void *params)
{
    puts("hello there");
    pthread_exit(0);
}

int main()
{
    pthread_t t1;
    pthread_create(&t1, NULL, thread_main, NULL);
    pthread_join(t1, NULL);
    return 0;
}
```

This program contains two threads. The following values were retrieved for the threads local storage:

```bash
pwndbg> thread 1
[Switching to thread 1 (Thread 0x7ffff7dd0740 (LWP 2031))]
#0  0x00007ffff7e5dc5e in __futex_abstimed_wait_common ()
   from /nix/store/r8qsxm85rlxzdac7988psm7gimg4dl3q-glibc-2.39-52/lib/libc.so.6
pwndbg> fsbase
0x7ffff7dd0740

pwndbg> thread 2
[Switching to thread 2 (Thread 0x7ffff7c006c0 (LWP 2034))]
#0  thread_main (params=0x0) at test.c:8
8           puts("hello there");
pwndbg> fsbase
0x7ffff7c006c0
```

I've inspected the memory region of the main thread's TLS:

```bash
pwndbg> vmmap 0x7ffff7dd0740                                                                                                                                                                                                                                       
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                                                                                                                                                                                  
             Start                End Perm     Size Offset File                                                                                                                                                                                                    
    0x7ffff7401000     0x7ffff7c01000 rw-p   800000      0 [anon_7ffff7401]                                                                                                                                                                                        ►   0x7ffff7dd0000     0x7ffff7dd3000 rw-p     3000      0 [anon_7ffff7dd0] +0x740                                               
    0x7ffff7dd3000     0x7ffff7dfb000 r--p    28000      0 /nix/store/r8qsxm85rlxzdac7988psm7gimg4dl3q-glibc-2.39-52/lib/libc.so.6
```

This is very interesting - we can see it is stored at some anonymous mapping, which **is adjacent to libc memory mapping**. This means that upon having a libc leakage, we can deterministically know the memory address in which the TLS of the main thread resides! Cool. \
Unfortunately, the address of the non-main thread's TLS is located in the prior region, `anon_7ffff7401`, which isn't adjacent to `anon_7ffff7dd0` in memory. By having multiple executions of this program, I've seen the offset between the TLS addresses is actually constant among runs, which is very cool. \
Moreover, we can see both TLSs are having the same canary, at offset `0x28`:

```bash
pwndbg> x/10gx 0x7ffff7dd0740                                                                                            
0x7ffff7dd0740: 0x00007ffff7dd0740      0x00007ffff7dd10e0
0x7ffff7dd0750: 0x00007ffff7dd0740      0x0000000000000001                                                               
0x7ffff7dd0760: 0x0000000000000000      0x6a1e90f1efec8800

pwndbg> x/20gx 0x7ffff7c006c0                                                                                            
0x7ffff7c006c0: 0x00007ffff7c006c0      0x00000000004052b0
0x7ffff7c006d0: 0x00007ffff7c006c0      0x0000000000000001
0x7ffff7c006e0: 0x0000000000000000      0x6a1e90f1efec8800
```

## ELF Handling

The keyword `__thread` can be used in variable definitions, making them being allocated local to each thread. I've added the following declaration within the "global" scope of the C program:

```c
__thread int i;

void* thread_main(void *params)
{
    puts("hello there");
    i = 0x42424242;
    printf("i addr: %p\n", &i);
    pthread_exit(0);
}

int main()
{
    i = 0x41414141;
    ...
}
```

Interestingly, this variable was allocated **prior** to `fsbase` address, for each thread:

```bash
pwndbg> x/10gx 0x7ffff7dd0740 - 0x10
0x7ffff7dd0730: 0x0000000000000000      0x4141414100000000
0x7ffff7dd0740: 0x00007ffff7dd0740      0x00007ffff7dd10e0
```

This makes sense, in a similar manner to how stack grows downwards. \
Moreover, thread-local variables are found in the `.tdata, .tbss` sections - which are the thread-specific equivalents of `.data, .bss`. The only difference is that `SHF_TLS` section flag is being set. According to the paper, for each thread, new memory is allocated into which the content of the `.tdata, .tbss` content is copied to. These are exactly the anonymous mapping I've debugged earlier via `pwndbg`. \
To handle TLS in runtime, as opposed to regular data sections, which are just being available to the process (all threads) and then used, the eventual `.tdata, .tbss` that are created at compile-time are loaded as multiple different copies, one for each thread, but **all are initialized from the same initialization-image**. Moreover, the normal linking process cannot happen. Hence, a thread-local variable is identified by both a reference to the object, and the offset of the variable in the thread-local storage section. In order to support this feature, many new internal structures to the linker and the ELF file format were added. 


[tls-impl]: https://www.akkadia.org/drepper/tls.pdf
[pwndbg-source]: https://github.com/pwndbg/pwndbg/blob/f492622924f79c134455653e68a08710eff0f683/pwndbg/gdblib/regs.py#L266
