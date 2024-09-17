---
layout: post
title:  "Pwn College - Kernel Security 2"
date:   2024-05-24 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview



## Background

We're given a suid userspace program, as well as a kernel module. The driver creates an interesting procfs entry, `ypu` - stands for "yan processing unit". It contains few multiple operations, including `device_ioctl, device_open, device_release` and `device_mmap`. \
The `open` handler of the device simply stores buffer within the `private_data` of the device, allocated by `vmalloc_user`. This means that this memory area is actually mapped to userspace, not kernel. The equivalent `release` handler just `vfree`s that data. \
The `mmap` handler calls `remap_vmalloc_range` to the newly-allocated chunk within `file->private_data`. This simply maps the pages, allocated by `vmalloc`, to userspace `vma`. 

### vma

Recall `struct vm_area_struct` represents contiguous VA area, meaning a single entry within `/proc/pid/maps`. The `vma`'s of a single task are stored within `struct mm`. Moreover, they are also chained via the `vma->next` member. \
Moreover, a driver that supports `mmap` operation must initialize its associated `vma`, and to map it to some pages. It can be further read [here][linux-kernel-labs-vma] and [here][litux-vma]. 

### `device_mmap`

From a driver's point of view, the `mmap` facility allows direct memory access from userspace. This is interesting - It means that the underlying physical pages may be accessed both by the `vma`'s virtual addresses (`vma->start` up to `vma->end` - which are the real userspace addresses), as well as the driver's VA, which is returned by the kernel allocator (for example, via `vmalloc_user`). \
The driver allocates memory (via `kmalloc, vmalloc, alloc_pages`), and then maps it to user address space via helper functions, such as `remap_pfn_range, remap_vmalloc_range`. \
To obtain the page frame number of physical memory, consider how memory allocation was performed:

1. For `kmalloc`, `pfn = virt_to_phys(addr) >> PAGE_SHIFT`

2. For `vmalloc`, `pfn = vmalloc_to_pfn(addr)`

3. For `alloc_pages`, `pfn = page_to_pfn(addr)`

Recall that userspace mapped pages may be swapped out. Therefore, we must set `PG_reserved` bit on the allocated page, done by `SetPageReserved, ClearPageReserved`. 

## Challenge 1

The userspace component of this challenge opens the driver's `fd`, and executes our shellcode. \
Our shellcode can only call `mmap, ioctl` on the device driver's `fd`. \
The `ioctl` handler is pretty interesting - it starts to execute yan-emulator inside the kernel, having its code segment initialized to the driver's `file->private_data`. Recall this memory was initialized by the module within `device_open`. Userspace may interact with this memory by mapping it via `mmap`, as the `device_mmap` handler assigns `file->private_data` to the requested userspace vma. 

In order for the `mmap` call to succeed, we must make sure `prot` corresponds to the device's protections, as presented within procfs. In our case:

```bash
$ ls -la /proc/ypu 
-rw-rw-rw- 1 root root 0 Sep 17 17:28 /proc/ypu
```

Hence `prot = PROT_READ | PROT_WRITE = 3`. Moreover, I've mapped this region as `MAP_SHARED = 1`, just because we can (and having the option for this region to be visible to other processes may only do good in terms of exploitation). I've set the requested `size = 0x1000`, as this is the size of the allocated `vmalloc` chunk, hence larger `vma` should not be supported. Lastly, I've set `addr = NULL`, so we would retrive any userspace address the OS chooses.

```python
context.arch = 'amd64'

BINARY = '/challenge/toddlersys_level1.0'
SHELLCODE = '''
user_shellcode:
mov rdi, 0
mov rsi, 0x1000
mov rdx, 3
mov r10, 1
mov r8, 3
mov r9, 0
mov rax, 9
syscall

mov rbx, rax

# TODO - write yan code to [rbx]


kernel_shellcode:
push rbx
push rbp
mov rbp, rsp
nop
nop
nop
nop
mov rsp, rbp
pop rbp
pop rbx
ret
'''

def main():     
    p = process(BINARY)
    
    user_shellcode = asm(SHELLCODE)
    with open('gdb_input.bin', 'wb') as f:
        f.write(user_shellcode)
    
    p.send(user_shellcode)

    p.interactive()


if __name__ == '__main__':
    main()
```




[linux-kernel-labs-vma]: https://linux-kernel-labs.github.io/refs/pull/222/merge/labs/memory_mapping.html
[litux-vma]: https://litux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html
