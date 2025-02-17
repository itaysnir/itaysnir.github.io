---
layout: post
title: "Pwnable.tw - Starbound"
date: 2025-02-15 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Starbound 

```bash
RELRO           Stack Canary      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY    Fortified   Fortifiable      Name
Partial RELRO   No Canary Found   NX enabled    PIE Disabled    No RPATH   No RUNPATH   150 symbols     Yes        4           6 

file ./starbound
./starbound: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5a960d92ab1e8594d377bd96eb6ea49980f412a9, not stripped
```

No canary, partial RELRO, no PIE. Only NX. \
Moreover, we're not provided with any libc version. 
For now, I'd assume it is the common `libc_32.so`, given within other challenges such as `death_note`. 

## Setup

First, I had to install Ubuntu-17.04 machine, as `libssl1.0.0` was missing. 
I've downloaded the image, and updated the apt as follows:

```bash
$ sudo vi /etc/apt/sources.list
:%s/archive/old-releases/g
:%s/us\.//g
$ sudo apt-get update
$ sudo apt-get upgrade
```

Unfortunately, `pwntools` for python3 isn't supported at this old version. 
Downgraded to `python2`. 

Interestingly, upon running the binary from my Ubuntu-17.04-64bit machine, the following occured:

```bash
meow@ubuntu:~/tmp$ ls -la
total 76
drwxr-xr-x  2 meow meow  4096 Feb 17 02:49 .
drwxr-xr-x 15 meow meow  4096 Feb 17 02:48 ..
-rwxr-xr-x  1 meow meow 66590 Jan 24  2017 starbound
meow@ubuntu:~/tmp$ ./starbound 
bash: ./starbound: No such file or directory
```

Well, the machine trolls me hard. \
After some research, apparently this what happens when trying to run 32-bit binaries on some old ubuntu-64 machines. \
In order to mimic the remote environment percisely, I've reinstalled Ubuntu-17.04 machine, this time for 32-bit. \
I had few issues while installing new `cryptography` versions, probably because it required rust toolchain. 
By issuing `python -m pip install cryptography==3.1`, I could install pwntools properly. 
Only to figure out `pwntools` doesn't works on 32-bit python executables. \
I've returned to the 17.04-64 bit machine, and installed the following packages, to support running 32-bit binaries:

```bash
sudo dpkg --add-architecture i386
sudo apt-get install multiarch-support
sudo apt-get update
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
# Required for the challenge
sudo apt-get install libssl1.0.0:i386
```

Now, the binary had finally the correct libaries resolved:

```bash
meow@ubuntu:~/pwnable_tw/starbound$ ldd ./starbound
        linux-gate.so.1 =>  (0xf7763000)
        libcrypto.so.1.0.0 => /lib/i386-linux-gnu/libcrypto.so.1.0.0 (0xf7555000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf739b000)
        libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xf7396000)
        /lib/ld-linux.so.2 (0x565a1000)
```

Upon verifying the binary works, I've used `patchelf` and set the known `libc_32.so` and its corresponding `ld-2.23.so` as the runtime environment. \
Hopefully, by doing this AND using an old ubuntu-17.04 machine, I can mimic as close as possible the remote environment. 

## Overview
