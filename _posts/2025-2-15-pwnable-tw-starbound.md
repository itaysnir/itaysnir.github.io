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

*Let's play starbound together!

multi-player features are disabled.*

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

First, I had to install Ubuntu-17.04 machine, as `libssl1.0.0` wasn't supported on my local ubuntu 22.04 machine. 
I've downloaded the image, and updated its apt as follows:

```bash
$ sudo vi /etc/apt/sources.list
:%s/archive/old-releases/g
:%s/us\.//g
$ sudo apt-get update
$ sudo apt-get upgrade
```

Unfortunately, `pwntools` for python3 isn't supported at this old version - as `unix_ar` requires at least `python3.6`. 
While I could (and did) compile the sources of `python3.12`, the easiest solution was to just downgrade into `python2`. 

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
After some research, apparently this what happens when trying to run 32-bit binaries on ubuntu-64 machines - incase they miss an adequate runtime environment (`libc, ld` for `i386`). \
I've reinstalled Ubuntu-17.04 machine, this time for 32-bit (I'm not sure if the remote server is 32-bit or 64-bit kernel). \
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
After doing a small research, I've figured out all 32-bit binaries which have used `libc_32.so` had the following specs:

```bash
$ uname -a
Linux 9847b2ff32d5 4.9.0-x86_64-linode79 #1 SMP Mon Dec 12 13:17:30 EST 2016 x86_64 x86_64 x86_64 GNU/Linux
```

This means all of them aren't an Ubuntu machine at all, but "Vanilla" kernel builds from commit `9847b2ff32d5`. \
On the other hand, on my configured Ubuntu-17.04 64-bit (`Zesty Zapus` stable release):

```bash
$ uname -a
Linux ubuntu 4.10.0-42-generic #46-Ubuntu SMP Mon Dec 4 14:38:01 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

By doing abit research, there seemed to be no stable Ubuntu release having kernel version 4.9.0. 
Hence, `Zesty Zapus` is as close as possible. \
Hopefully, by patching the runtime `libc, ld` and using this particular ubuntu-17.04 machine, I can mimic as close as possible the remote environment. \

## Overview

1. Within `main`, `init` is called - initializes some global pointers. 

2. Within `main`, within an infinite loop, `0x100` bytes are read into a local buffer of size `0x100`. Of course, it may be untruncated buffer. Hence, we might be able to leak content past that buffer using `strtol` return value:

```c
char nptr[256];
if ( !readn(nptr, 0x100u) )
        break;
option = strtol(nptr, 0, 10);
```

3. Vuln - Interestingly, the `main` loop executes an handler, based on the value of certain `.bss` pointer. It is very sus - because the value of `option` is nearly unconstrained, we might be able to perform OOB-access, obtaining limited branch primitive:

```c
((void (*)(void))dword_8058154[option])();
```

4. `init` - sets some sus signal handler, that executes `do_afk` (method that only prints player's name and exits). It then reads 4 random bytes as a random seed. 

5. Sus note - `init` saves the random seed at a global `.bss me`. If we can leak it, we can reverse-execute the random generator. 

6. `init` calls `init_map`. For now I won't focus on its initialization process, as this method is only called from this single site, which is executed before any user interaction. However, its main goal is to initialize the `char map_tmp[512]`. Notice the map's first byte might have special meaning. Also notice, that right after the `map_tmp`, the `me` random seed resides (and after it, various of `.bss` dwords). 

7. It then assigns heap buffer `cp` based on the remote's IP, yet leaves it uninitialized - and copies the src buf. In particular, the following code may leave untruncated string within the allocated heap buffer:

```c
// Doesn't initializes the returned buffer
cp = (char *)malloc(strlen(remote_ip_string) + 1);
...
// May leave non-null last byte, yielding untruncated string
strcpy(cp, remote_ip_string);  
```

8. `init` randomizes an index, and uses it to access `name_list[n % 2826]` (the name list is indeed `2826 * 4` bytes long). Recall that `rand` may return a value from anywhere between `0` to `INT32_MAX`. Can we somehow set this modulu operation as a negative return value? If so, possible OOB-access would occur. Based on that randomized index, it copies the randomized name string into `player_name`, which is a `.bss` buffer of size `0x80`.  

9. While most of the `name_list` strings seems decent, there are few interesting notes. First, due to a compiler optimization, in case there are 2 strings - `"Man-Ape"` and `"Ape"`, the compiler would store the `.rodata` pointer of the offset towards `"Ape"`, instead of generating a whole new string within the `.rodata` section. In addition, there are 2 name strings that doesn't gets parsed properly. This seems to be due to having a unicode-encoded character of 2-bytes, instead of a regular ASCII character:

```bash
.rodata:0804B363 aAralune        db 'Aralune',0          ; DATA XREF: .data:080553DC↓o
.rodata:0804B36B unk_804B36B     db  41h ; A             ; DATA XREF: .data:080553E0↓o
.rodata:0804B36C                 db  72h ; r
.rodata:0804B36D                 db  61h ; a
.rodata:0804B36E                 db 0C3h                # Unprintable
.rodata:0804B36F                 db 0B1h
.rodata:0804B370                 db  61h ; a
.rodata:0804B371                 db    0
.rodata:0804B372 unk_804B372     db  41h ; A             ; DATA XREF: .data:080553E4↓o
.rodata:0804B373                 db  72h ; r
.rodata:0804B374                 db  63h ; c
.rodata:0804B375                 db    0
.rodata:0804B376 aArcade         db 'Arcade',0           ; DATA XREF: .data:080553E8↓o


.rodata:080535AC aLilithTheDaugh db 'Lilith, the Daughter of Dracula ',0
.rodata:080535AC                                         ; DATA XREF: .data:08056834↓o
.rodata:080535CD                 align 10h
.rodata:080535D0 unk_80535D0     db  4Dh ; M             ; DATA XREF: .data:08056960↓o
.rodata:080535D1                 db  61h ; a
.rodata:080535D2                 db  64h ; d
.rodata:080535D3                 db  20h
.rodata:080535D4                 db  54h ; T
.rodata:080535D5                 db  68h ; h
.rodata:080535D6                 db  69h ; i
.rodata:080535D7                 db  6Eh ; n
.rodata:080535D8                 db  6Bh ; k
.rodata:080535D9                 db  65h ; e
.rodata:080535DA                 db  72h ; r
.rodata:080535DB                 db 0E2h                # Unprintable
.rodata:080535DC                 db  80h
.rodata:080535DD                 db  99h
.rodata:080535DE                 db  73h ; s
.rodata:080535DF                 db  20h
.rodata:080535E0                 db  41h ; A
.rodata:080535E1                 db  77h ; w
.rodata:080535E2                 db  65h ; e
.rodata:080535E3                 db  73h ; s
.rodata:080535E4                 db  6Fh ; o
.rodata:080535E5                 db  6Dh ; m
.rodata:080535E6                 db  65h ; e
.rodata:080535E7                 db  20h
.rodata:080535E8                 db  41h ; A
.rodata:080535E9                 db  6Eh ; n
.rodata:080535EA                 db  64h ; d
.rodata:080535EB                 db  72h ; r
.rodata:080535EC                 db  6Fh ; o
.rodata:080535ED                 db  69h ; i
.rodata:080535EE                 db  64h ; d
.rodata:080535EF                 db    0
.rodata:080535F0 aNukeSquadronSu db 'Nuke - Squadron Supreme Member',0
```

10. In addition, few other strings also contain embedded special characters, such as `"Katherine \"Kitty\" Pryde", MN-E (Ultraverse)`. Maybe we can utilize this. 

11. It then prints the current "map" using `cmd_view`. This method is abit complex, as it parses the whole map - which has many features. The map contains `18` rows, and `50` coloumns. It may contain interesting vulns, would look further into this after I figure out which data I may be able to control.

12. Finally, `init` sets the global `.bss command` function pointer, to `show_main_menu`.

13. `show_main_menu` - also contains many handlers by itself - `exit, info, move, view, tools, kill, settings, multiplayer`. The challenge's hint seems to be pointing towards the multiplayer feature. 

14. `show_main_menu` first initializes all of its `.bss` function pointers to `cmd_nop`, which seems to be only calling `puts()` on some jetpack image (its pointer is also stored on the `.bss`). Notice that it initializes all 10 pointers of that array, eventhough the program only uses the first 8. This means there are `2` unused function pointers slots. In particular, notice the `.bss command` resides right after this buffer's end. This means that by supplying `index == 10` (11'th slot) within main, we'd be able to execute it. Indeed, because `command` is first initialized to `show_main_menu`, upon setting the desired index to `10`, the main menu is printed twice. Thats a clear OOB vuln. We can (and should) take this idea further, and by supplying huge index - gain arbitrary branch primitive. For high addresses (libc) - just supply high index. For low addresse, prior to `command`, supply HUGE index, such that the VA space would wrap-around. In particular, since the binary isn't PIE, we can easily execute any program function / libc function within the program (by jumping into the `.plt`). 

15. `cmd_info` - prints lots of interesting information. This includes the random seed (meaning, we can reverse-execute all `rand` operations), the server ID (which is retrieved by the very sus method `get_server_key`), and many more. In particular, we might be able to utilize this as leak primitive, via the `player_name, cp(remote ip buffer)` printings in particular. 

16. `cmd_move` - opens a whole new move menu, containing handlers of its own - move `back, left, right, jump`. GAH, so many handlers. Just as `show_main_init`, this method also initializes all function pointers handlers and overwrites them. Vuln: this means that we can overwrite the original handlers with these handlers, and executing them out of context:

```c
 for ( result = 0; result <= 9; ++result )
    fps_array_0[result] = (int)cmd_nop;
  info_fp = (int)cmd_go_back;
  move_vp = (int)cmd_move_left;
  view_vp = (int)cmd_move_right;
  build_fp = (int)cmd_move_jump;
```

17. `cmd_view` - prints the map. As mentioned, it may contain interesting parsing vulns. 

18. `cmd_build` - In a similar manner to `cmd_move`, opens yet another menu of handlers:

```c
for ( result = 0; result <= 9; ++result )
    fps_array_0[result] = (int)cmd_nop;
  info_fp = (int)cmd_go_back;
  move_vp = (int)cmd_build_dig;
  view_vp = (int)cmd_build_place;
```

19. `cmd_kill` - reads arbtirary `0x100` bytes into `268` bytes buffer and truncates it. Interestingly, it calls `do_die`, which issues `__printf_chk`, possibly sends packet to remote server, and `exit`s. While this method shall check for stack overflows, it doesn't checks for sus format strings. This means it can serve as a great leak primitive:

```c
__printf_chk(1, die_prompt);
```

Indeed: 

```bash
-+STARBOUND v1.0+-
  0. Exit
  1. Info
  2. Move
  3. View
  4. Tools
  5. Kill
  6. Settings
  7. Multiplayer
> 5
Why???? %s%s%s%s%s
GG`Ne^_]Í&<?ld-linux.so.2
Save your record? (y/n)[Info] Cannonball I is AFK
```

20. `cmd_settings` - opens another menu:

```c
for ( result = 0; result <= 9; ++result )
    fps_array_0[result] = (int)cmd_nop;
  info_fp = (int)cmd_go_back;
  move_vp = (int)cmd_set_name;
  view_vp = (int)cmd_set_ip;
  build_fp = (int)cmd_set_autoview;
```


21. `cmd_set_name` - read `0x64` bytes into the `0x80` bytes `.bss player_name` buffer. Interestingly, it sets `name + read_size` to null. Because the `read_size` is asserted to be greater than `0`, there's no vuln and the string is truncated properly. 

22. `cmd_set_ip` - reads `0x100` bytes to `268` bytes local buffer. Vuln: the local buffer isn't initialized. This means that by reading only 1 byte, uninitialized bytes would remain there. But since `malloc(read_size)` is called, allong with adequate `memcpy` size and truncation, there's no direct vuln here. **However, notice that we can inject arbitrary bytes as legitimate IP address. In particular, we can inject format-string specifiers**.

23. `cmd_set_autoview` - switches the `enabled_autoview` flag. Notice it is 4-byte long. 

24. `cmd_multiplayaer` - opens the multiplayer menu. Recall there was a hint that the vuln is involved with this handler:

```c
for ( result = 0; result <= 9; ++result )
    fps_array_0[result] = (int)cmd_nop;
  info_fp = (int)cmd_go_back;
  move_vp = (int)cmd_multiplayer_enable;
  view_vp = (int)cmd_multiplayer_disable;
  build_fp = (int)cmd_multiplayer_recvmap;
  kill_fp = (int)cmd_multiplayer_sendmap;
```

All of these handlers are very sus:

1. 
