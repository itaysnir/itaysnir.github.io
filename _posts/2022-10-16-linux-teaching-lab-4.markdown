---
layout: post
title:  "Linux Kernel Lab 4 - Character Device Drivers"
date:   2022-10-16 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Hardware devices may be accessed by the user via special files, located under `/dev`, along with syscalls such as `open, read, write, close, mmap`, etc. \
The OS redirects these syscalls to their corresponding handlers, as defined by the device driver. \
The driver is usually a kernel module, that interacts with the hardware device. 

Character device drivers are managing relatively slow devices, with small amount of data. \
Usually there are no frequent `seek` queries towards the device data, as the data access is usually sequential on these devices (for example, keyboard, mouse, serial ports). \
The operations (e.g `read`) are performed byte by byte. 

The linux kernel offers a dedicated API for character device drivers, where system calls go directly to the driver (unlike block devices). 

## Majors And Minors

Devices has a unique fixed identifier associated with them. \
It consists of two parts: major and minor. \
The major stands for the device type (such as SCSI disk / IDE / Serial port, etc), and the second part identifies the device (first disk, second serial port, etc). 

The major identifies the **driver**, while the minor identifies each physical device served by the driver. 

For example:

```bash
$ ls -la /dev/sda* /dev/ttyS?
brw-rw---- 1 root disk    8,  0 Mar 10 00:32 /dev/sda
brw-rw---- 1 root disk    8,  1 Mar 10 00:32 /dev/sda1
brw-rw---- 1 root disk    8,  2 Mar 10 00:32 /dev/sda2
brw-rw---- 1 root disk    8,  3 Mar 10 00:32 /dev/sda3
crw-rw---- 1 root dialout 4, 64 Mar 10 00:32 /dev/ttyS0
crw-rw---- 1 root dialout 4, 65 Mar 10 00:32 /dev/ttyS1
crw-rw---- 1 root dialout 4, 66 Mar 10 00:32 /dev/ttyS2
crw-rw---- 1 root dialout 4, 67 Mar 10 00:32 /dev/ttyS3
crw-rw---- 1 root dialout 4, 68 Mar 10 00:32 /dev/ttyS4
crw-rw---- 1 root dialout 4, 69 Mar 10 00:32 /dev/ttyS5
crw-rw---- 1 root dialout 4, 70 Mar 10 00:32 /dev/ttyS6
crw-rw---- 1 root dialout 4, 71 Mar 10 00:32 /dev/ttyS7
crw-rw---- 1 root dialout 4, 72 Mar 10 00:32 /dev/ttyS8
crw-rw---- 1 root dialout 4, 73 Mar 10 00:32 /dev/ttyS9
```

### /dev/sda

We can see the `sda` is a block device, associated with major number `8`. \
Disk drivers have a major number of `8`, which assigns them as a SCSI block devices (hence `sd`). \
Hard drives that would previously be designated as `hd[a-z]` (usually means the old ATA subsystem) are now referred to as `sd[a-z]`, which is the most used way to refer to hard disks. \
Note that SCSI stands for *small computer system interface* - and is a smart bus (controlled by microprocessor) that allows adding up to 15 devices to the computer (HDAs, USB, printers, etc). 

Moreover, the `sda` driver has 4 "devices", having minors of `0-3`. \
Note  those aren't physical devices - they represent the partition number (there are up to 15 partitions per disk). \
If an another disk device would be presented, it will have the prefix `sdb`, and so on. 

We can learn more about the partition tables of devices via `fdisk`:

```bash
$ sudo fdisk -l 
Disk /dev/sda: 60 GiB, 64424509440 bytes, 125829120 sectors
Disk model: VMware Virtual S
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 8DD30760-4E1B-4E6C-95FB-F4D72B38D1CD

Device       Start       End   Sectors  Size Type
/dev/sda1     2048      4095      2048    1M BIOS boot
/dev/sda2     4096   1054719   1050624  513M EFI System
/dev/sda3  1054720 125827071 124772352 59.5G Linux filesystem
```

Cool - we can see the size of each partition (within sectors) and its type. 

The next command is `lsblk`, which displays the partitions in a tree-topology:

```bash
$ lsblk
sda      8:0    0    60G  0 disk
├─sda1   8:1    0     1M  0 part
├─sda2   8:2    0   513M  0 part /boot/efi
└─sda3   8:3    0  59.5G  0 part /var/snap/firefox/common/host-hunspell
```

### /dev/ttyS

The second type of devices we can see, are `ttyS` devices. \
There are 3 types of `tty` drivers: console, serial port and pty. \
The `console, pty` drivers are implemented, and probably the only ones needed of these types. \
Therefore, new `tty` drivers are usually serial port devices (such as `ttyUSB`).

The `/proc/tty/drivers` file represents the loaded `tty` drivers in the kernel:

```bash
$ cat /proc/tty/drivers
/dev/tty             /dev/tty        5       0 system:/dev/tty
/dev/console         /dev/console    5       1 system:console
/dev/ptmx            /dev/ptmx       5       2 system
/dev/vc/0            /dev/vc/0       4       0 system:vtmaster
dbc_serial           /dev/ttyDBC   240 0-63 serial
ttyprintk            /dev/ttyprintk   5       3 console
max310x              /dev/ttyMAX   204 209-224 serial
serial               /dev/ttyS       4 64-111 serial
pty_slave            /dev/pts      136 0-1048575 pty:slave
pty_master           /dev/ptm      128 0-1048575 pty:master
unknown              /dev/tty        4 1-63 console
```

We can see that `ttyS` stands for a `serial` tty driver, having major number of `4`. \
Particular information about some specific driver may be found under `/proc/tty/driver/`, as well as `/sys/class/tty/`:

```bash
$ ls -la /sys/class/tty/ttyS?
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS0 -> ../../devices/pnp0/00:05/tty/ttyS0
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS1 -> ../../devices/platform/serial8250/tty/ttyS1
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS2 -> ../../devices/platform/serial8250/tty/ttyS2
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS3 -> ../../devices/platform/serial8250/tty/ttyS3
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS4 -> ../../devices/platform/serial8250/tty/ttyS4
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS5 -> ../../devices/platform/serial8250/tty/ttyS5
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS6 -> ../../devices/platform/serial8250/tty/ttyS6
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS7 -> ../../devices/platform/serial8250/tty/ttyS7
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS8 -> ../../devices/platform/serial8250/tty/ttyS8
lrwxrwxrwx 1 root root 0 Mar 10 02:54 /sys/class/tty/ttyS9 -> ../../devices/platform/serial8250/tty/ttyS9
```

The driver tells the kernel the locations of the physical device associated with the tty device, by creating a symlink back to them. 

Moreover, by looking at `/proc/devices`, we can see the mapping of major number and relevant drivers, for all devices installed within the system. 

To send text to a terminal, we may redirect stdout of some CLI program to the appropriate special serial port (`ttyS`) file:

```bash
echo noder0 > /dev/ttyS0
echo noder1 > /dev/ttyS1
```

Each `ttyS` device is mapped to a different I/O address (bus-physical / PCI address) and IRQs. \
The `setserial` command shows this mapping:

```bash
$ sudo setserial -g /dev/ttyS0
/dev/ttyS0, UART: 16550A, Port: 0x03f8, IRQ: 4
```

Note that a `tty` is an abstraction for serial IO, for program that runs on a terminal (for example, it understands using backspace keys to erase characters before the program "sees" them). \
Serial device is a driver for real hardware, such as UART. \
It understands bit rates, parity, control lines, interrupts. 

Pseudo terminals have no physical connector on the PC, and are used to emulate serial port (they have no IO address, nor IRQ). \
If someone connects via telnet / ssh over the network, they may connect to a pseudo terminal port, such as `/dev/ptyp2`. \
Pseudo terminals come in pairs: the `pty` stands for the master controlling the terminal, and `tty` is the slave. \
They stand for the same port, but the slave is used by the network program, where the master is used by the userspace application. \
Modern unix doesn't use this approach, but uses a `pty master`, which is `/dev/ptmx`, which can supply a `pty` on demand. 

`/dev/tty` is the controlling terminal for the current process. \
By using `ps -a`, we can see the process <-> tty mapping:

```bash
$ ps -a 
 PID TTY          TIME CMD
   1339 tty2     00:00:00 gnome-session-b
   2783 pts/0    00:00:00 tmux: client
   4558 pts/2    00:00:00 ps
```

Note that `/dev/tty` stands for the current terminal that is now used:

```bash
$ tty
/dev/pts/1
```

In linux, the PC monitor is called console, and it has several special files - `ttyN`, which are called virtual terminals. \
Upon logging in, the console is set to `tty1`. We can switch to other virtual terminals using `ALT+F2` (for `tty2`). \
`tty0` is an alias for the current virtual terminal, and its where messages from the system are sent. 

Extra reading: [link1][ttyS], [link2][ttyS2], [link3][ttyS3], [link4][ttyS4], [link5][devices]. 

## Making New Device

We can create a new device (and type), via `mknod`:

```bash
mknod /dev/my_char_dev c 42 0
mknod /dev/my_block_dev b 240 0
```

## Char Devices - Structs

A character device is represented by `struct cdev`. \
The driver operations implementation utilizes three core structs: `struct file_operations, struct file, struct inode`. 

### struct file_operations




[ttyS]: https://tldp.org/HOWTO/Serial-HOWTO-10.html
[ttyS2]: https://www.mit.edu/afs.new/athena/system/rhlinux/redhat-6.2-docs/HOWTOS/other-formats/html/Text-Terminal-HOWTO-html/Text-Terminal-HOWTO-6.html
[ttyS3]: https://www.oreilly.com/library/view/linux-device-drivers/0596005903/ch18.html
[ttyS4]: https://www.linux.it/~rubini/docs/serial/serial.html
[devices]: https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
