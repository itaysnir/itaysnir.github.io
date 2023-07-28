---
layout: post
title:  "The Linux Audit Subsystem"
date:   2022-12-29 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview
Recently I've came across a need to monitor file modifications on a system-wide scale. 

Unfortunately, the `inotify` mechanism didn't met my needs. \
For example -  `inotify` API is too low level, demanding me to write C programs or using some external wrappers. \
It has horrible performance. It also doesn't record any data bound to the event - such as *PID, UID and Timestamp*. \
Last but not least, it only allows very limited, file-specific (instead of system-wide) monitoring. 

In this article, i will write about the *Audit Linux Subsystem*, mostly from userspace perspective (but will research abit into the kernel).

## Audit - General 
Linux kernels of versions `> 2.4`, contains a subsystem called the *Audit Subsystem*. \
It has a friendly userspace API, that allows setting rules that will be parsed and processed in-kernel (similar to `iptables`). \
The rules apply to various of system-level events, including file-system events. 

In case an event matches certain rule, it triggers write of a record within the disk, hence allows later inspection of interesting events within the system. \
The records are being written by the `auditd` userspace daemon. \
The kernel processes events via the `kauditd` kernel thread. 

## API 
The main command to control addition / deletion of new rules is `auditctl`. 

For example, deleting all previous rules and setting a new rule, to monitor all accesses of a file:

```bash
auditctl -l  # Inspect existing rules
auditctl -D  # Delete prev rules
auditctl -w /tmp/noder -p rwxa  # Monitor given path, for read, write, execute and inode changes. 
```

Note that rules are being processed according to the their order, in a similar manner to routing table. \
The first rule that applies, is the one taken. 

It is also possible to add exclude rules, and drop certain events from being recorded.

Inspection of an event is done via `ausearch`, and a search keyword:

```bash
ausearch -f noder
```

A comperhensive summary of the events can be found via `aureport`. 

## Records
The records themselves are stored under `/var/log/audit/audit.log`. \
The `ausearch` binary parses and filters the log file, and reports to stdout the found records. 

For example, I've set the following rule, to catch any process that opens certain file:

```bash
auditctl -a always,exit -F arch=b64 -S openat -S open -F path=/home/itay/Documents/audit_test
ausearch -f audit_test  # Flag of -k allows searching by string
```

An example record:

```bash
----
time->Thu Dec 29 10:12:04 2022
type=PROCTITLE msg=audit(1672326724.487:781): proctitle="/usr/libexec/tracker-extract-3"
type=PATH msg=audit(1672326724.487:781): item=0 name="/home/itay/Documents/audit_test" inode=920114 dev=08:03 mode=0100664 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1672326724.487:781): cwd="/home/itay"
type=SYSCALL msg=audit(1672326724.487:781): arch=c000003e syscall=257 success=yes exit=10 a0=ffffff9c a1=564510f91e70 a2=40000 a3=0 items=1 ppid=1122 pid=7657 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=2 comm="tracker-extract" exe="/usr/libexec/tracker-extract-3" subj=unconfined key=(null)
```

This record is written due to a write I've performed from the terminal to the file, that have triggered `openat` on a `O_WRITONLY` mode. 

Note it contains extremely valuable data, such as the `PID, uid, and timestamp` of the event. 
 
## Rules - Examples

### File Access

Monitor every access to a file, including modifications. \
The `-k` flag allows setting a label to the recorded log, hence making it easily distinguishable. 

```bash
auditctl -a always,exit -F arch=b64 -S openat -S open -F path=/tmp/noder -k OPEN_EVENT
auditctl -w /tmp/noder -p rwxa -k REGULAR_ACCESS_EVENT
```

Note that modification is abit wierd, and sometimes (for example, under redirections), the second rule doesn't catch write events (see [bug][bug]). \
Thats why I've also used the `open, openat` syscall catchers. 

### Recursive Dir Monitor

```bash
auditctl -a always,exit -F arch=b64 -S openat -S open -F dir=/home/itay/Documents/test -k DIR_TEST
auditctl -w /home/itay/Documents/test -p wxa  # Watch for changes
```

### Admin Access

Monitor every access event made by the root user, towards a file of lower priviledge.

```bash
auditctl -a always,exit -F dir=/home/ -F uid=0 -C auid!=obj_uid
```

### Syscalls Diagnosis

Monitor all syscalls that have triggered within the system, and returned with a `-ENOMEM` errno. 

```bash
auditctl -a always,exit -S all -F exit=ENOMEM -k SYSCALL
```

If only a particualr process is required, simply add `-F pid=9000`. 

Many more, extremely cool profiling rules can be easily made. 

[bug]: https://github.com/linux-audit/audit-userspace/issues/289
