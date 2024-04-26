---
layout: post
title:  "Pwn College - Debugging"
date:   2024-04-26 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module teaches basics of `gdb` debugging. \
Nothing too fancy here. 

## gdb Config

Useful `~/.gdbinit`:

```bash
set history save on
set disassembly-flavor intel
set pagination off
set follow-fork-mode child  # Depends on usage
```

## Challenge 4

`TUI` basic usefull commands:

```bash
display/10gx $rsp   # print it upon every si
display/8i $rip
finish              # continue execution until function scope end
```

## Challenge 5

```bash
start               # equivalent to 'break main; run'
silent              # usefull within bp-commands-end block. makes more clean output.
```

## Challenge 6

Catch syscalls using the debugger. 

```bash
start
  catch syscall read
  commands
    silent
    if ($rdi == 42)
      set $rdi = 0
    end
    continue
  end
  continue
```

## Challenge 7

```bash
call (void) win()
```

## Challenge 8

Now the win function causes a `SIGSEGV` upon invokation. 

The trick is to set `set unwindonsignal on`. \
By default, gdb remains in the same frame where its received its signal at, and won’t be in the called dummy context anymore. \
Notice this attribute is only relevant for dummy calls. 

Another trick, skipping the code that causes the segfault:
```bash
jump *win+35
```
