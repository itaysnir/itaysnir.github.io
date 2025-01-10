---
layout: post
title:  "Pwnable.tw - Applestore"
date:   2025-01-10 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Applestore

*tomcr00se rooted the galaxy S5, but we need you to jailbreak the iPhone8!* \
Smells like real-world pwnage, cool :)

```bash
$ checksec ./applestore
[*] '/home/itay/projects/pwnable_tw/applestore/applestore'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    Stripped:   No

$ file ./applestore
./applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
```

## Overview

Another menu-based challenge. There are 6 options: `Apple Store, add to cart, remove from cart, list, checkout, exit`. There's also an interesting `myCart` global variable, zero-initialized. 
The interesting handlers are `add, delete, cart, checkout`. \
Sus notes:

1. `add` handler - uses local `char nptr[22]` buffer on the stack. This buffer is uninitialized, and also contains weird un-aligned amount of bytes. 

2. The device number is called using `my_read`, which reads `n` bytes, and then truncates the last byte. Eventually `atoi` is being called on this buffer. Hence, we may store there some controlled bytes, such as `1/bin/sh`, and the output choice would still be parsed properly. 

3. Upon choosing an item to purchace, `create` is called - which allocates a new item and initializes it. Notice it uses the interesting function `asprintf` - similar to `sprintf`, but also allocates the buffer dynamically on the heap, including the null-byte. This means that for each invocation of `create`, two allocations are performed: `malloc(0x10)` of the item object, which is properly initialized, and another allocation for the name string, using `asprintf`. SUS: what happens in case the name string isn't aligned? In that case, is the returned chunk properly initialized to `0`, or only contains `\x00` at the string end, and having potential garbage past it? Anyways - we cannot control the name string directly, but there are 5 options we can pick from, having sizes (not including the null) of `8, 13, 10, 11, 10`. 

4. After creating an item, it is being inserted to the global `myCart` variable. The cart is the first `item` object, and because each `item` contains `next, prev` pointers, the items are actually stored within a linked list. Upon adding an item, the list is traversed until some item's `next` ptr is NULL, which denotes the list end. In that case, the newly-created item is appended to the linked list. 

5. After appending the item to the list, a prompt of `printf(%s, item->name)` is done. If we can corrupt the `item` pointer / object, this may serve as a good read primitive.

6. `delete` - receives an item index, starting at `1`, and traverses over the items linked list array until that number is reached. If thats the case, it unlinks the chunk off the list, and prints the chunk's `name` member (can also serve as leak primtive?)

7. Traversing is stopped only when `NULL` ptr is found. If we can corrupt some chunk's `next` ptr, we would perform OOB-R. 

8. The unlinked item **remains fully allocated**, and its content remains floating, unchanged, in memory. This is hella sus - why `free` isn't called? And in general - this program doesn't calls `free` at all!

9. `cart` - traverses the items linked list, printing their assigned `name` and `price`. If we can corrupt these, decent leak primitive. 

10. Notice the sus prompt, of asking to check the cart. It reads `0x15` bytes into a stack buffer, comparing the first byte to `y`. We can still set the other bytes to some garbage we'd like. 

11. The `total_price` is defined as `signed int`. Also, there seems to be possible integer overflow, hence we can set it to some low / negative value. 

12. The `checkout` handler is where the real interesting bug happens. If we've set the `total_price` to some specific value of `7174`, it **allocates a new item within the stack, and inserts it to the dynamic linked-list**. This vuln is very interesting, as the inserted item is allocated on the local stack frame of `checkout` - which is about to get destructed by some other stack frames to-be-called. 

13. Notice, the above special item is being added only in case the `total_price` matches a particular value, and this item has a value of `1`. Hence, it won't be trivial to insert this item more than once into the linked list. 

## Exploitation

The main vuln of this challenge seems to be "stack-frame UAF" - a reference to a stack object is saved somewhere, the frame is destructed but the reference remains:

```c
  item v2;
  total_price = cart();
  if ( total_price == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2.name, "%s", "iPhone 8");
    v2.price = 1;
    insert(&v2);
    total_price = 7175;
  }
```

The first question - how can we set `total_price == 7174`? \
We can achieve this by `20 * 299 + 6 * 199`. The mathematical trick here, is to utilize the fact that all prices are ending with `99`. Hence, each addition would add a multiple of `100`, and decrement the total sum by 1. This means we can inverse the logic, and count the amont of decrements (`7200 - 7174 = 26`) we need. The formula is equivalent to finding `a, b, c, d`, such that `a * 2 + b * 3 + c * 4 + d * 5 = 72`, where the sum `a + b + c + d = 26`. \
To generalize, we have the linear solution: `[6 + c + 2*d, 20 - 2*c - 3*d, c, d]`. This may serve us, in case we'd need particular items allocations. 

Our next goal is to find an adequate candidate function, that would allocate local stack content on the same address of the special item. We must be able to control that memory, at least partially. 
