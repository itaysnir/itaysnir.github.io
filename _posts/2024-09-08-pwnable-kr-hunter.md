---
layout: post
title:  "Pwnable.kr - Hunter"
date:   2024-09-08 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Recently I've learned new heap exploitation techniques, and wanted to put my new knowledge to the test. \
I've recalled `pwnable.kr` hosts a heap challenge that is considered pretty hard - "Hunter" (it also contains the lowest completions within pwnable!), which means a great new learning opportunity. \
I deem it as a very good challenge, as it contains many possible solution routes. Personally, I've been using only a subset of the existing vulns within that binary, in the cost of having pretty awful exploitation statistics. 

Since pwnable.kr forbids publishing a full solution, I will not post a solution script. \
However, a clever reader may understand my route, and pwn this easily. 

## Background

x86-32 binary, old libc of 2.23:

```bash
$ checksec hunter
[*] '/home/hunter/hunter'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

$ ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.3) 2.23
```

This is a classic menu-based heap challenge. We can:

1. Allocate large chunk, setting the global `monster` to its value

2. Free the previously allocated large chunk, `free(monster)`

3. Allocate small chunk, setting an internal pointer of global `player_state_ptr->items_head` to its value

4. Allocating small chunk, adding it to the last element within the items linked list: `player_state_ptr->items_head->first_item->next->next->next ... = malloc()`

5. Secret menu, containing few vulns

## Reverse Engineering

### Structs

Using the "constructors", I've defined few crucial structs:

```c
struct monster
{
  int32_t rand_1;
  int32_t expr;
  int32_t unk2;
  int body_color[4096];
  char *name_ptr;
};

struct player_state
{
  char player_name[8];
  item_head *items_head;
  uint32_t unk1;
  uint32_t unk2;
};

struct item_head
{
  item *first_item;
  uint32_t unk1;
  uint32_t unk2;
};

struct item
{
  int32_t item_num;
  item_data *data_ptr;
  struct item *next;
};

struct item_data
{
  int32_t unk1;
  char *data;
};
```

### alloc_chunk

All allocations of the program are being performed from this method, instead of raw `malloc`. \
This method allocates a surprise chunk of randomized size, and returns an offset between `0 - 3` to our allocated chunk, hence the returned chunk may be unaligned. 

## Vuln Research

### spawn_monster

This method gives us unlimited large allocations primitive, by calling `alloc_chunk(0x4010)`, and populates it with nearly arbitrary content of our wish:

```c
monst->rand_1 = random_num(31337);
monst->expr = get_number();                   // ACID
body_color = get_number();
for ( i = 0; i <= 4095; ++i )
  monst->body_color[i] = body_color;          // ACID
monst->name_ptr = read_string(8u);            // ACID
```

No vulns.

### hunt_monster

Frees the global `monst_ptr`, and setting it to NULL - preventing any UAFs using that pointer. \
While there are no vulns, upon freeing the monster, preceding allocations would be made by that exact monster's previously-occupied memory. 

```c
free_wrapper(monst_ptr);  // Allocations would now be performed from the freed chunk
monst_ptr = NULL;
```

### change_player

Allocates a new `items_head` chunk, initializes all of its members correctly to some junk. \
Reads 8 bytes to 8 byte name buffer, hence producing an **untruncated string vuln**:

```c
read(0, player_state_ptr, 8u);  // vuln: doesn't checks for null truncation!
player_state_ptr->items_head = s;
```

This means we are able to read past that string buffer, which, according to `struct player_state`, is the address of `items_head` (which is a heap addr).

### buy_item

Starts by reading an input number, denoting the `item_num`. **logical vuln:** incase an invalid number is supplied, the program flow continues, and the function isn't returned:

```c
number = get_number();
item_num = number;  // Note - we can set arbitrary value, lol
switch ( number )
{
...
default:
    puts("invalid choice"); 
    break;
}
// Regular flow
```

That is an interesting primitive, as this value is used for writing to some memory address later on:

```c
item_->next->item_num = item_num;  // Arbitrary value write
```

Afterwards, the items linked list is being traversed on, as follows:

```c
item_ = player_state_ptr->items_head->first_item;// Not guranteed to be initialized underneath
  if ( items_created )
  {
    for ( i = 1; i < items_created; ++i )       // sus: traverses based on items created, not up to finding a NULL ptr. 
      item_ = item_->next;
    ...
  }
```

While there is no direct vuln here, this implementation is exteremly sus. Usually we won't keep track of the amount of items within a linked list within some random global variable. In particular, the stop criteria of the loop is NOT if `item_->next == NULL`, but this global variable value. Very sus. \
Next, there are **2 uninitialized allocations vulns:**

```c
item_->next = (struct item *)alloc_chunk(0xC);  // Vuln: while data_ptr and item_num are initialized, 'next' isnt
next = item_->next;
next->data_ptr = (item_data *)alloc_chunk(8);   // Another vuln: doesn't initializes first 4 bytes of item_data
item_->next->data_ptr->data = item_name_ptr;    // Stores some crap pointer there, we dont care
item_->next->item_num = item_num;               // arbitrary value write
```

This is some very interesting vuln - if we would be able to allocate `struct item` on some garbage-containing memory, we would be able to control its `next` pointer! \
Along with a corruption of the start of the linked list head, or the amount of items to-be traversed over, we can perform OOB-read within `next = item_->next`. 

### secret_menu

Allocates a command string within the heap:

```c
cmd = read_string(0x14u);
```

Very sus behavior to allocate dynamically a string of known size. Moreover, its corresponding bin size matches `struct player_state`. \
Next, there are many handlers, giving us the following possible vulnerabilities:

```c
/* Vuln 1 - corrupt chunk's size LSB*/
*(cmd - 1) = 0xFF; 
/* Vuln 2 - corrupt chunk's size previous LSB*/
*(cmd - 2) = 0xFF;
/* Vuln 3 - triple free. But AFAIK even libc-2.23 mitigates this, AND the chunks aren't 100% aligned.. */
free(cmd);
free(cmd);
free(cmd);
/* Vuln 4 - Free of the player state, without nullifying its value. UAF. */
if ( (unsigned int)items_created > 0xA )
    free_wrapper(player_state_ptr);
/* Not a vuln by itself, but this means our goal is to overwrite the global command pointer */
system(command);   
```

Personally I've only used vuln(4). \
Vuln(2) can be used in addition to (4), forging a very large fake free chunk, hence - monsters would be allocated on it, overwriting any prior existing memory there. 

### gen_num

There's actually an OOB-read vuln within this function. Recall this method is pretty simple:

```c
char s[16]; 
memset(s, 0, sizeof(s));
if ( !read(0, s, 0x10u) )                     
{
  puts("I/O error2");
  exit(0);
}
return atoi(s);  
```

If we would fill all 16-bytes of the buffer with non-null characters, `atoi` would actually read past that buffer until it would encounter a null byte - and return the whole evaluated number. This may serve as a stack leak primitive, for whatever content that resides within the stack. \
However, for this compiled environment, the **stack canary** resides right after the `s` local buffer. Because the canary has LSB of `\x00`, the OOB-read is only 1 byte long, and it has no impact:

```bash
pwndbg> x/10gx $eax
0xffffd0dc:     0x3131313131313131      0x3131313131313131
0xffffd0ec:     0x08049540e8cc0d00      0xffffd1180804c052
```

If there would be other local variables, or the binary wouldv'e been compiled without canaries, this vuln would be useful. 

## Exploitation

For convenient debugging, I've wrote `patch_libs.sh` and fetched `ld` and `libc` off pwnable's servers:

```bash
#!/bin/sh

BINARY="./hunter"
patchelf --set-interpreter ./ld-linux.so.2 $BINARY
patchelf --replace-needed libc.so.6 ./libc.so.6 $BINARY
```

My goal exploitation idea is simple - using `item->next->item_num = item_num`, I'd overwrite an allocated chunk, stored at `item->next`, to arbitrary content. This chunk shall be stored within the global `char *command`. In order to do so, I'd have to control the value of `item_->next`. \
Because of the UAF, `player_state` is being added to `fastbins[0x20]`. The only other object that matches this bin, is the `cmd` within the secret menu, which we can fully control of. Hence, this would allow us complete control over the `player_state`, and `player_state->items_head` value in particular. If we'd make this value to point towards the SECOND element within the list, instead of the first, we would actually perform 1 extra read off the linked list, setting `item` to a possibly uninitalized `item->next`. \
But how can we control the uninitialized memory of `item->next`? We can utilize the large allocation performed by monster. Upon freeing its memory, all preceding allocations (and `struct item` in particular) would be formed by this freed chunk:

```bash
pwndbg> x/20wx 0x96c2190
0x96c2190:      0x00000000      0x00004019      0xeca8e7b0      0xeca8e7b0
0x96c21a0:      0x00000000      0x00000000      0x43434343      0x43434343
0x96c21b0:      0x43434343      0x43434343      0x43434343      0x43434343
```

And after 1 allocation (2 including the surprise allocation), the chunk is being consolidated:

```bash
pwndbg> x/30wx 0x8b9d120
0x8b9d120:      0x00000000      0x00000000      0x00000000      0x00000019
0x8b9d130:      0xee3bcb38      0xee3bcb38      0x08b9d128      0x08b9d128
0x8b9d140:      0x43434343      0x00000019      0x00000000      0x00007121
0x8b9d150:      0x00007149      0x00000000      0x43434343      0x00003fe9
0x8b9d160:      0xee3bc7b0      0xee3bc7b0      0x00000000      0x00000000
0x8b9d170:      0x43434343      0x43434343      0x43434343      0x43434343
```

This means that by carefully choosing the value to-be-sprayed within the monster, we can actually set the uninitialized value of `item->next`. \
One last question resides - for every allocation that is being made off the large monster chunk, a consolidation actually happens. In particular, we can see **it leaves trails of metadata within the heap**. For example, for the very first allocation, `fd, bk` pointers of `0xeca8e7b0` are being left. Moreover, 2 `NULL` ptrs are also being written! Those `NULL`s are actually `fd_nextsize, bk_nextsize`, which are written for chunks adequate to serve the largebins. \
Some exploitation routes may face big trouble due to that heap metadata corruption, but a clever reader shall find a way to bypass this from happening (hint: find a way to cause allocations to be performed NOT from the largebins!). \
Upon forging the `item->next` fake pointer, we're basically done - as we can allocate a chunk (whom first 4 bytes are fully controlled) to an arbitrary address. The only thing we have to consider, is the MASSIVE randomization that is being made - both for allocation amount, sizes, returned non-alignmented chunks, and more. Enough brute-force (~10 minutes) may solve this (and this was my approach..) but I'm sure there are better ways, probably involving the other vuln(2). 

## Control vs. Data

Upon solving this challenge, I was pretty surprised that such a mediocre challenge was ranked as the hardest within pwnable (I know it sounds arrogant, yet other challenges, such as "Tiny Hard" were WAYYY more challenging for me). Therefore, I've read some other solutions within pwnable to see what am I missing. \
Many (all) of them were indeed WAYYY more complicated than my approach, and only one other dude took a similar approach to my pretty-simple exploitation route. \
I don't think my solution is any better (in fact, its working statistics are awful, if not the worst of them all). However, I do think that all of these complicated solutions had one thing in common - **control plane exploitation**, as opposed to my solution, which was a pure **data plane exploitation**. What I mean by this, is that most solutions leveraged internals of the glibc allocator, such as corrupting the various `fd, bk, size, prevsize, flags`, or metadata arena addresses, and other objects of the allocator itself. However, my solution purely based on the **program** defined `item->next` corruption, making it completely agnostic to allocator-specific details (I guess most people didn't notice the uninitialized `next` pointer vulnerability). \
In general, I always prefer data-plane exploitation, as it is usually simpler. However, its learned techniques are very program-dependent, and not generic among different programs that uses the same allocator. 
