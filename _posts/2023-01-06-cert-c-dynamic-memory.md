---
layout: post
title:  "CERT C - Chapter 8 - Dynamic Memory"
date:   2023-01-09 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

The C specification provides 4 memory allocation functions, all are widely available on multiple platforms.

CERT C chapter 8 describes the secure coding guidelines for dynamic memory. \
It can be found [here-C][cert-c] or [here-CPP][cert-cpp].

The full CWE list can be found [here][cwe-list].


### malloc

`malloc(size_t size)` - allocates `size` bytes, returns ptr to the allocated memory chunk. 

The pointer is always aligned. 

For example, the `glibc - 64 bit` implementation of `malloc` allocates `align16(size + 8)` bytes - extra 8 for the header, and alignment of 16. 

It means that the optimum chunk size for "as tight as possible" allocations, is one that satisfies `size % 16 == 8`, for example `0x38`.

Note that the allocated memory *is not initialized to known value* - meaning if a chunk is being reused, old data might be reused.

### aligned_alloc

`aligned_alloc(size_t alignment, size_t size)` - generalization of `malloc`, that lets the user align memory as he wishes, not only to 16 bytes. 

Usually it may come handy by aligning to cache-lines / pages granularity.

Note that the value of `size` must be an integer multiple of `alignment` - otherwise *undefined behavior occurs*. 

### realloc

`realloc(void *p, size_t size)` - can change the size of an allocated memory block, pointed to by `p`, to a new size - `size`. 

There are many caveats with this function. 

newly allocated memory will be uninitialized. Content will be unchanged up to the `min(old_sz, new_sz)`, with the exception of `new_sz == 0`. 

If the memory request cannot be made successfully, the old memory is left intact. 

If `p == NULL`, the call is equivalent to `malloc(size)`.

If `size == 0`, the call is equivalent to `free(p)`! \
This may be very surprising, and lead to unexpected UAF / double free vulns. 

Moreover, sometimes memory chunks cannot be increased - as there is an allocated succeeding chunk after them. \
In such cases, `realloc` implicitly `free`s the old chunk, and copies its content to a newly-allocated chunk at another region. \
This may leave old memory on the heap (as it isn't `memset`'ed), and more importantly - invalidates any of the pointers to the original chunk! 

### calloc

`calloc(size_t nmemb, size_t size)` - allocates a total of `nmemb * size` bytes (must verify it does not wraps-around the maximal integer value), and returns pointer to allocated memory. \
This time, the content of the chunk is initialized to contain `\x00` bytes. 

All memory allocation functions returns a `NULL` ptr in case of fail - which should be checked prior dereferencing. 

### free

`free(void *p)` - Used for deallocation. \
Note that `free(NULL)` is completely fine, and no operation is performed in such case. 

## Alignment

As mentioned, `aligned_alloc` can be used for alignned allocations. 

The alignment of certain object may be found via `alignof`. 

The main issue with allocating strictly aligned memory is reallocation. \
If `realloc` is called on a pointer returned from `aligned_alloc`, there is no gurantee of an alignment stricter than the normal alignment. 

`MEM36-C` explains this issue. \
For example:

```c
size_t resize = 1024;
  size_t alignment = 4096;
  int *ptr;
  int *ptr1;
   
  if (NULL == (ptr = (int *)aligned_alloc(alignment, sizeof(int)))) {
    /* Handle error */
  }
 
  if (NULL == (ptr1 = (int *)realloc(ptr, resize))) {
    /* Handle error */
  }
```

Because `resize > sizeof(int)`, `realloc` allocates new chunk, which may start from a different memory address (in case there is a succeeding chunk). 

In that case, the newly allocated chunk may not be aligned anymore. 

The guideline recommends not using `realloc` at all, for allocations involving alignment constraints. 

Memory should be manually re-`aligned-alloc`'ed, `memcpy`'d, and `free`'d. 

## alloca

Allocates memory within the stack. \
Automatically freed when the function returns, should *not* be called within `free`.

Often implemented as `inline`, with *only a signle instruction to adjust $rsp*. \
It means it does not return a `NULL` upon error, and can make allocations that exceeds the stack's bounds. 

This macro should be avoided. It may easily exhaust the stack memory, for large allocations.

A better alternative that some compilers supports, are variable-length-arrays (VLAs). \
These are arrays, having `size` initialized as a runtime variable, instead of a constant integer:

```c
int f (size_t size)
{
    char vla[size];
}
```

The allocated buffer lifetime is its declaration scope. \
Note that jumpion to another block / embedded block *prior to the declaration*, should not allocate the buffer (in most compilers). 

If `size` is a signed, negative integer - undefined behavior occurs. 

Moreover, for extremely large values, allocations may exceed the bounds of the stack - and even wrap around the virtual address space. \
This can be useful in order to overwrite program data (recall that the stack grows downwards tho). 

Therefore, sanitazion of VLA arguments are very important. 

`ARR32-C` describes this issue. 

Note that `sizeof` operator on a VLA returns its real size. \
This kind of surprised me, as im used to think on `sizeof` as a fully compile-time mechanism. 

## Common Memory Management Errors

### Initialization Errors

A common error is to assume `malloc` initializes the returned memory chunk to all bytes zero. \
`MEM09-C` (`CWE-665`) describes this issue.

Instead, the program should explicitly call `memset`, or even better - call `calloc`. \
It is important to verify, that `calloc` arguments doesn't wraps around, after multiplied (`MEM07-C`). 

An example vuln occured within the `tarball` program - which creates archive files on Unix. \
A sequence of calls for `malloc, free` were used. \ Therefore, uninitalized memory chunks contained fragments of the `/etc/passwd` file!

The fix was a modification to `calloc(1, SIZE)` instead. 

Note that this solution is not hermetic - as it implicitly assumes the preceding `free`'d chunk (that contains the sensitive data) would be null'ed by the succeeding `calloc` call. \
However, it isn't guranteed. 

A better paradigm is to use both `calloc`, as well as explicitly `memset` the sensitive data buffer, prior to `free`ing it - as `MEM03-C` recommends.

Example vuln:

```c
char *secret;
 
/* Initialize secret */
 
size_t secret_size = strlen(secret);
/* ... */
if (secret_size > SIZE_MAX/2) {
   /* Handle error condition */
}
else {
secret = (char *)realloc(secret, secret_size * 2);
}
```

So because of the `realloc`, the memory chunk may be allocated elsewhere, leaving the old sensitive data on the heap (as a free chunk). 

Note that compiler optimizations may remove `memset` call. \
So it should be replaced by `memset_s` (`MSC06-C`).

### Unchecked Return Values

Once all virtual memory is allocated, requests for more memory will fail. 

Linux behavior supports large allocations, that may be of size of the whole virtual memory. \
However, whenever the process tries to access memory that cannot be backed up by RAM / swap memory, it is killed. 

Memory exhausion may be caused by:

1. memory leak primitive

2. Incorrect structs implementation

3. Overall system exhausion, due to other processes

`MEM11-C` suggests to never assume infinite heap space. 

The allocation functions always returns a `NULL` pointer, upon failure. 

An example vuln is `CVE-2007-0071`. \
A `calloc` might fail due to memory exhausion, and return a `NULL` pointer. \
Because the return value of the vulnerable program isn't checked, the program continues. \
While usually dereferencing null pointer crashes the program, in this specific case, the return value (0) was added with a certain offset - which was controlled by the attacker. \
It basically means an arbitrary write primitive. 

`MEM32-C` states the importance of detection and handling of memory allocation errors. 

Example of vulnerable code, where the attacker controls the various `temp*` variables:

```c
signal_info * start = malloc(num_of_records * sizeof(signal_info));
signal_info * point = (signal_info *)start;
point = start + temp_num - 1;
memcpy(point->sig_desc, tmp2, strlen(tmp2));
```

Of course, there is an integer overflow in case `num_of_records` is controlled. \
However, even if it isn't - in case there is a memory leakage primitive, that allows `malloc` to fail, `start` would contain the value of 0. \
Since attacker fully controls the `tmp` variables, the target address `point` is arbitrary, and so is its written content, `tmp2`.

### Dereferencing Null / Invalid Pointers

Typically, dereferencing null pointer results in a segmentation fault, with the exception of computer systems with memory starting from 0 (old supercomputers for example). \
Some embedded devices have registers mapped at address 0. 

`EXP34-C` describes this problem. \
For example:

```c
void f(const char *input_str) {
  size_t size = strlen(input_str) + 1;
  char *c_str = (char *)malloc(size);
  memcpy(c_str, input_str, size);
  /* ... */
  free(c_str);
  c_str = NULL;
  /* ... */
}
```

The above code lacks two checks: `input_str` might be `NULL`, hence the `strlen` may cause null-dereference, as well as the `c_str` returned by the `malloc` call. 

Another example from the linux 2.6 kernel, handling `tun` drivers:

```c
static unsigned int tun_chr_poll(struct file *file, poll_table *wait)  {
  struct tun_file *tfile = file->private_data;
  struct tun_struct *tun = __tun_get(tfile);
  struct sock *sk = tun->sk;
  unsigned int mask = 0;
 
  if (!tun)
    return POLLERR;
 
  DBG(KERN_INFO "%s: tun_chr_poll\n", tun->dev->name);
 
  poll_wait(file, &tun->socket.wait, wait);
 
  if (!skb_queue_empty(&tun->readq))
    mask |= POLLIN | POLLRDNORM;
 
  if (sock_writeable(sk) ||
     (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
     sock_writeable(sk)))
    mask |= POLLOUT | POLLWRNORM;
 
  if (tun->dev->reg_state != NETREG_REGISTERED)
    mask = POLLERR;
 
  tun_put(tun);
  return mask;
}
```

All pointers lacks sanitazion of `NULL` values: `file, tfile, tun, sk`.

The weirdest of them all is the assignment of `sk = tun->sk`, which occurs before `tun` sanitazion. 

An example vuln resides within an old version of `libpng`, which implements its own `malloc` wrapper:

```c
png_charp chunkdata;
chunkdata = (png_charp)png_malloc(png_ptr, length + 1);
```

`chunkdata` is later used in a destination of `memcpy`. 

If `length == -1`, an 0 bytes allocation is requested, and the wrapper returns a `NULL` ptr - which is assigned to `chunkdata`. \
This specific lib runned on an ARM cellphone, which had address 0 mapped in memory, served as the `exception vector table` - which made the bug exploitable. 

`MEM35-C` (under allocation) and `MEM04-C` (zero length allocations) are violated. \
Also, why the hell was `length` declared as a signed integer..?

An example classic vuln:

```c
struct tm *tmb;
  tmb = (struct tm *)malloc(sizeof(tmb));
  if (tmb == NULL) {
    return NULL;
  }
  *tmb = (struct tm) {
    .tm_sec = sec, .tm_min = min, .tm_hour = hour,
    .tm_mday = day, .tm_mon = mon, .tm_year = year
  };
```

`malloc` receives as an argument the `sizeof` a pointer type (4 / 8 bytes), NOT the underlying `struct tm`. 

It should be changed to `malloc(sizeof(*tmb))`. \
Note that it does not causes a segmentation fault.

### Referencing Freed Memory

It is possible to access freed memory, unless all pointers to that memory have been set to `NULL`. 

It is a common belief that `free` sets the pointer value to `NULL` - which is of course incorrect (as it cannot even modify the pointer value, being `void *` argument). 

A classic vuln, traversing over a linked list:

```c
for (p = head; p != NULL; p = p->next)
  free(p);
```

The iteration continues by actually exploiting a UAF - where `p->next` is accessed right after a prior `free`. 

Note that depending on the underlying type, this may actually be exploitable - as usually `free` involves by modifying the `fd, bk` internal pointers of the memory chunk (depending on its corresponding bin, tho). \
If `p->next` would be at least within offset 16 bytes of the struct (8 bytes for each of fd, bk), this won't be trivially exploitable. 

Note that there might still be reallocations, or even worse - races on the shared memory. 

### Freeing Memory Multiple Times

Most noteably, the `double-free` vulns. 

This may corrupt the internal data-structures of the memory manager (the arenas) in a manner that is usually not immediately apparent - usually, by *inserting a chunk twice to the same bin*.

These kind of vulnerabilities can be exploited via cool techniques, such as `tcache dup` and `fastbin dup`. 

A common error is caused by incorrect copy-paste:

```c
x = malloc(n * sizeof(int));
free(x);
y = malloc(n * sizeof(int));
free(x);
```

Another frequent cause is in error handling: where both cleanup handler, and the normal processing, `free`s a certain object. 

### Memory Leaks

There might be not trivial memory leaks.

For example, allocating a block of memory just once, during program startup (which often isn't considered to be memory leak) - In case this program is a loadable library, which is loaded and unloaded into memory, it can quickly exhaust the available memory. 

Once memory is exhausted, additional allocations will fail, and the application won't be able to process any user requests - without necessarily crashing (as there might be code handling for such cases). \
This can be used to probe error recovery code for double free vulns. 

### Zero Length Allocations

The behavior of zero length allocations is implementation-defined. 

Modern glibc returns a non `NULL` ptr, which should not be used to access an object (usually it is a chunk of `MINSIZE==0x20`). 

Other options are for the pointer to refer to a zero-length data block, hence the chunk consists entirely of control structures. 

`MEM04-C` describes this issue. 

`realloc` is very problematic. \
It deallocates the old object, and returns a pointer to a new object of the desired size. \
If new memory cannot be allocated, it doesn't frees the old object - and its value left unchanged. 

Usually, `realloc` of size 0 means a `free`. \
The return value in such case is a `NULL` ptr. \
This may easily cause double-frees and UAFs.

These types of bugs are so common, that the first ever DR (defect-record-400) of the C11, was about zero length allocations via `realloc` - [dr-400][dr-400].

This feature is so terrible, that it was even declared as an *obsolescent feature* - which shouldn't be used at all, according to `MSC23-C`.


## CERT C Examples

### MEM00-C

Freeing memory in different modules may cause some very non trivial vulns. \
For example, MIT Kerberos 5 - which contained error-handling logic, that freed memory in addition to other external libraries error handling, which yield double free vuln. 

```c
enum { MIN_SIZE_ALLOWED = 32 };
 
int verify_size(char *list, size_t size) {
  if (size < MIN_SIZE_ALLOWED) {
    /* Handle error condition */
    free(list);
    return -1;
  }
  return 0;
}
 
void process_list(size_t number) {
  char *list = (char *)malloc(number);
  if (list == NULL) {
    /* Handle allocation error */
  }
 
  if (verify_size(list, number) == -1) {
      free(list);
      return;
  }
 
  /* Continue processing list */
 
  free(list);
}
```

This code contains a double-free vuln, resulting from memory being allocated and freed at different levels of abstraction. 

### MEM01-C

Right after `free()`ing a pointer, store a new value `NULL` in it. 

For example:

```c
char *message;
int message_type;
 
/* Initialize message and message_type */
 
if (message_type == value_1) {
  /* Process message type 1 */
  free(message);
}
/* ...*/
if (message_type == value_2) {
   /* Process message type 2 */
  free(message);
}
```

Upon calling this flow multiple times, a double free vuln may occur. 

A better paradigm is to set `message = NULL` after `free`. \
Because `free(NULL)` doesn't do anything, this paradigm is perfectly fine. 


### MEM02-C

memory allocation results should be casted to the allocated type immediately. 

```c
typedef struct gadget gadget;
struct gadget {
  int i;
  double d;
};
 
typedef struct widget widget;
struct widget {
  char c[10];
  int i;
  double d;
};
 
widget *p;
 
/* ... */
 
p = malloc(sizeof(gadget)); /* Imminent problem */
if (p != NULL) {
  p->i = 0;                 /* Undefined behavior */
  p->d = 0.0;               /* Undefined behavior */
}
```

The above code implicitly sets the type of the allocated chunk, which is of legnth `gadget`, to `widget`. \
Accessing its fields may lead to UB. 

### MEM03-C

Clear memory from reusable resources. 

```c
char *secret;
/* Initialize secret to a null-terminated byte string,
   of less than SIZE_MAX chars */
 
size_t size = strlen(secret);
char *new_secret;
new_secret = (char *)malloc(size+1);
if (!new_secret) {
  /* Handle error */
}
strcpy(new_secret, secret);
 
/* Process new_secret... */
 
free(new_secret);
new_secret = NULL;
```

The problem with this code, is the `new_secret` data still remains on the heap memory. \
For sensitive content, a non-compiled-able `memset_s` of null bytes should be called, prior to `free`ing the `new_secret` variable. 

Moreover, usages of `calloc(size + 1, 1)` is better, as it initializes the given secret memory to 0. 

### MEM04-C

zero-length allocations are implementation-defined. \
Either a `NULL` pointer returned, a small chunk is allocated, or a zero-length heap buffer is allocated (hence, only metadata). 

### MEM05-C

Avoid large stack allocations. \
Especially in situations where the attacker may control its length (VLAs / recursive allocations). 

For example:

```c
unsigned long fib1(unsigned int n) {
  if (n == 0) {
    return 0;
  }
  else if (n == 1 || n == 2) {
    return 1;
  }
  else {
    return fib1(n-1) + fib1(n-2);
  }
}
```

An attacker may control the recursive depth.\
For each step, a stack frame is being allocated. 

Therefore, exhausion of the stack memory is possible, leading to DoS for example (or limiting the entropy of ASLR, etc).

### MEM06-C

Beware of sensitive data being written to disk.

Two common mechanisms are swapping (paging), and core dumps.

Assuming attacker may crash the program during its runtime, or swap out a page of his wish, the following code may leak secret data into the disk:

```c
char *secret;
 
secret = (char *)malloc(size+1);
if (!secret) {
  /* Handle error */
}
 
/* Perform operations using secret... */
 
memset_s(secret, '\0', size+1);
free(secret);
secret = NULL;
```

The solution is to use `setrlimit` to prevent any core dump being generated. 

Moreover, paging may be disabled via `mlock` - meaning the memory would never be copied to hard disk. 

```c
#include <sys/resource.h>
/* ... */
struct rlimit limit;
limit.rlim_cur = 0;
limit.rlim_max = 0;
if (setrlimit(RLIMIT_CORE, &limit) != 0) {
    /* Handle error */
}
 
long pagesize = sysconf(_SC_PAGESIZE);
if (pagesize == -1) {
  /* Handle error */
}
 
char *secret_buf;
char *secret;
 
secret_buf = (char *)malloc(size+1+pagesize);
if (!secret_buf) {
  /* Handle error */
}
 
/* mlock() may require that address be a multiple of PAGESIZE */
secret = (char *)((((intptr_t)secret_buf + pagesize - 1) / pagesize) * pagesize);
 
if (mlock(secret, size+1) != 0) {
    /* Handle error */
}
 
/* Perform operations using secret... */
 
if (munlock(secret, size+1) != 0) {
    /* Handle error */
}
secret = NULL;
 
memset_s(secret_buf, '\0', size+1+pagesize);
free(secret_buf);
secret_buf = NULL;
```

### MEM07-C

Beware of integer wraps-arounds inside library function calls. 

A classic example is `calloc`:

```c
size_t num_elements;
 
long *buffer = (long *)calloc(num_elements, sizeof(long));
if (buffer == NULL) {
  /* Handle error condition */
}
/* ... */
free(buffer);
buffer = NULL;
```

The multiplication of `num_elements * sizeof(long)` may wrap around, leading to an under-allocation. 

### MEM11-C

Do not assume infinite heap memory.

Example vuln:

```c
enum {MAX_LENGTH=100};
 
typedef struct namelist_s {
  char name[MAX_LENGTH];
  struct namelist_s* next;
} *namelist_t;
 
int main() {
  namelist_t names = NULL;
  char new_name[MAX_LENGTH];
 
  do {
    /*
     * Adding unknown number of records to a list;
     * the user can enter as much data as he wants
     * and exhaust the heap.
     */
    puts("To quit, enter \"quit\"");
    puts("Enter record:");
    fgets(new_name, MAX_LENGTH, stdin);
    if (strcmp(new_name, "quit") != 0) {
      /*
       * Names continue to be added without bothering
       * about the size on the heap.
       */
      unsigned int i = strlen(new_name) - 1;
      if (new_name[i] == '\n') new_name[i] = '\0';
      namelist_t new_entry = (namelist_t) malloc(sizeof( struct namelist_s));
      if (new_entry == NULL) {
        /* Handle error */
      }
      strcpy( new_entry->name, new_name);
      new_entry->next = names;
      names = new_entry;
    }
    puts(new_name);
  } while (strcmp( new_name, "quit") != 0);
 
  return 0;
}
```

### MEM12-C

Use a goto chain upon error. 

Example leakage:

```c
typedef struct object {  /* Generic struct: contents don't matter */
  int propertyA, propertyB, propertyC;
} object_t;
 
errno_t do_something(void){
  FILE *fin1, *fin2;
  object_t *obj;
  errno_t ret_val;
   
  fin1 = fopen("some_file", "r");
  if (fin1 == NULL) {
    return errno;
  }
 
  fin2 = fopen("some_other_file", "r");
  if (fin2 == NULL) {
    fclose(fin1);
    return errno;
  }
 
  obj = malloc(sizeof(object_t));
  if (obj == NULL) {
    ret_val = errno;
    fclose(fin1);
    return ret_val;  /* Forgot to close fin2!! */
  }
 
  /* ... More code ... */
 
  fclose(fin1);
  fclose(fin2);
  free(obj);
  return NOERR;
}
```

A correct solution may has a single `goto` label (which then identifies which resources should be handled back), or just multiple labels usage:

```c
SUCCESS:     /* Clean up everything */
  free(obj);
 
FAIL_OBJ:   /* Otherwise, close only the resources we opened */
  fclose(fin2);
 
FAIL_FIN2:
  fclose(fin1);
 
FAIL_FIN1:
  return ret_val;
```

However, these kind of teardowns may be too large, and non-scalable, such as `copy_process` from the Linux kernel(under `kernel/fork.c`). 

### MEM30-C

Do not access freed object / double free. 

#### Real World Double Free

```c
void f(char *c_str1, size_t size) {
  char *c_str2 = (char *)realloc(c_str1, size);
  if (c_str2 == NULL) {
    free(c_str1);
  }
}
```

However, upon supplying `size == 0`, `realloc` would call `free(c_str1)`, and return a `NULL` ptr. \
Then, another free would be called, resulting with a double free vuln. 

#### CVE-2009-1364

```c
void gdClipSetAdd(gdImagePtr im, gdClipRectanglePtr rect) {
  gdClipRectanglePtr more;
  if (im->clip == 0) {
   /* ... */
  }
  if (im->clip->count == im->clip->max) {
    more = gdRealloc (im->clip->list,(im->clip->max + 8) *
                      sizeof (gdClipRectangle));
    /*
     * If the realloc fails, then we have not lost the
     * im->clip->list value.
     */
    if (more == 0) return;
    im->clip->max += 8;
  }
  im->clip->list[im->clip->count] = *rect;
  im->clip->count++; 
}
```

The above code contains UAF. 

`(im->clip->max + 8) * sizeof (gdClipRectangle)` may wrap around to `0`, meaning `free(im->clip->list)` would be called.

However, since this pointer is still set (within the struct) to some valid heap address, another calls to this function may cause direct writes to the `freed` memory, for example via:

```c
im->clip->list[im->clip->count] = *rect;
```

This UAF allows an attacker to corrupt heap metadata. 

Another option is to cause a re-location of the chunk, instead of freeing it - as `realloc` calls may allocate a new chunk, while freeing the old chunk. 

Therefore, it is important to update the returned pointer by `realloc`:

```c
more = gdRealloc (im->clip->list,(im->clip->max + 8) *
                      sizeof (gdClipRectangle));
im->clip->list = more;
```

### MEM31-C

Free unused buffers, to prevent memory leaks.

```c
enum { BUFFER_SIZE = 32 };
 
int f(void) {
  char *text_buffer = (char *)malloc(BUFFER_SIZE);
  if (text_buffer == NULL) {
    return -1;
  }
  return 0;
}
```

The above code causes a memory leak, for every time the function `f` is called. 

### MEM33-C

Flexible array members should be treated with extra care. 

For example, when computing the `sizeof` of the following struct:

```c
struct flex_array_struct {
  int num;
  int data[];
};
```

Only the first member is considered. 

Therefore, such structures should always be allocated dynamically. \
They should also never be copied by value. 

#### Storage Duration

```c
struct flex_array_struct {
  size_t num;
  int data[];
};
  
void func(void) {
  struct flex_array_struct flex_struct;
  size_t array_size = 4;
 
  /* Initialize structure */
  flex_struct.num = array_size;
 
  for (size_t i = 0; i < array_size; ++i) {
    flex_struct.data[i] = 0;
  }
}
```

The above code has OOB-write upon the assignment `flex_struct.data[i] = 0`, as it was statically under-allocated on the stack.

#### Copying

```c
struct flex_array_struct {
  size_t num;
  int data[];
};
  
void func(struct flex_array_struct *struct_a,
          struct flex_array_struct *struct_b) {
  *struct_b = *struct_a;
}
```

The above code dereferences both pointers, hence copies the underlying `flex_array_struct` object. 

However, the flexible array member is not considered - only the first member `num`. 

It should be explicitly copied via `memcpy` call.

#### Function Arguments

```c
struct flex_array_struct {
  size_t num;
  int data[];
};
  
void print_array(struct flex_array_struct struct_p) {
  puts("Array is: ");
  for (size_t i = 0; i < struct_p.num; ++i) {
    printf("%d ", struct_p.data[i]);
  }
  putchar('\n');
}
 
void func(void) {
  struct flex_array_struct *struct_p;
  size_t array_size = 4;
 
  /* Space is allocated for the struct */
  struct_p = (struct flex_array_struct *)malloc(
    sizeof(struct flex_array_struct)
    + sizeof(int) * array_size);
  if (struct_p == NULL) {
    /* Handle error */
  }
  struct_p->num = array_size;
 
  for (size_t i = 0; i < array_size; ++i) {
    struct_p->data[i] = i;
  }
  print_array(*struct_p);
}
```

Note this bug has implicit conversion from `size_t i` to an `int struct_p->data[i]`. 

The function argument receives a copy of the underlying object, which doesn't have allocated memory for the `data` flexible array member. 

This causes OOB-read of the stack. 

### MEM34-C

call `free` only on dynamically allocated memory. 

For example, do not use `realloc` on statically allocated memory (duh):

```c
void f(void) {
  char buf[BUFSIZE];
  char *p = (char *)realloc(buf, 2 * BUFSIZE);
  if (p == NULL) {
    /* Handle error */
  }
}
```


[cwe-list]: https://cwe.mitre.org/data/definitions/658.html
[cert-c]: https://wiki.sei.cmu.edu/confluence/display/c
[cert-cpp]: https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046329
[dr-400]: https://www.open-std.org/jtc1/sc22/wg14/www/docs/dr_400.htm
