---
layout: post
title:  "One Days - Uninitialized Data"
date:   2022-11-21 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## IDE Note

At this point I've started to use [Ecplise C / C++ package][eclipse] for code auditing. 

This IDE works pretty well under large scale of platforms (Linux, Windows, different archs and compilers, etc), similar to VScode (and unlike Clion). \
However, unlike VScode, it has even better static parsing mechanism, and faster navigation times. 

### Eclipse Config

By initializing Eclipse, select *Create C or C++ project* -> *Makefile Project*, and uncheck the *Generate Source and Makefile* option. 

Then, go to *Window* -> *Preferences* -> *Scalability*, and uncheck *Disable editor live parsing*, as well as *Alert me when scalability mode turned on* (which stops doing parsing for large files). \
Finally, change the scalability lines threshold to `999999` instead of `5000`.  

Next, type *Folding*, and select both *Enable folding of preprocessor branchs*, as well as *Enable folding of control flow statements*. 

Afterwards, drag the project source folder into the workspace bar within the IDE (use *Link to Files and Folders* for projects involving many checkouts). 

After the indexing procedure has completed, right click on the project's properties. \
Navigate to *C / C++ Include Path* -> *Add Preprocessor Symbol*, and set interesting symbol values (may display different code paths, depending on `#ifdefs` for example). 

### Eclipse Tricks

1. Search: `ctrl + h`. \
It is suggested to disable `git search` via *customize*. 

File search - searches for *all* pattern matches within all files. \
C / C++ search - searches for particular elements we pick, for example functions definitions, symbols, structs, etc. 

2. To navigate between scopes, `alt + arrow`. 

3. Find all references: `ctrl + shift + g`. This is especially useful for variables. 

4. View all of the possible call paths involving a certain function: `ctrl + alt + h`. \
This is an *extremely* useful feature, as it can show us registration of function pointers, for example. \
This is a better alternative than the regular "find all references", and allows easy backtracing!


## Background

UDA - Whenever memory isn't initialized, it takes whatever values already in that memory location. 

This becomes a vuln whenever the leftover values are ACID. 

The common 4 cases are:

1. Non initialized stack local variables at declaration time

2. Non initialized heap data at allocation time (`malloc`)

3. Partial initialization of structs, classes and objects (for example, CTOR that sets only part of the object's members).

4. Uncommon control flow path initialization failure - for example, passing a pointer to some "initialization function", which returns earlier than expected, hence leaving the pointer uninitialized. 

## Trivial Example - Stack

```c
void uda_func(int * p){
    int i;
    printf("We all know that %x is leet, right?\n", i);
}

void acid_setter_func(int * p){
    int i = *p;
    printf("We all know that %x is leet, right?\n", i);
}

int main(int argc, char * argv[]){
    char buf[8] = {0};
    int i = 0x1337;
    printf("argc = %d\n", argc);
    if(argc > 1)
    {
        strcpy(buf, argv[1]);
        i = *(int *)(&buf[0]);
    }
    if(buf[0])
    {
        acid_setter_func(&i);
    }
    uda_func(&i);
    return 0;
}
```

The above code initializes `buf` on the stack, within `main`. \
The `i` var value corresponds to the first 4 bytes of the inserted `buf`, interpreted according to an `int`. 

By calling `acid_setter_func`, its new stack frame is allocated, and stores the value of `*p` somewhere of this temporary stack frame. \
The stack unwinding does a simple `add esp`, the values on this temporary allocated frame remains there. \
Therefore, by calling `uda_func` (which has an identical stack frame size and offsets), its local `i` variable is actually initialized to the value we've set via `acid_setter_func`. 

## Trivial Example - Heap

```c
void opt_realloc(char ** buf1, char ** buf2){
    free(*buf1);
    free(*buf2);
    *buf2 = malloc(BUF_SIZE); //XENO: Note, I switched the order of allocs
    *buf1 = malloc(BUF_SIZE); //XENO: This was based on system-specific knowledge
    printf("buf1 addr = %p, buf2 addr = %p\n", *buf1, *buf2);
}

int main(int argc, char * argv[]){
    char * buf1 = malloc(BUF_SIZE);
    char * buf2 = malloc(BUF_SIZE);
    int * i = (int *)buf1;
    printf("buf1 addr = %p, buf2 addr = %p\n", buf1, buf2);
    printf("argc = %d\n", argc);
    if(argc > 1)
    {
        strcpy(buf1, argv[1]);
        memset(buf2, '!', BUF_SIZE);
    }
    if(buf1[0])
    {
        opt_realloc(&buf1, &buf2);
    }
    for(unsigned int j = 0; j < strlen(argv[1])/4; j++)
    {
        printf("At %p+%d:\t %x\n", i, j*4, *(int *)(i+j));
    }
    i = (int *)buf2;
    printf("\n");
    for(unsigned int j = 0; j < strlen(argv[1])/4; j++)
    {
        printf("At %p+%d:\t %x\n", i, j*4, *(int *)(i+j));
    }
    printf("At the end of the day, the important thing is: %x\n", *(int *)&buf1[16]);
    return 0;
}
```

This code has few problems: the `malloc` calls return values aren't checked, arbitrary `strcpy` to `buf1` from `argv[1]`, off-by-one by the `memset(buf2)` call (as it doesn't takes into account the terminating null-byte).

However, the main focus of this vuln is within `opt_realloc`. \
This function `free`s the allocated chunks, and re-allocates them by the original order (note that the LIFO / FIFO pattern is both platform dependent, as well as allocator and chunk size dependent). 

This means that after the call to `opt_realloc`, both loops would print content of the buffers. \
Note, that some of the printed values would now be garbage! \
This is because the `free` and subsequent `malloc` call would reuse heap memory. 

For example, while freeing `buf2`, the `free` call have set its `fd` pointer towards the freed prior chunk, `buf1`. \
This means that the `free` call have reused this qword address, and 
because `fd` overlaps the `user_content`, printing `buf2` would show some reused heap memory of the `buf1` chunk - and would give us a heap leakage primitive!

The core vuln here, is that `malloc` actually returns uninitialized data. \
Therefore, prefer using `calloc(1, size)` instead. 

Note that in this particular case, even `memset_s` the buffer prior to `free`ing them wouldn't prevent the heap leakage, as the second `free` call sets the first qword of `buf2` to a heap address. 

## Bonus - Exploitation

For stack and heap UDA, mostly stack grooming and heap feng shui. 

## CVE-BLA

### Code

### Code Review

### Patch

[eclipse]: https://www.eclipse.org/downloads/packages/release/2022-12/r/eclipse-ide-cc-developers
