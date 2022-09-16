---
layout: post
title:  "Realloc Deep Shit"
date:   2022-09-10 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Lately i've researched some binary, and came across a funny exploitation scenario. 
This led me to research into realloc's pitfalls & implementation more in-depth, hence creating this post. 


## The problem

Within the binary, there were no calls to free() at all. 
Yet - it was still possible to craft *double* free vuln. 

A very simplistic form of the challenge's flow looks similar to the following code snippet:

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
        void *my_ptr = malloc(sizeof(int));  
        printf("my_ptr:%p\n", my_ptr);

        void *ret_val = realloc(my_ptr, 0);                     // Equivalent to free
        if (ret_val != NULL)
        {
                perror("realloc: free failed");
                exit(1);
        }

        void *my_new_ptr = realloc(my_ptr, 8 * sizeof(int));    // Different bin allocation
        printf("my_new_ptr:%p\n", my_new_ptr);

        return 0;
}

```

By running this code, a core dump is being generated. 

## realloc - edge cases
As stated by `realloc`'s manual page:
1. `realloc(NULL, size)` is equivalent to `malloc(size)`

2. `realloc(ptr, 0)` is equivalent to `free(ptr)`. 

3. `realloc` *might* move the allocated chunk, into some other memory address. 

Few rised questions: 

1. What is the return value of `realloc(NULL, 0)`? 

2. What are the criterias that trigger a move of a chunk? 

3. What happens when mixing allocations of multiple chunks, of the same size? 

4. Is the return value of a freed pointer by `realloc` always `NULL`? 








## Awesome resources
