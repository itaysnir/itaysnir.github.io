---
layout: post
title:  "realloc deep shit"
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

Within binary, there were no calls to free() at all. 
Yet - it was still possible to craft *double* free vuln (lol). 

A very basic form of the challenge's flow looks similar to this code snippet:

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
        void *my_ptr = realloc(NULL, sizeof(int));    // Equivalent to malloc
        printf("my_ptr:%p\n", my_ptr);


        void *ret_val = realloc(my_ptr, 0);           // Equivalent to free
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







## Awesome resources
