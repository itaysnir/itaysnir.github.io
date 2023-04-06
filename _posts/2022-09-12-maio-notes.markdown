---
layout: post
title:  "MAIO Notes"
date:   2022-09-12 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

In order to implement zerocopy RX flow for async mechanism (such as IO uring), we've implemented MAIO. 

MAIO stands for "memory allocator for I/O". \
It includes a page allocator, for shared memory (kernel<->user), for special dedicated I/O pages. 

This document summerizes the key implementation notes. \
The full code can be found at [github][github].

## API

Initialize MAIO pages: 

```c
void *cache = init_hp_memory(PAGE_CNT);
```

The custom kernel uses 2MB huge pages (not 1GB) for MAIO memory. \
The function `init_hp_memory` allocates `PAGE_CNT * 2MB` bytes, and creates a dedicated memory translation table (MTT) for this process. \
The MTT is used in order to avoid accessing the user's page table. 

Create kernel socket:

```c
int idx = create_connected_socket(dip, port);
```

Creates a kernel TCP socket, and connects to dest. \
Note the returned `idx` is not a file descriptor, but an internel MAIO id. 

```c
char *buffer = alloc_page(cache);
```

Allocates a 4KB page out of the allocated MAIO pages. 

Initialize TCP ring:

```c
init_tcp_ring(idx, cache);
```

This function associates an async I/O ring with dedicated MAIO pages memory pool. \
`idx` represents the TCP kernel socket, while `cache` the MAIO pages pool 

Send ZC operation:

```c
send_buffer(idx, buffer, len, flags);
```

Note the associated kernel thread uses `tcp_sendpage` in order to send the page without copying. 




[github]: https://github.com/itaysnir/maio_rfc
